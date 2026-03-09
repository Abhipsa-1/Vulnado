"""
VULNADO ReAct Agent
--------------------
Orchestrates the Thought → Action → Observation loop.

Flow:
  1. User message arrives at agent.run()
  2. Build message history with system prompt
  3. Call Groq LLM → get JSON response
  4. Parse JSON:
       - action == tool name  → call tool, append observation, loop
       - action == FINAL_ANSWER → return answer to caller
  5. Repeat up to MAX_ITERATIONS (5)
  6. If loop exhausted → return best partial answer

Model strategy (Groq free tier — as of March 2026):
  ┌──────────────────────────────────┬───────────┬──────────────┬──────────┐
  │ Model                            │ Context   │ Speed (t/s)  │ TPM      │
  ├──────────────────────────────────┼───────────┼──────────────┼──────────┤
  │ PRIMARY  llama-3.1-8b-instant    │ 131 072 t │ 560          │ 250k     │
  │ FALLBACK llama-3.3-70b-versatile │ 131 072 t │ 280          │ 300k     │
  │ ECONOMY  openai/gpt-oss-20b      │ 131 072 t │ 1000         │ 250k     │
  └──────────────────────────────────┴───────────┴──────────────┴──────────┘

  8b-instant is PRIMARY for latency:
  - 560 t/s vs 280 t/s for 70b  →  2× faster time-to-first-token
  - ReAct tool steps only need 512 tokens; 8b handles JSON format reliably
  - 70b as fallback for complex multi-hop reasoning if 8b rate-limited

max_tokens strategy (latency-critical):
  - Tool step:   512 tokens  (just a JSON action object, never needs more)
  - Final answer: 1024 tokens (enough for a rich markdown answer)
  Cutting from 2048→1024 and 1024→512 halves generation time per call.

LLM parameters:
  temperature=0.0  → fully deterministic JSON (no creative variation needed)
  top_p=0.9        → nucleus sampling — keeps 90% probability mass (avoids tail tokens)
  top_k=40         → only sample from top 40 tokens (prevents hallucination of CVE IDs)
  max_tokens=1024  → enough for one ReAct step; final answers get 2048
  frequency_penalty=0.1 → mild penalty against repeating the same JSON keys verbatim

Context window management:
  - Estimate tokens as len(text)//4 (conservative, ~4 chars/token)
  - Hard limit: 28k tokens (leaves 4k headroom in 32k context)
  - When approaching limit: drop oldest tool observation pairs, keep system+user+last 2 turns

Rate limit handling:
  - Primary model 429 → auto-retry with FALLBACK, then ECONOMY
  - All models 429 → return friendly error with exact retry time from Groq response
"""

import json
import logging
import os
import re
import time
from typing import Optional

from VULNADO.bot.prompts import SYSTEM_PROMPT, FEW_SHOT_PRIMER_USER, FEW_SHOT_PRIMER_ASSISTANT, observation_message
from VULNADO.bot.tools import TOOLS

logger = logging.getLogger(__name__)

# Mandatory 3-step CVE investigation tools (must all run before FINAL_ANSWER)
CVE_WORKFLOW_TOOLS = ["get_cve_detail", "get_mitre_techniques", "get_remediation"]

# ---------------------------------------------------------------------------
# Model cascade — ordered by SPEED first (all PRODUCTION models, March 2026)
# ---------------------------------------------------------------------------
PRIMARY_MODEL  = "llama-3.1-8b-instant"        # 560 t/s — fastest, PRIMARY for low latency
FALLBACK_MODEL = "llama-3.3-70b-versatile"     # 280 t/s — better reasoning, fallback
ECONOMY_MODEL  = "openai/gpt-oss-20b"          # 1000 t/s — ultra-fast emergency fallback
MODEL_CASCADE  = [PRIMARY_MODEL, FALLBACK_MODEL, ECONOMY_MODEL]

# Context window limits per model (tokens) — all 131k as of March 2026
MODEL_CTX_LIMIT = {
    PRIMARY_MODEL:  131_072,
    FALLBACK_MODEL: 131_072,
    ECONOMY_MODEL:  131_072,
}

# Stay 15% below the hard limit to be safe
CTX_SAFETY_FACTOR = 0.85

# max_tokens per call type — keep small to minimise generation time
MAX_TOKENS_TOOL_STEP    = 512    # a ReAct JSON action object is always < 200 tokens
MAX_TOKENS_FINAL_ANSWER = 1024   # enough for a rich markdown answer
MAX_ITERATIONS          = 5      # cap the ReAct loop


# ---------------------------------------------------------------------------
# Groq client — lazy singleton
# ---------------------------------------------------------------------------

_groq_client = None


def _get_groq():
    global _groq_client
    if _groq_client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "GROQ_API_KEY environment variable not set. "
                "Get a free key at https://console.groq.com"
            )
        try:
            from groq import Groq
            _groq_client = Groq(api_key=api_key)
        except ImportError:
            raise ImportError("groq package not installed. Run: pip install groq")
    return _groq_client


# ---------------------------------------------------------------------------
# Token estimation — fast heuristic (4 chars ≈ 1 token)
# ---------------------------------------------------------------------------

def _estimate_tokens(messages: list) -> int:
    """Estimate total token count for a message list."""
    total = 0
    for m in messages:
        total += len(m.get("content", "")) // 4
        total += 4   # role + formatting overhead per message
    return total


def _trim_messages(messages: list, model: str) -> list:
    """
    Trim conversation history to fit within the model's context window.

    Message layout from run():
      [0] system prompt
      [1] few-shot primer user
      [2] few-shot primer assistant
      [3] real user query          ← always keep
      [4+] tool call / observation pairs

    Strategy:
      - Hard anchors: [0] system + [3] real user query
      - Soft anchors: [1],[2] few-shot primer — drop these FIRST when trimming
      - Keep last 4 messages unconditionally (last 2 turns of real conversation)
    """
    ctx_limit = int(MODEL_CTX_LIMIT.get(model, 131_072) * CTX_SAFETY_FACTOR)

    if _estimate_tokens(messages) <= ctx_limit:
        return messages  # already fits — fast path

    # Hard anchors: system (0) + real user query (3 if primer present, else 1)
    has_primer = (
        len(messages) >= 4
        and messages[1].get("content") == FEW_SHOT_PRIMER_USER
    )

    if has_primer:
        hard_anchors = [messages[0], messages[3]]
        soft_primer  = messages[1:3]       # drop these first
        middle       = messages[4:]
    else:
        hard_anchors = [messages[0], messages[1]]
        soft_primer  = []
        middle       = messages[2:]

    tail = middle[-4:] if len(middle) >= 4 else middle[:]
    head = middle[:-4] if len(middle) >= 4 else []

    # Step 1: try dropping only the oldest head pairs
    candidate = hard_anchors + soft_primer + head + tail
    while head and _estimate_tokens(candidate) > ctx_limit:
        head = head[2:]
        candidate = hard_anchors + soft_primer + head + tail

    # Step 2: if still too long, drop the few-shot primer
    if _estimate_tokens(candidate) > ctx_limit:
        candidate = hard_anchors + head + tail
        logger.info("[Agent] Dropped few-shot primer to fit context window")

    dropped = len(messages) - len(candidate)
    if dropped:
        logger.info("[Agent] Trimmed %d messages for %s", dropped, model)
    return candidate


# ---------------------------------------------------------------------------
# LLM call — tuned parameters + 3-model cascade for rate limits
# ---------------------------------------------------------------------------

def _call_llm(messages: list, model: str = PRIMARY_MODEL, is_final: bool = False) -> str:
    """
    Send messages to Groq and return raw text response.

    Parameters:
      temperature=0.0   → deterministic; reliable JSON output
      top_p=0.9         → nucleus sampling; focus on high-probability tokens
      max_tokens        → 512 for tool steps (tiny JSON), 1024 for final answers
      frequency_penalty → 0.1 prevents repeating JSON scaffold verbatim

    On 429 → cascades through MODEL_CASCADE automatically.
    """
    client = _get_groq()
    max_tokens = MAX_TOKENS_FINAL_ANSWER if is_final else MAX_TOKENS_TOOL_STEP

    def _invoke(m: str) -> str:
        trimmed = _trim_messages(messages, m)
        logger.debug(
            "[Agent] Calling %s | est. %d tokens | max_tokens=%d",
            m, _estimate_tokens(trimmed), max_tokens,
        )
        response = client.chat.completions.create(
            model=m,
            messages=trimmed,
            temperature=0.0,          # fully deterministic — JSON must be exact
            top_p=0.9,                # nucleus: 90% probability mass
            max_tokens=max_tokens,
            frequency_penalty=0.1,    # slight penalty against copy-pasting prompt back
            # Note: top_k is not a standard OpenAI-compatible param on Groq's API.
            # Groq applies its own internal sampling; temperature=0 + top_p=0.9
            # achieves equivalent greedy-ish behaviour without needing top_k.
        )
        return response.choices[0].message.content.strip()

    # Try each model in cascade order starting from requested model
    start_idx = MODEL_CASCADE.index(model) if model in MODEL_CASCADE else 0
    last_exc = None

    for candidate in MODEL_CASCADE[start_idx:]:
        try:
            return _invoke(candidate)
        except Exception as exc:
            error_str = str(exc)
            if "429" in error_str or "rate_limit_exceeded" in error_str:
                retry_after = _parse_retry_after(error_str)
                logger.warning(
                    "[Agent] Model %s rate-limited (%ds). Trying next model.", candidate, retry_after
                )
                last_exc = RateLimitError(retry_after)
                continue   # try next model in cascade
            raise   # non-429 error — surface immediately

    # All models exhausted
    raise last_exc or RateLimitError(120)


def _parse_retry_after(error_str: str) -> int:
    """Extract wait seconds from Groq's 'Please try again in Xm Ys' error."""
    match = re.search(r"try again in\s+(?:(\d+)m)?(?:([\d.]+)s)?", error_str, re.IGNORECASE)
    if match:
        minutes = int(match.group(1) or 0)
        seconds = float(match.group(2) or 0)
        return int(minutes * 60 + seconds) + 5   # +5s buffer
    return 120


class RateLimitError(Exception):
    """Raised when all models in the cascade are rate-limited."""
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        mins  = retry_after // 60
        secs  = retry_after % 60
        human = f"{mins}m {secs}s" if mins else f"{secs}s"
        super().__init__(
            f"🚦 Rate limit reached on all models. "
            f"Please try again in **{human}**. "
            f"(Groq free tier: llama-3.3-70b=300k TPM, llama-3.1-8b=250k TPM)"
        )


# ---------------------------------------------------------------------------
# JSON parsing — robust extraction even if LLM adds extra prose
# ---------------------------------------------------------------------------

def _parse_llm_output(raw: str) -> Optional[dict]:
    """
    Extract the first valid JSON object from the LLM response.
    LLMs sometimes wrap JSON in markdown code fences or add preamble text.
    """
    # Strip markdown code fences
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()

    # Try direct parse first
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Extract first {...} block
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    logger.warning("Could not parse LLM output as JSON: %s", raw[:200])
    return None


# ---------------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------------

def _dispatch(tool_name: str, action_input: dict):
    """Call the named tool with provided parameters. Returns tool result."""
    if tool_name not in TOOLS:
        return {"error": f"Unknown tool '{tool_name}'. Available: {list(TOOLS.keys())}"}
    try:
        fn = TOOLS[tool_name]["fn"]
        result = fn(**action_input)
        return result
    except TypeError as exc:
        return {"error": f"Invalid parameters for {tool_name}: {exc}"}
    except Exception as exc:
        logger.error("Tool %s raised: %s", tool_name, exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# ReAct loop
# ---------------------------------------------------------------------------

def run(user_message: str) -> dict:
    """
    Run the ReAct agent for a user message.

    Returns:
        dict with keys:
          - answer (str): final response to show the user
          - iterations (int): number of LLM calls made
          - tools_used (list): names of tools called
          - latency_ms (int): total wall-clock time in ms
          - error (str | None): set if agent failed
    """
    import time
    t_start = time.monotonic()

    messages = [
        {"role": "system",    "content": SYSTEM_PROMPT},
        # Few-shot primer — injected once as a synthetic exchange.
        # The context trimmer will drop this pair first on long conversations,
        # so it never permanently inflates token cost.
        {"role": "user",      "content": FEW_SHOT_PRIMER_USER},
        {"role": "assistant", "content": FEW_SHOT_PRIMER_ASSISTANT},
        {"role": "user",      "content": user_message},
    ]

    tools_used = []
    iterations = 0

    for iteration in range(1, MAX_ITERATIONS + 1):
        iterations = iteration
        logger.debug("[Agent] Iteration %d", iteration)

        # Use is_final=True when on last iteration OR when prev tool results
        # suggest the model has enough data — reduces max_tokens on tool steps
        is_final_step = (iteration == MAX_ITERATIONS)

        try:
            t_llm = time.monotonic()
            raw = _call_llm(messages, is_final=is_final_step)
            logger.debug("[Agent] LLM call took %.2fs", time.monotonic() - t_llm)
        except RateLimitError as exc:
            logger.warning("[Agent] All models rate-limited: %s", exc)
            return {
                "answer": str(exc),
                "iterations": iterations,
                "tools_used": tools_used,
                "latency_ms": int((time.monotonic() - t_start) * 1000),
                "error": "rate_limit",
                "retry_after": exc.retry_after,
            }
        except Exception as exc:
            logger.error("[Agent] LLM call failed: %s", exc)
            return {
                "answer": f"⚠️ Agent error: {exc}",
                "iterations": iterations,
                "tools_used": tools_used,
                "latency_ms": int((time.monotonic() - t_start) * 1000),
                "error": str(exc),
            }

        logger.debug("[Agent] LLM raw output: %s", raw[:300])

        parsed = _parse_llm_output(raw)

        if parsed is None:
            # LLM returned un-parseable output — treat as plain text answer
            return {
                "answer": raw,
                "iterations": iterations,
                "tools_used": tools_used,
                "error": None,
            }

        action = parsed.get("action", "")

        # ── Final answer ──────────────────────────────────────────────────
        if action == "FINAL_ANSWER":
            answer = parsed.get("answer") or parsed.get("thought", "No answer produced.")
            # LLM sometimes returns the answer as a nested JSON string — unwrap it
            if isinstance(answer, str):
                nested = _parse_llm_output(answer)
                if nested and isinstance(nested.get("answer"), str):
                    answer = nested["answer"]
            elapsed = int((time.monotonic() - t_start) * 1000)
            logger.info("[Agent] Done in %dms | %d iterations | tools: %s", elapsed, iterations, tools_used)
            return {
                "answer": answer,
                "iterations": iterations,
                "tools_used": tools_used,
                "latency_ms": elapsed,
                "error": None,
            }

        # ── Tool call ─────────────────────────────────────────────────────
        if action in TOOLS:
            action_input = parsed.get("action_input", {})
            logger.info("[Agent] Calling tool: %s with %s", action, action_input)
            tools_used.append(action)

            # Append assistant turn (thought + action)
            messages.append({"role": "assistant", "content": raw})

            # Call the tool
            t_tool = time.monotonic()
            tool_result = _dispatch(action, action_input)
            logger.debug("[Agent] Tool %s took %.2fs", action, time.monotonic() - t_tool)

            # Append observation as a user turn (standard ReAct convention)
            obs = observation_message(action, tool_result)
            messages.append({"role": "user", "content": obs})

            # Only flip to final-answer mode once all 3 mandatory workflow steps
            # have been called: get_cve_detail → get_mitre_techniques → get_remediation.
            # Flipping too early cuts off steps 2 and 3 with only 1024 tokens budget.
            workflow_done = all(t in tools_used for t in CVE_WORKFLOW_TOOLS)
            is_final_step = workflow_done or (iteration >= MAX_ITERATIONS - 1)
            continue

        # ── Unknown action ────────────────────────────────────────────────
        logger.warning("[Agent] Unknown action '%s' from LLM", action)
        messages.append({"role": "assistant", "content": raw})
        messages.append({
            "role": "user",
            "content": (
                f"That action '{action}' is not valid. "
                f"Use one of: {list(TOOLS.keys())} or FINAL_ANSWER."
            ),
        })

    # Max iterations reached — return the last thought as answer
    logger.warning("[Agent] Max iterations (%d) reached", MAX_ITERATIONS)
    last_thought = ""
    for msg in reversed(messages):
        if msg["role"] == "assistant":
            parsed = _parse_llm_output(msg["content"])
            if parsed:
                last_thought = parsed.get("thought", msg["content"])
            else:
                last_thought = msg["content"]
            break

    return {
        "answer": (
            last_thought or
            "I wasn't able to produce a complete answer within the step limit. "
            "Please try rephrasing your question."
        ),
        "iterations": iterations,
        "tools_used": tools_used,
        "latency_ms": int((time.monotonic() - t_start) * 1000),
        "error": "max_iterations_reached",
    }
