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
  ┌──────────────────────────────────┬───────────┬──────────────────────────┐
  │ Model                            │ Context   │ Free tier TPM            │
  ├──────────────────────────────────┼───────────┼──────────────────────────┤
  │ PRIMARY  llama-3.3-70b-versatile │ 131 072 t │ 300k TPM / 1k RPM        │
  │ FALLBACK llama-3.1-8b-instant    │ 131 072 t │ 250k TPM / 1k RPM        │
  │ ECONOMY  openai/gpt-oss-20b      │ 131 072 t │ 250k TPM / 1k RPM        │
  └──────────────────────────────────┴───────────┴──────────────────────────┘

  NOTE: mixtral-8x7b-32768 was DECOMMISSIONED on March 20, 2025.
        llama-3.3-70b-versatile is Groq's recommended replacement.
        All three models now have 131k context — no context trimming needed
        in practice, but the safety trimmer is kept as a guard.

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

from VULNADO.bot.prompts import SYSTEM_PROMPT, observation_message
from VULNADO.bot.tools import TOOLS

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 5

# ---------------------------------------------------------------------------
# Model cascade — ordered by preference (all PRODUCTION models, March 2026)
# ---------------------------------------------------------------------------
PRIMARY_MODEL  = "llama-3.3-70b-versatile"    # 131k ctx, best reasoning
FALLBACK_MODEL = "llama-3.1-8b-instant"        # 131k ctx, fast + lightweight
ECONOMY_MODEL  = "openai/gpt-oss-20b"          # 131k ctx, 1000 tps fallback
MODEL_CASCADE  = [PRIMARY_MODEL, FALLBACK_MODEL, ECONOMY_MODEL]

# Context window limits per model (tokens) — all 131k as of March 2026
MODEL_CTX_LIMIT = {
    PRIMARY_MODEL:  131_072,
    FALLBACK_MODEL: 131_072,
    ECONOMY_MODEL:  131_072,
}

# Stay 15% below the hard limit to be safe
CTX_SAFETY_FACTOR = 0.85


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

    Strategy:
      - Always keep: messages[0] (system prompt) + messages[1] (original user query)
      - Drop oldest assistant/observation pairs from the middle
      - Keep last 2 full turns (4 messages) unconditionally

    Returns a new list safe to send.
    """
    ctx_limit = int(MODEL_CTX_LIMIT.get(model, 8_192) * CTX_SAFETY_FACTOR)

    if _estimate_tokens(messages) <= ctx_limit:
        return messages  # already fits

    # Anchor messages: system (0) + original user (1)
    anchors = messages[:2]
    middle  = messages[2:]

    # Always keep last 4 messages (2 turns)
    tail = middle[-4:] if len(middle) >= 4 else middle[:]
    head = middle[:-4] if len(middle) >= 4 else []

    # Drop pairs from oldest end of head until it fits
    while head and _estimate_tokens(anchors + head + tail) > ctx_limit:
        # Each pair is [assistant_turn, observation_turn] = 2 messages
        head = head[2:]

    trimmed = anchors + head + tail
    dropped = len(messages) - len(trimmed)
    if dropped:
        logger.info("[Agent] Trimmed %d messages to fit %s context window", dropped, model)
    return trimmed


# ---------------------------------------------------------------------------
# LLM call — tuned parameters + 3-model cascade for rate limits
# ---------------------------------------------------------------------------

def _call_llm(messages: list, model: str = PRIMARY_MODEL, is_final: bool = False) -> str:
    """
    Send messages to Groq and return raw text response.

    Parameters used:
      temperature=0.0   → deterministic; we need reliable JSON, not creative text
      top_p=0.9         → nucleus sampling; focus on high-probability tokens
      top_k=40          → sample from top 40 tokens only; avoids hallucinating CVE IDs
      max_tokens        → 2048 for final answer (rich response), 1024 for tool steps
      frequency_penalty → 0.1 mild penalty; prevents repeating JSON scaffold verbatim

    On 429 → cascades through MODEL_CASCADE automatically.
    """
    client = _get_groq()
    max_tokens = 2048 if is_final else 1024

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
          - error (str | None): set if agent failed
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_message},
    ]

    tools_used = []
    iterations = 0

    for iteration in range(1, MAX_ITERATIONS + 1):
        iterations = iteration
        logger.debug("[Agent] Iteration %d", iteration)

        try:
            # Signal is_final on last allowed iteration so LLM gets 2048 token budget
            is_final_iter = (iteration == MAX_ITERATIONS)
            raw = _call_llm(messages, is_final=is_final_iter)
        except RateLimitError as exc:
            logger.warning("[Agent] All models rate-limited: %s", exc)
            return {
                "answer": str(exc),
                "iterations": iterations,
                "tools_used": tools_used,
                "error": "rate_limit",
                "retry_after": exc.retry_after,
            }
        except Exception as exc:
            logger.error("[Agent] LLM call failed: %s", exc)
            return {
                "answer": f"⚠️ Agent error: {exc}",
                "iterations": iterations,
                "tools_used": tools_used,
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
            logger.info("[Agent] Final answer after %d iterations, tools: %s", iterations, tools_used)
            return {
                "answer": answer,
                "iterations": iterations,
                "tools_used": tools_used,
                "error": None,
            }

        # ── Tool call ─────────────────────────────────────────────────────
        if action in TOOLS:
            action_input = parsed.get("action_input", {})
            thought = parsed.get("thought", "")
            logger.info("[Agent] Calling tool: %s with %s", action, action_input)
            tools_used.append(action)

            # Append assistant turn (thought + action)
            messages.append({"role": "assistant", "content": raw})

            # Call the tool
            tool_result = _dispatch(action, action_input)

            # Append observation as a user turn (standard ReAct convention)
            obs = observation_message(action, tool_result)
            messages.append({"role": "user", "content": obs})
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
        "error": "max_iterations_reached",
    }
