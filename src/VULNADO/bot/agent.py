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

LLM: Groq API (llama-3.3-70b-versatile) — free tier, no GPU needed
     Set GROQ_API_KEY environment variable.
"""

import json
import logging
import os
import re
from typing import Optional

from VULNADO.bot.prompts import SYSTEM_PROMPT, observation_message
from VULNADO.bot.tools import TOOLS

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 5


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
# LLM call
# ---------------------------------------------------------------------------

def _call_llm(messages: list) -> str:
    """Send messages to Groq and return raw text response."""
    client = _get_groq()
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=messages,
        temperature=0.1,        # low temp = deterministic, consistent JSON
        max_tokens=1024,
    )
    return response.choices[0].message.content.strip()


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
            raw = _call_llm(messages)
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
