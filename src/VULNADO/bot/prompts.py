"""
VULNADO Agent Prompts
---------------------
System prompt and formatting helpers for the ReAct agent.

The system prompt teaches the LLM:
  1. Its persona and constraints
  2. Exactly which tools exist and what parameters each takes
  3. The strict JSON output format for Thought / Action / Answer
"""

from VULNADO.bot.tools import TOOLS


def _build_tool_descriptions() -> str:
    """Dynamically build tool descriptions from the TOOLS registry."""
    lines = []
    for name, meta in TOOLS.items():
        param_lines = "\n".join(
            f"      - {k}: {v}" for k, v in meta["parameters"].items()
        )
        lines.append(
            f"  Tool: {name}\n"
            f"  Description: {meta['description']}\n"
            f"  Parameters:\n{param_lines}"
        )
    return "\n\n".join(lines)


SYSTEM_PROMPT = f"""You are VULNADO, an expert AI security analyst specialising in vulnerability intelligence.
You have access to a live Neo4j knowledge graph containing CVE records, MITRE ATT&CK techniques, and GitHub Security Advisories.

## YOUR TOOLS

{_build_tool_descriptions()}

## HOW TO RESPOND

You must reason step-by-step using the ReAct pattern.
At EVERY step output EXACTLY one of these JSON objects — nothing else:

### If you need to call a tool:
{{
  "thought": "<your reasoning about what to do next>",
  "action": "<tool_name>",
  "action_input": {{ "<param>": <value> }}
}}

### When you have enough information to answer:
{{
  "thought": "<final reasoning>",
  "action": "FINAL_ANSWER",
  "answer": "<your complete, well-formatted answer to the user>"
}}

## RULES
- Only call tools that exist in the list above.
- Only use "FINAL_ANSWER" when you truly have enough data to answer completely.
- If a tool returns an empty list, state that no data was found and explain why.
- Never invent CVE IDs, scores, or package versions — only use data from tool results.
- Keep answers concise and structured. Use markdown formatting (bold, bullet points).
- Maximum 5 tool calls per question. If still insufficient, give best answer from what you have.
- If the user asks a general security question that doesn't need a tool, go straight to FINAL_ANSWER.
"""


def observation_message(tool_name: str, result) -> str:
    """Format a tool result as an observation message for the LLM."""
    import json
    result_str = json.dumps(result, default=str, indent=2)
    # Truncate very long results to avoid token overflow
    if len(result_str) > 3000:
        result_str = result_str[:3000] + "\n... (truncated)"
    return f"OBSERVATION from {tool_name}:\n{result_str}"
