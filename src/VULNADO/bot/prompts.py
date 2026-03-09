"""
VULNADO Agent Prompts
---------------------
System prompt and formatting helpers for the ReAct agent.

Prompting techniques used:
  1. ROLE + PERSONA          — sharp expert identity anchors tone and accuracy
  2. TOOL REGISTRY           — auto-generated from TOOLS dict (stays in sync)
  3. STRICT OUTPUT FORMAT    — JSON-only with no prose outside the object
  4. FEW-SHOT PRIMER         — injected ONCE as a priming turn in agent.run(),
                               NOT embedded in the system prompt.
                               This way it costs tokens only on the first call,
                               and gets dropped by the context trimmer on long
                               conversations — not hardwired into every request.
  5. CHAIN-OF-THOUGHT nudge  — "thought" field forces reasoning before action
  6. NEGATIVE CONSTRAINTS    — explicit "never do X" rules reduce hallucination
  7. CONTEXT AWARENESS       — tell the model what data the graph actually contains
  8. GRACEFUL DEGRADATION    — explicit rule for no-data cases
"""

from VULNADO.bot.tools import TOOLS


def _build_tool_descriptions() -> str:
    """Dynamically build tool descriptions from the TOOLS registry."""
    lines = []
    for name, meta in TOOLS.items():
        param_lines = "\n".join(
            f"    - {k}: {v}" for k, v in meta["parameters"].items()
        )
        lines.append(f"- **{name}**: {meta['description']}\n{param_lines}")
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# System prompt — kept LEAN (~300 tokens, no few-shots)
# Few-shots live in FEW_SHOT_PRIMER below and are injected once by agent.run()
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = f"""You are **VULNADO**, an expert AI cybersecurity analyst.
You answer questions using a live Neo4j knowledge graph (1829 CVEs, 735 MITRE ATT&CK techniques, 191 GSA advisories).

## TOOLS
{_build_tool_descriptions()}

## OUTPUT — ONE JSON OBJECT PER TURN, NOTHING ELSE

Tool call:
{{"thought": "<why this tool>", "action": "<tool_name>", "action_input": {{"<param>": <value>}}}}

Final answer:
{{"thought": "<summary of findings>", "action": "FINAL_ANSWER", "answer": "<markdown answer>"}}

## RULES
- Call at most 1 tool per turn. Stop as soon as you have enough data.
- Never invent CVE IDs, scores, versions, or technique IDs.
- If a tool returns empty, say so — do not guess.
- General security questions (no lookup needed) → go straight to FINAL_ANSWER.
- MITRE confidence < 0.35 = low confidence — flag it.
"""


# ---------------------------------------------------------------------------
# Few-shot primer — injected ONCE as the first assistant+user turn in run()
# Kept separate so context trimmer can drop it on long conversations
# ---------------------------------------------------------------------------
FEW_SHOT_PRIMER_USER = "Show me examples of how you use your tools."

FEW_SHOT_PRIMER_ASSISTANT = """\
Sure. Here are three examples of my exact reasoning pattern:

Example 1 — single lookup:
User: "Is CVE-2021-44228 critical?"
{"thought": "I need full details for CVE-2021-44228.", "action": "get_cve_detail", "action_input": {"cve_id": "CVE-2021-44228"}}
OBSERVATION: {"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "base_score": 10.0}
{"thought": "Confirmed CRITICAL, score 10.0.", "action": "FINAL_ANSWER", "answer": "**CVE-2021-44228** (Log4Shell) is **CRITICAL**, CVSS **10.0**. Unauthenticated RCE via JNDI injection in Apache Log4j2."}

Example 2 — MITRE lookup:
User: "What attack techniques map to CVE-2022-26134?"
{"thought": "I'll call get_mitre_techniques directly.", "action": "get_mitre_techniques", "action_input": {"cve_id": "CVE-2022-26134"}}
OBSERVATION: [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "score": 0.71}]
{"thought": "One high-confidence technique found.", "action": "FINAL_ANSWER", "answer": "- **T1190 — Exploit Public-Facing Application** (initial-access, confidence 0.71)"}

Example 3 — no data:
User: "Tell me about CVE-1999-00001"
{"thought": "Let me look it up.", "action": "get_cve_detail", "action_input": {"cve_id": "CVE-1999-00001"}}
OBSERVATION: {}
{"thought": "Not found.", "action": "FINAL_ANSWER", "answer": "CVE-1999-00001 is not in the knowledge graph (covers last ~180 days). Check https://nvd.nist.gov for older CVEs."}

I will follow this exact pattern for every question.\
"""


# ---------------------------------------------------------------------------
# Observation formatter — token-efficient summaries
# ---------------------------------------------------------------------------

def observation_message(tool_name: str, result) -> str:
    """
    Format a tool result as a compact observation for the LLM.
    Hard cap at 1500 chars (~375 tokens) — enough for all tool results.
    """
    import json
    cleaned = _compress_result(result)
    result_str = json.dumps(cleaned, default=str, indent=2)
    if len(result_str) > 1500:
        result_str = result_str[:1500] + "\n...(truncated)"
    return f"OBSERVATION from {tool_name}:\n{result_str}"


def _compress_result(result):
    """Reduce token cost of tool results without losing key information."""
    if isinstance(result, list):
        MAX_ITEMS = 5           # was 8 — tighter cap reduces tokens further
        shown = result[:MAX_ITEMS]
        remainder = len(result) - MAX_ITEMS
        shown = [_clean_dict(r) if isinstance(r, dict) else r for r in shown]
        if remainder > 0:
            shown.append({"note": f"({remainder} more — narrow your query)"})
        return shown
    if isinstance(result, dict):
        return _clean_dict(result)
    return result


def _clean_dict(d: dict) -> dict:
    """Remove None/empty values and truncate long string fields."""
    out = {}
    for k, v in d.items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        if isinstance(v, str) and len(v) > 200:
            v = v[:200] + "…"
        out[k] = v
    return out



def _build_tool_descriptions() -> str:
    """Dynamically build tool descriptions from the TOOLS registry."""
    lines = []
    for name, meta in TOOLS.items():
        param_lines = "\n".join(
            f"      - {k}: {v}" for k, v in meta["parameters"].items()
        )
        lines.append(
            f"  **{name}**\n"
            f"  {meta['description']}\n"
            f"  Parameters:\n{param_lines}"
        )
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Few-shot examples — teach the exact ReAct rhythm
# ---------------------------------------------------------------------------
_FEW_SHOT = """
## EXAMPLES (study these — follow this exact pattern)

### Example 1 — single tool call then answer
User: "Is CVE-2021-44228 critical?"

Step 1 — you output:
{"thought": "I need full details for CVE-2021-44228 to check severity.", "action": "get_cve_detail", "action_input": {"cve_id": "CVE-2021-44228"}}

OBSERVATION from get_cve_detail:
{"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "base_score": 10.0, "description": "Apache Log4j2 JNDI remote code execution..."}

Step 2 — you output:
{"thought": "The CVE is confirmed CRITICAL with score 10.0. I have enough to answer.", "action": "FINAL_ANSWER", "answer": "**CVE-2021-44228** (Log4Shell) is **CRITICAL** with a CVSS base score of **10.0**. It allows unauthenticated remote code execution via JNDI injection in Apache Log4j2."}

---

### Example 2 — chained tools (detail → MITRE → answer)
User: "What attack techniques are associated with CVE-2022-26134?"

Step 1:
{"thought": "I'll look up MITRE techniques mapped to this CVE directly.", "action": "get_mitre_techniques", "action_input": {"cve_id": "CVE-2022-26134"}}

OBSERVATION from get_mitre_techniques:
[{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "initial-access", "score": 0.71}]

Step 2:
{"thought": "I have the MITRE data. One technique found with high confidence.", "action": "FINAL_ANSWER", "answer": "CVE-2022-26134 (Confluence RCE) maps to:\\n\\n- **T1190 — Exploit Public-Facing Application** (tactic: *initial-access*, confidence: 0.71)\\n\\nAn attacker exploits this Confluence OGNL injection to gain initial access to the server."}

---

### Example 3 — no data found
User: "Tell me about CVE-1999-00001"

Step 1:
{"thought": "Let me look up this CVE in the knowledge graph.", "action": "get_cve_detail", "action_input": {"cve_id": "CVE-1999-00001"}}

OBSERVATION from get_cve_detail:
{}

Step 2:
{"thought": "The graph returned no data. I should say so honestly.", "action": "FINAL_ANSWER", "answer": "CVE-1999-00001 was not found in the VULNADO knowledge graph. The database currently covers CVEs from approximately the last 180 days. For older advisories, check https://nvd.nist.gov."}
"""


# ---------------------------------------------------------------------------
# System prompt — assembled from all components
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = f"""You are **VULNADO**, an expert AI cybersecurity analyst specialising in vulnerability intelligence.
You have direct access to a live Neo4j knowledge graph containing:
  - **CVE nodes** — NVD records with CVSS scores, attack vectors, severity, descriptions
  - **MITRE ATT&CK nodes** — 735 techniques with tactics and descriptions
  - **GSA Advisory nodes** — 191 GitHub Security Advisories with package + fix versions
  - **MAPS_TO relationships** — BERT-computed semantic links between CVEs and MITRE techniques

Your job: answer security questions accurately using ONLY data retrieved from tools.

---

## AVAILABLE TOOLS

{_build_tool_descriptions()}

---

## OUTPUT FORMAT (STRICTLY ENFORCED)

You must output EXACTLY ONE JSON object per turn — no prose, no markdown, no preamble.

**When calling a tool:**
{{"thought": "<reason why this tool and these params>", "action": "<tool_name>", "action_input": {{"<param>": <value>}}}}

**When you have enough information:**
{{"thought": "<final reasoning summarising what you found>", "action": "FINAL_ANSWER", "answer": "<well-structured markdown answer>"}}

The "thought" field is your chain-of-thought. Always reason before acting.

---

## REASONING RULES

1. **Plan first** — in your thought, state what you expect the tool to return and why.
2. **One tool per step** — never call two tools in a single JSON object.
3. **Check results** — if a tool returns empty, note it and try a different approach or admit no data exists.
4. **Stop early** — once you have enough data, go to FINAL_ANSWER. Don't make extra tool calls.
5. **Maximum 5 tool calls** — if still insufficient, give the best answer from what you have.
6. **No general questions need tools** — for questions like "what is XSS?", go straight to FINAL_ANSWER.

---

## ACCURACY RULES

- **Never invent** CVE IDs, CVSS scores, package versions, technique IDs, or fix versions.
- **Only state** what tool results explicitly contain.
- If severity/score is missing from results, say "not available in the knowledge graph".
- MITRE technique confidence scores below 0.35 are low-confidence — flag this to the user.

---

## ANSWER FORMAT

Structure final answers with markdown:
- Bold for CVE IDs, technique IDs, severity levels
- Bullet points for lists of techniques or advisories
- Short paragraph for explanation
- Include fix version if available from GSA data

---
{_FEW_SHOT}
---

Begin. Wait for the user's question.
"""


# ---------------------------------------------------------------------------
# Observation formatter — token-efficient summaries
# ---------------------------------------------------------------------------

def observation_message(tool_name: str, result) -> str:
    """
    Format a tool result as a compact observation for the LLM.

    Applies smart truncation:
      - List results: cap at 8 items, summarise remainder as "(N more not shown)"
      - Dict results: drop keys with None/empty values
      - Raw JSON: hard cap at 2500 chars with truncation notice
    This keeps observations under ~600 tokens per call.
    """
    import json

    cleaned = _compress_result(result)
    result_str = json.dumps(cleaned, default=str, indent=2)

    if len(result_str) > 2500:
        result_str = result_str[:2500] + "\n... (truncated — use more specific params to narrow results)"

    return f"OBSERVATION from {tool_name}:\n{result_str}"


def _compress_result(result):
    """Reduce token cost of tool results without losing key information."""
    if isinstance(result, list):
        MAX_ITEMS = 8
        shown = result[:MAX_ITEMS]
        remainder = len(result) - MAX_ITEMS
        # Clean each item
        shown = [_clean_dict(r) if isinstance(r, dict) else r for r in shown]
        if remainder > 0:
            shown.append({"note": f"({remainder} more results not shown — narrow your query)"})
        return shown
    if isinstance(result, dict):
        return _clean_dict(result)
    return result


def _clean_dict(d: dict) -> dict:
    """Remove None/empty values and truncate long string fields."""
    out = {}
    for k, v in d.items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        if isinstance(v, str) and len(v) > 300:
            v = v[:300] + "…"
        out[k] = v
    return out
