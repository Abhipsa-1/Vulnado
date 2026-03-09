"""
VULNADO Agent Tools
-------------------
Five Neo4j-backed tool functions used by the ReAct agent.
Each tool builds a dynamic Cypher query from its parameters,
runs it against Neo4j, and returns clean structured JSON.

Tools:
  1. search_cves          — find CVEs by keyword / severity / recency
  2. get_cve_detail       — full detail for one CVE
  3. get_mitre_techniques — MAPS_TO relationships for a CVE
  4. search_packages      — GSA advisories for a software package
  5. get_remediation      — fix versions + patch guidance for a CVE
"""

import logging
from typing import Optional
from VULNADO.config.configuration import get_config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Neo4j driver — persistent connection pool
# ---------------------------------------------------------------------------
# A new GraphDatabase.driver() is created ONCE at import time (warm path).
# driver.session() is cheap — it checks out a connection from the pool
# rather than opening a new TCP socket each time.
#
# Key pool settings (tuned for t3.medium, single-worker Flask):
#   max_connection_pool_size=10  — keep up to 10 idle bolt connections
#   connection_acquisition_timeout=5  — fail fast if pool exhausted
#   max_connection_lifetime=3600  — recycle connections every hour
#   keep_alive=True  — TCP keepalive to avoid stale connections
# ---------------------------------------------------------------------------
_driver = None


def _get_driver():
    global _driver
    if _driver is None:
        try:
            from neo4j import GraphDatabase
            cfg = get_config()
            ns = cfg.neo4j_service
            _driver = GraphDatabase.driver(
                ns.uri,
                auth=(ns.username, ns.password),
                max_connection_pool_size=10,
                connection_acquisition_timeout=5.0,
                max_connection_lifetime=3600,
                keep_alive=True,
            )
            # verify_connectivity() intentionally NOT called here —
            # it adds ~200ms on every cold start. The first real query
            # will surface connectivity errors fast enough.
        except Exception as exc:
            logger.error("Neo4j driver init failed in tools: %s", exc)
            _driver = None
    return _driver


def _run(query: str, params: dict) -> list:
    """Execute a Cypher query and return list of record dicts."""
    driver = _get_driver()
    if not driver:
        return []
    try:
        with driver.session() as session:
            result = session.run(query, **params)
            return [dict(r) for r in result]
    except Exception as exc:
        logger.error("Cypher error: %s | query: %s", exc, query[:120])
        return []


# ---------------------------------------------------------------------------
# Tool 1 — search_cves
# ---------------------------------------------------------------------------

def search_cves(
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    days_back: Optional[int] = 180,
    limit: int = 10,
) -> list:
    """
    Search CVEs by keyword in description, severity level, and/or recency.

    Args:
        keyword:   Word or phrase to match inside CVE description (case-insensitive)
        severity:  'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'  (optional)
        days_back: Only return CVEs published in the last N days (default 180)
        limit:     Max results to return (default 10)

    Returns:
        List of dicts: cve_id, description, severity, base_score, published
    """
    conditions = []
    params: dict = {"limit": limit}

    if keyword:
        conditions.append("toLower(c.description) CONTAINS toLower($keyword)")
        params["keyword"] = keyword

    if severity:
        conditions.append("c.severity = $severity")
        params["severity"] = severity.upper()

    if days_back:
        conditions.append(
            "c.published >= toString(datetime() - duration({days: $days_back}))"
        )
        params["days_back"] = days_back

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    query = f"""
    MATCH (c:CVE)
    {where}
    RETURN c.cve_id        AS cve_id,
           c.description   AS description,
           c.severity      AS severity,
           c.base_score    AS base_score,
           c.published     AS published
    ORDER BY c.base_score DESC
    LIMIT $limit
    """

    rows = _run(query, params)
    # Trim description for readability
    for r in rows:
        if r.get("description"):
            r["description"] = r["description"][:200]
    return rows


# ---------------------------------------------------------------------------
# Tool 2 — get_cve_detail
# ---------------------------------------------------------------------------

def get_cve_detail(cve_id: str) -> dict:
    """
    Fetch full details for a single CVE.

    Args:
        cve_id: Standard CVE identifier, e.g. 'CVE-2021-44228'

    Returns:
        Dict with all CVE properties, or empty dict if not found.
    """
    query = """
    MATCH (c:CVE {cve_id: $cve_id})
    RETURN c.cve_id          AS cve_id,
           c.description     AS description,
           c.severity        AS severity,
           c.base_score      AS base_score,
           c.attack_vector   AS attack_vector,
           c.cvss_vector     AS cvss_vector,
           c.published       AS published,
           c.last_modified   AS last_modified,
           c.vuln_status     AS vuln_status,
           c.source          AS source
    """
    rows = _run(query, {"cve_id": cve_id.upper()})
    return rows[0] if rows else {}


# ---------------------------------------------------------------------------
# Tool 3 — get_mitre_techniques
# ---------------------------------------------------------------------------

def get_mitre_techniques(cve_id: str) -> list:
    """
    Return MITRE ATT&CK techniques mapped to a CVE via MAPS_TO relationships.

    Args:
        cve_id: Standard CVE identifier

    Returns:
        List of dicts: technique_id, technique_name, tactics, platforms,
                       detection, score, mapped_by
    """
    query = """
    MATCH (c:CVE {cve_id: $cve_id})-[r:MAPS_TO]->(m:MITRE)
    RETURN m.technique_id    AS technique_id,
           m.technique_name  AS technique_name,
           m.tactics         AS tactics,
           m.platforms       AS platforms,
           m.detection       AS detection,
           r.score           AS score,
           r.mapped_by       AS mapped_by
    ORDER BY r.score DESC
    """
    rows = _run(query, {"cve_id": cve_id.upper()})
    for r in rows:
        if r.get("detection") and len(r["detection"]) > 200:
            r["detection"] = r["detection"][:200] + "…"
    return rows


# ---------------------------------------------------------------------------
# Tool 4 — search_packages
# ---------------------------------------------------------------------------

def search_packages(package_name: str, ecosystem: Optional[str] = None, limit: int = 10) -> list:
    """
    Find GitHub Security Advisories (GSA) affecting a software package.

    Args:
        package_name: Name of the package, e.g. 'django', 'log4j', 'requests'
        ecosystem:    'PyPI' | 'npm' | 'Maven' | 'Go' | etc. (optional)
        limit:        Max results (default 10)

    Returns:
        List of dicts: ghsa_id, cve_id, summary, severity, package_name,
                       ecosystem, vulnerable_versions, fixed_version
    """
    conditions = ["toLower(g.package_name) CONTAINS toLower($package_name)"]
    params: dict = {"package_name": package_name, "limit": limit}

    if ecosystem:
        conditions.append("toLower(g.ecosystem) = toLower($ecosystem)")
        params["ecosystem"] = ecosystem

    where = "WHERE " + " AND ".join(conditions)

    query = f"""
    MATCH (g:GSA)
    {where}
    RETURN g.ghsa_id              AS ghsa_id,
           g.cve_id               AS cve_id,
           g.summary              AS summary,
           g.severity             AS severity,
           g.package_name         AS package_name,
           g.ecosystem            AS ecosystem,
           g.vulnerable_versions  AS vulnerable_versions,
           g.fixed_version        AS fixed_version
    ORDER BY g.severity DESC
    LIMIT $limit
    """
    return _run(query, params)


# ---------------------------------------------------------------------------
# Tool 5 — get_remediation
# ---------------------------------------------------------------------------

def get_remediation(cve_id: str) -> dict:
    """
    Fetch remediation / patch guidance for a CVE by joining CVE, GSA, and MITRE data.

    Args:
        cve_id: Standard CVE identifier

    Returns:
        Dict with:
          - cve_id, severity, description
          - advisories: list of {ghsa_id, package, ecosystem, fixed_version}
          - mitre_techniques: list of {technique_id, technique_name, tactics}
    """
    cve_id = cve_id.upper()

    # CVE base info
    cve = get_cve_detail(cve_id)

    # GSA advisories linked via shared cve_id property
    gsa_query = """
    MATCH (g:GSA {cve_id: $cve_id})
    RETURN g.ghsa_id             AS ghsa_id,
           g.summary             AS summary,
           g.package_name        AS package,
           g.ecosystem           AS ecosystem,
           g.vulnerable_versions AS affected_versions,
           g.fixed_version       AS fixed_version
    LIMIT 5
    """
    advisories = _run(gsa_query, {"cve_id": cve_id})

    # MITRE techniques
    mitre_query = """
    MATCH (c:CVE {cve_id: $cve_id})-[r:MAPS_TO]->(m:MITRE)
    RETURN m.technique_id   AS technique_id,
           m.technique_name AS technique_name,
           m.tactics        AS tactics
    ORDER BY r.score DESC
    LIMIT 3
    """
    techniques = _run(mitre_query, {"cve_id": cve_id})

    return {
        "cve_id":           cve.get("cve_id", cve_id),
        "severity":         cve.get("severity"),
        "base_score":       cve.get("base_score"),
        "description":      (cve.get("description") or "")[:300],
        "advisories":       advisories,
        "mitre_techniques": techniques,
    }


# ---------------------------------------------------------------------------
# Tool registry — used by agent to validate and dispatch tool calls
# ---------------------------------------------------------------------------

TOOLS = {
    "search_cves": {
        "fn":          search_cves,
        "description": (
            "Search CVEs by keyword in description, severity (CRITICAL/HIGH/MEDIUM/LOW), "
            "and/or how many days back to look. Returns list of matching CVEs with scores."
        ),
        "parameters": {
            "keyword":   "str (optional) — word/phrase to find in CVE description",
            "severity":  "str (optional) — CRITICAL | HIGH | MEDIUM | LOW",
            "days_back": "int (optional) — only CVEs from last N days, default 180",
        },
    },
    "get_cve_detail": {
        "fn":          get_cve_detail,
        "description": "Get full details of a single CVE by its ID (e.g. CVE-2021-44228).",
        "parameters": {
            "cve_id": "str (required) — standard CVE identifier",
        },
    },
    "get_mitre_techniques": {
        "fn":          get_mitre_techniques,
        "description": (
            "Get MITRE ATT&CK techniques mapped to a CVE. "
            "Returns technique IDs, names, tactics, and similarity scores."
        ),
        "parameters": {
            "cve_id": "str (required) — standard CVE identifier",
        },
    },
    "search_packages": {
        "fn":          search_packages,
        "description": (
            "Find GitHub Security Advisories for a software package. "
            "Returns affected versions and fixed versions."
        ),
        "parameters": {
            "package_name": "str (required) — package name, e.g. 'django', 'log4j'",
            "ecosystem":    "str (optional) — PyPI | npm | Maven | Go | etc.",
        },
    },
    "get_remediation": {
        "fn":          get_remediation,
        "description": (
            "Get full remediation guidance for a CVE: combines CVE details, "
            "affected package advisories (fixed versions), and MITRE techniques."
        ),
        "parameters": {
            "cve_id": "str (required) — standard CVE identifier",
        },
    },
}
