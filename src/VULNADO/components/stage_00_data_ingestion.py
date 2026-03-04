import requests
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
from VULNADO.config.configuration import get_config

# NVD 2.0 REST API - replaces old zip feeds
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 2000  # NVD max per page
NVD_RATE_LIMIT_DELAY = 6     # seconds between requests without API key (30 req/30s)
NVD_RATE_LIMIT_DELAY_WITH_KEY = 0.6  # seconds with API key (50 req/30s)

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


class DataIngestion:
    def __init__(self, base_dir, extract_dir, mitre_path, gsa_path):
        self.base_dir = base_dir
        self.extract_dir = extract_dir
        self.mitre_path = mitre_path
        self.gsa_path = gsa_path

        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.extract_dir, exist_ok=True)

        config = get_config()
        self.nvd_api_key = os.getenv("NVD_API_KEY")  # Optional — get free key at https://nvd.nist.gov/developers/request-an-api-key
        self.github_token = os.getenv("GITHUB_TOKEN")  # Optional — increases GSA rate limit from 60 to 5000 req/hr
        self.rate_delay = NVD_RATE_LIMIT_DELAY_WITH_KEY if self.nvd_api_key else NVD_RATE_LIMIT_DELAY

    # =========================================================================
    # CVE — NVD 2.0 REST API
    # =========================================================================

    def _nvd_headers(self) -> Dict:
        headers = {"Accept": "application/json"}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        return headers

    def _parse_cve_record(self, cve: Dict) -> Dict:
        """Extract all relevant fields from a single NVD 2.0 CVE object."""
        metrics = cve.get("metrics", {})

        # Prefer CVSSv3.1 → CVSSv3.0 → CVSSv2
        base_score = None
        severity = None
        attack_vector = None
        cvss_vector = None

        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            base_score = m.get("baseScore")
            severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity") or \
                       metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "").upper()
            attack_vector = m.get("attackVector")
            cvss_vector = m.get("vectorString")
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]["cvssData"]
            base_score = m.get("baseScore")
            severity = m.get("baseSeverity", "").upper()
            attack_vector = m.get("attackVector")
            cvss_vector = m.get("vectorString")
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            base_score = m["cvssData"].get("baseScore")
            severity = m.get("baseSeverity", "").upper()
            attack_vector = m["cvssData"].get("accessVector")
            cvss_vector = m["cvssData"].get("vectorString")

        # English description
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
        )

        # CWE IDs
        cwes = [
            desc["value"]
            for w in cve.get("weaknesses", [])
            for desc in w.get("description", [])
            if desc["lang"] == "en"
        ]

        # Affected software (CPE)
        affected_software = []
        for config_node in cve.get("configurations", []):
            for node in config_node.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected_software.append(cpe_match.get("criteria", ""))

        return {
            "cve_id": cve["id"],
            "description": description,
            "severity": severity or "UNKNOWN",
            "base_score": base_score,
            "attack_vector": attack_vector,
            "cvss_vector": cvss_vector,
            "cwes": cwes,
            "affected_software": affected_software[:10],  # cap at 10
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "vuln_status": cve.get("vulnStatus", ""),
            "source": "NVD"
        }

    def fetch_cve_data(
        self,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        days_back: int = 120,
        output_path: Optional[str] = None,
    ) -> List[Dict]:
        """
        Fetch CVEs from NVD 2.0 REST API with full pagination.

        Args:
            pub_start_date: ISO format "YYYY-MM-DDTHH:MM:SS.000" — defaults to `days_back` ago
            pub_end_date:   ISO format "YYYY-MM-DDTHH:MM:SS.000" — defaults to now
            days_back:      How many days back to fetch if no explicit dates given
            output_path:    Where to save JSON output — defaults to cve_extract_dir/nvdcve-realtime.json

        Returns:
            List of parsed CVE dicts
        """
        if not pub_end_date:
            pub_end_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
        if not pub_start_date:
            pub_start_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000")

        if not output_path:
            output_path = os.path.join(self.extract_dir, "nvdcve-realtime.json")

        print(f"\nFetching CVEs from NVD 2.0 API")
        print(f"  Range: {pub_start_date} → {pub_end_date}")
        if self.nvd_api_key:
            print("  API key: present (higher rate limit)")
        else:
            print("  API key: not set (set NVD_API_KEY env var for faster fetching)")

        all_cves = []
        start_index = 0
        total = None

        while True:
            params = {
                "pubStartDate": pub_start_date,
                "pubEndDate": pub_end_date,
                "resultsPerPage": NVD_RESULTS_PER_PAGE,
                "startIndex": start_index,
            }

            try:
                response = requests.get(
                    NVD_API_BASE,
                    params=params,
                    headers=self._nvd_headers(),
                    timeout=60
                )
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                print(f"  Error fetching CVEs at startIndex={start_index}: {e}")
                break

            if total is None:
                total = data.get("totalResults", 0)
                print(f"  Total CVEs to fetch: {total}")

            batch = data.get("vulnerabilities", [])
            if not batch:
                break

            parsed = [self._parse_cve_record(v["cve"]) for v in batch]
            all_cves.extend(parsed)

            fetched_so_far = start_index + len(batch)
            print(f"  Fetched {fetched_so_far}/{total} CVEs...", end="\r")

            if fetched_so_far >= total:
                break

            start_index += NVD_RESULTS_PER_PAGE
            time.sleep(self.rate_delay)

        print(f"\n  Done — {len(all_cves)} CVEs fetched")

        result = {
            "fetched_at": datetime.utcnow().isoformat(),
            "pub_start_date": pub_start_date,
            "pub_end_date": pub_end_date,
            "total": len(all_cves),
            "vulnerabilities": all_cves
        }
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"  Saved to {output_path}")

        return all_cves

    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """Fetch a single CVE by ID from NVD in real time."""
        try:
            response = requests.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                headers=self._nvd_headers(),
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return self._parse_cve_record(vulns[0]["cve"])
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {cve_id}: {e}")
        return None

    # =========================================================================
    # MITRE ATT&CK — STIX 2.1 via GitHub raw
    # =========================================================================

    def fetch_mitre_attack_data(self) -> List[Dict]:
        """
        Fetch MITRE ATT&CK Enterprise framework from official STIX data repo.
        Parses all attack-pattern objects into flat dicts.

        Returns:
            List of technique dicts with technique_id, name, description, tactics, platforms
        """
        print(f"\nFetching MITRE ATT&CK data from {MITRE_ATTACK_URL}")
        try:
            response = requests.get(MITRE_ATTACK_URL, timeout=60)
            response.raise_for_status()
            raw = response.json()
        except requests.exceptions.RequestException as e:
            print(f"  Error fetching MITRE data: {e}")
            return []

        objects = raw.get("objects", [])
        techniques = []

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False):
                continue

            # Get the canonical MITRE technique ID (e.g. T1055.011)
            technique_id = None
            url = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    url = ref.get("url")
                    break

            if not technique_id:
                continue

            # Tactics from kill_chain_phases
            tactics = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            techniques.append({
                "technique_id": technique_id,
                "technique_name": obj.get("name", ""),
                "description": obj.get("description", "")[:500],
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "detection": obj.get("x_mitre_detection", "")[:300],
                "url": url,
                "version": obj.get("x_mitre_version", ""),
                "modified": obj.get("modified", ""),
                "source": "MITRE_ATTACK"
            })

        print(f"  Parsed {len(techniques)} MITRE ATT&CK techniques (non-deprecated)")

        # Save raw stix to original path for compatibility
        with open(self.mitre_path, "w") as f:
            json.dump(raw, f, indent=2)
        print(f"  Raw STIX saved to {self.mitre_path}")

        # Also save parsed flat version alongside
        parsed_path = self.mitre_path.replace(".json", "_parsed.json")
        with open(parsed_path, "w") as f:
            json.dump(techniques, f, indent=2)
        print(f"  Parsed techniques saved to {parsed_path}")

        return techniques

    # =========================================================================
    # GSA — GitHub Advisory Database REST API
    # =========================================================================

    def _github_headers(self) -> Dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def fetch_gsa_data(self, per_page: int = 100, max_pages: int = 10) -> List[Dict]:
        """
        Fetch GitHub Security Advisories (GHSA) from GitHub REST API.
        Returns reviewed advisories sorted by most recently updated.

        Args:
            per_page: Records per page (max 100)
            max_pages: Max pages to fetch

        Returns:
            List of advisory dicts
        """
        print(f"\nFetching GitHub Security Advisories")
        if self.github_token:
            print("  GitHub token: present (higher rate limit: 5000 req/hr)")
        else:
            print("  GitHub token: not set (set GITHUB_TOKEN env var — limit is 60 req/hr)")

        gsa_records = []

        for page in range(1, max_pages + 1):
            params = {
                "per_page": min(per_page, 100),
                "page": page,
                "sort": "updated",
                "direction": "desc",
                "type": "reviewed"   # only reviewed advisories (higher quality)
            }

            try:
                response = requests.get(
                    GITHUB_ADVISORY_URL,
                    params=params,
                    headers=self._github_headers(),
                    timeout=30
                )
                response.raise_for_status()
                advisories = response.json()
            except requests.exceptions.RequestException as e:
                print(f"  Error fetching GSA page {page}: {e}")
                break

            if not advisories:
                print(f"  No more advisories at page {page}")
                break

            for advisory in advisories:
                vulnerabilities = advisory.get("vulnerabilities", [])

                # Flatten CVSS scores
                cvss_severities = advisory.get("cvss_severities", {})
                cvss_v3 = cvss_severities.get("cvss_v3", {})
                cvss_v4 = cvss_severities.get("cvss_v4", {})

                # CWE IDs
                cwes = [c.get("cwe_id", "") for c in advisory.get("cwes", [])]

                if vulnerabilities:
                    for vuln in vulnerabilities:
                        pkg = vuln.get("package", {})
                        record = {
                            "ghsa_id": advisory.get("ghsa_id", ""),
                            "cve_id": advisory.get("cve_id") or "",
                            "summary": advisory.get("summary", ""),
                            "description": (advisory.get("description") or "")[:400],
                            "severity": advisory.get("severity", "").upper(),
                            "package": pkg.get("name", ""),
                            "ecosystem": pkg.get("ecosystem", ""),
                            "vulnerable_versions": vuln.get("vulnerable_version_range", ""),
                            "fixed_version": vuln.get("first_patched_version", ""),
                            "cwes": cwes,
                            "cvss_v3_score": cvss_v3.get("score", 0.0),
                            "cvss_v3_vector": cvss_v3.get("vector_string", ""),
                            "cvss_v4_score": cvss_v4.get("score", 0.0),
                            "cvss_v4_vector": cvss_v4.get("vector_string", ""),
                            "published_at": advisory.get("published_at", ""),
                            "updated_at": advisory.get("updated_at", ""),
                            "html_url": advisory.get("html_url", ""),
                            "source": "GHSA"
                        }
                        gsa_records.append(record)
                else:
                    # Advisory with no specific vuln packages — still useful
                    gsa_records.append({
                        "ghsa_id": advisory.get("ghsa_id", ""),
                        "cve_id": advisory.get("cve_id") or "",
                        "summary": advisory.get("summary", ""),
                        "description": (advisory.get("description") or "")[:400],
                        "severity": advisory.get("severity", "").upper(),
                        "package": "",
                        "ecosystem": "",
                        "vulnerable_versions": "",
                        "fixed_version": "",
                        "cwes": cwes,
                        "cvss_v3_score": cvss_v3.get("score", 0.0),
                        "cvss_v3_vector": cvss_v3.get("vector_string", ""),
                        "cvss_v4_score": cvss_v4.get("score", 0.0),
                        "cvss_v4_vector": cvss_v4.get("vector_string", ""),
                        "published_at": advisory.get("published_at", ""),
                        "updated_at": advisory.get("updated_at", ""),
                        "html_url": advisory.get("html_url", ""),
                        "source": "GHSA"
                    })

            print(f"  Page {page}: {len(advisories)} advisories → running total: {len(gsa_records)}")

            # Respect GitHub rate limits
            time.sleep(1)

        print(f"\n  Total GSA records: {len(gsa_records)}")
        with open(self.gsa_path, "w") as f:
            json.dump(gsa_records, f, indent=2)
        print(f"  Saved to {self.gsa_path}")

        return gsa_records

    # =========================================================================
    # Extraction helpers (downstream compatibility)
    # =========================================================================

    def extract_cve_fields(self, cve_json_path: str) -> List[Dict]:
        """Load parsed CVE data from file — compatible with NVD 2.0 output."""
        with open(cve_json_path) as f:
            data = json.load(f)
        # New format: {"vulnerabilities": [...]}
        if isinstance(data, dict) and "vulnerabilities" in data:
            return data["vulnerabilities"]
        # Already a flat list
        if isinstance(data, list):
            return data
        return []

    def extract_mitre_fields(self) -> List[Dict]:
        """Load parsed MITRE techniques. Uses _parsed.json if available."""
        parsed_path = self.mitre_path.replace(".json", "_parsed.json")
        if os.path.exists(parsed_path):
            with open(parsed_path) as f:
                return json.load(f)
        # Fallback: parse raw STIX on the fly
        with open(self.mitre_path) as f:
            raw = json.load(f)
        techniques = []
        for obj in raw.get("objects", []):
            if obj.get("type") != "attack-pattern" or obj.get("x_mitre_deprecated"):
                continue
            technique_id = next(
                (r.get("external_id") for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"), None
            )
            if not technique_id:
                continue
            techniques.append({
                "technique_id": technique_id,
                "technique_name": obj.get("name", ""),
                "description": obj.get("description", "")[:500],
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"],
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "source": "MITRE_ATTACK"
            })
        return techniques

    def extract_gsa_fields(self) -> List[Dict]:
        """Load GSA records from file."""
        with open(self.gsa_path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []


# =============================================================================
# Entry point
# =============================================================================
if __name__ == "__main__":
    config = get_config()

    BASE_DIR = config.data.cve_base_dir
    EXTRACT_DIR = config.data.cve_extract_dir
    MITRE_PATH = config.data.mitre_file
    GSA_PATH = config.data.gsa_file

    ingestion = DataIngestion(BASE_DIR, EXTRACT_DIR, MITRE_PATH, GSA_PATH)

    # Fetch CVEs published in last 120 days (adjust days_back as needed)
    cve_data = ingestion.fetch_cve_data(days_back=120)

    # Fetch all MITRE ATT&CK techniques
    mitre_data = ingestion.fetch_mitre_attack_data()

    # Fetch latest GitHub Security Advisories (10 pages × 100 = up to 1000 advisories)
    gsa_data = ingestion.fetch_gsa_data(per_page=100, max_pages=10)

    print(f"\n=== Ingestion Complete ===")
    print(f"  CVEs:       {len(cve_data)}")
    print(f"  MITRE:      {len(mitre_data)}")
    print(f"  GSA:        {len(gsa_data)}")
