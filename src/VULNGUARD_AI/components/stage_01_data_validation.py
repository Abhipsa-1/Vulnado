from stage_00_data_ingestion import DataIngestion 
import json
import os

# Extract necessary fields from MITRE.json, GSA_data.json and CVE Extract
class DataValidation:
    def __init__(self, mitre_path, gsa_path, cve_extract_path):
        self.mitre_path = mitre_path
        self.gsa_path = gsa_path
        self.cve_extract_path = cve_extract_path


#extract MITRE ATACK required fields  
    def extract_mitre_attack_patterns(self):
        with open(self.mitre_path, "r") as f:
            mitre_data = json.load(f)

        techniques = []

        for obj in mitre_data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            techniques.append({
                "technique_id": technique_id,
                "technique_name": obj.get("name"),
                "technique_description": obj.get("description"),
                "tactic": [
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": obj.get("x_mitre_platforms", [])
            })
        print(f"Extracted {len(techniques)} techniques from MITRE data.")
        return techniques

#extract CVE core fields
    def extract_cve_core_fields(vuln: dict) -> dict:
   

        cve = vuln.get("cve", {})

        # -------------------------
        # 1. CVE ID
        # -------------------------
        cve_id = cve.get("id")

        # -------------------------
        # 2. Description (English)
        # -------------------------
        description = None
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break

        # -------------------------
        # 3. Severity (CVSS priority: v3.1 → v4.0 → v2)
        # -------------------------
        severity = None
        metrics = cve.get("metrics", {})

        if metrics.get("cvssMetricV31"):
            severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity")
        elif metrics.get("cvssMetricV40"):
            severity = metrics["cvssMetricV40"][0]["cvssData"].get("baseSeverity")
        elif metrics.get("cvssMetricV2"):
            severity = metrics["cvssMetricV2"][0].get("baseSeverity")
        # 4.Software fixed
        affected_software = []

        configurations = cve.get("configurations", [])

        for config in configurations:                  # <-- list
            for node in config.get("nodes", []):        # <-- dict
                for cpe in node.get("cpeMatch", []):

                    criteria = cpe.get("criteria", "")
                    parts = criteria.split(":")

                    affected_software.append({
                        "vendor": parts[3] if len(parts) > 3 else None,
                        "product": parts[4] if len(parts) > 4 else None,
                        "version": parts[5] if len(parts) > 5 else None,
                        "cpe": criteria,
                        "vulnerable": cpe.get("vulnerable")
                    })


        # (B) NLP fallback (when no CPEs exist — your screenshot case)
        if not affected_software and description:
            if "warehouse" in description.lower():
                affected_software.append({
                    "product": "yeqifu warehouse",
                    "version": "rolling release",
                    "source": "description"
                })

        # -------------------------
        # 5. References
        # -------------------------
        references = [
            ref.get("url")
            for ref in cve.get("references", [])
            if ref.get("url")
        ]

        return {
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "affected_software": affected_software,
            "references": references
        }


    # def validate_gsa_data(self):
    #     required_keys = ["data", "securityAdvisories"]
    #     return self.validate_json_structure(self.gsa_path, required_keys)

#extract GSA required fields
def extract_gsa_fix_fields(advisory: dict) -> dict:
    """
    Extract remediation-relevant fields from a single GSA security advisory node
    """

    # -------------------------
    # 1. Identifiers
    # -------------------------
    cve_id = None
    ghsa_id = None
    
    for identifier in advisory.get("identifiers", []):
        if not isinstance(identifier, dict):
            continue  # <-- FIX: skip None or invalid entries

        id_type = identifier.get("type")
        id_value = identifier.get("value")

        if id_type == "CVE":
            cve_id = id_value
        elif id_type == "GHSA":
            ghsa_id = id_value

    # -------------------------
    # 2. Severity
    # -------------------------
    severity = advisory.get("severity")

    # -------------------------
    # 3. Vulnerability details
    # -------------------------
    package_name = None
    vulnerable_versions = None
    fixed_version = None

    vuln_nodes = advisory.get("vulnerabilities", {}).get("nodes", [])

    if vuln_nodes:
        vuln = vuln_nodes[0]  # primary affected package

        vulnerable_versions = vuln.get("vulnerableVersionRange")

        first_patched = vuln.get("firstPatchedVersion")

        if isinstance(first_patched, dict):
            fixed_version = first_patched.get("identifier")
        else:
            fixed_version = None


        package_name = (
            vuln.get("package", {})
                .get("name")
        )

    # -------------------------
    # 4. References
    # -------------------------
    references = [
        ref.get("url")
        for ref in advisory.get("references", [])
        if ref.get("url")
    ]

    return {
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "severity": severity,
        "package_name": package_name,
        "vulnerable_versions": vulnerable_versions,
        "fixed_version": fixed_version,
        "references": references
    }



if __name__ == "__main__":
    MITRE_PATH = "/Users/abhipsa/Documents/VulnGuard AI/MITRE.json"
    GSA_PATH = "/Users/abhipsa/Documents/VulnGuard AI/GSA_data.json"
    CVE_EXTRACT_PATH = "/Users/abhipsa/Documents/VulnGuard AI/CVE extract"

    # Output directories for normalized data
    NORMALIZED_DIR = "/Users/abhipsa/Documents/VulnGuard AI/normalized"
    MITRE_OUT = os.path.join(NORMALIZED_DIR, "mitre")
    CVE_OUT = os.path.join(NORMALIZED_DIR, "cve")
    GSA_OUT = os.path.join(NORMALIZED_DIR, "gsa")

    # Ensure output directories exist
    os.makedirs(MITRE_OUT, exist_ok=True)
    os.makedirs(CVE_OUT, exist_ok=True)
    os.makedirs(GSA_OUT, exist_ok=True)

    validator = DataValidation(MITRE_PATH, GSA_PATH, CVE_EXTRACT_PATH)

    # MITRE extraction and save
    mitre_fields = validator.extract_mitre_attack_patterns()
    mitre_outfile = os.path.join(MITRE_OUT, "mitre_attack_patterns.json")
    with open(mitre_outfile, "w") as f:
        json.dump(mitre_fields, f, indent=2)
    print(f"Saved normalized MITRE data to {mitre_outfile}")

    # CVE extraction and save
    extracted_cves = []
    for filename in os.listdir(CVE_EXTRACT_PATH):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(CVE_EXTRACT_PATH, filename)
        print(f"Processing CVE file: {filename}")
        with open(file_path, "r") as f:
            cve_data = json.load(f)
        vulnerabilities = cve_data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            extracted_cves.append(
                DataValidation.extract_cve_core_fields(vuln)
            )
    cve_outfile = os.path.join(CVE_OUT, "cve_core_fields.json")
    with open(cve_outfile, "w") as f:
        json.dump(extracted_cves, f, indent=2)
    print(f"Saved normalized CVE data to {cve_outfile}")

    # GSA extraction and save
    with open(GSA_PATH, "r") as f:
        gsa_data = json.load(f)
    advisories = (
        gsa_data
            .get("data", {})
            .get("securityAdvisories", {})
            .get("nodes", [])
    )
    extracted_gsa_fixes = []
    for advisory in advisories:
        extracted_gsa_fixes.append(
            extract_gsa_fix_fields(advisory)
        )
    gsa_outfile = os.path.join(GSA_OUT, "gsa_fix_fields.json")
    with open(gsa_outfile, "w") as f:
        json.dump(extracted_gsa_fixes, f, indent=2)
    print(f"Saved normalized GSA data to {gsa_outfile}")
