import requests
import json
import zipfile
import os

class DataIngestion:
    def __init__(self, base_dir, extract_dir, mitre_path, gsa_path):
        self.base_dir = base_dir
        self.extract_dir = extract_dir
        self.mitre_path = mitre_path
        self.gsa_path = gsa_path

        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.extract_dir, exist_ok=True)

        self.NVD_FEEDS = {
            "recent": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip",
            "modified": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip",
            "2026": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.zip",
        }
        self.MITREURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.GITHUB_API_URL = "https://api.github.com/graphql"
        self.QUERY = """
            query {
            securityAdvisories(first: 50) {
            nodes {
                summary
                severity
                identifiers {
                type
                value
                }
                vulnerabilities(first: 5) {
                nodes {
                    vulnerableVersionRange
                    firstPatchedVersion {
                    identifier
                    }
                    package {
                    name
                    }
                }
                }
                references {
                url
                }
            }
            }
            }
        """

    def fetch_mitre_attack_data(self):
        try:
            response = requests.get(self.MITREURL, timeout=30)
            response.raise_for_status()
            data = response.json()
            with open(self.mitre_path, "w") as f:
                json.dump(data, f, indent=2)
            return data
        except requests.exceptions.RequestException as e:
            print(f"Error fetching MITRE data: {e}")
            return None

    def download_feed(self, url, output_path):
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

    def extract_zip(self, zip_path, extract_to):
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_to)

    def download_CVE_feeds(self):
        for feed_name, feed_url in self.NVD_FEEDS.items():
            print(f"Downloading {feed_name} feed...")
            zip_file_path = os.path.join(self.base_dir, f"{feed_name}.zip")
            self.download_feed(feed_url, zip_file_path)
            print(f"Extracting {feed_name} feed...")
            self.extract_zip(zip_file_path, self.extract_dir)
            print(f"{feed_name} feed processed successfully\n")

    def fetch_gsa_data(self):
        headers = {
            "Authorization": f"Bearer {self.GITHUB_TOKEN}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            self.GITHUB_API_URL,
            headers=headers,
            json={"query": self.QUERY},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        with open(self.gsa_path, "w") as f:
            json.dump(data, f, indent=4)
        return data

    # Extraction methods for mapping
    def extract_cve_fields(self, cve_json_path):
        with open(cve_json_path) as f:
            data = json.load(f)
        # Example: extract CVE ID and description
        extracted = []
        for item in data.get("CVE_Items", []):
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            desc = item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value")
            extracted.append({"cve_id": cve_id, "description": desc})
        return extracted

    def extract_mitre_fields(self):
        with open(self.mitre_path) as f:
            data = json.load(f)
        # Example: extract technique IDs and names
        extracted = []
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                extracted.append({
                    "id": obj.get("external_references", [{}])[0].get("external_id"),
                    "name": obj.get("name")
                })
        return extracted

    def extract_gsa_fields(self):
        with open(self.gsa_path) as f:
            data = json.load(f)
        # Example: extract summary and severity
        advisories = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        extracted = []
        for adv in advisories:
            extracted.append({
                "summary": adv.get("summary"),
                "severity": adv.get("severity"),
                "identifiers": adv.get("identifiers", [])
            })
        return extracted

# Example usage:
if __name__ == "__main__":
    BASE_DIR = "/Users/abhipsa/Documents/VulnGuard AI/CVE base"
    EXTRACT_DIR = "/Users/abhipsa/Documents/VulnGuard AI/CVE extract"
    MITRE_PATH = "/Users/abhipsa/Documents/VulnGuard AI/MITRE.json"
    GSA_PATH = "/Users/abhipsa/Documents/VulnGuard AI/GSA_data.json"

    ingestion = DataIngestion(BASE_DIR, EXTRACT_DIR, MITRE_PATH, GSA_PATH)
    mitre_data = ingestion.fetch_mitre_attack_data()
    ingestion.download_CVE_feeds()
    gsa_data = ingestion.fetch_gsa_data()

    # Extraction examples
    # cve_fields = ingestion.extract_cve_fields(<path_to_extracted_cve_json>)
    # mitre_fields = ingestion.extract_mitre_fields()
    # gsa_fields = ingestion.extract_gsa_fields()
