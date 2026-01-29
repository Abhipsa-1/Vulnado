import requests
import json
import zipfile
import os

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_API_URL = "https://api.github.com/graphql"
QUERY = """
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
# Endpoint URL
MITREURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

def fetch_mitre_attack_data(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # Raises HTTPError for 4xx/5xx

        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None


# NVD Feeds
NVD_FEEDS = {
    "recent": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip",
    "modified": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip",
    "2026": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.zip",
}

BASE_DIR = "/Users/abhipsa/Documents/VulnGuard AI/CVE base"
EXTRACT_DIR = "/Users/abhipsa/Documents/VulnGuard AI/CVE extract"

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)


def download_feed(url, output_path):
    response = requests.get(url, stream=True, timeout=60)
    response.raise_for_status()

    with open(output_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)


def extract_zip(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)


def download_CVE_feeds(feeds):
    for feed_name, feed_url in feeds.items():
        print(f"Downloading {feed_name} feed...")

        zip_file_path = os.path.join(BASE_DIR, f"{feed_name}.zip")
        download_feed(feed_url, zip_file_path)

        print(f"Extracting {feed_name} feed...")
        extract_zip(zip_file_path, EXTRACT_DIR)

        print(f"{feed_name} feed processed successfully\n")

def fetch_gsa_data():
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    response = requests.post(
        GITHUB_API_URL,
        headers=headers,
        json={"query": QUERY},
        timeout=30
    )

    response.raise_for_status()
    return response.json()

def save_gsa_data_to_file(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)



#extract the required fields from CVE.json
# def extract_cve_fields(cve_file, output_file):
#     with open(cve_file, "r") as f:
#         data = json.load(f)

#     extracted_data = []
#     for item in data.get("CVE_Items", []):
#         cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
#         description_data = item.get("cve", {}).get("description", {}).get("description_data", [])
#         description = description_data[0].get("value", "") if description_data else ""
#         published_date = item.get("publishedDate", "")
#         last_modified_date = item.get("lastModifiedDate", "")

#         extracted_data.append({
#             "cve_id": cve_id,
#             "description": description,
#             "published_date": published_date,
#             "last_modified_date": last_modified_date
#         })

#     with open(output_file, "w") as f:
#         json.dump(extracted_data, f, indent=2)

#     print(f"Extracted data saved to {output_file}")


if __name__ == "__main__":
    mitre_data = fetch_mitre_attack_data(MITREURL)

    if mitre_data:
        print("Data fetched successfully!")
        print(f"Top-level keys: {mitre_data.keys()}")

        # Optional: save to file
        with open("/Users/abhipsa/Documents/VulnGuard AI/MITRE.json", "w") as f:
            json.dump(mitre_data, f, indent=2)

        print("JSON saved as MITRE.json")

    download_CVE_feeds(NVD_FEEDS)

# Fetch data and save to a JSON file in the current folder
    gsa_data = fetch_gsa_data()
    save_gsa_data_to_file(gsa_data, "/Users/abhipsa/Documents/VulnGuard AI/GSA_data.json")
    print("GSA SAVED as GSA_data.json")

    # extract_cve_fields("/Users/abhipsa/Documents/VulnGuard AI/MITRE.json", "/Users/abhipsa/Documents/VulnGuard AI/MITRE_extracted.json")
    
#Extracted field from CVE>json


