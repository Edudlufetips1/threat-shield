import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev_feed(url: str) -> dict:
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError(f"Failed to fetch KEV feed: {response.status_code}")

    return response.json()

def normalize_item(raw_vuln: dict) -> dict:
    return {
        "id": raw_vuln.get("cveID", ""),
        "title": raw_vuln.get("vulnerabilityName", "Unknown Vulnerability"),
        "description": raw_vuln.get("shortDescription", ""),
        "source": "cisa_kev",
        "date": raw_vuln.get("dateAdded", ""),
        "ransomware_use": raw_vuln.get("knownRansomwareCampaignUse", "Unknown"),
        "due_date": raw_vuln.get("dueDate", "")
    }

def process_kev_feed(data_dict: dict) -> list:
    raw_list = data_dict.get("vulnerabilities", [])
    normalized_list = []
    for item in raw_list:
        normalized_item_data = normalize_item(item)
        normalized_list.append(normalized_item_data)
    return normalized_list

GO_SERVER_URL = "http://localhost:8080/api/vulnerabilities"  

def send_vulnerabilities_to_go(normalized_list: list):
    try:
        response = requests.post(GO_SERVER_URL, json=normalized_list)
        if response.status_code in [200, 201, 202]:
            print(f"Successfully sent: {len(normalized_list)} vulnerabilities.")
        else:
            print(f"Failed to send vulnerabilities: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("Failed to connect to the Go server.")

if __name__ == "__main__":
    print("Step 1: Fetching CISA KEV feed...")
    raw_data = fetch_kev_feed(KEV_URL)
    print("Step 2: Normalizing KEV feed data...")
    normalized_data = process_kev_feed(raw_data)
    print(f"Step 3: Sending {len(normalized_data)} vulnerabilities to Go server...")
    send_vulnerabilities_to_go(normalized_data)
    print("CISA KEV pipeline run complete.")