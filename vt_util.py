import requests

API_KEY = "d3816e6fbbd1bfca6677cd25cdb97bfa95fd9fb5373a4cfe634eb3ae66c44b1a"  # 🔁 Replace with your actual key

def check_url_virustotal(url: str) -> str:
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": API_KEY}

    # Submit URL for scanning
    response = requests.post(scan_url, headers=headers, data={"url": url})
    if response.status_code != 200:
        return "Error: unable to scan with VirusTotal"

    data_id = response.json()["data"]["id"]
    
    # Fetch analysis result
    result_url = f"https://www.virustotal.com/api/v3/analyses/{data_id}"
    result_response = requests.get(result_url, headers=headers)
    if result_response.status_code != 200:
        return "Error: unable to fetch VT result"

    stats = result_response.json()["data"]["attributes"]["stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]

    if malicious > 0 or suspicious > 0:
        return f"{malicious} malicious, {suspicious} suspicious"
    return "No issues detected"
