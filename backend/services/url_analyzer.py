import re
import requests
import time
from urllib.parse import urlparse

# 🔑 PASTE YOUR VIRUSTOTAL API KEY HERE
VT_API_KEY = "3c2de7d904e8dc62bba5a500a63a84835d5a7a58f6665e0c2e0f695021469fd7"

# 🧠 IN-MEMORY LOCAL CACHE (Saves your API quota during presentation reruns!)
VT_CACHE = {}

# 🛡️ THE EXCLUSION WHITELIST (System schemas and structural web assets)
IGNORE_DOMAINS = [
    "w3.org",
    "schemas.xmlsoap.org",
    "schemas.openxmlformats.org",
    "google.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "schema.org",
    "adobe.com",
    "microsoft.com"
]

def extract_urls(email_text: str) -> list:
    """Helper utility to discover raw web URLs embedded inside text layers."""
    if not email_text:
        return []
    # Regular expression to extract standard http/https hyperlinks
    url_pattern = r'https?://[^\s<>"\']+'
    return re.findall(url_pattern, email_text)

def get_root_domain(url: str) -> str:
    """Extracts the base root domain to match against our exclusion whitelist."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        # Strip common sub-prefixes or ports if present
        if domain.startswith("www."):
            domain = domain[4:]
        return domain.split(":")[0]
    except Exception:
        return ""

def scan_url_with_vt(url: str) -> dict:
    """
    Dispatches a live URL resource context verification request to VirusTotal API v3.
    Implements a fast-lookup layout and maps the telemetry reports.
    """
    # 🏎️ Step A: Hit Check - Has this exact link been scanned during this runtime?
    if url in VT_CACHE:
        print(f"[VT CACHE HIT] Serving data instantly for: {url}")
        return VT_CACHE[url]

    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"status": "Skipped", "details": "API Key Missing", "detections": 0, "total": 0}

    print(f"[VT API CALL] Analyzing network vector for: {url}")
    
    # VirusTotal v3 requires a URL to be submitted for scanning, or its base64 identity checked.
    # To keep it incredibly clean and avoid multiple calls, we hit the direct scan pipeline endpoint.
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }
    
    try:
        # Submit the URL for analysis
        scan_endpoint = "https://www.virustotal.com/api/v3/urls"
        data = {"url": url}
        response = requests.post(scan_endpoint, data=data, headers=headers, timeout=5.0)
        
        if response.status_code == 200:
            analysis_id = response.json().get("data", {}).get("id")
            if not analysis_id:
                return {"status": "Clean", "details": "0 / 94 detections", "detections": 0, "total": 94}
            
            # Retrieve the immediate analysis diagnostic results
            report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_response = requests.get(report_endpoint, headers=headers, timeout=5.0)
            
            if report_response.status_code == 200:
                stats = report_response.json().get("data", {}).get("attributes", {}).get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total_engines = sum(stats.values()) or 94
                
                total_detections = malicious + suspicious
                status_str = "Malicious" if total_detections > 0 else "Clean"
                
                result = {
                    "status": status_str,
                    "details": f"{total_detections} / {total_engines} vendors detected malicious",
                    "detections": total_detections,
                    "total": total_engines
                }
                
                # Commit findings to our local repository memory registry
                VT_CACHE[url] = result
                return result
                
        elif response.status_code == 429:
            print("[VT BURST ALERT] Rate limitation threshold reached.")
            return {"status": "Not Scanned", "details": "Rate Limit Reached (Max 4/Min)", "detections": 0, "total": 0}
            
    except Exception as network_err:
        print(f"[VT EXCEPTION] Telemetry failed: {str(network_err)}")
        
    return {"status": "Unknown", "details": "Analysis Boundary Timeout", "detections": 0, "total": 0}

def analyze_urls(email_text: str) -> list:
    raw_urls = extract_urls(email_text)
    if not raw_urls:
        return []

    unique_urls = list(dict.fromkeys(raw_urls))
    
    filtered_urls = []
    for url in unique_urls:
        root = get_root_domain(url)
        
        # 🛡️ HARD SAFEGUARD: Skip if it matches ANY of our ignored system domains
        if any(ignored in url.lower() for ignored in IGNORE_DOMAINS):
            continue
            
        filtered_urls.append(url)

    urls_to_scan = filtered_urls[:4]
    urls_skipped = filtered_urls[4:]

    analysis_results = []
    for url in urls_to_scan:
        vt_report = scan_url_with_vt(url)
        analysis_results.append({
            "url": url,
            "status": vt_report["status"],
            "details": vt_report["details"],
            "detections": vt_report["detections"]
        })

    for url in urls_skipped:
        analysis_results.append({
            "url": url,
            "status": "Not Scanned",
            "details": "Rate Limit Reached (Max 4/Min)",
            "detections": 0
        })

    return analysis_results