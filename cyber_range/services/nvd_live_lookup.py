import requests
import os
from functools import lru_cache

@lru_cache(maxsize=128)
def fetch_nvd_data(cve_id):
    """
    Fetches live Description and Severity from the NVD API using the configured key.
    Results are cached in memory for the duration of the web process.
    """
    if not cve_id or not str(cve_id).startswith("CVE-"):
        return {"description": None, "severity": None}
    
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, headers=headers, timeout=5)
        
        # NVD may 404 on unassigned/invalid CVEs or rate limit (403/429)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
                vuln = data["vulnerabilities"][0]["cve"]
                
                # Extract Description
                desc = "No description found in NVD."
                for d in vuln.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value")
                        break
                        
                # Extract Severity (v3.1 first, then v3.0, then v2)
                severity = None
                metrics = vuln.get("metrics", {})
                
                if "cvssMetricV31" in metrics:
                    severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity")
                elif "cvssMetricV3" in metrics:
                    severity = metrics["cvssMetricV3"][0].get("cvssData", {}).get("baseSeverity")
                elif "cvssMetricV2" in metrics:
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity")

                return {
                    "description": desc,
                    "severity": severity
                }
    except Exception as e:
        print("[NVD API ERROR]", e)
        
    return {"description": None, "severity": None}
