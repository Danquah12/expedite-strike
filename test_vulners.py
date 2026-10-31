# test_vulners.py
import os
import requests
import sys

api_key = os.getenv("VULNERS_API_KEY")
if not api_key:
    print("❗ VULNERS_API_KEY not set in environment. Set it with: export VULNERS_API_KEY=...")
    sys.exit(1)

url = "https://vulners.com/api/v3/search/lucene/"
params = {"query": "CVE-2021-44228", "size": 10}
headers = {"X-Api-Key": api_key}

try:
    resp = requests.get(url, params=params, headers=headers, timeout=12)
    resp.raise_for_status()
    data = resp.json()
    print("✅ Vulners responded. Top-level keys:", list(data.keys()))
    # Example: show first result summary if present
    results = data.get("data", {}).get("search", {}).get("results", [])
    if results:
        print("Sample result (first):")
        print(results[0])
    else:
        print("No results found in response data.")
except requests.HTTPError as e:
    print("HTTP error:", e)
    print("Response body:", resp.text if 'resp' in locals() else "no resp")
except Exception as e:
    print("Error:", e)
