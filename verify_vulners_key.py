#!/usr/bin/env python3
import os, requests, sys

api_key = os.getenv("VULNERS_API_KEY")
if not api_key:
    print("❗ VULNERS_API_KEY not set in environment. Export it or put it in .env")
    sys.exit(1)

try:
    resp = requests.get(
        "https://vulners.com/api/v3/search/lucene/",
        params={"query": "CVE-2021-44228", "size": 10},
        headers={"X-Api-Key": api_key},
        timeout=12
    )
    resp.raise_for_status()
    data = resp.json()
    print("✅ Vulners responded. Top-level JSON keys:", list(data.keys()))
except requests.HTTPError as e:
    print("HTTP error:", e)
    if 'resp' in locals():
        print("Response body:", resp.text)
except Exception as e:
    print("Error:", e)
