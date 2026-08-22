# cyber_range/services/kev_mapper.py

import json
from pathlib import Path

KEV_FILE = Path("cyber_range/data/kev.json")


def load_kev_index():
    """
    Loads CISA KEV JSON and returns a lookup dict keyed by CVE ID.
    """
    if not KEV_FILE.exists():
        raise FileNotFoundError(
            f"KEV file not found at {KEV_FILE}. "
            "Download it from CISA first."
        )

    with open(KEV_FILE, "r") as f:
        data = json.load(f)

    index = {}
    for item in data.get("vulnerabilities", []):
        index[item["cveID"]] = item

    return index


def enrich_with_kev(feed, kev_index):
    """
    Returns KEV metadata for an ImportFeed if applicable.
    """
    if feed.source == "cve" and feed.feed_id in kev_index:
        kev = kev_index[feed.feed_id]
        return {
            "in_kev": True,
            "due_date": kev.get("dueDate"),
            "ransomware": kev.get("knownRansomwareCampaignUse", False),
        }

    return {
        "in_kev": False,
        "due_date": None,
        "ransomware": False,
    }
