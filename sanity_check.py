import json, traceback
from pathlib import Path

base_dir = Path("/mnt/scans/incoming/aegisprobe")
for meta_path in base_dir.glob("*.json"):
    print(f"\n--- Testing {meta_path} ---")
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        
        ingest_val = meta.get("ingest", {})
        print(f"ingest_val is type: {type(ingest_val)}")
        if ingest_val.get("status") == "completed":
            print("Successfully skipped!")
            continue
        print("Did not skip. Scanner:", meta.get("scanner"))
    except Exception as e:
        print(f"FAILED: {repr(e)}")
