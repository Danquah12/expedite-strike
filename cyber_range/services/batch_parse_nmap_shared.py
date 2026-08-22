# batch_parse_nmap_shared.py
# STEP 3: Batch parse shared-drive Nmap XML files (NO Neo4j writes)

import os
from parse_nmap_xml import parse_nmap_xml

SCAN_ROOT = "/mnt/scans/incoming/nmap"

# GLOBAL, IMPORTABLE RESULTS
PARSED_RESULTS = {
    "assets": [],
    "services": [],
    "vulnerabilities": [],
    "files_processed": [],
    "files_failed": []
}

def run_batch_parse():
    xml_files = sorted(
        f for f in os.listdir(SCAN_ROOT)
        if f.endswith(".xml") and f.startswith("nmap_")
    )

    print(f"[+] Found {len(xml_files)} XML files")

    for fname in xml_files:
        path = os.path.join(SCAN_ROOT, fname)
        try:
            data = parse_nmap_xml(path)

            PARSED_RESULTS["assets"].extend(data["assets"])
            PARSED_RESULTS["services"].extend(data["services"])
            PARSED_RESULTS["vulnerabilities"].extend(data["vulnerabilities"])
            PARSED_RESULTS["files_processed"].append(fname)

            print(
                f"[OK] {fname} | "
                f"hosts={len(data['assets'])} "
                f"services={len(data['services'])} "
                f"vulns={len(data['vulnerabilities'])}"
            )

        except Exception as e:
            PARSED_RESULTS["files_failed"].append((fname, str(e)))
            print(f"[FAIL] {fname} → {e}")

    print("\n===== SUMMARY =====")
    print(f"assets: {len(PARSED_RESULTS['assets'])}")
    print(f"services: {len(PARSED_RESULTS['services'])}")
    print(f"vulnerabilities: {len(PARSED_RESULTS['vulnerabilities'])}")
    print(f"files_processed: {len(PARSED_RESULTS['files_processed'])}")
    print(f"files_failed: {len(PARSED_RESULTS['files_failed'])}")

# 🔥 CRITICAL: parse immediately on import
run_batch_parse()

if __name__ == "__main__":
    pass
