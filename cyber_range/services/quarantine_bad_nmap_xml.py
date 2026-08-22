# quarantine_bad_nmap_xml.py
# Deterministic quarantine of malformed Nmap XML files

import os
import shutil
import xml.etree.ElementTree as ET

SCAN_ROOT = "/mnt/scans/incoming/nmap"
QUARANTINE = "/mnt/scans/incoming/nmap/_quarantine"

os.makedirs(QUARANTINE, exist_ok=True)

def is_clean_xml(path):
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        return root.tag == "nmaprun"
    except Exception:
        return False

def main():
    xml_files = [f for f in os.listdir(SCAN_ROOT) if f.endswith(".xml")]

    clean = 0
    bad = 0

    for fname in xml_files:
        src = os.path.join(SCAN_ROOT, fname)
        if not os.path.isfile(src):
            continue

        if is_clean_xml(src):
            clean += 1
        else:
            bad += 1
            dst = os.path.join(QUARANTINE, fname)
            print(f"[QUARANTINE] {fname}")
            shutil.move(src, dst)

    print("\n===== RESULT =====")
    print(f"Clean XML files : {clean}")
    print(f"Quarantined     : {bad}")
    print(f"Quarantine dir  : {QUARANTINE}")

if __name__ == "__main__":
    main()
