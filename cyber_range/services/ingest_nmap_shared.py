#!/usr/bin/env python3

import os

SCAN_ROOT = "/mnt/scans/incoming/nmap"


def find_valid_nmap_xml(scan_root):
    """
    Deterministically identify valid Nmap XML files.
    Criteria:
      - File ends with .xml
      - File contains <nmaprun> anywhere in the first 4KB
    """
    valid_files = []

    for fname in sorted(os.listdir(scan_root)):
        if not fname.endswith(".xml"):
            continue

        path = os.path.join(scan_root, fname)

        if not os.path.isfile(path):
            continue

        try:
            with open(path, "r", errors="ignore") as fh:
                head = fh.read(4096)  # FIX: was too small before
                if "<nmaprun" not in head:
                    continue

            valid_files.append(path)

        except Exception as e:
            print(f"[SKIP] {path} -> {e}")

    return valid_files


def main():
    xml_files = find_valid_nmap_xml(SCAN_ROOT)

    print(f"Valid Nmap XML files: {len(xml_files)}")
    for f in xml_files:
        print(f" - {f}")


if __name__ == "__main__":
    main()

