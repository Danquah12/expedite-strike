#!/usr/bin/env python3
"""
import_scans.py
Locate XML reports in feeds/{nmap,openvas,zap,burp}/ and import them.
"""

import sys, os, glob
from pathlib import Path
import importlib

# --- Configuration ---
PROJECT_ROOT = Path("/root/vuln_intel")
FEEDS_ROOT = PROJECT_ROOT / "feeds"
SUBDIRS = ["nmap", "openvas", "zap", "burp"]

# --- Add project root to path ---
sys.path.insert(0, str(PROJECT_ROOT))

# --- Try to load app.xml_parser.import_xml ---
def load_importer():
    try:
        xml_parser = importlib.import_module("app.xml_parser")
        if hasattr(xml_parser, "import_xml"):
            print("✅ Loaded import_xml() from app.xml_parser")
            return xml_parser.import_xml
        else:
            print("⚠ app.xml_parser found but no import_xml() defined.")
    except ModuleNotFoundError:
        print("⚠ Module app.xml_parser not found.")
    return None

# --- Discover XML files ---
def discover_xmls():
    found = []
    for sub in SUBDIRS:
        scan_dir = FEEDS_ROOT / sub
        if not scan_dir.exists():
            continue
        for f in sorted(scan_dir.glob("*.xml")):
            found.append(f)
    return found

# --- Main routine ---
def main():
    importer = load_importer()
    if not importer:
        print("❌ Cannot continue — no importer function available.")
        print("Hint: create app/xml_parser.py with a function import_xml(path).")
        print("Alternatively, use merge_feeds.py to load feeds.")
        return 1

    xmls = discover_xmls()
    if not xmls:
        print("⚠ No XML files found under", FEEDS_ROOT)
        print("Expected structure:")
        print("  feeds/nmap/*.xml, feeds/openvas/*.xml, feeds/zap/*.xml, feeds/burp/*.xml")
        return 2

    print(f"\n📁 Found {len(xmls)} XML files:")
    for f in xmls:
        print(" -", f)

    for f in xmls:
        try:
            print(f"\n🚀 Importing {f} ...")
            importer(str(f))
            print(f"✅ Imported {f}")
        except Exception as e:
            print(f"❌ Error importing {f}: {e}")

    print("\n🎯 Import completed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
