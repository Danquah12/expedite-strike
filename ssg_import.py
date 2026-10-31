#!/usr/bin/env python3
"""
ssg_import.py — Ægis SCAP Security Guide Importer v3
======================================================
Handles SSG 0.1.75+ which ships as SCAP DataStream (.ds.xml) files
AND plain XCCDF (.xccdf.xml) files.

Can import from:
  - Extracted directory: /mnt/scans/incoming/scap/scap-security-guide-0.1.80/
  - Directly from zip:   /mnt/scans/incoming/scap/scap-security-guide-0.1.80.zip

Usage:
    # From directory (if already extracted)
    python3 /opt/vuln_intel/app/ssg_import.py

    # From zip (no extraction needed)
    python3 /opt/vuln_intel/app/ssg_import.py --from-zip

    # Custom path
    python3 /opt/vuln_intel/app/ssg_import.py --ssg-dir /path/to/ssg-dir
    python3 /opt/vuln_intel/app/ssg_import.py --ssg-zip /path/to/ssg.zip
"""

import os
import sys
import shutil
import argparse
import zipfile
import io
import xml.etree.ElementTree as ET

# ── Default paths ─────────────────────────────────────────────────────
APP_DIR     = os.path.dirname(os.path.abspath(__file__))
SSG_OUT_DIR = os.path.join(APP_DIR, "scap_benchmarks", "ssg")

DEFAULT_SSG_DIR = "/mnt/scans/incoming/scap/scap-security-guide-0.1.80"
DEFAULT_SSG_ZIP = "/mnt/scans/incoming/scap/scap-security-guide-0.1.80.zip"

# ── SSG filename → (category, human description) ──────────────────────
CATEGORY_MAP = [
    # (keyword_in_filename,   category,           description)
    ("rhel9",       "linux_server",   "Red Hat Enterprise Linux 9"),
    ("rhel10",      "linux_server",   "Red Hat Enterprise Linux 10"),
    ("rhel8",       "linux_server",   "Red Hat Enterprise Linux 8"),
    ("rhel7",       "linux_server",   "Red Hat Enterprise Linux 7"),
    ("fedora",      "linux_server",   "Fedora Linux"),
    ("ubuntu2404",  "linux_server",   "Ubuntu 24.04 LTS"),
    ("ubuntu2204",  "linux_server",   "Ubuntu 22.04 LTS"),
    ("ubuntu2004",  "linux_server",   "Ubuntu 20.04 LTS"),
    ("debian13",    "linux_server",   "Debian 13"),
    ("debian12",    "linux_server",   "Debian 12"),
    ("debian11",    "linux_server",   "Debian 11"),
    ("almalinux9",  "linux_server",   "AlmaLinux 9"),
    ("almalinux8",  "linux_server",   "AlmaLinux 8"),
    ("rockylinux9", "linux_server",   "Rocky Linux 9"),
    ("rockylinux8", "linux_server",   "Rocky Linux 8"),
    ("centos7",     "linux_server",   "CentOS 7"),
    ("sle15",       "linux_server",   "SUSE Linux Enterprise 15"),
    ("sle12",       "linux_server",   "SUSE Linux Enterprise 12"),
    ("ol9",         "linux_server",   "Oracle Linux 9"),
    ("ol8",         "linux_server",   "Oracle Linux 8"),
    ("alinux3",     "linux_server",   "Alibaba Cloud Linux 3"),
    ("anolis",      "linux_server",   "Anolis OS"),
    ("slmicro",     "linux_server",   "SUSE Linux Micro"),
    ("windows",     "windows_server", "Windows Server"),
    ("eks",         "cloud",          "Amazon EKS"),
    ("ocp4",        "cloud",          "Red Hat OpenShift 4"),
    ("kubernetes",  "cloud",          "Kubernetes"),
    ("openshift",   "cloud",          "OpenShift"),
    ("cs",          "cloud",          "Container Security"),
    ("nginx",       "applications",   "Nginx Web Server"),
    ("apache",      "applications",   "Apache HTTP Server"),
    ("jre",         "applications",   "Java Runtime Environment"),
    ("firefox",     "applications",   "Firefox"),
    ("chromium",    "applications",   "Chromium Browser"),
    ("rhel",        "linux_server",   "Red Hat Enterprise Linux"),
    ("ubuntu",      "linux_server",   "Ubuntu Linux"),
    ("debian",      "linux_server",   "Debian Linux"),
]

MAX_PER_CATEGORY = 3   # Keep top N per category


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def parse_xml_safely(data: bytes) -> ET.Element | None:
    """Parse XML bytes, return root or None."""
    try:
        return ET.fromstring(data)
    except Exception:
        return None


def xml_ns(tag: str) -> str:
    """Extract namespace from an XML tag like '{http://...}Benchmark'."""
    return tag.split("}")[0] + "}" if "{" in tag else ""


def benchmark_info(data: bytes) -> dict | None:
    """
    For a DataStream (.ds.xml) or XCCDF file, extract:
      - title, rule_count, type ('ds' or 'xccdf')
    Returns None if not a valid benchmark.
    """
    # Quick pre-check — look for key strings
    snippet = data[:2000].decode("utf-8", errors="ignore")
    if "Benchmark" not in snippet and "data-stream" not in snippet.lower():
        return None

    root = parse_xml_safely(data)
    if root is None:
        return None

    ns = xml_ns(root.tag)
    tag_local = root.tag.replace(ns, "")

    # SCAP 1.2 DataStream (ssg-*-ds.xml)
    if "data-stream-collection" in tag_local.lower() or "DataStreamCollection" in root.tag:
        # Count all Rules inside all components
        rules = root.findall(".//{http://checklists.nist.gov/xccdf/1.2}Rule")
        if not rules:
            rules = root.findall(".//Rule")
        # Get title from first embedded Benchmark
        bm = root.find(".//{http://checklists.nist.gov/xccdf/1.2}Benchmark")
        if bm is None:
            bm = root.find(".//Benchmark")
        title_el = bm.find("{http://checklists.nist.gov/xccdf/1.2}title") if bm is not None else None
        if title_el is None and bm is not None:
            title_el = bm.find("title")
        title = (title_el.text or "").strip()[:100] if title_el is not None else "SCAP DataStream"
        return {"type": "ds", "title": title, "rules": len(rules)}

    # Plain XCCDF Benchmark
    if "Benchmark" in tag_local:
        rules = root.findall(f".//{ns}Rule")
        title_el = root.find(f".//{ns}title")
        title = (title_el.text or "").strip()[:100] if title_el is not None else "XCCDF Benchmark"
        return {"type": "xccdf", "title": title, "rules": len(rules)}

    return None


def categorize(fname: str) -> tuple:
    """Match filename against category keywords (longest match wins)."""
    fl = fname.lower()
    for kw, cat, desc in CATEGORY_MAP:
        if kw in fl:
            return cat, desc
    return "general", "General Benchmark"


# ─────────────────────────────────────────────────────────────────────
# Core import functions
# ─────────────────────────────────────────────────────────────────────

def import_from_dir(ssg_dir: str, dry_run: bool = False):
    """Import from an extracted SSG directory."""
    print(f"\n[*] Scanning directory: {ssg_dir}")

    found = []
    for dirpath, dirnames, filenames in os.walk(ssg_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in sorted(filenames):
            if not fname.endswith(".xml"):
                continue
            fpath = os.path.join(dirpath, fname)
            fsize = os.path.getsize(fpath)

            # Skip tiny/huge files and HTML reports
            if fsize < 10_000 or fsize > 300_000_000:
                continue
            # Skip HTML guide dirs
            if os.sep + "guides" + os.sep in dirpath:
                continue

            with open(fpath, "rb") as fh:
                data = fh.read()

            info = benchmark_info(data)
            if info and info["rules"] > 0:
                cat, desc = categorize(fname)
                found.append({
                    "path": fpath, "fname": fname, "size": fsize,
                    "cat": cat, "desc": desc, **info
                })
                print(f"  [{info['type'].upper():5s}][{cat:15s}] {fname}  "
                      f"({fsize//1024} KB, {info['rules']} rules)")

    return _copy_selected(found, dry_run)


def import_from_zip(zip_path: str, dry_run: bool = False):
    """Import directly from the SSG zip — no extraction needed."""
    print(f"\n[*] Reading zip: {zip_path}")

    found = []
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".xml")]
        print(f"    XML entries in zip: {len(names)}")

        for zname in sorted(names):
            info_z = zf.getinfo(zname)
            fsize = info_z.file_size
            fname = os.path.basename(zname)

            # Skip tiny files and HTML guide paths
            if fsize < 10_000:
                continue
            if "/guides/" in zname:
                continue

            data = zf.read(zname)
            info = benchmark_info(data)
            if info and info["rules"] > 0:
                cat, desc = categorize(fname)
                found.append({
                    "path": None, "fname": fname, "size": fsize,
                    "cat": cat, "desc": desc, "data": data, **info
                })
                print(f"  [{info['type'].upper():5s}][{cat:15s}] {fname}  "
                      f"({fsize//1024} KB, {info['rules']} rules)")

    return _copy_selected(found, dry_run)


def _copy_selected(found: list, dry_run: bool) -> list:
    """Select top N per category and copy to SSG_OUT_DIR."""
    if not found:
        print("\n[!] No valid SCAP benchmarks found.")
        print("    Ensure the SSG directory/zip is correct.")
        return []

    # Group by category
    by_cat: dict[str, list] = {}
    for item in found:
        by_cat.setdefault(item["cat"], []).append(item)

    # Sort each category by rule count (more = more comprehensive)
    selected = []
    print(f"\n[*] Selecting top {MAX_PER_CATEGORY} per category:\n")
    for cat, items in sorted(by_cat.items()):
        items_s = sorted(items, key=lambda x: x["rules"], reverse=True)
        chosen = items_s[:MAX_PER_CATEGORY]
        print(f"  [{cat.upper():20s}]  {len(items)} found → {len(chosen)} selected")
        for it in chosen:
            print(f"    + {it['fname']:55s}  {it['rules']:4d} rules  — {it['desc']}")
            selected.append(it)
        print()

    print(f"[*] Total to import: {len(selected)} benchmarks\n")

    if dry_run:
        print("[DRY RUN] No files written.")
        return selected

    # Copy
    os.makedirs(SSG_OUT_DIR, exist_ok=True)
    imported = []
    for item in selected:
        dst = os.path.join(SSG_OUT_DIR, item["fname"])
        try:
            if item.get("data"):
                with open(dst, "wb") as fh:
                    fh.write(item["data"])
            else:
                shutil.copy2(item["path"], dst)

            sz = os.path.getsize(dst) / 1024 / 1024
            print(f"  ✓ {item['fname']}  "
                  f"({sz:.1f} MB, {item['rules']} rules, {item['type'].upper()})")
            imported.append(item)
        except Exception as e:
            print(f"  ✗ {item['fname']}: {e}")

    # Manifest
    manifest = os.path.join(SSG_OUT_DIR, "manifest.txt")
    with open(manifest, "w") as mf:
        mf.write("# Ægis SSG Import Manifest — SSG 0.1.80\n")
        mf.write(f"# Imported: {len(imported)} benchmarks\n\n")
        for item in imported:
            mf.write(f"{item['cat']}|{item['fname']}|{item['rules']}|"
                     f"{item.get('title','')}\n")

    print(f"\n{'='*65}")
    print(f"  ✅  {len(imported)} benchmarks → {SSG_OUT_DIR}")
    print(f"  Manifest : {manifest}")
    print(f"\n  Ægis will auto-discover these on the next SCAP scan.")
    print(f"  No restart needed.")
    print(f"{'='*65}\n")
    return imported


# ─────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Import official SSG benchmarks into Ægis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--ssg-dir", default=DEFAULT_SSG_DIR,
                   help=f"Extracted SSG directory (default: {DEFAULT_SSG_DIR})")
    p.add_argument("--ssg-zip", default=DEFAULT_SSG_ZIP,
                   help=f"SSG zip file (default: {DEFAULT_SSG_ZIP})")
    p.add_argument("--from-zip", action="store_true",
                   help="Force reading from zip even if dir exists")
    p.add_argument("--dry-run", action="store_true",
                   help="Preview — don't copy files")
    args = p.parse_args()

    print(f"\n{'='*65}")
    print(f"  Ægis SCAP Security Guide Importer  v3")
    print(f"  Output: {SSG_OUT_DIR}")
    print(f"{'='*65}")

    if args.from_zip or not os.path.isdir(args.ssg_dir):
        # Try zip
        if os.path.exists(args.ssg_zip):
            import_from_zip(args.ssg_zip, dry_run=args.dry_run)
        elif os.path.isdir(args.ssg_dir):
            import_from_dir(args.ssg_dir, dry_run=args.dry_run)
        else:
            print(f"\n[ERROR] Neither found:")
            print(f"  Dir: {args.ssg_dir}")
            print(f"  Zip: {args.ssg_zip}")
            print(f"\nUsage: python3 ssg_import.py --ssg-dir /path/to/extracted/ssg")
            print(f"   or: python3 ssg_import.py --from-zip --ssg-zip /path/to/ssg.zip")
            sys.exit(1)
    else:
        import_from_dir(args.ssg_dir, dry_run=args.dry_run)
