#!/usr/bin/env python3
"""
Probe the SSG directory OR zip to show its structure.
Run from YOUR terminal (where /mnt/scans is accessible):
    python3 /opt/vuln_intel/app/ssg_probe.py
"""
import os, sys, zipfile

SSG_ZIP = "/mnt/scans/incoming/scap/scap-security-guide-0.1.80.zip"
SSG_DIR = "/mnt/scans/incoming/scap/scap-security-guide-0.1.80"

def probe_dir(d):
    print(f"\n📁 Directory: {d}")
    print(f"   Exists: {os.path.isdir(d)}\n")
    all_xml = []
    for dirpath, dirnames, filenames in os.walk(d):
        dirnames[:] = [dd for dd in dirnames if not dd.startswith(".")]
        for f in filenames:
            if f.endswith(".xml"):
                fp = os.path.join(dirpath, f)
                all_xml.append((os.path.getsize(fp), fp))

    all_xml.sort(reverse=True)
    print(f"   Total XML: {len(all_xml)}")
    print("   Largest 25:\n")
    for sz, fp in all_xml[:25]:
        rel = fp.replace(d, ".")
        print(f"   {sz//1024:8d} KB   {rel}")

def probe_zip(z):
    print(f"\n📦 Zip: {z}")
    print(f"   Exists: {os.path.exists(z)}\n")
    with zipfile.ZipFile(z) as zf:
        names = zf.namelist()
        xml = [(zf.getinfo(n).file_size, n) for n in names if n.endswith(".xml")]
        xml.sort(reverse=True)
        print(f"   Total files: {len(names)}")
        print(f"   XML files: {len(xml)}")
        print("   Largest 25 XML:\n")
        for sz, n in xml[:25]:
            print(f"   {sz//1024:8d} KB   {n}")

# Try directory first, then zip
if os.path.isdir(SSG_DIR):
    probe_dir(SSG_DIR)
elif os.path.exists(SSG_ZIP):
    probe_zip(SSG_ZIP)
else:
    print(f"[!] Neither found:\n    {SSG_DIR}\n    {SSG_ZIP}")
    print("\n[*] Searching /mnt for SSG files...")
    for root, dirs, files in os.walk("/mnt"):
        for f in files:
            if f.startswith("scap-security") or (f.endswith(".xml") and "ssg-" in f):
                print(f"    {os.path.join(root, f)}")
