#!/usr/bin/env python3
"""
ssg_extend.py — Add missing distro benchmarks to Ægis
Run from your terminal (where /mnt/scans is accessible):
    python3 /opt/vuln_intel/app/ssg_extend.py
"""
import os, shutil

SSG = "/mnt/scans/incoming/scap/scap-security-guide-0.1.80"
DST = "/opt/vuln_intel/app/scap_benchmarks/ssg"

EXTRA = [
    "ssg-ubuntu2204-ds.xml",
    "ssg-ubuntu2404-ds.xml",
    "ssg-fedora-ds.xml",
    "ssg-debian12-ds.xml",
    "ssg-almalinux9-ds.xml",
    "ssg-ol9-ds.xml",
]

os.makedirs(DST, exist_ok=True)
print(f"\nCopying extra SSG benchmarks to {DST}\n")
for f in EXTRA:
    src = os.path.join(SSG, f)
    dst = os.path.join(DST, f)
    if os.path.exists(dst):
        print(f"  ✓ {f} (already exists)")
        continue
    if not os.path.exists(src):
        print(f"  ✗ {f} — not found in {SSG}")
        continue
    shutil.copy2(src, dst)
    size = os.path.getsize(dst) / 1024 / 1024
    print(f"  ✓ {f}  ({size:.1f} MB)")

print(f"\nDone. Total benchmarks:")
xmls = [f for f in os.listdir(DST) if f.endswith('.xml')]
for f in sorted(xmls):
    print(f"  {f}")
