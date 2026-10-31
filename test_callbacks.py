"""Scan ALL .py files for Output() calls without allow_duplicate=True
that share the same (id, property) pair across multiple @callback blocks."""
import os, re
from collections import defaultdict

APP_DIR = r"D:\Software Engineering\Software-Engineering-Project-main\Software-Engineering-Project-main\tuhousing\AEGIS ON WINDOWS\app"

# Pattern to match Output("id", "prop") or Output("id", "prop", allow_duplicate=True)
output_re = re.compile(
    r'Output\(\s*"([^"]+)"\s*,\s*"([^"]+)"'
    r'(?:\s*,\s*allow_duplicate\s*=\s*True)?'
    r'\s*\)'
)

# Track: (id, prop) -> list of (file, line, has_allow_duplicate)
registry = defaultdict(list)

for root, dirs, files in os.walk(APP_DIR):
    dirs[:] = [d for d in dirs if d != "__pycache__"]
    for f in files:
        if not f.endswith(".py"):
            continue
        path = os.path.join(root, f)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    for m in output_re.finditer(line):
                        oid, prop = m.group(1), m.group(2)
                        has_ad = "allow_duplicate=True" in m.group(0)
                        registry[(oid, prop)].append((f, i, has_ad))
        except Exception:
            pass

# Find duplicates: same (id, prop) in multiple callbacks where ANY lacks allow_duplicate
print("=== Outputs used by multiple callbacks with at least one missing allow_duplicate ===\n")
count = 0
for (oid, prop), entries in sorted(registry.items()):
    if len(entries) < 2:
        continue
    missing = [e for e in entries if not e[2]]
    if missing:
        count += 1
        print(f"  {oid}.{prop}:")
        for fname, line, has_ad in entries:
            flag = "OK" if has_ad else "MISSING"
            print(f"    {fname}:{line}  {flag}")
        print()

if count == 0:
    print("  ✅ No remaining duplicates found!")
else:
    print(f"\n  ⚠️  {count} duplicate output(s) need fixing")
