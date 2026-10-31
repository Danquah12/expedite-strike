#!/usr/bin/env python3
"""
patch_pingcastle_paths.py
Patch the real PingCastle binary paths into ui_pingcastle.py and
update ScanOrchestrator / ScanParams defaults.
"""

PC_EXE  = "/home/kali/Downloads/PingCastle_3.5.0.44/PingCastle.exe"
PC_DIR  = "/home/kali/Downloads/PingCastle_3.5.0.44"

# ── 1. Patch ui_pingcastle.py ─────────────────────────────────────────────────
ui_path = "/opt/vuln_intel/app/cyber_range/moduls/ui_pingcastle.py"
with open(ui_path, encoding="utf-8") as f:
    src = f.read()

# Replace Windows-style default exe path with real Linux path
import re

new_src = re.sub(
    r'(id=["\']pc-exe-path["\'].*?value=)[^,\n]+',
    f'\\1"{PC_EXE}"',
    new_src if (new_src := src) else src,
    flags=re.DOTALL
)

with open(ui_path, "w", encoding="utf-8") as f:
    f.write(new_src)
print(f"[OK] ui_pingcastle.py  → pc-exe-path default = {PC_EXE}")

# ── 2. Patch scan_orchestrator.py ScanParams defaults ────────────────────────
orch_path = "/opt/vuln_intel/app/cyber_range/services/scan_orchestrator.py"
with open(orch_path, encoding="utf-8") as f:
    src = f.read()

src = src.replace(
    r"pc_exe:        str         = r\"C:\Tools\PingCastle\PingCastle.exe\"",
    f'pc_exe:        str         = "{PC_EXE}"'
)
with open(orch_path, "w", encoding="utf-8") as f:
    f.write(src)
print(f"[OK] scan_orchestrator.py → ScanParams.pc_exe default = {PC_EXE}")

# ── 3. Patch pingcastle_service.py Wine invocation to also pass --server correctly ─
svc_path = "/opt/vuln_intel/app/cyber_range/services/pingcastle_service.py"
with open(svc_path, encoding="utf-8") as f:
    svc = f.read()

# Insert --no-enum-limit flag and set output dir to PC_DIR/reports/
OLD = '            "--healthcheck",\n            "--server",   dc_ip,'
NEW = (
    '            "--healthcheck",\n'
    '            "--server",   dc_ip,\n'
    '            "--no-enum-limit",\n'
    f'            "--outputdirectory", "{PC_DIR}",\n'
)
if OLD in svc:
    svc = svc.replace(OLD, NEW)
    with open(svc_path, "w", encoding="utf-8") as f:
        f.write(svc)
    print("[OK] pingcastle_service.py → added --no-enum-limit + explicit --outputdirectory")
else:
    print("[SKIP] pingcastle_service.py — pattern not found (already patched?)")

# ── 4. Update _find_report to also check PC_DIR for any *.html report ─────────
OLD_FIND = '        try:\n            for fname in os.listdir(directory):\n                if fname.endswith(".html") and "ad_hc_" in fname.lower():'
NEW_FIND = (
    '        for search_dir in [directory, "' + PC_DIR + '"]:\n'
    '          try:\n'
    '            for fname in os.listdir(search_dir):\n'
    '                if fname.endswith(".html") and "ad_hc_" in fname.lower():'
)
with open(svc_path, encoding="utf-8") as f:
    svc = f.read()
if OLD_FIND in svc:
    svc = svc.replace(OLD_FIND, NEW_FIND)
    # Fix the indentation of the return inside the nested loop
    svc = svc.replace(
        '                    return os.path.join(directory, fname)',
        '                    return os.path.join(search_dir, fname)'
    )
    with open(svc_path, "w", encoding="utf-8") as f:
        f.write(svc)
    print("[OK] pingcastle_service.py → _find_report searches PC_DIR too")
else:
    print("[SKIP] _find_report — pattern not found")

print("\n✅  All patches applied.")
print(f"    PingCastle.exe   : {PC_EXE}")
print(f"    Reports saved to : {PC_DIR}/")
