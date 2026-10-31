#!/usr/bin/env python3
"""
patch_ui_paths.py — Replace default exe paths in ui_pingcastle.py by line number.
Run: python3 /opt/vuln_intel/app/patch_ui_paths.py
"""

UI_PATH = "/opt/vuln_intel/app/cyber_range/moduls/ui_pingcastle.py"
PC_EXE  = "/home/kali/Downloads/PingCastle_3.5.0.44/PingCastle.exe"
BH_EXE  = "/home/kali/Downloads/SharpHound.exe"

with open(UI_PATH, encoding="utf-8") as f:
    lines = f.readlines()

changed = 0
for i, line in enumerate(lines):
    if "pc-exe-path" in line or (
        'value=' in line and 'PingCastle.exe' in line
    ):
        # next line has the value=
        look_ahead = lines[i + 1] if i + 1 < len(lines) else ""
        if 'value=' in look_ahead and "PingCastle" in look_ahead:
            # replace that line's value
            import re
            lines[i + 1] = re.sub(
                r'value=.*?,',
                f'value="{PC_EXE}",',
                lines[i + 1]
            )
            changed += 1

    if "pc-bh-path" in line or (
        'value=' in line and 'SharpHound.exe' in line
    ):
        look_ahead = lines[i + 1] if i + 1 < len(lines) else ""
        if 'value=' in look_ahead and "SharpHound" in look_ahead:
            import re
            lines[i + 1] = re.sub(
                r'value=.*?,',
                f'value="{BH_EXE}",',
                lines[i + 1]
            )
            changed += 1

# Also do a direct string replace as a safety net
content = "".join(lines)
import re as re2
content = re2.sub(
    r'(id=["\']pc-exe-path["\'][^>]*\n\s*value=)[^\n,]+,',
    f'\\g<1>"{PC_EXE}",',
    content
)
content = content.replace(
    r'value=r"C:\Tools\PingCastle\PingCastle.exe"',
    f'value="{PC_EXE}"'
)
content = content.replace(
    r'value=r"C:\Tools\SharpHound\SharpHound.exe"',
    f'value="{BH_EXE}"'
)

with open(UI_PATH, "w", encoding="utf-8") as f:
    f.write(content)

print(f"[OK] Patched {UI_PATH}")
print(f"     PingCastle : {PC_EXE}")
print(f"     SharpHound : {BH_EXE}")
