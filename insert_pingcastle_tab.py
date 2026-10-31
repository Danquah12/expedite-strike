#!/usr/bin/env python3
"""Insert a hidden pingcastle tab into app.py at line 8569."""
import sys

path = "/opt/vuln_intel/app/app.py"
new_line = '                 dbc.Tab(label="", tab_id="pingcastle",      style={"display": "none"}),\n'

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Insert after line 8568 (0-indexed: 8567)
lines.insert(8568, new_line)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"Done. File now has {len(lines)} lines.")
# Verify
print("Lines 8568-8571:")
for i, l in enumerate(lines[8567:8572], start=8568):
    print(f"  {i}: {repr(l)}")
