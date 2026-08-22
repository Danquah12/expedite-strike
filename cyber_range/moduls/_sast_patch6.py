"""
Patch 6 — integrate sast_plugins + risk_scoring into _full_scan() as Engine #4.
SAFE TO RE-RUN: checks for existing patches before applying.
"""
import sys, shutil

SRC = "/opt/vuln_intel/app/cyber_range/moduls/ui_sast.py"
shutil.copy(SRC, SRC + ".bak6")

with open(SRC) as f:
    content = f.read()

changed = False

# ── 1. Add plugin imports near the scan engines section ─────────────────────
IMPORT_ANCHOR = "def _ensure_tool(tool: str) -> bool:"
IMPORT_BLOCK = '''\
# ── Plugin engine imports ─────────────────────────────────────────────────
try:
    from sast_plugins import run_all_plugins as _plugin_runner
    from sast_plugins.risk_scoring import score_all_findings as _score_findings
    from sast_plugins.remediation_plugin import enrich_fixes as _enrich_fixes
    from sast_plugins.exploit_generator import enrich_with_exploits as _enrich_exploits
    _PLUGINS_AVAILABLE = True
except ImportError:
    _PLUGINS_AVAILABLE = False
    def _plugin_runner(fp, code, lang): return []
    def _score_findings(findings): return findings
    def _enrich_fixes(findings): return findings
    def _enrich_exploits(findings): return findings


'''
if IMPORT_ANCHOR in content and "_PLUGINS_AVAILABLE" not in content:
    content = content.replace(IMPORT_ANCHOR, IMPORT_BLOCK + IMPORT_ANCHOR, 1)
    print("✅ Added plugin import block")
    changed = True
elif "_PLUGINS_AVAILABLE" in content:
    print("ℹ️  Plugin imports already present — skipping")
else:
    print("⚠️  Import anchor not found")

# ── 2. Add _run_plugins() function before _full_scan ─────────────────────────
FULL_SCAN_DEF = "def _full_scan(code: str, language: str) -> tuple:"
PLUGIN_FUNC = '''\
def _run_plugins(code: str, language: str, tmpfile: str) -> list:
    """Run all sast_plugins and normalise findings."""
    if not _PLUGINS_AVAILABLE:
        return []
    try:
        return _plugin_runner(tmpfile, code, language)
    except Exception:
        return []


'''
if FULL_SCAN_DEF in content and "_run_plugins" not in content:
    content = content.replace(FULL_SCAN_DEF, PLUGIN_FUNC + FULL_SCAN_DEF, 1)
    print("✅ Inserted _run_plugins() function")
    changed = True
elif "_run_plugins" in content:
    print("ℹ️  _run_plugins already present — skipping")
else:
    print("⚠️  _full_scan anchor not found")

# ── 3. Extend containers from 3 → 4 ─────────────────────────────────────────
OLD_CONTAINERS = '    containers  = [[] for _ in range(3)]\n    labels      = ["Regex", "Semgrep", "Bandit"]'
NEW_CONTAINERS = '    containers  = [[] for _ in range(4)]\n    labels      = ["Regex", "Semgrep", "Bandit", "Plugins"]'
if OLD_CONTAINERS in content:
    content = content.replace(OLD_CONTAINERS, NEW_CONTAINERS, 1)
    print("✅ Extended containers to 4")
    changed = True
elif '"Plugins"' in content:
    print("ℹ️  Containers already extended — skipping")
else:
    print("⚠️  containers pattern not found")

# ── 4. Add t3() plugin thread after t2() ─────────────────────────────────────
OLD_T2 = (
    "    def t2():\n"
    "        if language == \"python\":\n"
    "            containers[2].extend(_run_bandit(code, tmpfile))\n"
    "\n"
    "    threads = []"
)
NEW_T2 = (
    "    def t2():\n"
    "        if language == \"python\":\n"
    "            containers[2].extend(_run_bandit(code, tmpfile))\n"
    "    def t3(): containers[3].extend(_run_plugins(code, language, tmpfile))\n"
    "\n"
    "    threads = []"
)
if OLD_T2 in content:
    content = content.replace(OLD_T2, NEW_T2, 1)
    print("✅ Added t3() plugin thread")
    changed = True
elif "def t3():" in content:
    print("ℹ️  t3() already present — skipping")
else:
    print("⚠️  t2 thread pattern not found")

# ── 5. Include t3 in the thread loop ─────────────────────────────────────────
OLD_LOOP = "    for fn in [t0, t1, t2]:"
NEW_LOOP = "    for fn in [t0, t1, t2, t3]:"
if OLD_LOOP in content:
    content = content.replace(OLD_LOOP, NEW_LOOP, 1)
    print("✅ Added t3 to thread loop")
    changed = True
elif "t3" in content and "for fn in" in content:
    print("ℹ️  t3 already in loop — skipping")
else:
    print("⚠️  thread loop pattern not found")

# ── 6. Apply CVSS scoring as post-pass in _full_scan return ──────────────────
OLD_RETURN = (
    "    order = {s: i for i, s in enumerate(SEV_ORDER)}\n"
    "    results.sort(key=lambda x: order.get(x.get(\"severity\", \"INFO\"), 99))\n"
    "    return results, engine_counts"
)
NEW_RETURN = (
    "    order = {s: i for i, s in enumerate(SEV_ORDER)}\n"
    "    results.sort(key=lambda x: order.get(x.get(\"severity\", \"INFO\"), 99))\n"
    "    results = _score_findings(results)   # attach CVSS scores\n"
    "    results = _enrich_fixes(results)     # fill empty fix fields\n"
    "    results = _enrich_exploits(results)  # attach PoC payloads\n"
    "    return results, engine_counts"
)
if OLD_RETURN in content:
    content = content.replace(OLD_RETURN, NEW_RETURN, 1)
    print("✅ Applied CVSS risk scoring + auto-remediation post-pass")
    changed = True
elif "_score_findings" in content and "_enrich_fixes" in content:
    print("ℹ️  CVSS scoring + remediation already applied — skipping")
elif "_score_findings" in content:
    # Upgrade: add _enrich_fixes after existing _score_findings line
    old_partial = "    results = _score_findings(results)  # attach CVSS scores\n    return results, engine_counts"
    new_partial  = "    results = _score_findings(results)  # attach CVSS scores\n    results = _enrich_fixes(results)    # fill empty fix fields\n    return results, engine_counts"
    if old_partial in content:
        content = content.replace(old_partial, new_partial, 1)
        print("✅ Upgraded: added _enrich_fixes post-pass")
        changed = True
    else:
        print("⚠️  Could not locate _score_findings line to upgrade")
else:
    print("⚠️  return pattern not found")

# ── Write + syntax check ──────────────────────────────────────────────────────
with open(SRC, "w") as f:
    f.write(content)

import subprocess
r = subprocess.run([sys.executable, "-m", "py_compile", SRC], capture_output=True, text=True)
if r.returncode == 0:
    print("\n✅ Syntax check passed — all plugins + CVSS scoring integrated!")
else:
    print("\n❌ Syntax error:", r.stderr)
    shutil.copy(SRC + ".bak6", SRC)
    print("⚠️  Restored from backup")

if not changed:
    print("\nℹ️  No changes were needed — file is already up to date")
