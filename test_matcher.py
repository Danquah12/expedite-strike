#!/usr/bin/env python3
"""
Verify exploit-to-vulnerability mapping works correctly.
Simulates real scanner findings and validates only the RIGHT scripts match.
"""
import sys, json
sys.path.insert(0, "/opt/vuln_intel/app")

from cyber_range.exploit_db import load_all, match_findings, stats

load_all()
s = stats()
print(f"Database: {s['total_scripts']} scripts | {s['cve_count']} CVEs | {len(s['categories'])} categories")
print("=" * 70)

# ══════════════════════════════════════════════════════════════════════
# TEST 1: Nmap only (Port 80 HTTP + Apache) — should NOT trigger web vuln scripts
# ══════════════════════════════════════════════════════════════════════
print("\n[TEST 1] Nmap only (port 80 HTTP + Apache)")
findings1 = {
    "nmap": {"hosts": [{"addrs": {"ipv4": "10.0.0.5"}, "ports": [
        {"port": 80, "service": "http", "product": "Apache", "version": "2.4.52"},
        {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.9"},
    ]}]}
}
m1 = match_findings(findings1)
categories1 = set(e["meta"].get("category","") for e in m1)
web_vulns = {"sqli","xss","lfi","ssrf","cmdi","xxe","ssti","idor","file_upload","deserialization"}
leaked = categories1 & web_vulns
print(f"  Matched: {len(m1)} scripts")
print(f"  Categories: {categories1}")
if leaked:
    print(f"  ❌ FAIL: Web vuln scripts leaked from nmap: {leaked}")
else:
    print(f"  ✅ PASS: No web vuln scripts fired from nmap alone")

# ══════════════════════════════════════════════════════════════════════
# TEST 2: Nuclei SQLi finding — should trigger SQLi script ONLY
# ══════════════════════════════════════════════════════════════════════
print("\n[TEST 2] Nuclei finds SQL Injection")
findings2 = {
    "nuclei": [
        {"template_id": "sql-injection-detect", "name": "SQL Injection Detection",
         "severity": "high", "url": "http://vuln.local/?id=1", "cve": []},
    ],
    "nmap": findings1["nmap"],
}
m2 = match_findings(findings2)
print(f"  Matched: {len(m2)} scripts")
sqli_matches = [e for e in m2 if e["meta"].get("category") == "sqli"]
other_web = [e for e in m2 if e["meta"].get("category") in web_vulns - {"sqli"}]
print(f"  SQLi scripts: {len(sqli_matches)} → {[e['meta']['id'] for e in sqli_matches]}")
print(f"  Other web vuln scripts: {len(other_web)} → {[e['meta']['id'] for e in other_web]}")
if sqli_matches and not other_web:
    print(f"  ✅ PASS: Only SQLi scripts matched")
elif sqli_matches:
    print(f"  ⚠️  PARTIAL: SQLi matched but other web vulns also leaked")
else:
    print(f"  ❌ FAIL: No SQLi scripts matched!")

# ══════════════════════════════════════════════════════════════════════
# TEST 3: ZAP finds XSS + SQL Injection — should trigger both
# ══════════════════════════════════════════════════════════════════════
print("\n[TEST 3] ZAP finds XSS + SQL Injection")
findings3 = {
    "zap": [
        {"name": "Cross Site Scripting (Reflected)", "risk": "High", "url": "http://vuln.local/?q=test"},
        {"name": "SQL Injection", "risk": "High", "url": "http://vuln.local/?id=1"},
    ],
    "nmap": findings1["nmap"],
}
m3 = match_findings(findings3)
xss_matches = [e for e in m3 if e["meta"].get("category") == "xss"]
sqli_matches3 = [e for e in m3 if e["meta"].get("category") == "sqli"]
print(f"  Matched: {len(m3)} scripts")
print(f"  XSS scripts: {len(xss_matches)} → {[e['meta']['id'] for e in xss_matches]}")
print(f"  SQLi scripts: {len(sqli_matches3)} → {[e['meta']['id'] for e in sqli_matches3]}")
if xss_matches and sqli_matches3:
    print(f"  ✅ PASS: Both XSS and SQLi scripts correctly matched")
else:
    print(f"  ❌ FAIL: Missing matches!")

# ══════════════════════════════════════════════════════════════════════
# TEST 4: Full vuln_app scenario — all major vulns found
# ══════════════════════════════════════════════════════════════════════
print("\n[TEST 4] Full vuln_app scenario (SQLi + XSS + LFI + CMDi + SSRF)")
findings4 = {
    "nuclei": [
        {"template_id": "sqli-detect", "name": "SQL Injection", "severity": "high", "url": "http://vuln.local/?id=1", "cve": []},
        {"template_id": "lfi-detect", "name": "Local File Inclusion", "severity": "high", "url": "http://vuln.local/?file=test", "cve": []},
    ],
    "zap": [
        {"name": "Cross Site Scripting (Reflected)", "risk": "High", "url": "http://vuln.local/?q=test"},
        {"name": "OS Command Injection", "risk": "High", "url": "http://vuln.local/?cmd=test"},
        {"name": "Server Side Request Forgery", "risk": "High", "url": "http://vuln.local/?url=test"},
        {"name": "Information Disclosure", "risk": "Medium", "url": "http://vuln.local/"},
        {"name": "Missing Security Headers", "risk": "Low", "url": "http://vuln.local/"},
    ],
    "nmap": findings1["nmap"],
}
m4 = match_findings(findings4)
cats4 = {}
for e in m4:
    cat = e["meta"].get("category", "?")
    cats4.setdefault(cat, []).append(e["meta"]["id"])

print(f"  Matched: {len(m4)} scripts total")
for cat, ids in sorted(cats4.items()):
    sources = set(e.get("match_source","?") for e in m4 if e["meta"].get("category") == cat)
    print(f"    {cat}: {len(ids)} script(s) — {ids} (from {sources})")

expected_cats = {"sqli", "xss", "lfi", "cmdi", "ssrf", "info_disclosure", "security_headers"}
found_cats = set(cats4.keys())
missing = expected_cats - found_cats
extra_web = (found_cats & web_vulns) - expected_cats
print(f"\n  Expected cats: {expected_cats}")
print(f"  Found cats: {found_cats}")
if missing:
    print(f"  ❌ MISSING: {missing}")
else:
    print(f"  ✅ All expected categories matched")
if extra_web:
    print(f"  ⚠️  Extra web vuln scripts: {extra_web}")
else:
    print(f"  ✅ No spurious web vuln scripts")

# ══════════════════════════════════════════════════════════════════════
# TEST 5: CVE-specific match
# ══════════════════════════════════════════════════════════════════════
print("\n[TEST 5] CVE-specific match (CVE-2021-44228 Log4Shell)")
findings5 = {
    "nuclei": [
        {"template_id": "CVE-2021-44228", "name": "Log4Shell RCE", "severity": "critical",
         "url": "http://target.local/", "cve": ["CVE-2021-44228"]},
    ]
}
m5 = match_findings(findings5)
log4j = [e for e in m5 if "44228" in e["meta"]["id"]]
print(f"  Matched: {len(m5)} scripts")
print(f"  Log4Shell: {len(log4j)} → {[e['meta']['id'] for e in log4j]}")
if log4j:
    print(f"  ✅ PASS: CVE match works correctly")
else:
    print(f"  ❌ FAIL: CVE match failed!")

# ══════════════════════════════════════════════════════════════════════
# TEST 6: No findings at all — baseline only
# ══════════════════════════════════════════════════════════════════════
print("\n[TEST 6] No findings (empty) — should get baseline only")
m6 = match_findings({})
cats6 = set(e["meta"].get("category","") for e in m6)
print(f"  Matched: {len(m6)} scripts")
print(f"  Categories: {cats6}")
baseline_expected = {"security_headers", "info_disclosure", "clickjacking", "cors", "csrf"}
if cats6 <= baseline_expected:
    print(f"  ✅ PASS: Only baseline assessment scripts")
else:
    extra = cats6 - baseline_expected
    print(f"  ❌ FAIL: Extra categories beyond baseline: {extra}")

# ══════════════════════════════════════════════════════════════════════
# TEST 7: Confidence levels and sort order
# ══════════════════════════════════════════════════════════════════════
print("\n[TEST 7] Sort order — high confidence first, then critical severity")
m7 = match_findings(findings4)
if len(m7) >= 2:
    first_conf = m7[0].get("match_confidence", "low")
    last_conf = m7[-1].get("match_confidence", "low")
    print(f"  First match: {m7[0]['meta']['id']} confidence={first_conf}")
    print(f"  Last match:  {m7[-1]['meta']['id']} confidence={last_conf}")
    conf_order = {"high": 0, "medium": 1, "low": 2}
    if conf_order.get(first_conf, 3) <= conf_order.get(last_conf, 3):
        print(f"  ✅ PASS: High confidence matches come first")
    else:
        print(f"  ⚠️  Sort order may need review")

print("\n" + "=" * 70)
print("All tests complete.")
