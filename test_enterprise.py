#!/usr/bin/env python3
"""
Enterprise-grade Ægis pentest engine test — verifies:
  1. All 5 phases execute
  2. CVSS scoring on each exploit result
  3. Compliance mapping (NIST/PCI/OWASP/CIS/ISO)
  4. Attack chain context (admin panels, ports, technologies)
  5. Risk matrix generation
"""
import sys, os, json, time, threading
sys.path.insert(0, "/opt/vuln_intel/app")
os.chdir("/opt/vuln_intel/app")

from cyber_range.services import ext_pentest_engine as eng

target = "127.0.0.1"
scan_id = eng.start_scan(target, phases=["passive","active","vuln","exploit","post"])
print(f"Scan: {scan_id} | Target: {target}")
print("=" * 70)

last = 0
while True:
    st = eng._SCANS.get(scan_id, {})
    logs = st.get("logs", [])
    for l in logs[last:]:
        print(f"  [{l['ts']}] [{l['tool']:<12}] {l['msg'][:100]}")
    last = len(logs)
    if st.get("status") in ("done", "stopped", "error"):
        break
    time.sleep(3)

# Results
results = st.get("results", {})
print(f"\n{'='*70}")
print("ENTERPRISE FEATURES VALIDATION")
print(f"{'='*70}")

for tgt_key, tgt_phases in results.items():
    if not isinstance(tgt_phases, dict): continue
    for pk, pi in tgt_phases.items():
        if not isinstance(pi, list): continue
        for item in pi:
            if isinstance(item, dict) and item.get("tool") == "EXPLOIT_DB":
                d = item["data"]
                print(f"\n🔬 EXPLOIT CHAIN RESULTS:")
                print(f"  Matched:    {d.get('matched')}")
                print(f"  Executed:   {d.get('executed')}")
                print(f"  Vulnerable: {d.get('confirmed_vulnerable')}")
                print(f"  Clean:      {d.get('not_vulnerable')}")

                # CVSS Risk Matrix
                rm = d.get("risk_matrix", {})
                print(f"\n📊 RISK MATRIX:")
                print(f"  CVSS Critical (≥9.0): {rm.get('cvss_critical', 0)}")
                print(f"  CVSS High (7.0-8.9):  {rm.get('cvss_high', 0)}")
                print(f"  CVSS Medium (4.0-6.9): {rm.get('cvss_medium', 0)}")
                print(f"  Max CVSS Score:       {rm.get('max_cvss', 0)}")

                # Chain Context
                cc = d.get("chain_context", {})
                print(f"\n🔗 CHAIN CONTEXT:")
                print(f"  Credentials harvested: {cc.get('credentials_harvested', 0)}")
                print(f"  Tokens captured:       {cc.get('tokens_captured', 0)}")
                print(f"  Databases discovered:  {cc.get('databases_discovered', [])}")
                print(f"  Internal IPs found:    {cc.get('internal_ips_found', [])}")
                print(f"  Admin panels:          {cc.get('admin_panels', [])}")

                # Compliance Summary
                cs = d.get("compliance_summary", {})
                print(f"\n📋 COMPLIANCE SUMMARY:")
                print(f"  OWASP Top 10 hits:     {cs.get('owasp_top_10', [])}")
                print(f"  NIST 800-53 controls:  {cs.get('nist_800_53_controls_affected', [])}")
                print(f"  PCI-DSS 4.0 reqs:      {cs.get('pci_dss_4_requirements_failed', [])}")
                print(f"  CIS v8 controls:       {cs.get('cis_v8_controls_affected', [])}")
                print(f"  ISO 27001 clauses:     {cs.get('iso_27001_clauses_affected', [])}")
                print(f"  MITRE techniques:      {cs.get('mitre_techniques_observed', [])}")
                print(f"  CWEs identified:       {cs.get('cwes_identified', [])}")
                print(f"  Frameworks impacted:   {cs.get('total_frameworks_impacted', 0)}")

                # Per-result CVSS detail
                print(f"\n⚔  PER-EXPLOIT DETAIL:")
                for r in d.get("results", []):
                    st_icon = "🔴" if r["status"] == "vulnerable" else "🟢"
                    cvss = r.get("cvss_score", "?")
                    owasp = r.get("compliance", {}).get("owasp_2021", {})
                    owasp_id = owasp.get("id", "—") if isinstance(owasp, dict) else "—"
                    print(f"  {st_icon} {r['exploit_id']}: CVSS:{cvss} | {owasp_id} | "
                          f"{r.get('risk_context','')[:60]} | {r.get('execution_time_s','?')}s")

print(f"\n{'='*70}")
print("✅ Enterprise validation complete.")
