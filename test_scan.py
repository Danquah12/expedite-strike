#!/usr/bin/env python3
"""
Quick test: run the Ægis pentest engine directly and inspect results.
This bypasses the web UI so we can verify all 5 phases run correctly.
"""
import sys, os, json, time, threading
sys.path.insert(0, "/opt/vuln_intel/app")
os.chdir("/opt/vuln_intel/app")

from cyber_range.services import ext_pentest_engine as eng

# Start a scan with all 5 phases against localhost
target = "127.0.0.1"
scan_id = eng.start_scan(target, phases=["passive","active","vuln","exploit","post"])
print(f"Scan started: {scan_id}")
print(f"Target: {target}")
print(f"Phases: passive, active, vuln, exploit, post")
print("=" * 70)

# Poll every 5 seconds until done
last_log_count = 0
while True:
    state = eng._SCANS.get(scan_id, {})
    status = state.get("status", "unknown")
    logs = state.get("logs", [])
    ticked = state.get("ticked", set())
    results = state.get("results", {})
    
    # Print new logs
    for l in logs[last_log_count:]:
        print(f"  [{l['ts']}] [{l['tool']:<12}] {l['msg'][:100]}")
    last_log_count = len(logs)
    
    if status in ("done", "stopped", "error"):
        break
    time.sleep(3)

print("\n" + "=" * 70)
print(f"FINAL STATUS: {status}")
print(f"TOTAL LOGS: {len(logs)}")
print(f"TICKED ITEMS: {len(ticked)}")

# Show results structure
print(f"\nRESULTS STRUCTURE:")
for tgt_key, tgt_phases in results.items():
    print(f"\n  TARGET: {tgt_key}")
    if isinstance(tgt_phases, dict):
        for phase_key, phase_items in tgt_phases.items():
            if isinstance(phase_items, list):
                tools = [item.get('tool','?') for item in phase_items if isinstance(item, dict)]
                print(f"    PHASE '{phase_key}': {len(phase_items)} tools → {tools}")
                for item in phase_items:
                    if isinstance(item, dict):
                        data = item.get("data", {})
                        if isinstance(data, dict):
                            if "error" in data:
                                print(f"      ❌ {item['tool']}: ERROR — {data['error'][:80]}")
                            elif "findings" in data:
                                print(f"      ✔ {item['tool']}: {len(data['findings'])} findings")
                            elif "results" in data:
                                print(f"      ✔ {item['tool']}: {len(data['results'])} results (matched={data.get('matched',0)})")
                            elif "open_ports" in data:
                                print(f"      ✔ {item['tool']}: ports={data['open_ports']}")
                            else:
                                print(f"      ✔ {item['tool']}: keys={list(data.keys())[:6]}")
    else:
        print(f"    (not a dict: {type(tgt_phases).__name__})")

# Check exploit chain results specifically
print(f"\n{'='*70}")
print("EXPLOIT CHAIN DETAIL:")
for tgt_key, tgt_phases in results.items():
    if isinstance(tgt_phases, dict):
        for phase_key, phase_items in tgt_phases.items():
            if not isinstance(phase_items, list): continue
            for item in phase_items:
                if isinstance(item, dict) and item.get("tool") == "EXPLOIT_DB":
                    d = item["data"]
                    print(f"  Matched: {d.get('matched',0)}")
                    print(f"  Executed: {d.get('executed',0)}")
                    print(f"  Vulnerable: {d.get('confirmed_vulnerable',0)}")
                    print(f"  Not Vuln: {d.get('not_vulnerable',0)}")
                    print(f"  Skipped: {d.get('skipped',0)}")
                    print(f"  Errors: {d.get('errors',0)}")
                    for r in d.get("results", []):
                        status_icon = "🔴" if r["status"] == "vulnerable" else \
                                      "🟢" if r["status"] == "not_vulnerable" else "⚪"
                        print(f"    {status_icon} {r['exploit_id']}: {r['name']} [{r['severity']}] — {r['status']}")

print("\nDone.")
