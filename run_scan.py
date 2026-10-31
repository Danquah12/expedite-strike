#!/usr/bin/env python3
"""Expedite Strike Scan Runner — runs a full pentest and generates PDF report."""
import sys, time, os, glob, json
sys.path.insert(0, '/opt/vuln_intel/app')

# Suppress proxy
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ[k] = ""

from dotenv import load_dotenv
load_dotenv('/opt/vuln_intel/app/.env', override=True)

from cyber_range.services import ext_pentest_engine as eng
from cyber_range.services import pt_pdf_generator as pdf

target = sys.argv[1] if len(sys.argv) > 1 else "owasp.org"
phases = ["passive", "active", "vuln", "exploit"]

print(f"[{time.strftime('%H:%M:%S')}] 🚀 Starting scan: {target}")
print(f"[{time.strftime('%H:%M:%S')}] Phases: {phases}")

scan_id = eng.start_scan([target], phases)
print(f"[{time.strftime('%H:%M:%S')}] Scan ID: {scan_id}")

# Wait for completion (up to 30 min)
for i in range(360):
    data = eng.get_all(scan_id)
    status = data.get("status", "unknown")
    ticked = data.get("ticked", [])
    logs = data.get("logs", [])
    last = logs[-1] if logs else {}
    
    print(f"\r[{time.strftime('%H:%M:%S')}] {status:8s} | Tools: {len(ticked):2d} | Logs: {len(logs):3d} | {last.get('tool','?')}: {last.get('msg','')[:55]}", end="  ", flush=True)
    
    if status in ("done", "stopped", "error"):
        print()
        break
    time.sleep(5)

print(f"\n[{time.strftime('%H:%M:%S')}] Scan finished: {status}")

# Collect results
results = data.get("results", {})
all_findings = []
all_exploits = []
for tgt_key, tgt_data in results.items():
    all_findings.extend(tgt_data.get("findings", []))
    all_exploits.extend(tgt_data.get("auto_exploits", []))

print(f"[{time.strftime('%H:%M:%S')}] Total findings: {len(all_findings)}")
print(f"[{time.strftime('%H:%M:%S')}] Total exploits: {len(all_exploits)}")

# Severity breakdown
sev = {}
for f in all_findings:
    s = f.get("severity", f.get("risk", "info")).lower()
    sev[s] = sev.get(s, 0) + 1
for s, c in sorted(sev.items()):
    print(f"  {s:12s}: {c}")

# Exploit breakdown
exp_status = {}
for e in all_exploits:
    st = e.get("status", "?")
    exp_status[st] = exp_status.get(st, 0) + 1
for st, c in sorted(exp_status.items()):
    print(f"  Exploit {st:15s}: {c}")

# Generate PDF report
print(f"\n[{time.strftime('%H:%M:%S')}] 📄 Generating PDF report...")
os.makedirs("/opt/vuln_intel/app/reports", exist_ok=True)
ts = time.strftime("%Y%m%d_%H%M%S")
pdf_path = f"/opt/vuln_intel/app/reports/ext_pentest_{target.replace('.','_')}_{ts}.pdf"

# Build the results dict that pt_pdf_generator expects
report_data = {
    "target": target,
    "targets": data.get("targets", [target]),
    "timestamp": time.strftime("%Y-%m-%d %H:%M"),
    "phases_run": phases,
    "data": results.get(f"Tgt1:{target}", results.get(target, {})),
}

# If data is nested under target keys, flatten
if not report_data["data"]:
    # Try first target key
    for k, v in results.items():
        report_data["data"] = v
        break

try:
    out = pdf.generate_pdf(report_data, pdf_path)
    print(f"[{time.strftime('%H:%M:%S')}] ✅ Report: {out}")
    print(f"[{time.strftime('%H:%M:%S')}] Size: {os.path.getsize(out):,} bytes")
except Exception as e:
    print(f"[{time.strftime('%H:%M:%S')}] ❌ PDF error: {e}")
    import traceback
    traceback.print_exc()

print(f"\n[{time.strftime('%H:%M:%S')}] Done.")
