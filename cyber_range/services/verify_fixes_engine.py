"""
Expedite Strike Verify Fixes Engine — Hack-Fix-Verify Loop
===================================================
Save baselines, compare scan results, generate verification reports.
"""

import os
import json
import time
from typing import Callable
from datetime import datetime

BASELINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scan_baselines")

_log_fn = None
def _log(msg):
    if _log_fn:
        _log_fn(msg)


def save_baseline_legacy(state: dict, name: str = None, log_fn: Callable = None) -> str:
    """Save current scan results as JSON baseline."""
    global _log_fn
    _log_fn = log_fn

    os.makedirs(BASELINE_DIR, exist_ok=True)
    name = name or datetime.now().strftime("baseline_%Y%m%d_%H%M%S")
    path = os.path.join(BASELINE_DIR, f"{name}.json")

    baseline = {
        "timestamp": datetime.now().isoformat(),
        "name": name,
        "findings": state.get("findings", []),
        "stats": state.get("stats", {}),
        "hosts": [h.get("ip", "") for h in state.get("hosts_discovered", [])],
        "exploits": state.get("exploits_succeeded", []),
        "credentials": state.get("credentials", []),
    }

    with open(path, "w") as f:
        json.dump(baseline, f, indent=2, default=str)

    _log(f"  [VERIFY] Baseline saved: {path}")
    _log_fn = None
    return path


def load_baseline_legacy(path: str = None, log_fn: Callable = None) -> dict:
    """Load the most recent baseline."""
    global _log_fn
    _log_fn = log_fn

    if not path:
        os.makedirs(BASELINE_DIR, exist_ok=True)
        files = sorted([f for f in os.listdir(BASELINE_DIR) if f.endswith(".json")])
        if not files:
            _log("  [VERIFY] No baselines found")
            _log_fn = None
            return {}
        path = os.path.join(BASELINE_DIR, files[-1])

    with open(path, "r") as f:
        baseline = json.load(f)

    _log(f"  [VERIFY] Loaded baseline: {baseline.get('name', path)} ({baseline.get('timestamp', '?')})")
    _log_fn = None
    return baseline


def compare_results_legacy(baseline: dict, current: dict) -> dict:
    """Diff baseline vs current scan results."""
    base_findings = {f"{f.get('title','')}__{f.get('host','')}" for f in baseline.get("findings", [])}
    curr_findings = {f"{f.get('title','')}__{f.get('host','')}" for f in current.get("findings", [])}

    fixed_keys = base_findings - curr_findings
    still_vuln_keys = base_findings & curr_findings
    new_keys = curr_findings - base_findings

    fixed = [f for f in baseline.get("findings", [])
             if f"{f.get('title','')}__{f.get('host','')}" in fixed_keys]
    still_vulnerable = [f for f in current.get("findings", [])
                        if f"{f.get('title','')}__{f.get('host','')}" in still_vuln_keys]
    new_findings = [f for f in current.get("findings", [])
                    if f"{f.get('title','')}__{f.get('host','')}" in new_keys]

    return {
        "fixed": fixed,
        "still_vulnerable": still_vulnerable,
        "new_findings": new_findings,
        "stats": {
            "fixed_count": len(fixed),
            "remaining": len(still_vulnerable),
            "new_count": len(new_findings),
            "remediation_rate": f"{len(fixed)/max(len(base_findings),1)*100:.1f}%",
            "baseline_date": baseline.get("timestamp", ""),
            "current_date": datetime.now().isoformat(),
        },
    }


def generate_verification_report_legacy(comparison: dict, log_fn: Callable = None) -> str:
    """Generate human-readable verification report."""
    global _log_fn
    _log_fn = log_fn

    stats = comparison["stats"]
    lines = [
        "=" * 60,
        "  EXPEDITE STRIKE REMEDIATION VERIFICATION REPORT",
        "=" * 60,
        f"  Baseline: {stats.get('baseline_date', 'N/A')}",
        f"  Current:  {stats.get('current_date', 'N/A')}",
        "",
        f"  ✅ FIXED:            {stats['fixed_count']}",
        f"  ❌ STILL VULNERABLE: {stats['remaining']}",
        f"  ⚠  NEW FINDINGS:    {stats['new_count']}",
        f"  📊 REMEDIATION RATE: {stats['remediation_rate']}",
        "",
    ]

    if comparison["fixed"]:
        lines.append("  ── FIXED VULNERABILITIES ──")
        for f in comparison["fixed"]:
            lines.append(f"    ✅ {f.get('title','')} @ {f.get('host','')}")
        lines.append("")

    if comparison["still_vulnerable"]:
        lines.append("  ── STILL VULNERABLE ──")
        for f in comparison["still_vulnerable"]:
            lines.append(f"    ❌ {f.get('title','')} @ {f.get('host','')}")
        lines.append("")

    if comparison["new_findings"]:
        lines.append("  ── NEW FINDINGS ──")
        for f in comparison["new_findings"]:
            lines.append(f"    ⚠ {f.get('title','')} @ {f.get('host','')}")

    lines.append("=" * 60)
    report = "\n".join(lines)
    _log(report)
    _log_fn = None
    return report

# --- NEW ENGINE CAPABILITIES ---

APP_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
NEW_BASELINE_DIR = os.path.join(APP_ROOT_DIR, "scan_cache", "baselines")

def _get_baseline_path(scan_id: str) -> str:
    os.makedirs(NEW_BASELINE_DIR, exist_ok=True)
    return os.path.join(NEW_BASELINE_DIR, f"{scan_id}.json")

def save_baseline(scan_id: str, findings: list) -> str:
    """Save findings as a JSON baseline file in scan_cache/baselines/."""
    path = _get_baseline_path(scan_id)
    baseline_data = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "findings": findings
    }
    with open(path, "w") as f:
        json.dump(baseline_data, f, indent=2)
    return path

def load_baseline(scan_id: str) -> list:
    """Load a saved baseline by scan_id."""
    path = _get_baseline_path(scan_id)
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        data = json.load(f)
        return data.get("findings", [])

def list_baselines() -> list:
    """List all saved baselines with metadata."""
    if not os.path.exists(NEW_BASELINE_DIR):
        return []
    
    baselines = []
    for filename in os.listdir(NEW_BASELINE_DIR):
        if filename.endswith(".json"):
            path = os.path.join(NEW_BASELINE_DIR, filename)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    baselines.append({
                        "scan_id": data.get("scan_id", filename.replace(".json", "")),
                        "timestamp": data.get("timestamp"),
                        "findings_count": len(data.get("findings", []))
                    })
            except Exception:
                pass
    return baselines

def _get_finding_key(finding: dict) -> tuple:
    title = finding.get("title", "")
    severity = finding.get("severity", "")
    affected_object = finding.get("affected_object", finding.get("host", ""))
    return (title, severity, affected_object)

def compare_with_baseline(baseline_id: str, current_findings: list) -> dict:
    """Compare current findings against a baseline."""
    baseline_findings = load_baseline(baseline_id)
    
    base_dict = {_get_finding_key(f): f for f in baseline_findings}
    curr_dict = {_get_finding_key(f): f for f in current_findings}
    
    base_keys = set(base_dict.keys())
    curr_keys = set(curr_dict.keys())
    
    fixed_keys = base_keys - curr_keys
    still_vulnerable_keys = base_keys & curr_keys
    new_keys = curr_keys - base_keys
    
    fixed = [base_dict[k] for k in fixed_keys]
    still_vulnerable = [curr_dict[k] for k in still_vulnerable_keys]
    new_findings = [curr_dict[k] for k in new_keys]
    
    fix_rate = 0.0
    if len(baseline_findings) > 0:
        fix_rate = len(fixed) / len(baseline_findings)
        
    return {
        "fixed": fixed,
        "still_vulnerable": still_vulnerable,
        "new": new_findings,
        "stats": {
            "total_baseline": len(baseline_findings),
            "total_current": len(current_findings),
            "fixed_count": len(fixed),
            "regression_count": len(new_findings),
            "fix_rate": fix_rate,
        }
    }

def generate_verification_report(diff_result: dict, output_path: str = None) -> str:
    """Generates a simple text verification report."""
    stats = diff_result.get("stats", {})
    
    lines = [
        "VERIFICATION REPORT",
        "===================",
        f"Baseline Findings: {stats.get('total_baseline', 0)}",
        f"Current Findings:  {stats.get('total_current', 0)}",
        f"Fixed:             {stats.get('fixed_count', 0)}",
        f"Regressions:       {stats.get('regression_count', 0)}",
        f"Fix Rate:          {stats.get('fix_rate', 0.0):.2%}",
        "",
        "FIXED FINDINGS:",
        "---------------"
    ]
    for f in diff_result.get("fixed", []):
        lines.append(f"- {f.get('title', 'Unknown')} ({f.get('severity', 'Unknown')}) on {f.get('affected_object', f.get('host', 'Unknown'))}")
        
    lines.extend([
        "",
        "STILL VULNERABLE:",
        "-----------------"
    ])
    for f in diff_result.get("still_vulnerable", []):
        lines.append(f"- {f.get('title', 'Unknown')} ({f.get('severity', 'Unknown')}) on {f.get('affected_object', f.get('host', 'Unknown'))}")
        
    lines.extend([
        "",
        "NEW FINDINGS (REGRESSIONS):",
        "---------------------------"
    ])
    for f in diff_result.get("new", []):
        lines.append(f"- {f.get('title', 'Unknown')} ({f.get('severity', 'Unknown')}) on {f.get('affected_object', f.get('host', 'Unknown'))}")
        
    report = "\n".join(lines)
    
    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
            
    return report
