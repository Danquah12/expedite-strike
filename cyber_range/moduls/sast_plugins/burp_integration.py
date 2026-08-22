"""
burp_integration.py — Burp Suite DAST → SAST Bridge Plugin

Queries the Burp Suite Professional REST API (v0.1) running on localhost:1337
and imports DAST findings into the SAST scanner findings list.

This bridges DAST (dynamic) results into the static analysis workflow so that
Burp-discovered issues appear alongside code-level findings.

Burp REST API must be enabled:
  Burp → Settings → Suite → REST API → Enable service on port 1337

Trigger: runs as part of every scan. Returns 0 findings if Burp is unreachable.
"""
import re
from .base_plugin import BasePlugin

_BURP_BASE = "http://localhost:1337/v0.1"

# Map Burp severity → our severity
_SEV_MAP = {
    "high":         "HIGH",
    "medium":       "MEDIUM",
    "low":          "LOW",
    "information":  "INFO",
    "false positive": "INFO",
}

# Map common Burp issue types → CWE
_CWE_MAP = {
    "sql injection":             "CWE-89",
    "cross-site scripting":      "CWE-79",
    "cross site scripting":      "CWE-79",
    "path traversal":            "CWE-22",
    "xml injection":             "CWE-91",
    "os command injection":      "CWE-78",
    "reflected":                 "CWE-79",
    "stored":                    "CWE-79",
    "ssrf":                      "CWE-918",
    "server-side request forgery": "CWE-918",
    "open redirect":             "CWE-601",
    "clickjacking":              "CWE-1021",
    "csrf":                      "CWE-352",
    "information disclosure":    "CWE-200",
    "broken access control":     "CWE-284",
    "authentication bypass":     "CWE-287",
}


class BurpIntegrationPlugin(BasePlugin):
    name        = "Burp Suite DAST Bridge"
    description = (
        "Imports Burp Suite Professional scan results via REST API and surfaces "
        "DAST findings alongside SAST findings for unified analysis."
    )
    engine_tag  = "Plugin-Burp"

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        try:
            import requests as _req
        except ImportError:
            return []

        # ── Check if Burp REST API is reachable ──────────────────────────────
        try:
            r = _req.get(f"{_BURP_BASE}/", timeout=2)
            if r.status_code not in (200, 404):
                return []
        except Exception:
            # Burp not running — silent skip
            return []

        findings = []

        # ── Pull active scan issues ───────────────────────────────────────────
        try:
            r = _req.get(f"{_BURP_BASE}/scan", timeout=5)
            scan_list = r.json() if r.status_code == 200 else []
            if not isinstance(scan_list, list):
                scan_list = []
        except Exception:
            scan_list = []

        for scan in scan_list[:10]:   # cap at 10 scans
            scan_id = scan.get("task_id") or scan.get("id", "")
            try:
                ir = _req.get(f"{_BURP_BASE}/scan/{scan_id}/issues", timeout=5)
                issues = ir.json() if ir.status_code == 200 else []
                if not isinstance(issues, list):
                    issues = []
            except Exception:
                issues = []

            for issue in issues[:50]:   # cap per scan
                issue_name = issue.get("issue_name", issue.get("name", "Burp Finding"))
                severity   = _SEV_MAP.get(
                    str(issue.get("severity", "information")).lower(), "INFO"
                )
                url        = issue.get("origin") or issue.get("path") or ""
                detail     = issue.get("issue_detail") or issue.get("description") or ""

                # CWE lookup
                cwe = ""
                for keyword, cwe_id in _CWE_MAP.items():
                    if keyword in issue_name.lower():
                        cwe = cwe_id
                        break

                rid = f"PI-BURP-{abs(hash(issue_name)) % 9000 + 1000}"
                findings.append(self.make_finding(
                    rule_id=rid,
                    rule=f"Burp: {issue_name}",
                    severity=severity,
                    cwe=cwe,
                    message=(
                        f"DAST finding from Burp Suite. URL: {url}. "
                        f"{detail[:200]}"
                    ),
                    line=0,
                    code=url[:200],
                    fix="Refer to Burp Suite issue detail for reproduction steps.",
                    engine=self.engine_tag,
                ))

        # ── Status finding ────────────────────────────────────────────────────
        findings.append(self.make_finding(
            rule_id="PI-BURP-INFO",
            rule="Burp Suite Connected",
            severity="INFO", cwe="",
            message=f"Burp Suite REST API reachable at {_BURP_BASE}. "
                    f"Imported {len(findings)} DAST findings.",
            line=0, code="", engine=self.engine_tag,
        ))

        return findings
