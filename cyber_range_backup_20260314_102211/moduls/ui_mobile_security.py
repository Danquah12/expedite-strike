"""
Mobile Security — Android & iOS Security Assessment
Working MobSF integration: file upload, static analysis, live findings,
scan history, PDF report download, OWASP Mobile Top 10, AI analysis.
"""
from __future__ import annotations

import base64
import io
import logging
import os
import time
from datetime import datetime
from typing import Any

import dash
import requests
from dash import callback, dcc, html, Input, Output, State, ctx, dash_table
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

_log = logging.getLogger("ui_mobile_security")

# ── Styling ───────────────────────────────────────────────────────────────────
DARK_BG  = "#141820"
CARD_BG  = "#1e2230"
BORDER   = "1px solid #2e3450"
INPUT_STY = {"background": "#252a36", "color": "#e6e6e6",
             "border": "1px solid #3a4055", "borderRadius": "6px", "fontSize": "13px"}
BTN_SM   = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL    = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
            "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}

SEV_MAP  = {"high": "danger", "warning": "warning", "info": "info",
            "secure": "success", "hotspot": "danger", "good": "success"}

OWASP_MOBILE = [
    ("M1",  "Improper Credential Usage",          "Hardcoded keys, weak token storage",          "HIGH"),
    ("M2",  "Inadequate Supply Chain Security",    "Malicious SDK/dependency",                    "HIGH"),
    ("M3",  "Insecure Authentication",             "Weak auth, biometric bypass",                 "CRITICAL"),
    ("M4",  "Insufficient Input/Output Validation", "Injection, path traversal",                  "HIGH"),
    ("M5",  "Insecure Communication",              "No cert pinning, SSL bypass",                 "CRITICAL"),
    ("M6",  "Inadequate Privacy Controls",         "PII leakage in logs/backups",                 "HIGH"),
    ("M7",  "Insufficient Binary Protections",     "No obfuscation, root detection bypass",       "MEDIUM"),
    ("M8",  "Security Misconfiguration",           "Debug enabled, ADB over network",             "HIGH"),
    ("M9",  "Insecure Data Storage",               "Plaintext SQLite, world-readable files",      "CRITICAL"),
    ("M10", "Insufficient Cryptography",           "Weak algos, hardcoded IV/key",                "HIGH"),
]


# ── UI helpers ────────────────────────────────────────────────────────────────
def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background": CARD_BG, "border": BORDER,
                           "borderRadius": "8px", "marginBottom": "12px"})

def _cmd(t):
    return html.Pre(t, style={"background": "#0d0f1a", "color": "#00e6e6",
                               "padding": "8px", "borderRadius": "6px",
                               "fontSize": "11px", "overflowX": "auto",
                               "marginBottom": "6px"})

def _badge(t, c):
    return dbc.Badge(t, color=c, className="me-1 mb-1")

def _label(t):
    return html.Div(t, style=LABEL)


# ── MobSF API helpers ────────────────────────────────────────────────────────
def _mobsf_headers(api_key: str) -> dict:
    return {"Authorization": api_key, "X-Mobsf-Api-Key": api_key}


def _mobsf_upload(content_bytes: bytes, filename: str,
                  api_url: str, api_key: str) -> dict | None:
    """Upload APK/IPA/ZIP to MobSF. Returns {hash, file_name, scan_type}."""
    try:
        resp = requests.post(
            f"{api_url.rstrip('/')}/api/v1/upload",
            files={"file": (filename, io.BytesIO(content_bytes), "application/octet-stream")},
            headers=_mobsf_headers(api_key),
            timeout=120,
        )
        if resp.status_code == 200:
            return resp.json()
        _log.warning("MobSF upload %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        _log.warning("MobSF upload error: %s", exc)
    return None


def _mobsf_scan(file_hash: str, api_url: str, api_key: str,
                re_scan: bool = False) -> dict | None:
    """Trigger static analysis scan."""
    try:
        resp = requests.post(
            f"{api_url.rstrip('/')}/api/v1/scan",
            data={"hash": file_hash, "re_scan": "1" if re_scan else "0"},
            headers=_mobsf_headers(api_key),
            timeout=300,
        )
        if resp.status_code == 200:
            return resp.json()
        _log.warning("MobSF scan %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        _log.warning("MobSF scan error: %s", exc)
    return None


def _mobsf_report(file_hash: str, api_url: str, api_key: str) -> dict | None:
    """Fetch the JSON report for a completed scan."""
    try:
        resp = requests.post(
            f"{api_url.rstrip('/')}/api/v1/report_json",
            data={"hash": file_hash},
            headers=_mobsf_headers(api_key),
            timeout=60,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        _log.warning("MobSF report error: %s", exc)
    return None


def _mobsf_scans(api_url: str, api_key: str) -> list[dict]:
    """List recent scans."""
    try:
        resp = requests.get(
            f"{api_url.rstrip('/')}/api/v1/scans",
            headers=_mobsf_headers(api_key),
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("content", data) if isinstance(data, dict) else data
    except Exception as exc:
        _log.warning("MobSF scans error: %s", exc)
    return []


def _mobsf_pdf_url(file_hash: str, api_url: str) -> str:
    """Return the URL for PDF download (user downloads via browser)."""
    return f"{api_url.rstrip('/')}/api/v1/download_pdf"


# ── Parse MobSF report into findings ──────────────────────────────────────────
def _parse_findings(report: dict) -> list[dict]:
    """Extract a flat list of findings from a MobSF report JSON."""
    findings: list[dict] = []

    # Code analysis findings
    for sev_key in ("high", "warning", "info", "hotspot", "secure", "good"):
        items = report.get("code_analysis", {})
        if isinstance(items, dict):
            for path, issue_list in items.items():
                if isinstance(issue_list, dict) and issue_list.get("metadata", {}).get("severity", "").lower() == sev_key:
                    findings.append({
                        "title": issue_list.get("metadata", {}).get("description", path),
                        "severity": sev_key.upper(),
                        "section": "Code Analysis",
                        "detail": str(issue_list.get("metadata", {}).get("input_case", "")),
                    })
                elif isinstance(issue_list, list):
                    for issue in issue_list:
                        if isinstance(issue, dict):
                            findings.append({
                                "title": issue.get("title", issue.get("description", "Unknown")),
                                "severity": issue.get("severity", sev_key).upper(),
                                "section": issue.get("section", "Code Analysis"),
                                "detail": issue.get("description", "")[:200],
                            })

    # Manifest analysis
    for item in report.get("manifest_analysis", []):
        if isinstance(item, dict):
            findings.append({
                "title": item.get("title", "Manifest Issue"),
                "severity": item.get("severity", "info").upper(),
                "section": "Manifest",
                "detail": item.get("description", "")[:200],
            })

    # Binary analysis
    for item in report.get("binary_analysis", []):
        if isinstance(item, dict):
            findings.append({
                "title": item.get("title", item.get("description", "Binary Issue")),
                "severity": item.get("severity", "info").upper(),
                "section": "Binary Analysis",
                "detail": item.get("description", "")[:200],
            })

    # Certificate analysis
    cert = report.get("certificate_analysis", {})
    if isinstance(cert, dict):
        for finding in cert.get("certificate_findings", []):
            if isinstance(finding, list) and len(finding) >= 2:
                findings.append({
                    "title": finding[1] if len(finding) > 1 else "Certificate Issue",
                    "severity": finding[0].upper() if finding else "INFO",
                    "section": "Certificate",
                    "detail": finding[1] if len(finding) > 1 else "",
                })

    # Network security
    for item in report.get("network_security", []):
        if isinstance(item, dict):
            findings.append({
                "title": item.get("description", "Network Issue"),
                "severity": item.get("severity", "info").upper(),
                "section": "Network Security",
                "detail": item.get("description", "")[:200],
            })

    # Permission findings
    for perm_key, perm_data in report.get("permissions", {}).items():
        if isinstance(perm_data, dict):
            status = perm_data.get("status", "")
            if status in ("dangerous", "normal"):
                findings.append({
                    "title": f"Permission: {perm_data.get('description', perm_key)}",
                    "severity": "HIGH" if status == "dangerous" else "INFO",
                    "section": "Permissions",
                    "detail": perm_data.get("description", "")[:200],
                })

    return findings


def _security_score(report: dict) -> int:
    """Extract the security score from MobSF report (0-100)."""
    val = report.get("security_score", report.get("average_cvss", 0))
    try:
        return int(val) if val is not None else 0
    except (TypeError, ValueError):
        return 0


# ── Layout ────────────────────────────────────────────────────────────────────
def layout():
    default_key = os.environ.get("MOBSF_API_KEY", "")
    default_url = os.environ.get("MOBSF_URL", "http://localhost:8000")

    return html.Div([
        dcc.Store(id="mob-scan-hash",   data=""),
        dcc.Store(id="mob-scan-report", data={}),
        dcc.Store(id="mob-findings",    data=[]),

        # Header
        html.Div([
            html.H4("📱 Mobile Security — Android & iOS Assessment",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("MobSF static/dynamic analysis, OWASP Mobile Top 10, cert pinning bypass, ADB testing, Frida instrumentation.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left: Controls ────────────────────────────────────────────────
            dbc.Col([
                # MobSF Config
                _card(
                    _label("MobSF URL"),
                    dbc.Input(id="mob-mobsf-url", value=default_url,
                              style={**INPUT_STY, "marginBottom": "6px"}),
                    _label("MobSF API Key"),
                    dbc.Input(id="mob-mobsf-key", value=default_key,
                              placeholder="Paste from MobSF → API Docs",
                              type="password",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    title="⚙️ MobSF Connection",
                ),

                # File Upload
                _card(
                    _label("Platform"),
                    dbc.RadioItems(id="mob-platform", options=[
                        {"label": "Android (APK)", "value": "android"},
                        {"label": "iOS (IPA)",     "value": "ios"},
                    ], value="android", inline=True,
                    style={"color": "#ccc", "fontSize": "12px", "marginBottom": "8px"}),

                    dcc.Upload(
                        id="mob-upload",
                        children=html.Div([
                            html.I(className="fas fa-cloud-upload-alt",
                                   style={"fontSize": "24px", "color": "#ffd700",
                                          "marginBottom": "6px"}),
                            html.Div("Drag & drop APK / IPA / ZIP",
                                     style={"color": "#ccc", "fontSize": "12px"}),
                            html.Div("or click to browse",
                                     style={"color": "#666", "fontSize": "11px"}),
                        ], style={"textAlign": "center", "padding": "20px"}),
                        style={
                            "border": "2px dashed #3a4055",
                            "borderRadius": "8px",
                            "background": "#0d0f1a",
                            "cursor": "pointer",
                            "marginBottom": "8px",
                        },
                        multiple=False,
                    ),
                    html.Div(id="mob-upload-name",
                             style={"color": "#aaa", "fontSize": "11px",
                                    "marginBottom": "6px", "minHeight": "14px"}),

                    dbc.Button("▶ Static Analysis (MobSF)", id="mob-static-btn",
                               color="warning", size="sm", className="w-100 mb-1",
                               style={"color": "#000", "fontWeight": "600"}),
                    dbc.Button("🔄 Refresh Results", id="mob-refresh-btn",
                               color="outline-info", size="sm", className="w-100 mb-1"),
                    dbc.Button("📄 Download PDF Report", id="mob-pdf-btn",
                               color="outline-secondary", size="sm", className="w-100 mb-2"),
                    dcc.Download(id="mob-pdf-download"),

                    html.Div(id="mob-run-status",
                             style={"color": "#636e72", "fontSize": "11px",
                                    "marginTop": "4px", "minHeight": "28px"}),
                    title="📤 Upload & Scan",
                ),

                # AI Report
                _card(
                    dbc.Button("🤖 AI Security Report", id="mob-ai-btn",
                               color="secondary", size="sm", className="w-100"),
                    html.Div(id="mob-ai-out",
                             style={"marginTop": "8px", "maxHeight": "300px",
                                    "overflowY": "auto"}),
                    title="AI Report",
                ),
            ], width=3),

            # ── Center: Tabs ─────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="mob-tabs", active_tab="mob-owasp", children=[
                    dbc.Tab(label="OWASP Mobile Top 10", tab_id="mob-owasp"),
                    dbc.Tab(label="🔍 Findings",         tab_id="mob-findings-tab"),
                    dbc.Tab(label="📋 Scan History",      tab_id="mob-history"),
                    dbc.Tab(label="Android Testing",      tab_id="mob-android"),
                    dbc.Tab(label="iOS Testing",          tab_id="mob-ios"),
                    dbc.Tab(label="Frida / Dynamic",      tab_id="mob-frida"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="mob-tab-content"),
            ], width=6),

            # ── Right: Info ──────────────────────────────────────────────────
            dbc.Col([
                # Security Score
                _card(
                    html.Div(id="mob-score-display", children=[
                        html.Div("—", style={"fontSize": "42px", "fontWeight": "700",
                                             "color": "#636e72", "textAlign": "center"}),
                        html.Div("Security Score", style={"color": "#8e9eb0",
                                                           "fontSize": "11px",
                                                           "textAlign": "center"}),
                    ]),
                    title="📊 Score",
                ),

                _card(
                    _badge("OWASP Mobile", "danger"), _badge("MobSF", "info"),
                    _badge("Frida", "success"),
                    html.Hr(style={"borderColor": "#333"}),
                    html.P("MobSF (Mobile Security Framework) — automated static "
                           "and dynamic analysis for APK and IPA files.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    html.P("Frida — dynamic instrumentation for bypassing certificate "
                           "pinning, root detection, and anti-tampering.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    title="Key Tools",
                ),

                _card(
                    _cmd("# Start MobSF via Docker\n"
                         "docker run -it -p 8000:8000 \\\n"
                         "  opensecurity/mobile-security-framework-mobsf:latest\n\n"
                         "# Get API key from:\n"
                         "# http://localhost:8000/api_docs\n\n"
                         "# Frida server on device\n"
                         "adb push frida-server /data/local/tmp/\n"
                         "adb shell chmod 755 /data/local/tmp/frida-server\n"
                         "adb shell /data/local/tmp/frida-server &"),
                    title="Quick Setup",
                ),
            ], width=3),
        ]),
    ], style={"padding": "20px", "background": DARK_BG, "minHeight": "100vh"})


# ── Show uploaded filename ────────────────────────────────────────────────────

@callback(
    Output("mob-upload-name", "children"),
    Input("mob-upload", "filename"),
    prevent_initial_call=True,
)
def show_filename(filename):
    if filename:
        return html.Span([
            html.I(className="fas fa-file", style={"marginRight": "4px"}),
            f" {filename}",
        ], style={"color": "#ffd700", "fontSize": "12px"})
    return ""


# ── Static Analysis: Upload → Scan → Report ──────────────────────────────────

@callback(
    Output("mob-scan-hash",   "data"),
    Output("mob-scan-report", "data"),
    Output("mob-findings",    "data"),
    Output("mob-run-status",  "children"),
    Output("mob-score-display", "children"),
    Input("mob-static-btn",   "n_clicks"),
    Input("mob-refresh-btn",  "n_clicks"),
    State("mob-upload",       "contents"),
    State("mob-upload",       "filename"),
    State("mob-mobsf-url",    "value"),
    State("mob-mobsf-key",    "value"),
    State("mob-scan-hash",    "data"),
    prevent_initial_call=True,
)
def run_static_analysis(static_n, refresh_n, contents, filename,
                        api_url, api_key, existing_hash):
    if not api_url or not api_key:
        return (dash.no_update, dash.no_update, dash.no_update,
                dbc.Alert("⚠ Set MobSF URL and API Key first.", color="warning",
                          style={"fontSize": "11px"}),
                dash.no_update)

    triggered = ctx.triggered_id
    file_hash = existing_hash or ""

    # ── Refresh existing report ───────────────────────────────────────────
    if triggered == "mob-refresh-btn":
        if not file_hash:
            return (dash.no_update, dash.no_update, dash.no_update,
                    dbc.Alert("No scan to refresh. Upload and scan first.",
                              color="info", style={"fontSize": "11px"}),
                    dash.no_update)
        report = _mobsf_report(file_hash, api_url, api_key)
        if report:
            findings = _parse_findings(report)
            score = _security_score(report)
            return (file_hash, report, findings,
                    dbc.Alert(f"✅ Report refreshed — {len(findings)} findings",
                              color="success", style={"fontSize": "11px"}),
                    _score_display(score))
        return (dash.no_update, dash.no_update, dash.no_update,
                dbc.Alert("⚠ Could not fetch report.", color="warning",
                          style={"fontSize": "11px"}),
                dash.no_update)

    # ── New scan ──────────────────────────────────────────────────────────
    if not contents or not filename:
        return (dash.no_update, dash.no_update, dash.no_update,
                dbc.Alert("⚠ Upload an APK/IPA file first.", color="warning",
                          style={"fontSize": "11px"}),
                dash.no_update)

    # Decode base64 content from dcc.Upload
    try:
        content_type, content_string = contents.split(",", 1)
        file_bytes = base64.b64decode(content_string)
    except Exception:
        return (dash.no_update, dash.no_update, dash.no_update,
                dbc.Alert("⚠ Error reading file.", color="danger",
                          style={"fontSize": "11px"}),
                dash.no_update)

    # Step 1: Upload
    upload_result = _mobsf_upload(file_bytes, filename, api_url, api_key)
    if not upload_result or "hash" not in upload_result:
        return ("", {}, [],
                dbc.Alert("❌ Upload failed. Check MobSF URL and API key.",
                          color="danger", style={"fontSize": "11px"}),
                dash.no_update)

    file_hash = upload_result["hash"]

    # Step 2: Scan (this blocks until scan completes)
    scan_result = _mobsf_scan(file_hash, api_url, api_key)
    if not scan_result:
        return (file_hash, {}, [],
                dbc.Alert("❌ Scan failed. Check MobSF logs.",
                          color="danger", style={"fontSize": "11px"}),
                dash.no_update)

    # Step 3: Fetch report
    report = _mobsf_report(file_hash, api_url, api_key)
    if not report:
        return (file_hash, {}, [],
                dbc.Alert("⚠ Scan completed but report fetch failed. Try Refresh.",
                          color="warning", style={"fontSize": "11px"}),
                dash.no_update)

    findings = _parse_findings(report)
    score = _security_score(report)
    app_name = report.get("app_name", report.get("file_name", filename))

    return (file_hash, report, findings,
            dbc.Alert([
                html.Strong(f"✅ {app_name}"),
                f" — {len(findings)} findings | Score: {score}/100",
            ], color="success", style={"fontSize": "11px"}),
            _score_display(score))


def _score_display(score):
    score = int(score) if score is not None else 0
    if score >= 70:
        color = "#27ae60"
    elif score >= 40:
        color = "#e67e22"
    else:
        color = "#c0392b"
    return [
        html.Div(str(score), style={"fontSize": "42px", "fontWeight": "700",
                                     "color": color, "textAlign": "center",
                                     "lineHeight": "1"}),
        html.Div("/ 100", style={"color": "#636e72", "fontSize": "14px",
                                  "textAlign": "center"}),
        html.Div("Security Score", style={"color": "#8e9eb0",
                                           "fontSize": "11px",
                                           "textAlign": "center"}),
    ]


# ── Tab content renderer ─────────────────────────────────────────────────────

@callback(
    Output("mob-tab-content", "children"),
    Input("mob-tabs",      "active_tab"),
    Input("mob-findings",  "data"),
    State("mob-scan-report", "data"),
    State("mob-mobsf-url", "value"),
    State("mob-mobsf-key", "value"),
)
def render_mob_tab(tab, findings, report, api_url, api_key):
    findings = findings or []
    report = report or {}

    if tab == "mob-owasp":
        return _render_owasp(findings)
    elif tab == "mob-findings-tab":
        return _render_findings(findings, report)
    elif tab == "mob-history":
        return _render_history(api_url, api_key)
    elif tab == "mob-android":
        return _render_android()
    elif tab == "mob-ios":
        return _render_ios()
    elif tab == "mob-frida":
        return _render_frida()
    return html.Div()


def _render_owasp(findings: list[dict]):
    """OWASP Mobile Top 10 with auto-populated status from findings."""
    finding_titles = " ".join(f.get("title", "").lower() for f in findings)

    owasp_keywords = {
        "M1":  ["credential", "hardcoded", "api_key", "secret", "token", "password"],
        "M2":  ["supply chain", "sdk", "dependency", "library"],
        "M3":  ["auth", "biometric", "login", "session"],
        "M4":  ["injection", "traversal", "input", "xss", "sql"],
        "M5":  ["ssl", "tls", "certificate", "pinning", "cleartext", "http"],
        "M6":  ["privacy", "pii", "log", "backup", "leak"],
        "M7":  ["obfuscat", "root detect", "binary", "tamper", "debug"],
        "M8":  ["misconfiguration", "debug", "export", "backup", "allowbackup"],
        "M9":  ["storage", "sqlite", "shared_pref", "readable", "world"],
        "M10": ["crypto", "encrypt", "aes", "des", "md5", "sha1", "iv", "ecb"],
    }

    rows = []
    for mid, name, detail, risk in OWASP_MOBILE:
        color = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info"}.get(risk, "secondary")
        keywords = owasp_keywords.get(mid, [])
        matched = any(kw in finding_titles for kw in keywords) if findings else False
        status = "Fail" if matched else ("Not Tested" if not findings else "Pass")
        status_color = "#c0392b" if status == "Fail" else (
            "#636e72" if status == "Not Tested" else "#27ae60")

        rows.append(html.Tr([
            html.Td(mid, style={"color": "#ffd700", "fontSize": "11px"}),
            html.Td(name, style={"color": "#ccc", "fontSize": "11px"}),
            html.Td(detail, style={"color": "#aaa", "fontSize": "11px"}),
            html.Td(_badge(risk, color)),
            html.Td(status, style={"color": status_color, "fontSize": "11px",
                                    "fontWeight": "700"}),
        ]))

    return _card(
        html.H6("OWASP Mobile Top 10 Checklist", style={"color": "#ffd700"}),
        html.P("Auto-populated from MobSF scan findings" if findings else
               "Upload and scan an app to auto-populate results",
               style={"color": "#636e72", "fontSize": "11px", "marginBottom": "8px"}),
        dbc.Table([
            html.Thead(html.Tr([
                html.Th("ID"), html.Th("Category"), html.Th("Details"),
                html.Th("Risk"), html.Th("Result"),
            ])),
            html.Tbody(rows),
        ], bordered=True, hover=True, size="sm"),
    )


def _render_findings(findings: list[dict], report: dict):
    """Live findings table from MobSF scan."""
    if not findings:
        return _card(
            html.Div("No findings yet. Upload an APK/IPA and run Static Analysis.",
                     style={"color": "#636e72", "fontSize": "13px",
                            "textAlign": "center", "padding": "30px"}),
        )

    sev_order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3, "SECURE": 4, "GOOD": 5}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "INFO"), 3))

    rows = []
    for f in sorted_findings[:100]:
        sev = f.get("severity", "INFO")
        color = {"CRITICAL": "danger", "HIGH": "warning", "WARNING": "warning",
                 "INFO": "info", "SECURE": "success", "GOOD": "success"}.get(sev, "secondary")
        rows.append(html.Tr([
            html.Td(_badge(sev, color)),
            html.Td(f.get("title", "—")[:80], style={"color": "#e6e6e6", "fontSize": "11px"}),
            html.Td(f.get("section", "—"), style={"color": "#8e9eb0", "fontSize": "10px"}),
            html.Td(f.get("detail", "")[:100], style={"color": "#636e72", "fontSize": "10px"}),
        ]))

    # Summary stats
    high_count = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
    warn_count = sum(1 for f in findings if f.get("severity") == "WARNING")
    info_count = sum(1 for f in findings if f.get("severity") in ("INFO", "SECURE", "GOOD"))
    app_name = report.get("app_name", report.get("file_name", "Unknown"))

    return _card(
        html.Div([
            html.H6(f"🔍 {len(findings)} Findings — {app_name}",
                     style={"color": "#ffd700", "marginBottom": "4px"}),
            html.Div([
                _badge(f"{high_count} Critical/High", "danger"),
                _badge(f"{warn_count} Warning", "warning"),
                _badge(f"{info_count} Info", "info"),
            ], style={"marginBottom": "8px"}),
        ]),
        html.Div(
            dbc.Table([
                html.Thead(html.Tr([
                    html.Th("Severity"), html.Th("Finding"),
                    html.Th("Section"), html.Th("Detail"),
                ])),
                html.Tbody(rows),
            ], bordered=True, hover=True, size="sm"),
            style={"maxHeight": "500px", "overflowY": "auto"},
        ),
    )


def _render_history(api_url, api_key):
    """Show recent MobSF scans."""
    if not api_url or not api_key:
        return _card(html.Div("Set MobSF URL and API Key to view scan history.",
                              style={"color": "#636e72", "fontSize": "13px",
                                     "textAlign": "center", "padding": "30px"}))

    scans = _mobsf_scans(api_url, api_key)
    if not scans:
        return _card(html.Div("No previous scans found. Upload an app to begin.",
                              style={"color": "#636e72", "fontSize": "13px",
                                     "textAlign": "center", "padding": "30px"}))

    rows = []
    for s in (scans if isinstance(scans, list) else []):
        fname = s.get("FILE_NAME", s.get("file_name", "—"))
        fhash = s.get("MD5", s.get("hash", "—"))
        scan_type = s.get("SCAN_TYPE", s.get("scan_type", "—"))
        timestamp = s.get("TIMESTAMP", s.get("timestamp", "—"))
        rows.append(html.Tr([
            html.Td(fname[:30], style={"color": "#e6e6e6", "fontSize": "11px"}),
            html.Td(scan_type, style={"color": "#8e9eb0", "fontSize": "10px"}),
            html.Td(fhash[:12] + "…" if len(str(fhash)) > 12 else fhash,
                     style={"color": "#636e72", "fontSize": "10px",
                            "fontFamily": "monospace"}),
            html.Td(str(timestamp)[:19], style={"color": "#636e72", "fontSize": "10px"}),
        ]))

    return _card(
        html.H6(f"📋 {len(rows)} Previous Scans", style={"color": "#ffd700"}),
        dbc.Table([
            html.Thead(html.Tr([
                html.Th("File"), html.Th("Type"), html.Th("Hash"), html.Th("Date"),
            ])),
            html.Tbody(rows),
        ], bordered=True, hover=True, size="sm"),
    )


def _render_android():
    return _card(
        html.H6("Android Testing Techniques", style={"color": "#ffd700"}),
        dbc.Row([
            dbc.Col([
                html.P("Static Analysis:", style={"color": "#00e6e6", "fontSize": "12px"}),
                _cmd("# APK extraction & analysis\napktool d app.apk -o ./decoded\n"
                     "grep -r 'api_key\\|secret\\|password' ./decoded/\n\n"
                     "# Decompile with jadx\njadx -d ./src app.apk\n\n"
                     "# Check permissions\naapt dump permissions app.apk"),
            ], width=6),
            dbc.Col([
                html.P("Dynamic Analysis:", style={"color": "#00e6e6", "fontSize": "12px"}),
                _cmd("# ADB shell\nadb devices\nadb shell\n\n"
                     "# Capture traffic (Burp proxy)\nadb shell settings put global "
                     "http_proxy 192.168.1.100:8080\n\n"
                     "# Extract data\nadb pull /data/data/com.example.app/ .\n\n"
                     "# Logcat for secrets\nadb logcat | grep -i 'password\\|token\\|key'"),
            ], width=6),
        ]),
    )


def _render_ios():
    return _card(
        html.H6("iOS Testing Techniques", style={"color": "#ffd700"}),
        dbc.Row([
            dbc.Col([
                html.P("Static Analysis:", style={"color": "#00e6e6", "fontSize": "12px"}),
                _cmd("# Extract IPA\nunzip app.ipa -d extracted/\n\n"
                     "# Strings extraction\nstrings extracted/Payload/App.app/App"
                     " | grep -E 'http|key|secret|token'\n\n"
                     "# Check entitlements\ncodesign -d --entitlements - App.app"),
            ], width=6),
            dbc.Col([
                html.P("Dynamic / Frida:", style={"color": "#00e6e6", "fontSize": "12px"}),
                _cmd("# objection (Frida wrapper)\nobjection -g com.example.app explore\n\n"
                     "# Bypass cert pinning\nios sslpinning disable\n\n"
                     "# Keychain dump\nios keychain dump\n\n"
                     "# Bypass Touch ID\nios ui biometric_bypass"),
            ], width=6),
        ]),
    )


def _render_frida():
    return _card(
        html.H6("Frida Dynamic Instrumentation", style={"color": "#ffd700"}),
        _cmd("""# Certificate pinning bypass (Android)
frida -U -l bypass-ssl-pinning.js com.example.app

# Root detection bypass
frida -U -l bypass-root-detection.js -f com.example.app

# Hook function to log arguments
Java.perform(function() {
    var TargetClass = Java.use('com.example.SecurePrefs');
    TargetClass.getDecryptedData.implementation = function(key) {
        var result = this.getDecryptedData(key);
        console.log('[*] getDecryptedData(' + key + ') = ' + result);
        return result;
    };
});

# List loaded classes
Java.enumerateLoadedClasses({
    onMatch: function(c) { console.log(c); },
    onComplete: function() {}
});"""),
    )


# ── PDF Download ──────────────────────────────────────────────────────────────

@callback(
    Output("mob-pdf-download", "data"),
    Input("mob-pdf-btn",       "n_clicks"),
    State("mob-scan-hash",     "data"),
    State("mob-mobsf-url",     "value"),
    State("mob-mobsf-key",     "value"),
    prevent_initial_call=True,
)
def download_pdf(n, file_hash, api_url, api_key):
    if not n or not file_hash or not api_url or not api_key:
        raise PreventUpdate
    try:
        resp = requests.post(
            f"{api_url.rstrip('/')}/api/v1/download_pdf",
            data={"hash": file_hash},
            headers=_mobsf_headers(api_key),
            timeout=60,
        )
        if resp.status_code == 200:
            return dcc.send_bytes(resp.content, f"mobsf_report_{file_hash[:8]}.pdf")
    except Exception as exc:
        _log.warning("PDF download error: %s", exc)
    raise PreventUpdate


# ── AI Security Report ────────────────────────────────────────────────────────

@callback(
    Output("mob-ai-out", "children"),
    Input("mob-ai-btn",  "n_clicks"),
    State("mob-platform",    "value"),
    State("mob-findings",    "data"),
    State("mob-scan-report", "data"),
    prevent_initial_call=True,
)
def mob_ai_report(n, platform, findings, report):
    if not n:
        raise PreventUpdate

    findings = findings or []
    report = report or {}

    if not findings:
        # Fallback: generic report if no scan data
        return dbc.Alert(html.Pre(
            f"No scan data available. Upload and scan an app first.\n\n"
            "For a comprehensive AI report, the module needs MobSF findings "
            "to provide context-aware analysis.",
            style={"fontSize": "11px", "whiteSpace": "pre-wrap", "color": "#e6e6e6"}),
            color="dark", style={"marginTop": "8px"})

    app_name = report.get("app_name", report.get("file_name", "Unknown"))
    score = _security_score(report)

    finding_summary = "\n".join(
        f"- [{f['severity']}] {f['title'][:100]} ({f.get('section', '')})"
        for f in findings[:30]
    )
    perm_summary = "\n".join(
        f"- {k}: {v.get('description', '')[:60]}"
        for k, v in (report.get("permissions", {}) or {}).items()
        if isinstance(v, dict) and v.get("status") == "dangerous"
    )[:500]

    prompt = (
        f"You are a mobile application security expert. Analyze these MobSF "
        f"static analysis findings for {platform.upper()} app '{app_name}' "
        f"(security score: {score}/100).\n\n"
        f"Findings:\n{finding_summary}\n\n"
        f"Dangerous Permissions:\n{perm_summary or 'None flagged'}\n\n"
        f"Provide:\n"
        f"1) **Executive Summary** — overall risk posture in 2-3 sentences\n"
        f"2) **Critical Issues** — top 5 highest-risk findings with exploitation scenarios\n"
        f"3) **OWASP Mobile Top 10 Mapping** — which categories are violated\n"
        f"4) **Remediation Plan** — prioritized fixes with code-level guidance\n"
        f"5) **Compliance Impact** — GDPR, PCI-DSS, HIPAA implications if applicable\n\n"
        f"Format as a concise penetration test report."
    )

    try:
        result = call_llm(prompt)
        return dbc.Alert(html.Pre(
            result, style={"fontSize": "11px", "whiteSpace": "pre-wrap",
                           "color": "#e6e6e6"}),
            color="dark", style={"marginTop": "8px"})
    except Exception as e:
        return dbc.Alert(f"LLM error: {e}", color="danger",
                         style={"fontSize": "11px", "marginTop": "8px"})
