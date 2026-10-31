"""
Expedite Strike -- Universal Auth Bypass Assessment UI Module (Enhanced)
========================================================================
Interactive Dash interface for configuring and executing automated
multi-protocol authentication security assessments with pre-flight health & WAF
probing, live logging, SLA triage matrix, scan history persistence, and multi-format reporting.
"""

import io
import csv
import uuid
import time
import threading
from typing import Dict, Any, List
from dash import html, dcc, callback, Input, Output, State, no_update, ctx
import dash_bootstrap_components as dbc

from cyber_range.services.auth_bypass_engine import (
    AuthTarget,
    run_assessment,
    detect_protocol,
    probe_target_health,
    _ALL_CHECKS,
    _PROTOCOL_MAP,
)
from cyber_range.services.scan_history_service import list_scans, get_scan, delete_scan

# ---------------------------------------------------------------------------
# In-Memory State
# ---------------------------------------------------------------------------

_scans: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Color Palette & Badges
# ---------------------------------------------------------------------------

_DARK = "#080c14"
_CARD_BG = "#0d1117"
_BORDER = "#1e2a3a"
_TEXT_MUTED = "#8899aa"
_GREEN = "#00c88c"
_RED = "#ff4444"
_ORANGE = "#ff9500"
_YELLOW = "#ffd700"
_BLUE = "#00e5ff"
_GRAY = "#6e7681"

SEV_BADGE_STYLE = {
    "Critical": {"background": "rgba(255, 68, 68, 0.2)", "color": "#ff4444", "border": "1px solid #ff4444"},
    "High":     {"background": "rgba(255, 149, 0, 0.2)", "color": "#ff9500", "border": "1px solid #ff9500"},
    "Medium":   {"background": "rgba(255, 215, 0, 0.2)", "color": "#ffd700", "border": "1px solid #ffd700"},
    "Low":      {"background": "rgba(0, 229, 255, 0.2)", "color": "#00e5ff", "border": "1px solid #00e5ff"},
    "Info":     {"background": "rgba(110, 118, 129, 0.2)", "color": "#8b949e", "border": "1px solid #6e7681"},
}

STATUS_BADGE_STYLE = {
    "VULNERABLE":     {"background": "rgba(255, 68, 68, 0.25)", "color": "#ff6b6b", "border": "1px solid #ff4444"},
    "SECURE":         {"background": "rgba(0, 200, 140, 0.2)",  "color": "#00c88c", "border": "1px solid #00c88c"},
    "NOT_APPLICABLE": {"background": "rgba(110, 118, 129, 0.15)", "color": "#8b949e", "border": "1px solid #30363d"},
    "ERROR":          {"background": "rgba(255, 149, 0, 0.2)", "color": "#ffa94d", "border": "1px solid #ff9500"},
}

# ---------------------------------------------------------------------------
# UI Layout
# ---------------------------------------------------------------------------

def layout() -> html.Div:
    """Universal Auth Bypass Assessment Page Layout."""
    return html.Div([
        # Page Title Header
        html.Div([
            html.Div([
                html.Span("🔑", style={"fontSize": "26px", "marginRight": "12px"}),
                html.H3("Universal Authentication Bypass Assessment", style={
                    "display": "inline-block",
                    "color": "#e6edf3",
                    "fontWeight": "700",
                    "margin": "0",
                    "letterSpacing": "0.5px",
                }),
                html.Div(style={"flex": "1"}),
                dbc.Button(
                    "📜 Scan History",
                    id="ab-history-btn",
                    size="sm",
                    color="secondary",
                    outline=True,
                    style={"fontSize": "12px", "marginRight": "8px"}
                ),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "6px"}),
            html.P(
                "Automated multi-protocol security assessment executing 77 checks across 15 authentication protocols: "
                "OAuth 2.0 / OIDC, SAML 2.0, JWT, Multi-step Flows, Password Pages, Password Reset, Enumeration, "
                "Social Login, Basic/Digest Auth, API Key/Bearer, Session Management, LDAP Injection, XSW, Response Manipulation, and Host Header Injection.",
                style={"color": _TEXT_MUTED, "fontSize": "13px", "margin": "0", "maxWidth": "1200px"}
            ),
        ], style={"padding": "24px 24px 12px"}),

        # Configuration Card
        dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.Div([
                            html.Label("TARGET AUTHENTICATION URL", style={
                                "color": _TEXT_MUTED, "fontSize": "11px", "fontWeight": "700", "letterSpacing": "1px"
                            }),
                            html.Span(" (Auto-normalizes scheme & path)", style={"color": "#6e7681", "fontSize": "11px"}),
                        ]),
                        dbc.InputGroup([
                            dbc.Input(
                                id="ab-target-url",
                                placeholder="e.g. qx.issuenet.ihsmarkit.com/admin-website or https://example.com/oauth2/authorize?client_id=...",
                                type="text",
                                style={
                                    "background": "#080c14",
                                    "border": f"1px solid {_BORDER}",
                                    "color": "#e6edf3",
                                    "fontFamily": "'JetBrains Mono', monospace",
                                    "fontSize": "12px",
                                }
                            ),
                            dbc.Button(
                                "⚡ Pre-Flight Check",
                                id="ab-probe-btn",
                                color="secondary",
                                size="sm",
                                outline=True,
                                style={"fontSize": "11px", "fontWeight": "700", "letterSpacing": "0.5px"}
                            ),
                        ]),
                        html.Div(id="ab-probe-result", style={"marginTop": "6px", "fontSize": "11px"}),
                    ], md=12, className="mb-3"),
                ]),
                dbc.Row([
                    dbc.Col([
                        html.Label("PROTOCOL SCOPE", style={
                            "color": _TEXT_MUTED, "fontSize": "11px", "fontWeight": "700", "letterSpacing": "1px"
                        }),
                        dcc.Dropdown(
                            id="ab-protocol-dropdown",
                            options=[
                                {"label": "🔍 Auto-Detect Protocol", "value": "auto"},
                                {"label": "🔥 ALL 15 PROTOCOLS (Full Suite - 77 Checks)", "value": "all"},
                                {"label": "OAuth 2.0 / OpenID Connect (OA-01 - OA-12)", "value": "oauth2"},
                                {"label": "SAML 2.0 Identity Federation (SA-01 - SA-06)", "value": "saml"},
                                {"label": "JWT Algorithm & Key Attacks (JW-01 - JW-08)", "value": "jwt"},
                                {"label": "Multi-Step / Step-Up Auth (MS-01 - MS-05)", "value": "multistep"},
                                {"label": "Password Page & Input Attacks (PP-01 - PP-06)", "value": "password"},
                                {"label": "Password Reset & Account Recovery (PR-01 - PR-05)", "value": "reset"},
                                {"label": "Account & User Enumeration (EN-01 - EN-04)", "value": "enumeration"},
                                {"label": "Social & Federated Login (SL-01 - SL-04)", "value": "social"},
                                {"label": "HTTP Basic / Digest Auth (BA-01 - BA-04)", "value": "basic"},
                                {"label": "API Key & Bearer Token (AK-01 - AK-04)", "value": "apikey"},
                                {"label": "Session Management & Cookies (SE-01 - SE-05)", "value": "session"},
                                {"label": "LDAP Injection Attacks (LD-01 - LD-04)", "value": "ldap"},
                                {"label": "SAML Signature Wrapping / XSW (XW-01 - XW-03)", "value": "xsw"},
                                {"label": "Response Manipulation & Boolean Flip (RM-01 - RM-04)", "value": "response"},
                                {"label": "Host Header & Proxy Poisoning (HH-01 - HH-03)", "value": "hostheader"},
                            ],
                            value="auto",
                            clearable=False,
                            className="dash-bootstrap",
                            style={"background": "#080c14", "color": "#e6edf3", "fontSize": "12px"},
                        ),
                    ], md=4, className="mb-3"),
                    dbc.Col([
                        html.Label("AUTH MODE", style={
                            "color": _TEXT_MUTED, "fontSize": "11px", "fontWeight": "700", "letterSpacing": "1px"
                        }),
                        dcc.Dropdown(
                            id="ab-auth-mode-dropdown",
                            options=[
                                {"label": "Form POST (application/x-www-form-urlencoded)", "value": "form"},
                                {"label": "JSON Body (application/json)", "value": "json"},
                                {"label": "Header-Based Auth (Authorization Header)", "value": "header"},
                                {"label": "Cookie-Based Session Auth", "value": "cookie"},
                            ],
                            value="form",
                            clearable=False,
                            className="dash-bootstrap",
                            style={"background": "#080c14", "color": "#e6edf3", "fontSize": "12px"},
                        ),
                    ], md=4, className="mb-3"),
                    dbc.Col([
                        html.Label("BURP SUITE / PROXY (OPTIONAL)", style={
                            "color": _TEXT_MUTED, "fontSize": "11px", "fontWeight": "700", "letterSpacing": "1px"
                        }),
                        dbc.Input(
                            id="ab-proxy-input",
                            placeholder="http://127.0.0.1:8080",
                            type="text",
                            style={
                                "background": "#080c14",
                                "border": f"1px solid {_BORDER}",
                                "color": "#e6edf3",
                                "fontFamily": "'JetBrains Mono', monospace",
                                "fontSize": "12px",
                            }
                        ),
                    ], md=4, className="mb-3"),
                ]),
                dbc.Row([
                    dbc.Col([
                        html.Label("Test Username / Email (Optional)", style={"color": _TEXT_MUTED, "fontSize": "11px"}),
                        dbc.Input(
                            id="ab-username-input",
                            placeholder="e.g. testuser@company.com",
                            type="text",
                            style={"background": "#080c14", "border": f"1px solid {_BORDER}", "color": "#e6edf3", "fontSize": "12px"}
                        ),
                    ], md=3, className="mb-3"),
                    dbc.Col([
                        html.Label("Test Password (Optional)", style={"color": _TEXT_MUTED, "fontSize": "11px"}),
                        dbc.Input(
                            id="ab-password-input",
                            placeholder="e.g. Password123!",
                            type="password",
                            style={"background": "#080c14", "border": f"1px solid {_BORDER}", "color": "#e6edf3", "fontSize": "12px"}
                        ),
                    ], md=3, className="mb-3"),
                    dbc.Col([
                        html.Label("Bearer Token / Session Cookie (Optional)", style={"color": _TEXT_MUTED, "fontSize": "11px"}),
                        dbc.Input(
                            id="ab-token-input",
                            placeholder="eyJhbGci... or session_id=abc12345",
                            type="text",
                            style={
                                "background": "#080c14",
                                "border": f"1px solid {_BORDER}",
                                "color": "#e6edf3",
                                "fontFamily": "'JetBrains Mono', monospace",
                                "fontSize": "12px",
                            }
                        ),
                    ], md=6, className="mb-3"),
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Button(
                            [html.Span("▶ ", style={"fontWeight": "900"}), "Run Assessment"],
                            id="ab-run-btn",
                            color="success",
                            size="md",
                            style={
                                "fontWeight": "700",
                                "letterSpacing": "1px",
                                "background": "linear-gradient(135deg,#00c88c,#006644)",
                                "border": "none",
                                "padding": "8px 24px",
                                "marginRight": "12px",
                            }
                        ),
                        dbc.Button(
                            [html.Span("⏹ ", style={"fontWeight": "900"}), "Stop"],
                            id="ab-stop-btn",
                            color="danger",
                            size="md",
                            outline=True,
                            style={"fontWeight": "700", "letterSpacing": "1px", "padding": "8px 20px"}
                        ),
                    ], md=12),
                ]),
            ]),
        ], style={"background": _CARD_BG, "border": f"1px solid {_BORDER}", "margin": "0 24px 16px", "borderRadius": "8px"}),

        # KPI & SLA Row
        html.Div(id="ab-kpi-row", style={"padding": "0 24px", "display": "flex", "gap": "12px", "flexWrap": "wrap", "marginBottom": "16px"}),

        # Live Assessment Log
        dbc.Card([
            dbc.CardHeader([
                html.Span("📡 Live Assessment Log", style={
                    "fontWeight": "700", "color": _GREEN, "fontSize": "12px", "letterSpacing": "1px"
                }),
                html.Span(id="ab-log-status-badge", style={"float": "right", "fontSize": "11px", "color": _TEXT_MUTED}),
            ], style={"background": "#06090e", "borderBottom": f"1px solid {_BORDER}", "padding": "10px 16px"}),
            dbc.CardBody([
                html.Div(
                    id="ab-log-output",
                    style={
                        "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
                        "fontSize": "11px",
                        "color": _TEXT_MUTED,
                        "maxHeight": "200px",
                        "overflowY": "auto",
                        "background": "#06090e",
                        "padding": "12px",
                        "border": f"1px solid {_BORDER}",
                        "borderRadius": "6px",
                        "whiteSpace": "pre-wrap",
                    },
                    children=[html.Span("Ready. Configure target URL and click 'Run Assessment'.", style={"color": "#4a5568"})]
                ),
            ], style={"background": _CARD_BG, "padding": "12px"}),
        ], style={"background": _CARD_BG, "border": f"1px solid {_BORDER}", "margin": "0 24px 16px", "borderRadius": "8px"}),

        # Results Table Card
        dbc.Card([
            dbc.CardHeader([
                html.Span("🔍 Assessment Results & Vulnerability Proof", style={
                    "fontWeight": "700", "color": _GREEN, "fontSize": "12px", "letterSpacing": "1px"
                }),
                html.Div([
                    html.A(
                        dbc.Button(
                            "📄 PDF Report",
                            id="ab-pdf-btn",
                            size="sm",
                            color="secondary",
                            outline=True,
                            style={"fontSize": "11px", "marginRight": "8px"}
                        ),
                        id="ab-pdf-link",
                        href="#",
                        target="_blank",
                        style={"textDecoration": "none"}
                    ),
                    html.A(
                        dbc.Button(
                            "🌐 Interactive HTML",
                            id="ab-html-btn",
                            size="sm",
                            color="secondary",
                            outline=True,
                            style={"fontSize": "11px", "marginRight": "8px"}
                        ),
                        id="ab-html-link",
                        href="#",
                        target="_blank",
                        style={"textDecoration": "none"}
                    ),
                    dbc.Button(
                        "📊 Export CSV",
                        id="ab-csv-btn",
                        size="sm",
                        color="secondary",
                        outline=True,
                        style={"fontSize": "11px"}
                    ),
                ], style={"float": "right"}),
                dcc.Download(id="ab-dl-csv"),
            ], style={"background": "#06090e", "borderBottom": f"1px solid {_BORDER}", "padding": "10px 16px"}),
            dbc.CardBody([
                html.Div(
                    id="ab-results-table",
                    children=[
                        html.P("No assessment executed yet.", style={"color": "#4a5568", "fontFamily": "monospace", "fontSize": "12px", "margin": "12px 0"})
                    ]
                ),
            ], style={"background": _CARD_BG, "padding": "12px"}),
        ], style={"background": _CARD_BG, "border": f"1px solid {_BORDER}", "margin": "0 24px 24px", "borderRadius": "8px"}),

        # Scan History Modal
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("📜 Assessment Scan History"), style={"background": "#06090e", "borderBottom": f"1px solid {_BORDER}", "color": "#e6edf3"}),
            dbc.ModalBody(id="ab-history-modal-body", style={"background": _CARD_BG, "color": "#e6edf3"}),
            dbc.ModalFooter([
                dbc.Button("Close", id="ab-history-close-btn", className="ms-auto", n_clicks=0, size="sm", color="secondary")
            ], style={"background": "#06090e", "borderTop": f"1px solid {_BORDER}"})
        ], id="ab-history-modal", is_open=False, size="xl"),

        # Hidden Stores & Polling Interval
        dcc.Store(id="ab-scan-id-store", data=None),
        dcc.Store(id="ab-findings-store", data=[]),
        dcc.Interval(id="ab-poll-interval", interval=1500, disabled=True),
    ], style={"background": _DARK, "minHeight": "100vh"})


# ---------------------------------------------------------------------------
# Helper: KPI Card Builder with SLA Matrix
# ---------------------------------------------------------------------------

def _build_kpi_cards(vuln: int, secure: int, na: int, err: int, total: int, sev_counts: dict) -> List[html.Div]:
    crit = sev_counts.get("Critical", 0)
    high = sev_counts.get("High", 0)
    med  = sev_counts.get("Medium", 0)
    low  = sev_counts.get("Low", 0)

    cards = [
        html.Div([
            html.Div(str(vuln), style={"fontSize": "22px", "fontWeight": "800", "color": _RED}),
            html.Div("VULNERABLE", style={"fontSize": "10px", "fontWeight": "700", "color": "#ff8888", "letterSpacing": "1px"}),
            html.Div(f"Crit: {crit} | High: {high} | Med: {med}", style={"fontSize": "9px", "color": _TEXT_MUTED, "marginTop": "4px"}),
        ], style={"flex": "1", "minWidth": "140px", "background": "rgba(255,68,68,0.08)", "border": "1px solid rgba(255,68,68,0.3)", "borderRadius": "8px", "padding": "12px 16px"}),

        html.Div([
            html.Div(str(secure), style={"fontSize": "22px", "fontWeight": "800", "color": _GREEN}),
            html.Div("SECURE", style={"fontSize": "10px", "fontWeight": "700", "color": "#66ffcc", "letterSpacing": "1px"}),
            html.Div("Hardened controls", style={"fontSize": "9px", "color": _TEXT_MUTED, "marginTop": "4px"}),
        ], style={"flex": "1", "minWidth": "140px", "background": "rgba(0,200,140,0.08)", "border": "1px solid rgba(0,200,140,0.3)", "borderRadius": "8px", "padding": "12px 16px"}),

        html.Div([
            html.Div(str(na), style={"fontSize": "22px", "fontWeight": "800", "color": _GRAY}),
            html.Div("NOT APPLICABLE", style={"fontSize": "10px", "fontWeight": "700", "color": _TEXT_MUTED, "letterSpacing": "1px"}),
            html.Div("Out of scope", style={"fontSize": "9px", "color": _TEXT_MUTED, "marginTop": "4px"}),
        ], style={"flex": "1", "minWidth": "140px", "background": "rgba(110,118,129,0.08)", "border": f"1px solid {_BORDER}", "borderRadius": "8px", "padding": "12px 16px"}),

        html.Div([
            html.Div(str(err), style={"fontSize": "22px", "fontWeight": "800", "color": _ORANGE}),
            html.Div("ERRORS / TIMEOUT", style={"fontSize": "10px", "fontWeight": "700", "color": "#ffbb66", "letterSpacing": "1px"}),
            html.Div("Rate limit / offline", style={"fontSize": "9px", "color": _TEXT_MUTED, "marginTop": "4px"}),
        ], style={"flex": "1", "minWidth": "140px", "background": "rgba(255,149,0,0.08)", "border": "1px solid rgba(255,149,0,0.3)", "borderRadius": "8px", "padding": "12px 16px"}),

        html.Div([
            html.Div(str(total), style={"fontSize": "22px", "fontWeight": "800", "color": "#e6edf3"}),
            html.Div("TOTAL CHECKS", style={"fontSize": "10px", "fontWeight": "700", "color": _TEXT_MUTED, "letterSpacing": "1px"}),
            html.Div("15 protocols", style={"fontSize": "9px", "color": _TEXT_MUTED, "marginTop": "4px"}),
        ], style={"flex": "1", "minWidth": "140px", "background": "#0d1117", "border": f"1px solid {_BORDER}", "borderRadius": "8px", "padding": "12px 16px"}),
    ]
    return cards


# ---------------------------------------------------------------------------
# Helper: Results Table Builder
# ---------------------------------------------------------------------------

def _build_results_table(findings: List[dict]) -> html.Div:
    if not findings:
        return html.Div("No findings available.", style={"color": _TEXT_MUTED})

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            0 if f.get("status") == "VULNERABLE" else
            1 if f.get("status") == "SECURE" else
            2 if f.get("status") == "ERROR" else 3,
            -float(f.get("cvss_score") or 0.0),
            f.get("check_id", "")
        )
    )

    rows = []
    for f in sorted_findings:
        cid    = f.get("check_id", "")
        proto  = f.get("protocol", "")
        title  = f.get("title", "")
        status = f.get("status", "NOT_APPLICABLE")
        sev    = f.get("severity", "Info")
        cvss   = f.get("cvss_score", 0.0)
        mitre  = f.get("mitre_id", "")
        cwe    = f.get("cwe", "")
        evid   = f.get("evidence", "")
        recom  = f.get("recommendation", "")
        refs   = f.get("references", [])

        sev_st = SEV_BADGE_STYLE.get(sev, SEV_BADGE_STYLE["Info"])
        stat_st = STATUS_BADGE_STYLE.get(status, STATUS_BADGE_STYLE["NOT_APPLICABLE"])

        detail_block = html.Details([
            html.Summary([
                html.Span(cid, style={"fontFamily": "'JetBrains Mono', monospace", "fontWeight": "700", "marginRight": "12px", "color": "#e6edf3"}),
                html.Span(f"[{proto}]", style={"color": _TEXT_MUTED, "fontSize": "11px", "marginRight": "12px"}),
                html.Span(title, style={"color": "#e6edf3", "fontWeight": "600", "fontSize": "12px"}),
            ], style={"cursor": "pointer", "padding": "4px 0"}),
            html.Div([
                html.Div([
                    html.Strong("Evidence / Proof: ", style={"color": "#e6edf3", "fontSize": "11px"}),
                    html.Span(evid, style={"color": "#ffcccc" if status == "VULNERABLE" else "#a0aec0", "fontFamily": "monospace", "fontSize": "11px"}),
                ], style={"marginTop": "6px"}),
                html.Div([
                    html.Strong("Remediation: ", style={"color": "#00c88c", "fontSize": "11px"}),
                    html.Span(recom, style={"color": "#cbd5e0", "fontSize": "11px"}),
                ], style={"marginTop": "4px"}),
                html.Div([
                    html.Strong("Standards: ", style={"color": _TEXT_MUTED, "fontSize": "11px"}),
                    html.Span(f"CWE: {cwe or 'N/A'} | OWASP: {f.get('owasp','N/A')} | CREST: {f.get('crest','N/A')} | PTES: {f.get('ptes','N/A')}",
                              style={"color": _TEXT_MUTED, "fontSize": "11px"}),
                ], style={"marginTop": "4px"}),
                html.Div([
                    html.Strong("References: ", style={"color": _TEXT_MUTED, "fontSize": "11px"}),
                    html.Span(", ".join(refs) if refs else "Standard authentication testing guidance", style={"color": "#63b3ed", "fontSize": "11px"}),
                ], style={"marginTop": "4px"}),
            ], style={"background": "#06090e", "padding": "10px", "borderRadius": "6px", "marginTop": "6px", "border": f"1px solid {_BORDER}"}),
        ])

        row = html.Tr([
            html.Td(html.Span(cid, style={"fontFamily": "'JetBrains Mono', monospace", "fontWeight": "700", "color": "#e6edf3"}), style={"width": "90px"}),
            html.Td(html.Span(proto, style={"color": _TEXT_MUTED, "fontSize": "11px"}), style={"width": "120px"}),
            html.Td(detail_block),
            html.Td(
                html.Span(sev, style={
                    "padding": "2px 8px", "borderRadius": "4px", "fontSize": "10px", "fontWeight": "700", **sev_st
                }),
                style={"width": "90px", "textAlign": "center"}
            ),
            html.Td(html.Span(f"{cvss:.1f}" if cvss else "-", style={"color": "#e6edf3", "fontFamily": "monospace", "fontSize": "11px"}), style={"width": "60px", "textAlign": "center"}),
            html.Td(html.Span(mitre or "-", style={"color": "#ffd700", "fontFamily": "'JetBrains Mono', monospace", "fontSize": "11px"}), style={"width": "100px", "textAlign": "center"}),
            html.Td(
                html.Span(status, style={
                    "padding": "2px 8px", "borderRadius": "4px", "fontSize": "10px", "fontWeight": "700", **stat_st
                }),
                style={"width": "120px", "textAlign": "center"}
            ),
        ], style={"borderBottom": f"1px solid {_BORDER}", "background": "rgba(255,68,68,0.04)" if status == "VULNERABLE" else "transparent"})
        rows.append(row)

    return dbc.Table([
        html.Thead(
            html.Tr([
                html.Th("Check ID", style={"color": _TEXT_MUTED, "fontSize": "11px", "letterSpacing": "1px"}),
                html.Th("Protocol", style={"color": _TEXT_MUTED, "fontSize": "11px", "letterSpacing": "1px"}),
                html.Th("Vulnerability / Check Title", style={"color": _TEXT_MUTED, "fontSize": "11px", "letterSpacing": "1px"}),
                html.Th("Severity", style={"color": _TEXT_MUTED, "fontSize": "11px", "letterSpacing": "1px", "textAlign": "center"}),
                html.Th("CVSS", style={"color": _TEXT_MUTED, "fontSize": "11px", "letterSpacing": "1px", "textAlign": "center"}),
                html.Th("MITRE", style={"color": _TEXT_MUTED, "fontSize": "11px", "letterSpacing": "1px", "textAlign": "center"}),
                html.Th("Status", style={"color": _TEXT_MUTED, "fontSize": "11px", "letterSpacing": "1px", "textAlign": "center"}),
            ], style={"background": "#06090e", "borderBottom": f"1px solid {_BORDER}"})
        ),
        html.Tbody(rows),
    ], responsive=True, hover=True, style={"fontSize": "12px", "color": "#e6edf3", "marginBottom": "0"})


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------

@callback(
    Output("ab-probe-result", "children"),
    Input("ab-probe-btn", "n_clicks"),
    State("ab-target-url", "value"),
    prevent_initial_call=True,
)
def _ab_probe_target(n_clicks, url):
    if not url or not url.strip():
        return html.Span("Please enter a target URL to probe.", style={"color": _ORANGE})

    target = AuthTarget(url=url.strip())
    health = probe_target_health(target, timeout=4)

    if health.get("reachable"):
        waf_badge = html.Span(f" | WAF: {health['waf']}", style={"color": _YELLOW, "fontWeight": "700"}) if health.get("waf") else html.Span(" | No WAF header detected", style={"color": _TEXT_MUTED})
        return html.Div([
            html.Span("● REACHABLE ", style={"color": _GREEN, "fontWeight": "700"}),
            html.Span(f"(HTTP {health['status_code']} | {health['latency_ms']}ms latency | Server: {health['server']})", style={"color": "#e6edf3"}),
            waf_badge,
        ], style={"background": "#06090e", "padding": "6px 10px", "borderRadius": "4px", "border": f"1px solid {_BORDER}"})
    else:
        return html.Div([
            html.Span("● UNREACHABLE ", style={"color": _RED, "fontWeight": "700"}),
            html.Span(f"Error: {health.get('error', 'Connection failed')}", style={"color": _TEXT_MUTED}),
        ], style={"background": "#06090e", "padding": "6px 10px", "borderRadius": "4px", "border": "1px solid rgba(255,68,68,0.3)"})


@callback(
    Output("ab-scan-id-store", "data"),
    Output("ab-poll-interval", "disabled"),
    Output("ab-log-output", "children"),
    Output("ab-log-status-badge", "children"),
    Output("ab-pdf-link", "href"),
    Output("ab-html-link", "href"),
    Input("ab-run-btn", "n_clicks"),
    State("ab-target-url", "value"),
    State("ab-protocol-dropdown", "value"),
    State("ab-auth-mode-dropdown", "value"),
    State("ab-proxy-input", "value"),
    State("ab-username-input", "value"),
    State("ab-password-input", "value"),
    State("ab-token-input", "value"),
    prevent_initial_call=True,
)
def _ab_run_assessment(n_clicks, url, proto, auth_mode, proxy, username, password, token):
    if not url or not url.strip():
        return no_update, True, [html.Span("Error: Please provide a valid target URL.", style={"color": _RED})], "Validation Error", "#", "#"

    url = url.strip()
    scan_id = uuid.uuid4().hex[:12]

    session_cookie = ""
    bearer_token = ""
    if token:
        if token.lower().startswith("bearer "):
            bearer_token = token[7:].strip()
        elif "eyj" in token.lower() and "." in token:
            bearer_token = token.strip()
        else:
            session_cookie = token.strip()

    target = AuthTarget(
        url=url,
        protocol=proto or "auto",
        auth_mode=auth_mode or "form",
        username=username.strip() if username else "",
        password=password.strip() if password else "",
        session_cookie=session_cookie,
        bearer_token=bearer_token,
        proxy=proxy.strip() if proxy else "",
    )

    with _lock:
        _scans[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "logs": [f"[{time.strftime('%H:%M:%S')}] Initialized Auth Bypass Assessment for: {target.url}"],
            "target": target,
            "findings": [],
            "result": None,
            "start_time": time.time(),
        }

    def _worker():
        def _log_collector(msg: str):
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["logs"].append(f"[{time.strftime('%H:%M:%S')}] {msg}")

        try:
            protocols_list = None
            if proto and proto not in ("auto", "all"):
                protocols_list = [proto]
            elif proto == "all":
                protocols_list = list(_PROTOCOL_MAP.keys())

            res = run_assessment(target=target, protocols=protocols_list, log_fn=_log_collector)
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["status"] = "done"
                    _scans[scan_id]["result"] = res
                    _scans[scan_id]["findings"] = res.get("findings", [])
        except Exception as exc:
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["status"] = "error"
                    _scans[scan_id]["logs"].append(f"[{time.strftime('%H:%M:%S')}] FATAL ERROR: {exc}")

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    initial_log = [html.Span(f"[{time.strftime('%H:%M:%S')}] Starting assessment against {target.url} ...\n", style={"color": _GREEN})]
    pdf_href = f"/app/auth-bypass-report/{scan_id}"
    html_href = f"/app/auth-bypass-html/{scan_id}"
    return scan_id, False, initial_log, "Running assessment...", pdf_href, html_href


@callback(
    Output("ab-poll-interval", "disabled", allow_duplicate=True),
    Input("ab-stop-btn", "n_clicks"),
    State("ab-scan-id-store", "data"),
    prevent_initial_call=True,
)
def _ab_stop_assessment(n_clicks, scan_id):
    if scan_id and scan_id in _scans:
        with _lock:
            _scans[scan_id]["status"] = "stopped"
            _scans[scan_id]["logs"].append(f"[{time.strftime('%H:%M:%S')}] Assessment stopped by user.")
    return True


@callback(
    Output("ab-log-output", "children", allow_duplicate=True),
    Output("ab-results-table", "children"),
    Output("ab-kpi-row", "children"),
    Output("ab-poll-interval", "disabled", allow_duplicate=True),
    Output("ab-findings-store", "data"),
    Output("ab-log-status-badge", "children", allow_duplicate=True),
    Input("ab-poll-interval", "n_intervals"),
    State("ab-scan-id-store", "data"),
    prevent_initial_call=True,
)
def _ab_poll_results(n_intervals, scan_id):
    if not scan_id or scan_id not in _scans:
        return no_update, no_update, no_update, True, no_update, no_update

    with _lock:
        sdata = _scans[scan_id]
        status = sdata.get("status", "running")
        logs = list(sdata.get("logs", []))
        findings = list(sdata.get("findings", []))
        result = sdata.get("result") or {}

    log_elements = []
    for line in logs[-100:]:
        col = "#e6edf3"
        if "VULNERABLE" in line or "FATAL" in line or "Error" in line:
            col = _RED
        elif "SECURE" in line:
            col = _GREEN
        elif "N/A" in line:
            col = _GRAY
        elif "ERROR" in line:
            col = _ORANGE
        log_elements.append(html.Div(line, style={"color": col}))

    vuln_count = sum(1 for f in findings if f.get("status") == "VULNERABLE")
    sec_count  = sum(1 for f in findings if f.get("status") == "SECURE")
    na_count   = sum(1 for f in findings if f.get("status") == "NOT_APPLICABLE")
    err_count  = sum(1 for f in findings if f.get("status") == "ERROR")
    total_count = len(findings)

    kpi_cards = _build_kpi_cards(
        vuln=vuln_count,
        secure=sec_count,
        na=na_count,
        err=err_count,
        total=total_count,
        sev_counts=result.get("severity_counts", {})
    )

    table = _build_results_table(findings) if findings else html.P("Running checks...", style={"color": _TEXT_MUTED, "fontFamily": "monospace"})

    is_done = status in ("done", "stopped", "error")
    status_text = "Completed" if status == "done" else "Stopped" if status == "stopped" else "Error" if status == "error" else f"Scanning... ({total_count} checks)"

    return log_elements, table, kpi_cards, is_done, findings, status_text


@callback(
    Output("ab-history-modal", "is_open"),
    Output("ab-history-modal-body", "children"),
    Input("ab-history-btn", "n_clicks"),
    Input("ab-history-close-btn", "n_clicks"),
    State("ab-history-modal", "is_open"),
    prevent_initial_call=True,
)
def _ab_toggle_history(open_clicks, close_clicks, is_open):
    triggered = ctx.triggered_id
    if triggered == "ab-history-close-btn":
        return False, no_update

    # Load scans from sqlite history
    scans = list_scans(limit=30)
    if not scans:
        body = html.P("No historical assessment scans found.", style={"color": _TEXT_MUTED, "padding": "16px"})
        return True, body

    table_rows = []
    for s in scans:
        sid = s.get("scan_id", "")
        ts = time.strftime("%Y-%m-%d %H:%M", time.gmtime(s.get("created_at", time.time())))
        tgt = s.get("target_url", "")
        vuln = s.get("vulnerable_count", 0)
        proto = s.get("protocol", "auto")

        row = html.Tr([
            html.Td(html.Code(sid, style={"color": "#ffd700"}), style={"fontSize": "11px"}),
            html.Td(ts, style={"fontSize": "11px", "color": _TEXT_MUTED}),
            html.Td(html.Span(tgt, style={"fontSize": "11px", "fontFamily": "monospace"}), style={"maxWidth": "280px", "overflow": "hidden", "textOverflow": "ellipsis"}),
            html.Td(html.Span(proto.upper(), style={"fontSize": "10px", "color": _TEXT_MUTED})),
            html.Td(html.Span(f"{vuln} Vulns", style={"color": _RED if vuln else _GREEN, "fontWeight": "700", "fontSize": "11px"})),
            html.Td([
                html.A(
                    dbc.Button("PDF", size="sm", color="secondary", outline=True, style={"fontSize": "10px", "marginRight": "4px"}),
                    href=f"/app/auth-bypass-report/{sid}",
                    target="_blank"
                ),
                html.A(
                    dbc.Button("HTML", size="sm", color="secondary", outline=True, style={"fontSize": "10px"}),
                    href=f"/app/auth-bypass-html/{sid}",
                    target="_blank"
                ),
            ]),
        ])
        table_rows.append(row)

    history_table = dbc.Table([
        html.Thead(
            html.Tr([
                html.Th("Scan ID"),
                html.Th("Date (UTC)"),
                html.Th("Target URL"),
                html.Th("Protocol"),
                html.Th("Findings"),
                html.Th("Reports"),
            ], style={"background": "#06090e", "color": _TEXT_MUTED, "fontSize": "11px"})
        ),
        html.Tbody(table_rows),
    ], responsive=True, hover=True, style={"fontSize": "12px", "color": "#e6edf3"})

    return True, history_table


@callback(
    Output("ab-dl-csv", "data"),
    Input("ab-csv-btn", "n_clicks"),
    State("ab-findings-store", "data"),
    prevent_initial_call=True,
)
def _ab_export_csv(n_clicks, findings):
    if not findings:
        return no_update

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "check_id", "protocol", "title", "status", "severity",
        "cvss_score", "mitre_id", "mitre_name", "cwe", "owasp",
        "crest", "ptes", "evidence", "recommendation", "references"
    ])
    for f in findings:
        refs_str = " | ".join(f.get("references", []))
        writer.writerow([
            f.get("check_id", ""),
            f.get("protocol", ""),
            f.get("title", ""),
            f.get("status", ""),
            f.get("severity", ""),
            f.get("cvss_score", ""),
            f.get("mitre_id", ""),
            f.get("mitre_name", ""),
            f.get("cwe", ""),
            f.get("owasp", ""),
            f.get("crest", ""),
            f.get("ptes", ""),
            f.get("evidence", ""),
            f.get("recommendation", ""),
            refs_str,
        ])

    return dcc.send_string(out.getvalue(), filename=f"auth_bypass_findings_{int(time.time())}.csv")
