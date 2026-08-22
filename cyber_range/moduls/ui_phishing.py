"""
ui_phishing.py
Phishing Simulation & Email Security Tab
GoPhish Builder · SPF/DKIM/DMARC Analyser · Email Header Inspector ·
Phishing Kit Detector · Campaign Tracker · AI Lure Generator
"""
from __future__ import annotations

import re
import subprocess
import threading
import time
from datetime import datetime

import requests
from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "6px", "fontSize": "13px"}
BTN_SM    = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL     = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
             "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}
MONO      = {"fontFamily": "monospace", "fontSize": "11px"}

_OUTPUTS: dict[str, str] = {}
_LOCK     = threading.Lock()


def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)

def _label(t): return html.Div(t, style=LABEL)
def _cmd(c):   return html.Div(c, style={**MONO, "color": "#50fa7b",
                                          "background": "#0d0d0d",
                                          "padding": "3px 8px",
                                          "borderRadius": "4px",
                                          "marginBottom": "3px"})

def _run_bg(cmd: str, key: str):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        out = r.stdout + ("\n[STDERR]\n" + r.stderr if r.stderr else "")
    except subprocess.TimeoutExpired:
        out = "[TIMEOUT]"
    except Exception as e:
        out = f"[ERROR] {e}"
    with _LOCK:
        _OUTPUTS[key] = out


def _check_result(label, value, ok, detail=""):
    color = "#27ae60" if ok else "#c0392b"
    icon  = "✅" if ok else "❌"
    return html.Div([
        html.Span(f"{icon} {label}: ", style={"color": color, "fontWeight": "700",
                                               "fontSize": "12px"}),
        html.Span(value, style={"color": "#e0e0e0", "fontSize": "12px",
                                 "fontFamily": "monospace"}),
        html.Div(detail, style={"color": "#8e9eb0", "fontSize": "10px",
                                 "paddingLeft": "20px"}) if detail else html.Span(),
    ], style={"marginBottom": "6px"})


def _fetch_email_records(domain: str) -> dict:
    """Check SPF, DKIM, DMARC records via DNS."""
    import subprocess as sp
    results = {}
    # SPF
    try:
        r = sp.run(f"dig +short TXT {domain}", shell=True,
                   capture_output=True, text=True, timeout=10)
        spf = next((l for l in r.stdout.splitlines() if "v=spf1" in l.lower()), None)
        results["spf"] = spf
    except Exception:
        results["spf"] = None
    # DMARC
    try:
        r = sp.run(f"dig +short TXT _dmarc.{domain}", shell=True,
                   capture_output=True, text=True, timeout=10)
        dmarc = r.stdout.strip().strip('"')
        results["dmarc"] = dmarc if "v=DMARC1" in dmarc else None
    except Exception:
        results["dmarc"] = None
    # DKIM (common selectors)
    dkim_found = None
    for sel in ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]:
        try:
            r = sp.run(f"dig +short TXT {sel}._domainkey.{domain}", shell=True,
                       capture_output=True, text=True, timeout=5)
            if "v=DKIM1" in r.stdout:
                dkim_found = f"{sel}: {r.stdout.strip()[:80]}"
                break
        except Exception:
            pass
    results["dkim"] = dkim_found
    return results


def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="ph-records", data={}),

        html.Div([
            html.H4("🎣 Phishing Simulation & Email Security",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("GoPhish · SPF/DKIM/DMARC · Email Headers · "
                     "Phishing Kit Detection · AI Lure Generator",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🔍 Email Security Check",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("Target Domain"),
                    dbc.Input(id="ph-domain", placeholder="example.com",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("🔍 Check SPF/DKIM/DMARC", id="ph-check-btn",
                               color="primary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="ph-record-results"),
                ),
                _card(
                    html.Div("🤖 AI Tools", style={"color": "#e0e0e0",
                                                    "fontWeight": "600",
                                                    "marginBottom": "10px"}),
                    dbc.Button("✍️ Generate Phishing Lure", id="ph-ai-lure",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("🛡️ Awareness Training", id="ph-ai-train",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("📊 Campaign Analysis", id="ph-ai-camp",
                               color="outline-warning", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("✨ AI Lure for Template", id="ph-camp-ai",
                               color="outline-secondary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Select(id="ph-camp-template",
                               options=[
                                   {"label": "Password Reset",    "value": "pwd"},
                                   {"label": "Invoice/Payment",   "value": "invoice"},
                                   {"label": "IT Urgency",        "value": "it"},
                                   {"label": "HR Announcement",   "value": "hr"},
                                   {"label": "Package Delivery",  "value": "pkg"},
                                   {"label": "CEO Fraud/BEC",     "value": "bec"},
                               ], value="pwd",
                               style={**INPUT_STY, "fontSize": "11px",
                                      "marginBottom": "8px"}),
                    html.Div(id="ph-ai-out",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "280px", "overflowY": "auto"}),
                ),
            ], width=3),

            # ── Centre ───────────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="ph-tabs", active_tab="ph-tab-gophish",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="📧 GoPhish",       tab_id="ph-tab-gophish"),
                     dbc.Tab(label="📨 Email Headers", tab_id="ph-tab-headers"),
                     dbc.Tab(label="😈 Kit Detector",  tab_id="ph-tab-kit"),
                     dbc.Tab(label="📋 Campaign",      tab_id="ph-tab-campaign"),
                 ]),
                html.Div(id="ph-phase-content"),
            ], width=6),

            # ── Right ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("✅ Email Security Checklist",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("□ ", style={"color": "#636e72"}),
                        html.Span(item, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for item in [
                          "SPF record configured",
                          "DMARC with p=reject",
                          "DKIM signing enabled",
                          "BIMI record for brand protection",
                          "MTA-STS enforced",
                          "DANE/TLSA records",
                          "Email gateway with sandboxing",
                          "Anti-spoofing rules active",
                          "User awareness training done",
                          "Phishing reporting button in MUA",
                          "Incident response for phish reports",
                          "Domain monitoring for lookalikes",
                      ]],
                ),
                _card(
                    html.Div("📋 Quick Commands",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[_cmd(c) for c in [
                        "dig +short TXT example.com",
                        "dig +short TXT _dmarc.example.com",
                        "dig +short MX example.com",
                        "nmap -p 25,465,587 mail.server",
                        "openssl s_client -connect mail:587 -starttls smtp",
                        "swaks --to user@target.com --from spoofed@sender.com",
                    ]],
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


@callback(
    Output("ph-record-results", "children"),
    Output("ph-records",        "data"),
    Input("ph-check-btn",       "n_clicks"),
    State("ph-domain",          "value"),
    prevent_initial_call=True,
)
def check_records(n, domain):
    if not n or not domain:
        raise PreventUpdate
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    rec = _fetch_email_records(domain)
    spf   = rec.get("spf")
    dmarc = rec.get("dmarc")
    dkim  = rec.get("dkim")

    dmarc_policy = ""
    if dmarc:
        m = re.search(r"p=(\w+)", dmarc)
        dmarc_policy = m.group(1) if m else "unknown"

    results = [
        _check_result("SPF",   spf or "NOT FOUND",   bool(spf),
                      "Prevents sender spoofing" if spf else "⚠ Domain can be spoofed!"),
        _check_result("DKIM",  dkim or "NOT FOUND",  bool(dkim),
                      "Ensures email integrity"),
        _check_result("DMARC", dmarc_policy or "NOT FOUND",
                      dmarc_policy in ("reject", "quarantine"),
                      f"Policy: {dmarc_policy}" if dmarc else "⚠ No enforcement!"),
    ]
    score = sum([bool(spf), bool(dkim), dmarc_policy in ("reject", "quarantine")])
    color = "#27ae60" if score == 3 else ("#e67e22" if score >= 1 else "#c0392b")
    results.append(html.Div(
        f"Email Security Score: {score}/3",
        style={"color": color, "fontWeight": "700", "fontSize": "14px",
               "marginTop": "10px", "textAlign": "center"}
    ))
    return html.Div(results), rec


@callback(
    Output("ph-phase-content", "children"),
    Input("ph-tabs",           "active_tab"),
    State("ph-domain",         "value"),
)
def render_phase(tab, domain):
    d = domain or "example.com"
    if tab == "ph-tab-gophish":
        cmd = f"""# ── GoPhish Setup & Campaign ─────────────────────────────
# Download: https://github.com/gophish/gophish/releases
./gophish &  # Starts on https://localhost:3333

# API: Create a campaign
GOPHISH_API="http://localhost:3333/api"
API_KEY="your_api_key"

# Create sending profile
curl -X POST "$GOPHISH_API/smtp/" \\
  -H "Authorization: Bearer $API_KEY" \\
  -d '{{"name":"Test SMTP","host":"smtp.server:587","from_address":"hr@{d}"}}'

# Create landing page
curl -X POST "$GOPHISH_API/pages/" \\
  -H "Authorization: Bearer $API_KEY" \\
  -d '{{"name":"Microsoft Login Clone","capture_credentials":true}}'

# Launch campaign
curl -X POST "$GOPHISH_API/campaigns/" \\
  -H "Authorization: Bearer $API_KEY" \\
  -d '{{"name":"Q1 Phishing Test","smtp":{{"id":1}},"url":"http://phishing.internal"}}'

# Get results
curl "$GOPHISH_API/campaigns/1/results" \\
  -H "Authorization: Bearer $API_KEY" | jq

# King Phisher (alternative)
# king-phisher-client

# SET (Social Engineering Toolkit)
# setoolkit → 1 (Social-Engineering Attacks) → 2 (Website Attack Vectors)"""

        return _card(
            html.Div(f"📧 GoPhish Campaign Builder — {d}",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("Command"),
            dbc.Textarea(id="ph-gophish-cmd", value=cmd,
                         style={**INPUT_STY, "height": "250px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("▶ Run", id="ph-gophish-run",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=6),
            ], style={"marginBottom": "8px"}),
            dbc.Textarea(id="ph-gophish-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "150px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b"}),
        )

    elif tab == "ph-tab-headers":
        return _card(
            html.Div("📨 Email Header Analyser",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("Paste Raw Email Headers"),
            dbc.Textarea(id="ph-headers-raw",
                         placeholder="Paste full email headers here...",
                         style={**INPUT_STY, "height": "200px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("🔍 Analyse Headers", id="ph-headers-analyse",
                                   color="primary", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=6),
                dbc.Col(dbc.Button("✨ AI Analyse", id="ph-headers-ai",
                                   color="outline-info", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=6),
            ], style={"marginBottom": "8px"}),
            html.Div(id="ph-headers-out",
                     style={"color": "#b0b0b0", "fontSize": "12px",
                            "whiteSpace": "pre-wrap", "minHeight": "50px",
                            "maxHeight": "300px", "overflowY": "auto"}),
        )

    elif tab == "ph-tab-kit":
        cmd = f"""# ── Phishing Kit Detector ─────────────────────────────────
# Check URL for phishing indicators
curl -sI "https://{d}" | grep -E "Server:|Content-Type:|Location:"

# URLhaus check (free API)
curl -X POST "https://urlhaus-api.abuse.ch/v1/url/" \\
  -d "url=https://{d}"

# PhishTank check
curl "https://checkurl.phishtank.com/checkurl/" \\
  -d "url=https://{d}&format=json"

# Google Safe Browsing (requires API key)
# curl "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=KEY" ...

# Wayback Machine for phishing kit artifacts
curl "http://web.archive.org/cdx/search/cdx?url={d}/*&output=json&limit=10"

# Check for classic phishing kit markers
curl -s "https://{d}/" | grep -iE "submit|password|credential|login|bank|paypal|amazon"

# Identify cloned website
curl -s "https://{d}/" | grep -i "original_domain\\|phishing\\|clone"

# VirusTotal domain report (requires API key)
# curl --request GET "https://www.virustotal.com/api/v3/domains/{d}" \\
#   --header "x-apikey: VT_API_KEY" """

        return _card(
            html.Div("😈 Phishing Kit Detector",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("Command"),
            dbc.Textarea(id="ph-kit-cmd", value=cmd,
                         style={**INPUT_STY, "height": "220px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("▶ Run", id="ph-kit-run",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=6),
            ], style={"marginBottom": "8px"}),
            dbc.Textarea(id="ph-kit-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "150px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b"}),
        )

    elif tab == "ph-tab-campaign":
        return _card(
            html.Div("📋 Campaign Tracker",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            dbc.Row([
                dbc.Col([
                    _label("Campaign Name"),
                    dbc.Input(id="ph-camp-name", placeholder="Q1 2025 Test",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Targets (one per line)"),
                    dbc.Textarea(id="ph-camp-targets",
                                 placeholder="user@company.com\nmanager@company.com",
                                 style={**INPUT_STY, "height": "100px",
                                        "marginBottom": "8px"}),
                ], width=6),
                dbc.Col([
                    _label("Template (set in AI Tools panel)"),
                    dbc.Select(
                               options=[
                                   {"label": "Password Reset",    "value": "pwd"},
                                   {"label": "Invoice/Payment",   "value": "invoice"},
                                   {"label": "IT Urgency",        "value": "it"},
                                   {"label": "HR Announcement",   "value": "hr"},
                                   {"label": "Package Delivery",  "value": "pkg"},
                                   {"label": "CEO Fraud/BEC",     "value": "bec"},
                               ], value="pwd",
                               id="ph-camp-template-display",
                               disabled=True,
                               style={**INPUT_STY, "opacity": "0.5",
                                      "marginBottom": "8px"}),
                    _label("Status"),
                    dbc.Select(id="ph-camp-status",
                               options=[
                                   {"label": "Planning",    "value": "planning"},
                                   {"label": "Active",      "value": "active"},
                                   {"label": "Completed",   "value": "completed"},
                               ], value="planning",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                ], width=6),
            ]),
            html.Div(html.Small("Use '✨ AI Lure for Template' in the AI Tools panel →",
                               style={"color": "#636e72", "fontSize": "10px",
                                      "fontStyle": "italic"})),
        )

    return html.Div()


@callback(
    Output("ph-headers-out", "children"),
    Input("ph-headers-analyse", "n_clicks"),
    State("ph-headers-raw",     "value"),
    prevent_initial_call=True,
)
def analyse_headers(n, raw):
    if not n or not raw:
        raise PreventUpdate
    lines = []
    # Extract key fields
    for field in ["From:", "To:", "Reply-To:", "Return-Path:", "Subject:",
                  "Received:", "X-Originating-IP:", "X-Mailer:", "DKIM-Signature:",
                  "Authentication-Results:", "ARC-Authentication-Results:"]:
        matches = [l.strip() for l in raw.splitlines() if l.startswith(field)]
        for m in matches[:3]:
            lines.append(html.Div(m, style={**MONO, "color": "#e0e0e0",
                                             "marginBottom": "2px"}))
    # Check for suspicious indicators
    suspicious = []
    if "bulk" in raw.lower():            suspicious.append("Bulk mail marker detected")
    if "x-phpmailer" in raw.lower():     suspicious.append("PHPMailer detected (common phishing tool)")
    if "x-mailer: swaks" in raw.lower(): suspicious.append("SWAKS (testing tool) detected")
    if re.search(r"reply-to.+\n?.+from", raw, re.I):
        suspicious.append("Reply-To differs from From — potential BEC")
    for s in suspicious:
        lines.append(html.Div(f"⚠ {s}", style={"color": "#e74c3c", "fontWeight": "700",
                                                  "fontSize": "12px", "marginTop": "6px"}))
    return html.Div(lines) if lines else "No fields extracted."


@callback(
    Output("ph-ai-out",    "children"),
    Input("ph-ai-lure",    "n_clicks"),
    Input("ph-ai-train",   "n_clicks"),
    Input("ph-ai-camp",    "n_clicks"),
    Input("ph-camp-ai",    "n_clicks"),
    State("ph-domain",     "value"),
    State("ph-records",    "data"),
    State("ph-camp-template", "value"),
    prevent_initial_call=True,
)
def ai_phishing(lure_n, train_n, camp_n, camp_ai_n, domain, records, template):
    if not ctx.triggered_id:
        raise PreventUpdate
    d   = domain or "example.com"
    tid = ctx.triggered_id
    if tid in ("ph-ai-lure", "ph-camp-ai"):
        tpl_names = {"pwd": "Password Reset", "invoice": "Invoice Urgency",
                     "it": "IT Security Alert", "hr": "HR Announcement",
                     "pkg": "Package Delivery", "bec": "CEO Fraud"}
        tpl = tpl_names.get(template, "Password Reset")
        prompt = (
            f"You are a red team security professional performing an authorised "
            f"phishing awareness test for {d}.\n\n"
            f"Generate a realistic-looking {tpl} phishing email that would be used "
            f"in a controlled security awareness test.\n\n"
            f"Include:\n"
            f"1) **Subject line** (convincing, urgent)\n"
            f"2) **Email body** (HTML-formatted, professional)\n"
            f"3) **Call to action** (click link / download attachment)\n"
            f"4) **Red flags** — list what users should have noticed\n"
            f"5) **Training points** — what this test teaches\n\n"
            f"This is for AUTHORISED security awareness training only."
        )
    elif tid == "ph-ai-train":
        spf   = records.get("spf", "not found") if records else "unknown"
        dmarc = records.get("dmarc", "not found") if records else "unknown"
        prompt = (
            f"Create a security awareness training guide for employees of {d}.\n\n"
            f"Email security status: SPF={bool(spf)}, DMARC={bool(dmarc)}\n\n"
            f"Include:\n"
            f"1) **How to spot phishing** — visual indicators checklist\n"
            f"2) **Common lure types** used against companies like {d}\n"
            f"3) **What to do** when you receive a suspicious email\n"
            f"4) **Real examples** of phishing language patterns\n"
            f"5) **Quick Quiz** — 5 questions to test employee awareness"
        )
    else:  # campaign analysis
        prompt = (
            f"Analyse the phishing simulation campaign approach for {d}.\n\n"
            f"Email security: SPF={records.get('spf') if records else 'unknown'}, "
            f"DMARC={records.get('dmarc') if records else 'unknown'}\n\n"
            f"Provide:\n"
            f"1) **Deliverability** — will phishing emails reach inboxes?\n"
            f"2) **Bypass techniques** for existing email security\n"
            f"3) **Best templates** to test this specific org\n"
            f"4) **Success metrics** — what click rate is concerning?\n"
            f"5) **Follow-up training** recommendations"
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"
