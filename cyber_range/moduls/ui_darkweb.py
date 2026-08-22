"""
ui_darkweb.py
Dark Web Monitor
Paste Site Monitor · Credential Leak Alerts · Ransomware Group Tracker ·
Tor Hidden Services · IOC from Dark Web Feeds · AI Threat Intel
"""
from __future__ import annotations

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

_LOCK = threading.Lock()

# Active ransomware groups (2025) with known leak sites
RANSOMWARE_GROUPS = [
    {"name": "LockBit 3.0",  "status": "active",  "victims": "3500+",
     "targets": "Healthcare, Manufacturing", "tactic": "double-extortion"},
    {"name": "ALPHV/BlackCat","status": "active",  "victims": "600+",
     "targets": "Critical Infrastructure",  "tactic": "triple-extortion"},
    {"name": "Cl0p",         "status": "active",  "victims": "500+",
     "targets": "MOVEit, GoAnywhere vulns",  "tactic": "bulk-exploitation"},
    {"name": "Black Basta",  "status": "active",  "victims": "300+",
     "targets": "Financial, Healthcare",    "tactic": "double-extortion"},
    {"name": "Akira",        "status": "active",  "victims": "250+",
     "targets": "SMB, Education",           "tactic": "double-extortion"},
    {"name": "Play",         "status": "active",  "victims": "200+",
     "targets": "Government, Finance",      "tactic": "double-extortion"},
    {"name": "8Base",        "status": "active",  "victims": "180+",
     "targets": "Business Services",        "tactic": "shaming"},
    {"name": "NoEscape",     "status": "active",  "victims": "150+",
     "targets": "Healthcare, Finance",      "tactic": "triple-extortion"},
    {"name": "RansomHub",    "status": "active",  "victims": "400+",
     "targets": "Multi-sector",             "tactic": "RaaS"},
    {"name": "Medusa",       "status": "active",  "victims": "200+",
     "targets": "Education, Government",    "tactic": "double-extortion"},
]


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


def _fetch_paste_search(query: str) -> list[dict]:
    """Search psbdmp.ws (free paste dump API) for mentions."""
    results = []
    try:
        r = requests.get(
            f"https://psbdmp.ws/api/search/{query}",
            timeout=15, headers={"User-Agent": "DarkWebMonitor/1.0"}
        )
        if r.status_code == 200:
            data = r.json()
            for item in data.get("data", [])[:10]:
                results.append({
                    "id":   item.get("id", ""),
                    "url":  f"https://pastebin.com/{item.get('id','')}",
                    "date": item.get("time", ""),
                    "tags": item.get("tags", []),
                })
    except Exception:
        pass
    return results


def _fetch_breach_domain(domain: str) -> list[dict]:
    """Check ProxyNova COMB for domain mentions."""
    results = []
    try:
        r = requests.get(
            f"https://api.proxynova.com/comb?query={domain}&start=0&limit=10",
            timeout=15, headers={"User-Agent": "DarkWebMonitor/1.0"}
        )
        if r.status_code == 200:
            data = r.json()
            lines = data.get("lines", [])
            for line in lines[:10]:
                parts = line.split(":")
                results.append({
                    "email":    parts[0] if parts else line,
                    "password": ":".join(parts[1:]) if len(parts) > 1 else "***",
                    "source":   "ProxyNova COMB",
                })
    except Exception:
        pass
    return results


def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="dw-paste-results", data=[]),
        dcc.Store(id="dw-breach-results", data=[]),

        html.Div([
            html.H4("🕵️ Dark Web Monitor",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("Paste Site Monitor · Credential Leak Alerts · "
                     "Ransomware Group Tracker · AI Threat Intel",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🔍 Monitor Target",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("Domain / Email / Keyword"),
                    dbc.Input(id="dw-target",
                              placeholder="example.com or user@domain.com",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Row([
                        dbc.Col(dbc.Button("📋 Paste Search", id="dw-paste-btn",
                                           color="primary", size="sm",
                                           style={**BTN_SM, "width": "100%"}), width=6),
                        dbc.Col(dbc.Button("🔓 Breach Lookup", id="dw-breach-btn",
                                           color="outline-danger", size="sm",
                                           style={**BTN_SM, "width": "100%"}), width=6),
                    ], style={"marginBottom": "8px"}),
                    html.Div(id="dw-search-status",
                             style={"color": "#636e72", "fontSize": "11px",
                                    "minHeight": "14px"}),
                ),
                _card(
                    html.Div("🤖 AI Dark Web Intel",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    dbc.Button("🎯 Threat Profile", id="dw-ai-profile",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("🛡️ Exposure Report", id="dw-ai-exposure",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="dw-ai-out",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "280px", "overflowY": "auto"}),
                ),
                _card(
                    html.Div("📋 Dark Web OSINT Commands",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[_cmd(c) for c in [
                        "torsocks curl http://<.onion>/",
                        "torify wget http://leaksite.onion/",
                        "curl https://psbdmp.ws/api/search/QUERY",
                        "curl https://api.proxynova.com/comb?query=DOMAIN",
                        "grep -r email@domain.com /datasets/",
                        "h8mail -t email@domain.com",
                    ]],
                ),
            ], width=3),

            # ── Centre ───────────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="dw-tabs", active_tab="dw-tab-ransomware",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="☠️ Ransomware Groups", tab_id="dw-tab-ransomware"),
                     dbc.Tab(label="📋 Paste Monitor",     tab_id="dw-tab-paste"),
                     dbc.Tab(label="🔓 Credential Leaks",  tab_id="dw-tab-breach"),
                 ]),
                html.Div(id="dw-phase-content"),
            ], width=6),

            # ── Right ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("⚠️ Exposure Indicators",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("⚡ ", style={"color": "#e67e22"}),
                        html.Span(ind, style={"color": "#b0b0b0",
                                              "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for ind in [
                          "Domain found in paste sites",
                          "Credentials in COMB dataset",
                          "Email in HaveIBeenPwned",
                          "Source code leaked to GitHub",
                          "Internal docs on paste sites",
                          "Employee credentials for sale",
                          "VPN credentials leaked",
                          "API keys exposed",
                          "Database dumps for sale",
                          "Ransomware group claimed attack",
                      ]],
                ),
                _card(
                    html.Div("🛡️ Response Checklist",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("□ ", style={"color": "#636e72"}),
                        html.Span(step, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for step in [
                          "Force password reset for affected accounts",
                          "Revoke leaked API keys immediately",
                          "Enable MFA for all accounts",
                          "Notify affected users",
                          "Submit GDPR breach notification (<72h)",
                          "Take down paste content",
                          "Monitor for further exposure",
                          "Contact ransomware negotiator",
                          "Engage IR team",
                          "Preserve evidence for forensics",
                      ]],
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


@callback(
    Output("dw-paste-results", "data"),
    Output("dw-search-status", "children"),
    Input("dw-paste-btn",      "n_clicks"),
    State("dw-target",         "value"),
    prevent_initial_call=True,
)
def search_paste(n, target):
    if not n or not target:
        raise PreventUpdate
    results = _fetch_paste_search(target.strip())
    status = f"✅ {len(results)} paste entries found for '{target}'" if results else \
             f"No results for '{target}' in paste sites"
    return results, status


@callback(
    Output("dw-breach-results", "data"),
    Output("dw-search-status",  "children",
           allow_duplicate=True),
    Input("dw-breach-btn",      "n_clicks"),
    State("dw-target",          "value"),
    prevent_initial_call=True,
)
def search_breach(n, target):
    if not n or not target:
        raise PreventUpdate
    results = _fetch_breach_domain(target.strip())
    status = f"🔓 {len(results)} credentials found for '{target}'" if results else \
             f"No credentials found for '{target}'"
    return results, status


@callback(
    Output("dw-phase-content", "children"),
    Input("dw-tabs",           "active_tab"),
    Input("dw-paste-results",  "data"),
    Input("dw-breach-results", "data"),
)
def render_phase(tab, paste_results, breach_results):
    paste_results  = paste_results  or []
    breach_results = breach_results or []

    if tab == "dw-tab-ransomware":
        rows = []
        for g in RANSOMWARE_GROUPS:
            status_color = "#c0392b" if g["status"] == "active" else "#636e72"
            rows.append(html.Div([
                html.Div([
                    html.Span(g["name"], style={"color": "#e74c3c",
                                                 "fontWeight": "700",
                                                 "fontSize": "13px",
                                                 "marginRight": "8px"}),
                    html.Span(f"● {g['status'].upper()}",
                              style={"color": status_color, "fontSize": "10px",
                                     "fontWeight": "700", "marginRight": "8px"}),
                    html.Span(f"Victims: {g['victims']}",
                              style={"color": "#8e9eb0", "fontSize": "10px",
                                     "marginRight": "8px"}),
                    html.Span(g["tactic"],
                              style={"color": "#9b59b6", "fontSize": "10px",
                                     "background": "#1a1d24",
                                     "padding": "1px 5px",
                                     "borderRadius": "3px"}),
                ]),
                html.Div(f"Primary targets: {g['targets']}",
                         style={"color": "#8e9eb0", "fontSize": "10px",
                                "paddingLeft": "4px", "marginTop": "2px"}),
            ], style={"padding": "10px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div("☠️ Active Ransomware Groups (2025)",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div("CLEARNET data only. For actual .onion sites, "
                     "use Tor Browser + Tails OS.",
                     style={"color": "#636e72", "fontSize": "11px",
                            "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "520px", "overflowY": "auto"}),
        )

    elif tab == "dw-tab-paste":
        if not paste_results:
            return _card(html.Div("Enter target and click 📋 Paste Search to start.",
                                   style={"color": "#636e72", "fontSize": "13px",
                                          "textAlign": "center", "padding": "30px"}))
        rows = []
        for r in paste_results:
            rows.append(html.Div([
                html.Span("📋 ", style={"color": "#3498db"}),
                html.A(r.get("id", ""), href=r.get("url", "#"), target="_blank",
                       style={"color": "#3498db", "fontSize": "12px",
                              "fontWeight": "700", "marginRight": "8px"}),
                html.Span(r.get("date", ""),
                          style={"color": "#636e72", "fontSize": "10px"}),
            ], style={"padding": "6px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div(f"📋 {len(paste_results)} Paste Site Results",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div(rows),
        )

    elif tab == "dw-tab-breach":
        if not breach_results:
            return _card(html.Div("Enter target and click 🔓 Breach Lookup to start.",
                                   style={"color": "#636e72", "fontSize": "13px",
                                          "textAlign": "center", "padding": "30px"}))
        rows = []
        for r in breach_results:
            email = r.get("email", "")
            parts = email.split("@")
            masked = parts[0][:2] + "***@" + parts[1] if len(parts) == 2 else email
            rows.append(html.Div([
                html.Span("🔓 ", style={"color": "#c0392b"}),
                html.Span(masked, style={"color": "#e74c3c",
                                          "fontFamily": "monospace",
                                          "fontSize": "12px",
                                          "marginRight": "8px"}),
                html.Span(f"Source: {r.get('source', '?')}",
                          style={"color": "#636e72", "fontSize": "10px"}),
            ], style={"padding": "6px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div(f"🔓 {len(breach_results)} Credential Entries Found",
                     style={"color": "#e74c3c", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div("⚠️ Passwords are masked. Force reset for all found accounts.",
                     style={"color": "#e67e22", "fontSize": "11px",
                            "marginBottom": "10px"}),
            html.Div(rows),
        )
    return html.Div()


@callback(
    Output("dw-ai-out",      "children"),
    Input("dw-ai-profile",   "n_clicks"),
    Input("dw-ai-exposure",  "n_clicks"),
    State("dw-target",       "value"),
    State("dw-paste-results","data"),
    State("dw-breach-results","data"),
    prevent_initial_call=True,
)
def ai_darkweb(profile_n, exp_n, target, paste, breach):
    if not ctx.triggered_id:
        raise PreventUpdate
    t = target or "the target organisation"
    tid = ctx.triggered_id
    n_paste  = len(paste or [])
    n_breach = len(breach or [])
    if tid == "dw-ai-profile":
        prompt = (
            f"Dark web threat profile for {t}:\n\n"
            f"Findings: {n_paste} paste entries, {n_breach} credential records\n\n"
            f"Provide:\n"
            f"1) **Threat Actor Interest** — which groups may target {t}?\n"
            f"2) **Likely Attack Vectors** based on their sector\n"
            f"3) **Ransomware Risk** — probability and which group?\n"
            f"4) **Data at Risk** — what sensitive data could be exposed?\n"
            f"5) **Immediate Actions** to reduce dark web exposure"
        )
    else:
        prompt = (
            f"Dark web exposure report for {t}:\n\n"
            f"Paste sites: {n_paste} mentions\n"
            f"Credential leaks: {n_breach} records\n\n"
            f"Write an executive exposure report:\n"
            f"1) **Exposure Summary** — severity and scope\n"
            f"2) **Risk to Employees** — targeted phishing/credential stuffing\n"
            f"3) **Risk to Systems** — credential reuse, lateral movement\n"
            f"4) **Regulatory Impact** — GDPR/breach notification obligations\n"
            f"5) **Remediation Plan** — 30/60/90 day response"
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"
