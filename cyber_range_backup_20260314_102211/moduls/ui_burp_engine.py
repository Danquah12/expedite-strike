"""
Burp Suite-Like Engine UI
=========================
6-tab interface: Target/Crawler, Scanner, Repeater, Intruder, Findings, Decoder.
Powered by AegisProbeEngine (aegis_probe.py).
"""
import base64
import json
import threading
import urllib.parse
import requests
import dash
from dash import html, dcc, callback, Input, Output, State, ctx, ALL
import dash_bootstrap_components as dbc

from cyber_range.services import findings_service as fs
from cyber_range.services.aegis_probe import AegisProbeEngine, get_plugin_names

requests.packages.urllib3.disable_warnings()

# ── style constants ────────────────────────────────────────────────────
_BG    = "#0d1117"
_CARD  = "#161b22"
_BORDER= "#30363d"
_CYAN  = "#00f0ff"
_ORANGE= "#ff9900"
_RED   = "#ff3333"
_GREEN = "#00ff66"
_GOLD  = "#ffd700"
_MUTED = "#8b949e"

_CARD_STYLE = {"background": _CARD, "border": f"1px solid {_BORDER}",
               "borderRadius": "8px", "marginBottom": "12px"}
_TERM_STYLE = {
    "whiteSpace": "pre-wrap", "background": "#050505", "color": _GREEN,
    "padding": "14px", "borderRadius": "4px", "height": "340px",
    "fontFamily": "'Fira Code', monospace", "fontSize": "12px",
    "border": f"1px solid {_BORDER}", "overflowY": "auto", "lineHeight": "1.4"
}
_INPUT = {"background": "#111", "color": "#e6e6e6",
          "border": f"1px solid {_BORDER}", "fontSize": "12px"}
_BTN_S = {"fontSize": "12px", "fontWeight": "700"}


# ── helpers ─────────────────────────────────────────────────────────
def _card(*children, title=None, style=None):
    header = []
    if title:
        header = [html.H6(title, style={"color": _GOLD, "marginBottom": "8px", "fontSize": "13px"})]
    s = {**_CARD_STYLE, **(style or {}), "padding": "14px"}
    return html.Div(header + list(children), style=s)


def _sev_badge(s):
    c = {"Critical": "danger", "High": "warning", "Medium": "info",
         "Low": "secondary", "Information": "light"}.get(s, "secondary")
    return dbc.Badge(s, color=c, className="me-1")


def _label(t):
    return html.Label(t, style={"color": _MUTED, "fontWeight": "700",
                                 "fontSize": "12px", "marginBottom": "4px"})


# ── Plugin panel ────────────────────────────────────────────────────
def _plugin_checklist():
    names = get_plugin_names()
    # names is now: {"passive": [{"label": display_name, "value": ClassName}, ...], "active": [...]}
    passive_opts = [{"label": f"🔵 {n['label']}", "value": n["value"]} for n in names["passive"]]
    active_opts  = [{"label": f"🔴 {n['label']}", "value": n["value"]} for n in names["active"]]
    return html.Div([
        html.P("Passive Plugins:", style={"color": _CYAN, "fontSize": "11px", "marginBottom": "4px"}),
        dbc.Checklist(id="burp-plugins-passive", options=passive_opts,
                      value=[o["value"] for o in passive_opts],
                      style={"color": "#ccc", "fontSize": "11px"}),
        html.Hr(style={"borderColor": _BORDER, "margin": "8px 0"}),
        html.P("Active Plugins:", style={"color": _RED, "fontSize": "11px", "marginBottom": "4px"}),
        dbc.Checklist(id="burp-plugins-active", options=active_opts,
                      value=[o["value"] for o in active_opts],
                      style={"color": "#ccc", "fontSize": "11px"}),
    ])


# ── Layout ───────────────────────────────────────────────────────────
def layout():
    return html.Div([
        # Stores
        dcc.Store(id="burp-findings-store", data=[]),
        dcc.Store(id="burp-crawl-store", data=[]),
        dcc.Interval(id="burp-interval", interval=1200, n_intervals=0, disabled=True),

        # Header
        html.Div([
            html.H3("🕷 AegisProbe",
                    style={"color": _GOLD, "fontWeight": "700", "marginBottom": "2px"}),
            html.P("Active web vulnerability scanner · 15 plugins · Repeater · Intruder · Decoder",
                   style={"color": _MUTED, "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        # Main tabs
        dbc.Tabs(id="burp-tabs", active_tab="burp-target", children=[
            dbc.Tab(label="🌐 Target",    tab_id="burp-target"),
            dbc.Tab(label="🔍 Scanner",   tab_id="burp-scanner"),
            dbc.Tab(label="🔄 Repeater",  tab_id="burp-repeater"),
            dbc.Tab(label="💥 Intruder",  tab_id="burp-intruder"),
            dbc.Tab(label="📋 Findings",  tab_id="burp-findings"),
            dbc.Tab(label="🔐 Decoder",   tab_id="burp-decoder"),
        ], style={"marginBottom": "12px"}),

        html.Div(id="burp-tab-content"),

    ], style={"padding": "20px", "background": _BG, "minHeight": "100vh"})


# ──────────────────────────────────────────────────────────────────────
# TAB RENDER CALLBACK
# ──────────────────────────────────────────────────────────────────────
@callback(Output("burp-tab-content", "children"),
          Input("burp-tabs", "active_tab"))
def render_burp_tab(tab):

    # ── TAB 1: TARGET / CRAWLER ──────────────────────────────────────
    if tab == "burp-target":
        return dbc.Row([
            dbc.Col([
                _card(
                    _label("Seed URL(s) — one per line"),
                    dbc.Textarea(
                        id="burp-target-url",
                        placeholder=(
                            "https://target.example.com\n"
                            "https://target.example.com/admin\n"
                            "https://target.example.com/api"
                        ),
                        style={**_INPUT, "height": "100px", "fontFamily": "monospace",
                               "fontSize": "11px", "marginBottom": "8px"},
                    ),
                    _label("Crawl Depth"),
                    dcc.Slider(id="burp-crawl-depth", min=1, max=6, step=1, value=3,
                               marks={i: str(i) for i in range(1, 7)},
                               tooltip={"placement": "bottom"}),
                    html.Div(style={"marginBottom": "10px"}),
                    dbc.Row([
                        dbc.Col([
                            _label("Max URLs"),
                            dbc.Input(id="burp-max-urls", type="number",
                                      min=10, max=1000, step=10, value=200,
                                      style={**_INPUT, "fontSize": "11px"}),
                        ], width=6),
                        dbc.Col([
                            _label("Fetch Workers"),
                            dbc.Input(id="burp-crawl-workers", type="number",
                                      min=1, max=50, step=1, value=10,
                                      style={**_INPUT, "fontSize": "11px"}),
                        ], width=6),
                    ], className="g-2 mb-3"),
                    dbc.Button("🕷 Start Crawl", id="burp-crawl-btn", color="info",
                               size="sm", className="w-100", style=_BTN_S),
                    title="Site Crawler",
                ),
                _card(
                    html.P("Scope Options", style={"color": _MUTED, "fontSize": "11px"}),
                    dbc.Checklist(
                        options=[
                            {"label": "Stay in-scope (same host)", "value": "inscope"},
                            {"label": "Follow redirects",           "value": "redirects"},
                            {"label": "Include subdomains",         "value": "subdomains"},
                        ],
                        value=["inscope", "redirects"],
                        id="burp-scope-opts",
                        style={"fontSize": "11px", "color": "#ccc"}
                    ),
                    title="Crawl Options",
                ),
            ], width=3),
            dbc.Col([
                _card(
                    dbc.Row([
                        dbc.Col(html.H6("Site Map", style={"color": _CYAN, "fontSize": "12px",
                                                            "margin": "0"})),
                        dbc.Col(html.Small(id="burp-crawl-status", style={"color": _MUTED,
                                                                            "fontSize": "10px",
                                                                            "textAlign": "right"}),
                                width="auto"),
                    ], className="mb-2 align-items-center"),
                    html.Div(
                        id="burp-sitemap",
                        children=html.P("Enter seed URLs (one per line) and click Start Crawl.",
                                        style={"color": "#444", "fontSize": "12px"}),
                        style={"maxHeight": "460px", "overflowY": "auto"},
                    ),
                    dcc.Store(id="burp-crawl-store"),
                    dcc.Interval(id="burp-crawl-interval", interval=1500,
                                 n_intervals=0, disabled=True),
                ),
            ], width=9),
        ])

    # ── TAB 2: SCANNER ───────────────────────────────────────────────
    elif tab == "burp-scanner":
        return dbc.Row([
            dbc.Col([
                _card(
                    _label("Target URL(s) — one per line"),
                    dbc.Textarea(id="burp-scan-targets", rows=5,
                                 placeholder="https://app.example.com\nhttps://api.example.com",
                                 style={**_INPUT, "fontFamily": "monospace",
                                        "marginBottom": "8px", "height": "110px"}),
                    _label("Scan Mode"),
                    dbc.Select(id="burp-scan-mode", options=[
                        {"label": "🔵 Passive Only", "value": "passive"},
                        {"label": "🔴 Active Only",  "value": "active"},
                        {"label": "⚡ Full (Passive + Active)", "value": "full"},
                    ], value="full", style={**_INPUT, "marginBottom": "8px"}),
                    _label("Intensity"),
                    dbc.Select(id="burp-intensity", options=[
                        {"label": "🟢 Low   (5 targets | 2 plugin threads)",  "value": "low"},
                        {"label": "🟡 Medium (10 targets | 5 plugin threads)", "value": "medium"},
                        {"label": "🔴 Aggressive (25 targets | 12 plugin threads)", "value": "aggressive"},
                    ], value="medium", style={**_INPUT, "marginBottom": "8px"}),
                    _label("Concurrent Targets"),
                    dbc.Input(
                        id="burp-target-concurrency", type="number",
                        min=1, max=50, step=1, value=10,
                        placeholder="Max simultaneous targets",
                        style={**_INPUT, "marginBottom": "8px"},
                    ),
                    dbc.Row([
                        dbc.Col(dbc.Button("▶ Run Scan", id="burp-run-btn", color="danger",
                                           size="sm", n_clicks=0, style=_BTN_S), width=4),
                        dbc.Col(dbc.Button("⛔ Cancel",  id="burp-cancel-btn", color="secondary",
                                           size="sm", n_clicks=0, style=_BTN_S), width=4),
                    ], className="g-2"),
                    title="Scan Config"
                ),
                _card(_plugin_checklist(), title="Plugin Selection"),
            ], width=3),
            dbc.Col([
                _card(
                    html.Div(id="burp-scan-log",
                             children="[AegisProbe] Engine ready. Configure scan and click Run Scan.\n",
                             style=_TERM_STYLE),
                    html.Div(id="burp-scan-progress", style={"marginTop": "8px"}),
                ),
            ], width=9),
        ])

    # ── TAB 3: REPEATER ──────────────────────────────────────────────
    elif tab == "burp-repeater":
        return dbc.Row([
            dbc.Col([
                _card(
                    _label("Method"),
                    dbc.Select(id="rep-method",
                               options=[{"label": m, "value": m} for m in
                                        ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]],
                               value="GET", style={**_INPUT, "marginBottom": "8px"}),
                    _label("URL"),
                    dbc.Input(id="rep-url", placeholder="https://target.example.com/api/v1/users",
                              style={**_INPUT, "marginBottom": "8px"}),
                    _label("Headers (one per line: Name: Value)"),
                    dbc.Textarea(id="rep-headers", rows=4,
                                 placeholder="Content-Type: application/json\nAuthorization: Bearer TOKEN",
                                 style={**_INPUT, "height": "90px", "marginBottom": "8px",
                                        "fontFamily": "monospace"}),
                    _label("Request Body"),
                    dbc.Textarea(id="rep-body", rows=4,
                                 placeholder='{"key": "value"}',
                                 style={**_INPUT, "height": "90px",
                                        "marginBottom": "8px", "fontFamily": "monospace"}),
                    dbc.Button("▶ Send Request", id="rep-send-btn", color="warning",
                               size="sm", className="w-100", n_clicks=0,
                               style={**_BTN_S, "color": "#000"}),
                    title="HTTP Repeater"
                ),
            ], width=4),
            dbc.Col([
                _card(
                    html.Div(id="rep-response",
                             children=html.P("Response will appear here after sending.",
                                             style={"color": "#444"}),
                             style={**_TERM_STYLE, "height": "490px"}),
                ),
            ], width=8),
        ])

    # ── TAB 4: INTRUDER ──────────────────────────────────────────────
    elif tab == "burp-intruder":
        return dbc.Row([
            dbc.Col([
                _card(
                    _label("Target URL (use §value§ to mark fuzz points)"),
                    dbc.Input(id="intruder-url",
                              placeholder="https://target.com/login?user=§admin§",
                              style={**_INPUT, "marginBottom": "8px"}),
                    _label("Attack Type"),
                    dbc.Select(id="intruder-type",
                               options=[
                                   {"label": "Sniper (single position)", "value": "sniper"},
                                   {"label": "Battering Ram (all positions same payload)", "value": "batram"},
                               ], value="sniper", style={**_INPUT, "marginBottom": "8px"}),
                    _label("Payload List"),
                    dbc.Select(id="intruder-wordlist",
                               options=[
                                   {"label": "XSS Payloads",          "value": "xss"},
                                   {"label": "SQLi Payloads",         "value": "sqli"},
                                   {"label": "Common Passwords",       "value": "passwords"},
                                   {"label": "Path Traversal",        "value": "lfi"},
                                   {"label": "Admin Paths",           "value": "paths"},
                                   {"label": "Template Injection",    "value": "ssti"},
                               ], value="xss", style={**_INPUT, "marginBottom": "8px"}),
                    _label("Custom Payloads (optional, one per line)"),
                    dbc.Textarea(id="intruder-custom", rows=4,
                                 placeholder="payload1\npayload2\n...",
                                 style={**_INPUT, "height": "80px",
                                        "marginBottom": "8px", "fontFamily": "monospace"}),
                    dbc.Button("💥 Start Attack", id="intruder-run-btn", color="danger",
                               size="sm", className="w-100", n_clicks=0, style=_BTN_S),
                    html.Div(id="intruder-status", style={"marginTop": "8px"}),
                    title="Intruder"
                ),
            ], width=4),
            dbc.Col([
                _card(
                    html.H6("Attack Results", style={"color": _CYAN, "fontSize": "12px",
                                                      "marginBottom": "8px"}),
                    html.Div(id="intruder-results",
                             children=html.P("Results appear here after starting the attack.",
                                             style={"color": "#444"}),
                             style={"maxHeight": "460px", "overflowY": "auto"}),
                ),
            ], width=8),
        ])

    # ── TAB 5: FINDINGS ──────────────────────────────────────────────
    elif tab == "burp-findings":
        # Load saved findings from DB
        saved = fs.get_findings(module="AegisProbe", limit=100)
        return html.Div([
            dbc.Row([
                dbc.Col([
                    dbc.Select(id="burp-filter-sev", options=[
                        {"label": "All Severities", "value": "all"},
                        {"label": "Critical", "value": "Critical"},
                        {"label": "High",     "value": "High"},
                        {"label": "Medium",   "value": "Medium"},
                        {"label": "Low",      "value": "Low"},
                        {"label": "Information","value": "Information"},
                    ], value="all",
                    style={**_INPUT, "width": "180px", "display": "inline-block"}),
                ], width="auto"),
                dbc.Col([
                    dbc.Button("🔄 Refresh", id="burp-refresh-findings",
                               color="secondary", size="sm", style=_BTN_S),
                ], width="auto"),
                dbc.Col([
                    dbc.Button("📤 Export JSON", id="burp-export-btn",
                               color="info", size="sm", style=_BTN_S),
                    dcc.Download(id="burp-download"),
                ], width="auto"),
                dbc.Col([
                    dbc.Button("📄 Export PTES Report", id="burp-ptes-btn",
                               color="warning", size="sm",
                               style={**_BTN_S, "color": "#000", "fontWeight": "800"}),
                    dcc.Download(id="burp-ptes-download"),
                ], width="auto"),
            ], className="mb-3 g-2", align="center"),

            html.Div(id="burp-ptes-status", style={"marginBottom": "6px"}),
            html.Div(id="burp-findings-display",
                     children=_render_findings_table(saved)),
        ])


    # ── TAB 6: DECODER ───────────────────────────────────────────────
    elif tab == "burp-decoder":
        return dbc.Row([
            dbc.Col([
                _card(
                    _label("Input"),
                    dbc.Textarea(id="decoder-input", rows=6,
                                 style={**_INPUT, "height": "130px",
                                        "fontFamily": "monospace", "marginBottom": "8px"}),
                    _label("Operation"),
                    dbc.Select(id="decoder-op", options=[
                        {"label": "URL Encode",       "value": "url_encode"},
                        {"label": "URL Decode",       "value": "url_decode"},
                        {"label": "Base64 Encode",    "value": "b64_encode"},
                        {"label": "Base64 Decode",    "value": "b64_decode"},
                        {"label": "HTML Encode",      "value": "html_encode"},
                        {"label": "HTML Decode",      "value": "html_decode"},
                        {"label": "Hex Encode",       "value": "hex_encode"},
                        {"label": "Hex Decode",       "value": "hex_decode"},
                        {"label": "MD5 Hash",         "value": "md5"},
                        {"label": "SHA256 Hash",      "value": "sha256"},
                        {"label": "JWT Decode",       "value": "jwt_decode"},
                    ], value="url_encode",
                    style={**_INPUT, "marginBottom": "8px"}),
                    dbc.Button("▶ Apply", id="decoder-run-btn", color="info",
                               size="sm", className="w-100", style=_BTN_S),
                    title="Encoder / Decoder"
                ),
            ], width=4),
            dbc.Col([
                _card(
                    _label("Output"),
                    html.Pre(id="decoder-output",
                             style={**_TERM_STYLE, "height": "280px", "color": _CYAN}),
                    title="Result"
                ),
            ], width=8),
        ])

    return html.Div("Select a tab.")

# ─── Scan summary table ───────────────────────────────────────────────
def _render_scan_summary(findings):
    if not findings:
        return html.Div()

    sev_order = ["Critical", "High", "Medium", "Low", "Information"]
    sev_colors = {
        "Critical":    (_RED,    "danger"),
        "High":        (_ORANGE, "warning"),
        "Medium":      (_CYAN,   "info"),
        "Low":         ("#aaa",  "secondary"),
        "Information": ("#555",  "light"),
    }
    counts = {s: 0 for s in sev_order}
    for f in findings:
        s = f.get("severity", "Information")
        if s in counts:
            counts[s] += 1

    total = len(findings)

    # Severity bar
    bar_segments = []
    for sev in sev_order:
        if counts[sev]:
            pct = counts[sev] / total * 100
            bar_segments.append(html.Div(
                f"{counts[sev]}",
                style={
                    "flex": str(pct), "background": sev_colors[sev][0],
                    "color": "#000" if sev in ("Medium", "Low", "Information") else "#fff",
                    "textAlign": "center", "fontSize": "11px", "fontWeight": "700",
                    "padding": "3px 0", "minWidth": "28px",
                }
            ))

    severity_bar = html.Div([
        html.Div("Risk Distribution",
                 style={"color": _MUTED, "fontSize": "11px", "marginBottom": "4px"}),
        html.Div(bar_segments,
                 style={"display": "flex", "borderRadius": "4px", "overflow": "hidden",
                        "height": "24px", "marginBottom": "10px"}),
    ])

    # KPI pills
    pills = dbc.Row([
        dbc.Col(html.Div([
            html.Div(str(counts[sev]), style={"fontSize": "22px", "fontWeight": "900",
                                              "color": sev_colors[sev][0]}),
            html.Div(sev, style={"fontSize": "10px", "color": _MUTED}),
        ], style={"textAlign": "center", "padding": "8px",
                   "border": f"1px solid {sev_colors[sev][0]}20",
                   "borderRadius": "6px", "background": _CARD}),
        width="auto") for sev in sev_order
    ], className="g-2 mb-3")

    # Findings table — grouped by plugin
    plugin_groups = {}
    for f in findings:
        pl = f.get("plugin", "Unknown")
        plugin_groups.setdefault(pl, []).append(f)

    rows = []
    for plugin_name, pfindings in sorted(plugin_groups.items(),
                                          key=lambda x: -len(x[1])):
        for f in pfindings:
            sev = f.get("severity", "")
            _, badge_color = sev_colors.get(sev, ("#aaa", "secondary"))
            rows.append(html.Tr([
                html.Td(_sev_badge(sev)),
                html.Td(html.Small(plugin_name, style={"color": _MUTED})),
                html.Td(f.get("name", ""),
                        style={"color": "#e6e6e6", "fontSize": "12px", "fontWeight": "600"}),
                html.Td(dbc.Badge(f.get("cwe", "") or "", color="secondary",
                                  style={"fontSize": "10px"})),
                html.Td(html.Code(
                    str(f.get("url", f.get("param", "")) or "")[:55],
                    style={"fontSize": "10px", "color": _CYAN}
                )),
                html.Td(
                    str(f.get("evidence", "") or "")[:80],
                    style={"fontSize": "10px", "color": "#666"}
                ),
            ], style={"borderLeft": f"3px solid {sev_colors.get(sev, ('',''))[0]}"})
            )

    table = dbc.Table(
        [html.Thead(html.Tr([
            html.Th("Severity", style={"width": "90px"}),
            html.Th("Plugin"),
            html.Th("Finding"),
            html.Th("CWE"),
            html.Th("URL / Param"),
            html.Th("Evidence"),
        ], style={"fontSize": "11px", "color": _GOLD, "background": "#111"})),
         html.Tbody(rows)],
        bordered=False, hover=True, size="sm",
        style={"fontSize": "11px", "marginBottom": "0"}
    )

    return html.Div([
        html.Hr(style={"borderColor": _BORDER, "margin": "14px 0"}),
        html.H6(f"📊 Scan Summary — {total} Finding{'s' if total != 1 else ''}",
                style={"color": _GOLD, "fontWeight": "700", "marginBottom": "10px"}),
        pills,
        severity_bar,
        html.Div(table, style={"maxHeight": "400px", "overflowY": "auto",
                                "border": f"1px solid {_BORDER}",
                                "borderRadius": "6px"}),
    ], style={"marginTop": "8px"})



def _render_findings_table(findings):
    if not findings:
        return html.P("No findings yet. Run a scan to populate.",
                      style={"color": "#444", "fontSize": "12px", "padding": "20px"})
    rows = []
    for f in findings:
        rows.append(html.Tr([
            html.Td(_sev_badge(f.get("severity", "")), style={"minWidth": "80px"}),
            html.Td(f.get("plugin", f.get("module", "")),
                    style={"color": _MUTED, "fontSize": "11px"}),
            html.Td(f.get("name", f.get("title", "")),
                    style={"color": "#e6e6e6", "fontSize": "11px"}),
            html.Td(dbc.Badge(f.get("cwe","") or f.get("mitre_id",""), color="secondary",
                              style={"fontSize": "10px"})),
            html.Td([
                html.Code(str(f.get("url", f.get("host","")) or "")[:50],
                          style={"fontSize": "10px", "color": _CYAN}),
            ]),
            html.Td(str(f.get("param", ""))[:20], style={"color": "#888", "fontSize": "10px"}),
            html.Td(str(f.get("evidence", f.get("description","")) or "")[:60],
                    style={"color": "#666", "fontSize": "10px"}),
        ]))
    return dbc.Table(
        [html.Thead(html.Tr([
            html.Th("Severity"), html.Th("Plugin"), html.Th("Finding"),
            html.Th("CWE"), html.Th("URL"), html.Th("Param"), html.Th("Evidence"),
        ], style={"fontSize": "11px", "color": _GOLD})),
         html.Tbody(rows)],
        bordered=True, hover=True, size="sm", style={"fontSize": "11px"}
    )


# ──────────────────────────────────────────────────────────────────────
# CALLBACKS
# ──────────────────────────────────────────────────────────────────────

# ── Scan Start / Interval ─────────────────────────────────────────────
_scan_log_buffer = []
_scan_running = False
_scan_findings_live = []
_scan_summary_cache = None   # set to rendered summary when scan completes


@callback(
    Output("burp-scan-log",      "children"),
    Output("burp-interval",      "disabled"),
    Output("burp-findings-store","data"),
    Output("burp-scan-progress", "children"),
    Input("burp-run-btn",        "n_clicks"),
    Input("burp-cancel-btn",     "n_clicks"),
    Input("burp-interval",       "n_intervals"),
    State("burp-scan-targets",   "value"),
    State("burp-scan-mode",      "value"),
    State("burp-intensity",          "value"),
    State("burp-target-concurrency", "value"),
    State("burp-plugins-passive",    "value"),
    State("burp-plugins-active",     "value"),
    State("burp-scan-log",       "children"),
    prevent_initial_call=True,
)
def handle_scan(run_n, cancel_n, _tick,
                targets, scan_mode, intensity, target_concurrency,
                passive_sel, active_sel,
                current_log):
    global _scan_log_buffer, _scan_running, _scan_findings_live, _engine, _scan_summary_cache
    triggered = ctx.triggered_id

    if triggered == "burp-cancel-btn":
        if _scan_running:
            try: _engine.cancel_scan()
            except Exception: pass
        _scan_running = False
        return current_log + "\n[AegisProbe] ⛔ Scan cancelled by user.\n", True, _scan_findings_live, dash.no_update

    if triggered == "burp-interval":
        log_chunk = "".join(_scan_log_buffer)
        _scan_log_buffer.clear()
        new_log = (current_log or "") + log_chunk
        if len(new_log) > 12000:
            new_log = new_log[-12000:]
        interval_disabled = not _scan_running
        # If scan just finished and we have a summary ready, show it
        summary = dash.no_update
        if interval_disabled and _scan_summary_cache is not None:
            summary = _scan_summary_cache
            _scan_summary_cache = None
        return new_log, interval_disabled, _scan_findings_live, summary

    # Run button
    if triggered == "burp-run-btn":
        if not targets or not targets.strip():
            return current_log + "\n[!] No targets specified.\n", True, _scan_findings_live, dash.no_update

        _scan_log_buffer.clear()
        _scan_findings_live = []
        _scan_summary_cache = None
        _scan_running = True

        raw_targets = [t.strip() for t in targets.strip().splitlines() if t.strip()]
        selected = list(set((passive_sel or []) + (active_sel or []))) or None

        def on_output(msg):
            _scan_log_buffer.append(msg)

        def on_complete(cancelled, meta_path):
            global _scan_running, _scan_findings_live, _scan_summary_cache
            _scan_running = False
            status = "⛔ Cancelled" if cancelled else "✅ Complete"
            _scan_log_buffer.append(f"\n[AegisProbe] Scan {status}\n")
            # Read full findings from the JSON report
            if meta_path and not cancelled:
                try:
                    report_path = meta_path.replace(".meta.json", ".json")
                    with open(report_path) as fp:
                        data = json.load(fp)
                    _scan_findings_live = data.get("findings", [])
                except Exception:
                    pass
            # Build summary table (runs in the scan thread, cached for next interval tick)
            _scan_summary_cache = _render_scan_summary(_scan_findings_live)
            # Auto-save to DB
            for f in _scan_findings_live:
                try:
                    fs.save_finding(
                        "AegisProbe",
                        f.get("name", "Unknown"),
                        f.get("severity", "Medium"),
                        f.get("url", ""),
                        f.get("evidence", ""),
                        f.get("cwe", ""),
                    )
                except Exception:
                    pass

        try:
            _engine = AegisProbeEngine(
                scan_mode=scan_mode or "full",
                intensity=intensity or "medium",
                selected_plugins=selected,
            )
            _engine.start_scan(raw_targets, on_output, on_complete,
                               target_concurrency=int(target_concurrency or 10))
        except Exception as e:
            _scan_running = False
            return current_log + f"\n[!] Engine error: {e}\n", True, _scan_findings_live, dash.no_update

        return (
            f"[AegisProbe] Scan started — {len(raw_targets)} target(s) | "
            f"mode={scan_mode} intensity={intensity}\n",
            False,
            _scan_findings_live,
            html.Div(),  # clear previous summary
        )

    raise dash.exceptions.PreventUpdate


# ── Repeater ───────────────────────────────────────────────────────────
@callback(
    Output("rep-response", "children"),
    Input("rep-send-btn", "n_clicks"),
    State("rep-method",  "value"),
    State("rep-url",     "value"),
    State("rep-headers", "value"),
    State("rep-body",    "value"),
    prevent_initial_call=True,
)
def send_repeater_request(n, method, url, headers_raw, body):
    if not n or not url:
        raise dash.exceptions.PreventUpdate
    import time as _time
    headers = {}
    if headers_raw:
        for line in headers_raw.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
    try:
        t0 = _time.time()
        r = requests.request(method, url, headers=headers,
                             data=body.encode() if body else None,
                             timeout=15, verify=False, allow_redirects=False)
        elapsed = _time.time() - t0
        resp_headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_preview = r.text[:4000]
        output = (
            f"HTTP/1.1 {r.status_code} {r.reason}  [{elapsed*1000:.0f}ms | {len(r.content)} bytes]\n"
            f"{'─'*60}\n"
            f"{resp_headers}\n\n"
            f"{'─'*60}\n"
            f"{body_preview}\n"
        )
        color = _GREEN if r.status_code < 300 else (_ORANGE if r.status_code < 400 else _RED)
        return html.Pre(output, style={**_TERM_STYLE, "height": "490px", "color": color})
    except Exception as e:
        return html.Pre(f"[Error] {e}", style={**_TERM_STYLE, "color": _RED})


# ── Intruder Attack ────────────────────────────────────────────────────
WORDLISTS = {
    "xss":       ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
                  "<svg/onload=alert(1)>", "javascript:alert(1)", "'-alert(1)-'"],
    "sqli":      ["'", "' OR 1=1--", "\" OR 1=1--", "' UNION SELECT NULL--",
                  "1; DROP TABLE users--", "' AND SLEEP(3)--"],
    "passwords": ["admin", "password", "123456", "letmein", "qwerty",
                  "Password1!", "admin123", "root", "toor", "changeme"],
    "lfi":       ["../etc/passwd", "../../etc/passwd", "/etc/passwd",
                  "....//....//etc/passwd", "php://filter/read=convert.base64-encode/resource=index"],
    "paths":     ["/admin", "/administrator", "/dashboard", "/api/v1/users",
                  "/actuator", "/phpinfo.php", "/.env", "/.git/config"],
    "ssti":      ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>",
                  "{{config}}", "{% debug %}", "${T(java.lang.Runtime)}"],
}


@callback(
    Output("intruder-results", "children"),
    Output("intruder-status",  "children"),
    Input("intruder-run-btn",  "n_clicks"),
    State("intruder-url",      "value"),
    State("intruder-type",     "value"),
    State("intruder-wordlist", "value"),
    State("intruder-custom",   "value"),
    prevent_initial_call=True,
)
def run_intruder(n, url, attack_type, wl_key, custom):
    if not n or not url:
        raise dash.exceptions.PreventUpdate
    import re as _re, time as _t
    payloads = WORDLISTS.get(wl_key, [])
    if custom:
        payloads = [p.strip() for p in custom.strip().splitlines() if p.strip()] + payloads
    # Replace §marker§ with each payload
    baseline_url = _re.sub(r"§[^§]*§", "BASELINE", url)
    try:
        base_r = requests.get(baseline_url, timeout=8, verify=False, allow_redirects=False)
        baseline_status = base_r.status_code
        baseline_len = len(base_r.text)
    except Exception:
        baseline_status, baseline_len = 200, 0
    rows = []
    for i, payload in enumerate(payloads[:30]):
        try:
            fuzz_url = _re.sub(r"§[^§]*§", urllib.parse.quote(payload, safe=""), url)
            t0 = _t.time()
            r = requests.get(fuzz_url, timeout=8, verify=False, allow_redirects=False)
            elapsed = int((_t.time() - t0) * 1000)
            delta = abs(len(r.text) - baseline_len)
            anomaly = (r.status_code != baseline_status or delta > 150
                       or any(kw in r.text.lower() for kw in ["error","exception","warning","uid=","root:"]))
            badge = dbc.Badge("⚠ Anomaly", color="danger") if anomaly else dbc.Badge("OK", color="secondary")
            rows.append(html.Tr([
                html.Td(str(i+1), style={"color": _MUTED, "fontSize": "10px"}),
                html.Td(html.Code(str(payload)[:40], style={"fontSize": "10px", "color": _CYAN})),
                html.Td(str(r.status_code), style={"color": (_RED if r.status_code >= 400 else _GREEN), "fontSize": "11px"}),
                html.Td(str(len(r.text)), style={"fontSize": "10px"}),
                html.Td(f"+{delta}", style={"color": (_ORANGE if delta > 150 else _MUTED), "fontSize": "10px"}),
                html.Td(f"{elapsed}ms", style={"fontSize": "10px"}),
                html.Td(badge),
            ]))
        except Exception as ex:
            rows.append(html.Tr([
                html.Td(str(i+1)), html.Td(str(payload)[:40]),
                html.Td("ERR", colSpan=5, style={"color": _RED, "fontSize": "10px"}),
            ]))
    table = dbc.Table(
        [html.Thead(html.Tr([
            html.Th("#"), html.Th("Payload"), html.Th("Status"), html.Th("Length"),
            html.Th("Δ Len"), html.Th("Time"), html.Th("Result"),
        ], style={"fontSize": "11px", "color": _GOLD})),
         html.Tbody(rows)],
        bordered=True, hover=True, size="sm"
    )
    status = dbc.Alert(f"Attack complete — {len(payloads[:30])} payloads fired.", color="info",
                       style={"fontSize": "12px", "marginTop": "6px"})
    return table, status


# ── Findings Refresh & Export ─────────────────────────────────────────
@callback(
    Output("burp-findings-display", "children"),
    Input("burp-refresh-findings",  "n_clicks"),
    State("burp-filter-sev",        "value"),
    prevent_initial_call=True,
)
def refresh_findings(n, sev_filter):
    sev = sev_filter if sev_filter != "all" else None
    findings = fs.get_findings(module="AegisProbe", severity=sev, limit=200)
    return _render_findings_table(findings)


@callback(
    Output("burp-download", "data"),
    Input("burp-export-btn", "n_clicks"),
    prevent_initial_call=True,
)
def export_findings(n):
    findings = fs.get_findings(module="AegisProbe", limit=500)
    return dict(
        content=json.dumps(findings, indent=2, default=str),
        filename="aegisprobe_findings.json",
    )


# ── PTES Report Export ─────────────────────────────────────────────────
@callback(
    Output("burp-ptes-download", "data"),
    Output("burp-ptes-status",   "children"),
    Input("burp-ptes-btn",       "n_clicks"),
    prevent_initial_call=True,
)
def export_ptes_report(n):
    from cyber_range.services.report_generator import generate_report, get_latest_report_json
    if not n:
        raise dash.exceptions.PreventUpdate
    report_path = get_latest_report_json()
    if not report_path:
        return dash.no_update, dbc.Alert(
            "⚠ No scan report found. Run a scan first, then export.",
            color="warning", style={"fontSize": "12px", "padding": "6px 12px"}
        )
    try:
        out_path, html_content = generate_report(report_path)
        import os as _os
        fname = _os.path.basename(out_path)
        status = dbc.Alert(
            [html.Span("✅ PTES report generated: "), html.Code(fname)],
            color="success", style={"fontSize": "12px", "padding": "6px 12px"}
        )
        return dict(content=html_content, filename=fname, type="text/html"), status
    except Exception as e:
        return dash.no_update, dbc.Alert(
            f"❌ Report generation failed: {e}",
            color="danger", style={"fontSize": "12px", "padding": "6px 12px"}
        )


# ── Decoder ───────────────────────────────────────────────────────────
@callback(
    Output("decoder-output", "children"),
    Input("decoder-run-btn", "n_clicks"),
    State("decoder-input",   "value"),
    State("decoder-op",      "value"),
    prevent_initial_call=True,
)
def run_decoder(n, text, op):
    if not n: raise dash.exceptions.PreventUpdate
    text = text or ""
    import hashlib as _h, html as _html
    try:
        result = {
            "url_encode": urllib.parse.quote(text),
            "url_decode": urllib.parse.unquote(text),
            "b64_encode": base64.b64encode(text.encode()).decode(),
            "b64_decode": base64.b64decode(text.encode() + b"==").decode("utf-8", errors="replace"),
            "html_encode": _html.escape(text),
            "html_decode": _html.unescape(text),
            "hex_encode": text.encode().hex(),
            "hex_decode": bytes.fromhex(text.replace(" ","")).decode("utf-8","replace"),
            "md5":    _h.md5(text.encode()).hexdigest(),
            "sha256": _h.sha256(text.encode()).hexdigest(),
            "jwt_decode": _decode_jwt(text),
        }.get(op, "Unknown operation")
        return result
    except Exception as e:
        return f"[Error] {e}"


def _decode_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return "Not a valid JWT (need 3 dot-separated parts)"
        def _dec(s): return base64.b64decode(s + "==").decode("utf-8", errors="replace")
        hdr  = json.loads(_dec(parts[0]))
        body = json.loads(_dec(parts[1]))
        return f"HEADER:\n{json.dumps(hdr,indent=2)}\n\nPAYLOAD:\n{json.dumps(body,indent=2)}\n\nSIGNATURE: {parts[2][:30]}..."
    except Exception as e:
        return f"JWT decode error: {e}"


# ── Crawl State ─────────────────────────────────────────────────────────
_crawl_log   = []
_crawl_done  = False
_crawl_urls  = []


# ── Start Crawl ──────────────────────────────────────────────────────────
@callback(
    Output("burp-sitemap",        "children",  allow_duplicate=True),
    Output("burp-crawl-status",   "children",  allow_duplicate=True),
    Output("burp-crawl-interval", "disabled",  allow_duplicate=True),
    Input("burp-crawl-btn",       "n_clicks"),
    State("burp-target-url",      "value"),
    State("burp-crawl-depth",     "value"),
    State("burp-max-urls",        "value"),
    State("burp-crawl-workers",   "value"),
    prevent_initial_call=True,
)
def run_crawl(n, seeds_text, depth, max_urls, workers):
    global _crawl_log, _crawl_done, _crawl_urls
    if not n or not seeds_text:
        raise dash.exceptions.PreventUpdate

    # Parse seed URLs
    seeds = [s.strip() for s in seeds_text.strip().splitlines() if s.strip()]
    if not seeds:
        raise dash.exceptions.PreventUpdate
    for i, s in enumerate(seeds):
        if not s.startswith(("http://", "https://")):
            seeds[i] = f"https://{s}"

    primary      = seeds[0]
    extra_seeds  = seeds[1:]

    _crawl_log  = []
    _crawl_done = False
    _crawl_urls = []

    def on_output(msg): _crawl_log.append(msg)

    def do_crawl():
        global _crawl_done, _crawl_urls
        from cyber_range.services.aegis_probe import CrawlerPlugin
        crawler = CrawlerPlugin()
        crawler.extra_seeds   = extra_seeds
        crawler.crawl_workers = int(workers  or 10)
        crawler.max_depth     = int(depth    or 3)
        crawler.max_urls      = int(max_urls or 200)
        findings = crawler.scan(primary, on_output)
        _crawl_urls = sorted({
            f.get("url", "") for f in findings
            if f.get("url", "").startswith("http")
        })
        _crawl_done = True

    threading.Thread(target=do_crawl, daemon=True).start()

    status = html.Small(f"🕷 Crawling {len(seeds)} seed(s)…",
                        style={"color": _CYAN})
    loading = html.Div([
        html.Div("⏳ Crawl running — site map will populate when complete.",
                 style={"color": "#555", "fontSize": "12px"}),
    ])
    return loading, status, False   # enable interval


# ── Crawl Interval — poll until done ─────────────────────────────────────
@callback(
    Output("burp-sitemap",        "children"),
    Output("burp-crawl-status",   "children"),
    Output("burp-crawl-interval", "disabled"),
    Input("burp-crawl-interval",  "n_intervals"),
    prevent_initial_call=True,
)
def poll_crawl(n):
    global _crawl_done, _crawl_urls
    if not _crawl_done:
        return dash.no_update, dash.no_update, False   # keep polling

    urls   = _crawl_urls
    items  = [
        dbc.ListGroupItem(
            dbc.Row([
                dbc.Col(html.A(u, href=u, target="_blank",
                               style={"color": _CYAN, "fontSize": "11px",
                                      "textDecoration": "none"})),
                dbc.Col(html.Small(urllib.parse.urlparse(u).netloc,
                                   style={"color": _MUTED, "fontSize": "10px"}),
                        width="auto"),
            ], align="center"),
            style={"background": "#111", "border": f"1px solid {_BORDER}",
                   "padding": "4px 10px", "marginBottom": "2px"}
        )
        for u in urls
    ]
    status = html.Small(f"✅ {len(urls)} endpoints — crawl complete",
                        style={"color": _GREEN})
    if not items:
        sitemap = html.P("No URLs discovered. Check connectivity or relax scope options.",
                         style={"color": "#555", "fontSize": "12px"})
    else:
        sitemap = html.Div([
            dbc.ListGroup(items),
        ])
    return sitemap, status, True   # disable interval
