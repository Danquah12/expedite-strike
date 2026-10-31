#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Red Team Suite  (Standalone Application)
=================================================
Runs the complete RED TEAM section + Assessment Manager as an independent
Dash app on port 9014.

Included modules:
  📋 Assessment Manager            ui_assessment  (scanner + pipeline)
  🔍 Recon / Unified Scan         ui_unified_scan
  💥 Exploitation Engine           ui_pentest  (exploitation tab)
  🎭 Post Exploitation             ui_pentest  (post-exploitation tab)
  🤖 Automated Pen Testing         ui_pentest  (automated PT tab)
  🔑 Privilege Escalation          ui_privesc
  🔀 Kill Chain / Lateral Movement ui_killchain
  🏰 AD RedOps / BloodHound        ui_bloodhound
  🏗️ Red Team Infrastructure      ui_red_team_ops
  🛡️ Ægis AD Analytic Scanner      ui_pingcastle
  🔑 IAM / MFA Bypass              ui_iam_redteam
  🧠 LLM Red Teaming               ui_llm_redteam

Usage:
  python red_team_suite_app.py              # production (port 9014)
  python red_team_suite_app.py --debug      # dev mode
"""

import sys
import os
from pathlib import Path

# ── Sys path ─────────────────────────────────────────────────────────────────
_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))
_EXTRA = "/home/kali/.local/lib/python3.13/site-packages"
if _EXTRA not in sys.path:
    sys.path.insert(0, _EXTRA)

# ── Env ───────────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(os.path.join(str(_APP_DIR), ".env"), override=True)
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ[_k] = ""

# ── Dash core ─────────────────────────────────────────────────────────────────
from dash import Dash, html, dcc, Input, Output, callback, no_update
import dash_bootstrap_components as dbc

# ── Create app FIRST ──────────────────────────────────────────────────────────
app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
    ],
    suppress_callback_exceptions=True,
    title="Ægis — Red Team Suite",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#0d1117"},
        {"name": "description", "content": "Ægis Red Team Suite — Full Red Team toolchain standalone"},
        {"name": "apple-mobile-web-app-capable", "content": "yes"},
        {"name": "apple-mobile-web-app-status-bar-style", "content": "black-translucent"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "rt-suite-secret-2026-!@#")

# ── Flask route: serve Ægis AD Analytic Scanner HTML report (rebranded) ──────
import glob as _glob
from flask import Response as _Response

_PC_REPORT_DIR = "/home/kali/Downloads/PingCastle_3.5.0.44"

# Branding replacements applied to the raw HTML before serving
_PC_REBRAND = [
    ("PingCastle — Active Directory Security Report",
     "Ægis AD Analytic Scanner — Active Directory Security Report"),
    ("PingCastle - AD Security Report",
     "Ægis AD Analytic Scanner — AD Security Report"),
    ("PingCastle 3.5.0.44",          "Ægis AD Analytic Scanner"),
    ("PingCastle 3.5",               "Ægis AD Analytic Scanner 3.5"),
    ("PingCastle Telemetry",         "Ægis AD Scanner Telemetry"),
    ("PingCastle evidence",          "Ægis AD Scanner evidence"),
    ("PingCastle findings",          "Ægis AD Scanner findings"),
    ("PingCastle with ",             "Ægis AD Scanner with "),
    # Title tag
    ("PingCastle - ",                "Ægis AD Analytic Scanner — "),
]

# CSS injected into <head> to rebrand the red PingCastle header bar
_XSTRIKE_CSS = """
<style>
/* ── Ægis AD Analytic Scanner rebrand overlay ── */
.header { background: linear-gradient(90deg,#060e0e,#0a1a1a) !important;
          border-bottom: 2px solid #00c2ff !important; }
.header h1 { color: #00e5b0 !important;
             font-family: 'JetBrains Mono',monospace !important; }
.header h1::before { content: "🛡️  Ægis AD Analytic Scanner — "; font-size:14px; }
.header .meta  { color: #3a7a8a !important; }
/* Hide native PingCastle version badge */
.header .meta::before { content: ""; }
</style>
"""

@server.route("/pingcastle-report")
def serve_pingcastle_report():
    """Read, rebrand and serve the latest Ægis AD Scanner HTML report."""
    reports = sorted(
        _glob.glob(f"{_PC_REPORT_DIR}/ad_hc_*.html"),
        key=lambda p: __import__('os').path.getmtime(p),
        reverse=True,
    )
    if not reports:
        return _Response(
            "<html><body style='background:#0d0e14;color:#00c2ff;"
            "font-family:JetBrains Mono,monospace;padding:40px'>"
            "<h2>🛡️ No Ægis AD Analytic Scanner report found yet</h2>"
            "<p>Run a scan first — the HTML report will appear here automatically.</p>"
            f"<p style='color:#3a5a70'>Expected location: {_PC_REPORT_DIR}/ad_hc_*.html</p>"
            "</body></html>",
            mimetype="text/html",
        )

    # Read and rebrand
    html = open(reports[0], encoding="utf-8", errors="replace").read()
    for old, new in _PC_REBRAND:
        html = html.replace(old, new)
    # Inject Ægis CSS after <head>
    html = html.replace("<head>", "<head>" + _XSTRIKE_CSS, 1)

    return _Response(html, mimetype="text/html")

# ── Import all Red Team UI modules AFTER app is created ──────────────────────
from cyber_range.moduls import ui_red_team_ops       # noqa: E402
from cyber_range.moduls import ui_iam_redteam        # noqa: E402
from cyber_range.moduls import ui_llm_redteam        # noqa: E402
from cyber_range.moduls import ui_privesc            # noqa: E402
from cyber_range.moduls import ui_bloodhound         # noqa: E402

from cyber_range.moduls.ui_pentest import (          # noqa: E402
    layout_automated_pt,
    layout_exploitation,
    layout_post_exploitation,
)
from cyber_range.moduls.ui_pingcastle import layout_pingcastle_live  # noqa: E402

# register_callbacks ones need the app object passed in
from cyber_range.moduls.ui_killchain import (        # noqa: E402
    killchain_tab,
    register_callbacks as _kc_register,
)
from cyber_range.moduls.ui_unified_scan import (     # noqa: E402
    unified_scan_layout,
    register_callbacks as _uscan_register,
)

_kc_register(app)
_uscan_register(app)

# ── Assessment Manager imports ────────────────────────────────────────────────
from cyber_range.moduls.ui_assessment import assessment_layout   # noqa: E402

# ── Assessment scanner callbacks (self-contained module) ─────────────────────
from cyber_range.services import assessment_callbacks            # noqa: E402
assessment_callbacks.register(app)

# ── Reporting module ──────────────────────────────────────────────────────────
from cyber_range.moduls import ui_rt_reporting                   # noqa: E402
ui_rt_reporting.register_callbacks(app)

# ── Tab definitions ───────────────────────────────────────────────────────────
_TABS = [
    # ── Assessment Manager (top, so scan → pipeline flows naturally) ──
    ("rt-suite-assessment",    "📋 Assessment Manager"),
    # ── Red Team modules ─────────────────────────────────────────────
    ("rt-suite-automated-pt",  "🤖 Automated PT"),
    ("rt-suite-exploitation",  "💥 Exploitation"),
    ("rt-suite-post-ex",       "🎭 Post Exploitation"),
    ("rt-suite-unified-scan",  "🔍 Recon / Scan"),
    ("rt-suite-killchain",     "🔀 Kill Chain"),
    ("rt-suite-privesc",       "🔑 Privilege Escalation"),
    ("rt-suite-bloodhound",    "🏰 AD / BloodHound"),
    ("rt-suite-redteam-infra", "🏗️ RT Infrastructure"),
    ("rt-suite-pingcastle",    "🛡️ Ægis AD Intelligence"),
    ("rt-suite-iam",           "🔑 IAM / MFA Bypass"),
    ("rt-suite-llm",           "🧠 LLM Red Team"),
    # ── Reporting ────────────────────────────────────────────────────
    ("rt-suite-reporting",     "📊 Reporting"),
]

_DARK = "#0d0d0d"
_CARD = "#111317"
_RED  = "#ff3355"

# ── Header ────────────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("🔴", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": _RED, "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  RED TEAM SUITE", style={
            "color": "#546e8a", "fontWeight": "700", "fontSize": "11px",
            "letterSpacing": "3px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
        }),
    ]),
    html.Div(style={"flex": "1"}),
    
    html.A([
        html.Span("🚀", style={"fontSize": "13px", "marginRight": "6px"}),
        html.Span("Launch Pad", style={
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1px", "color": "#f97316",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#f9731610",
        "border": f"1px solid #f9731630",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": _RED, "marginRight": "6px",
                               "fontSize": "10px",
                               "animation": "rt-pulse 2s ease-in-out infinite"}),
        html.Span("STANDALONE  •  PORT 9014", style={
            "color": "#546e8a", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#1a0a0d", "border": f"1px solid {_RED}33",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #0d0808 0%, #140a0a 60%, #0d0808 100%)",
    "borderBottom": f"2px solid {_RED}33",
    "padding": "12px 24px",
    "display": "flex", "alignItems": "center", "gap": "14px",
    "position": "sticky", "top": "0", "zIndex": "999",
    "boxShadow": "0 4px 24px rgba(0,0,0,0.7)",
})

# ── Sidebar nav ───────────────────────────────────────────────────────────────
def _nav_btn(tab_id, label, active_tab):
    is_active = tab_id == active_tab
    return html.Button(
        label,
        id={"type": "rt-suite-nav-btn", "index": tab_id},
        n_clicks=0,
        style={
            "display": "block", "width": "100%", "textAlign": "left",
            "background": f"linear-gradient(90deg, {_RED}22, {_RED}11)" if is_active else "transparent",
            "border": f"1px solid {_RED}55" if is_active else "1px solid transparent",
            "borderRadius": "8px",
            "color": "#ffffff" if is_active else "#8e9eb0",
            "fontSize": "12px", "fontWeight": "700" if is_active else "400",
            "padding": "10px 14px", "marginBottom": "4px",
            "cursor": "pointer", "transition": "all .2s ease",
            "letterSpacing": "0.3px",
        }
    )

def _sidebar(active_tab):
    return html.Div([
        html.Div("MODULES", style={
            "color": "#3a4a5a", "fontSize": "9px", "fontWeight": "900",
            "letterSpacing": "2px", "padding": "8px 14px 4px",
        }),
        *[_nav_btn(tid, lbl, active_tab) for tid, lbl in _TABS],
    ], style={
        "width": "210px", "minWidth": "210px",
        "background": "#0a0808",
        "borderRight": f"1px solid {_RED}22",
        "padding": "12px 8px",
        "overflowY": "auto",
        "minHeight": "100vh",
    })

# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _header,
    dcc.Store(id="rt-suite-active-tab", data="rt-suite-assessment"),
    html.Div([
        # Sidebar
        html.Div(id="rt-suite-sidebar",
                 children=_sidebar("rt-suite-assessment")),
        # Content pane
        html.Div(
            id="rt-suite-content",
            style={"flex": "1", "overflowY": "auto",
                   "background": _DARK, "padding": "0"},
        ),
    ], style={"display": "flex", "flexDirection": "row",
              "minHeight": "calc(100vh - 60px)"}),
], style={"background": _DARK, "minHeight": "100vh"})

# ── CSS via index_string ───────────────────────────────────────────────────────
app.index_string = (
    "<!DOCTYPE html><html>"
    "    <head>"
    "        {%metas%}<title>{%title%}</title>{%favicon%}{%css%}"
    "        <style>"
    f"          html,body{{margin:0;padding:0;background:{_DARK};font-family:'Inter','Segoe UI',sans-serif;}}"
    "          ::-webkit-scrollbar{width:5px;}"
    f"          ::-webkit-scrollbar-track{{background:{_DARK};}}"
    "          ::-webkit-scrollbar-thumb{background:#1e2230;border-radius:3px;}"
    f"          @keyframes rt-pulse{{0%,100%{{opacity:1;}}50%{{opacity:0.4;}}}}"
    "          .rt-nav-btn:hover{background:rgba(255,51,85,0.08)!important;color:#ccc!important;}"
    "        </style>"
    "    </head>"
    "    <body>"
    "        {%app_entry%}"
    "        <footer>{%config%}{%scripts%}{%renderer%}</footer>"
    "    </body>"
    "</html>"
)


# ── Nav routing callback ───────────────────────────────────────────────────────
from dash import ALL, ctx as _ctx

@callback(
    Output("rt-suite-active-tab", "data"),
    Input({"type": "rt-suite-nav-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _update_active_tab(n_clicks_list):
    if not _ctx.triggered_id:
        return no_update
    return _ctx.triggered_id["index"]


@callback(
    Output("rt-suite-sidebar", "children"),
    Output("rt-suite-content", "children"),
    Input("rt-suite-active-tab", "data"),
)
def _render_content(active_tab):
    sidebar = _sidebar(active_tab or "rt-suite-assessment")

    tab = active_tab or "rt-suite-assessment"

    if tab == "rt-suite-assessment":
        content = assessment_layout
    elif tab == "rt-suite-automated-pt":
        content = layout_automated_pt()
    elif tab == "rt-suite-exploitation":
        content = layout_exploitation()
    elif tab == "rt-suite-post-ex":
        content = layout_post_exploitation()
    elif tab == "rt-suite-unified-scan":
        content = unified_scan_layout()
    elif tab == "rt-suite-killchain":
        content = killchain_tab()
    elif tab == "rt-suite-privesc":
        content = ui_privesc.layout()
    elif tab == "rt-suite-bloodhound":
        content = ui_bloodhound.layout_bh_dashboard()
    elif tab == "rt-suite-redteam-infra":
        content = ui_red_team_ops.layout()
    elif tab == "rt-suite-pingcastle":
        content = layout_pingcastle_live()
    elif tab == "rt-suite-iam":
        content = ui_iam_redteam.layout()
    elif tab == "rt-suite-llm":
        content = ui_llm_redteam.layout()
    elif tab == "rt-suite-reporting":
        content = ui_rt_reporting.layout()
    else:
        content = html.Div(f"Unknown tab: {tab}",
                           style={"color": "#ff3355", "padding": "40px"})

    return sidebar, html.Div(content, style={"padding": "0"})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis Red Team Suite — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0", help="Bind host")
    parser.add_argument("--port",  default=9014, type=int, help="Port (default: 9014)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Red Team Suite  (Standalone)                        ║
╠══════════════════════════════════════════════════════════════════╣
║  URL   →  http://{args.host}:{args.port}/                       ║
║  Tabs  →  13 modules (Assessment + 11 Red Team + Reporting)     ║
║  Debug →  {str(args.debug):<54} ║
╚══════════════════════════════════════════════════════════════════╝
""")

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        threaded=True,
    )
