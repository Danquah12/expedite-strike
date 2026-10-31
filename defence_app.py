#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Cyber Defence Suite  (Standalone Application)
======================================================
Runs the complete DEFENCE section as an independent Dash app on port 9015.
Mirrors the full DEFENCE nav-dropdown from the main Ægis SOC platform.

Included modules:
  🔬 SAST Scanner              ui_sast
  ⚙️ API Assessment            ui_api_assessment
  🐳 Container & K8s           ui_container_security
  🔗 Supply Chain Security     ui_supply_chain
  🎣 Phishing & Email Security ui_phishing
  🏹 Threat Hunting            ui_threat_hunting
  🔐 OAuth / OIDC Security     ui_oauth_security
  🛡️ AI Model Hardening        ui_ai_hardening
  🔎 EDR Gap Analysis          ui_edr_gaps

Usage:
  python defence_app.py              # port 9015
  python defence_app.py --debug      # dev mode
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
from dash import Dash, html, dcc, Input, Output, callback, no_update, ALL, ctx
import dash_bootstrap_components as dbc

# ── Create app FIRST ──────────────────────────────────────────────────────────
app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
    ],
    suppress_callback_exceptions=True,
    title="Ægis — Cyber Defence Suite",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#0d1117"},
        {"name": "description", "content": "Ægis Cyber Defence Suite — Standalone defensive security toolchain"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "defence-suite-secret-2026")

# ── Import all Defence UI modules AFTER app is created ───────────────────────
from cyber_range.moduls import ui_sast               # noqa: E402
from cyber_range.moduls.ui_sast import layout_sast_dashboard as _sast_layout  # noqa: E402
from cyber_range.moduls import ui_api_assessment     # noqa: E402
from cyber_range.moduls import ui_container_security # noqa: E402
from cyber_range.moduls import ui_supply_chain       # noqa: E402
from cyber_range.moduls import ui_phishing           # noqa: E402
from cyber_range.moduls import ui_threat_hunting     # noqa: E402
from cyber_range.moduls import ui_oauth_security     # noqa: E402
from cyber_range.moduls import ui_ai_hardening       # noqa: E402
from cyber_range.moduls import ui_edr_gaps           # noqa: E402

# ── Tab definitions ───────────────────────────────────────────────────────────
_TABS = [
    # ── Code & API Security ──────────────────────────────────────────
    ("def-sast",          "🔬 SAST Scanner"),
    ("def-api",           "⚙️ API Assessment"),
    ("def-container",     "🐳 Container & K8s"),
    ("def-supply-chain",  "🔗 Supply Chain"),
    # ── Threat Defence & Hardening ───────────────────────────────────
    ("def-phishing",      "🎣 Phishing & Email"),
    ("def-threat-hunt",   "🏹 Threat Hunting"),
    ("def-oauth",         "🔐 OAuth / OIDC"),
    ("def-ai-hardening",  "🛡️ AI Hardening"),
    ("def-edr-gaps",      "🔎 EDR Gap Analysis"),
]

# ── Design tokens ─────────────────────────────────────────────────────────────
_DARK  = "#0a0d10"
_CARD  = "#0f1419"
_BLUE  = "#00c2ff"   # Ægis shield-blue accent
_CYAN  = "#00f0ff"

# ── Section labels for sidebar ────────────────────────────────────────────────
_SECTION_BEFORE = {
    "def-sast":         "CODE & API SECURITY",
    "def-phishing":     "THREAT DEFENCE",
}

# ── Header ────────────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("🛡️", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": _BLUE, "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  CYBER DEFENCE SUITE", style={
            "color": "#3a5a70", "fontWeight": "700", "fontSize": "11px",
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
            "letterSpacing": "1px", "color": "#00c2ff",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#00c2ff10",
        "border": f"1px solid #00c2ff30",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": _BLUE, "marginRight": "6px",
                               "fontSize": "10px",
                               "animation": "def-pulse 2s ease-in-out infinite"}),
        html.Span("STANDALONE  •  PORT 9015", style={
            "color": "#3a5a70", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#08131a",
        "border": f"1px solid {_BLUE}33",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #050b10 0%, #080f17 60%, #050b10 100%)",
    "borderBottom": f"2px solid {_BLUE}33",
    "padding": "12px 24px",
    "display": "flex", "alignItems": "center", "gap": "14px",
    "position": "sticky", "top": "0", "zIndex": "999",
    "boxShadow": "0 4px 24px rgba(0,0,0,0.7)",
})

# ── Sidebar nav ───────────────────────────────────────────────────────────────
def _sidebar(active_tab: str) -> html.Div:
    items = []
    for tab_id, label in _TABS:
        # Insert section divider label if needed
        if tab_id in _SECTION_BEFORE:
            items.append(html.Div(_SECTION_BEFORE[tab_id], style={
                "color": "#253545", "fontSize": "9px", "fontWeight": "900",
                "letterSpacing": "2px", "padding": "12px 14px 4px",
                "borderTop": "1px solid #1a2530",
                "marginTop": "6px",
            }))

        is_active = tab_id == active_tab
        items.append(html.Button(
            label,
            id={"type": "def-suite-nav-btn", "index": tab_id},
            n_clicks=0,
            style={
                "display": "block", "width": "100%", "textAlign": "left",
                "background": f"linear-gradient(90deg, {_BLUE}22, {_BLUE}08)" if is_active else "transparent",
                "border": f"1px solid {_BLUE}55" if is_active else "1px solid transparent",
                "borderRadius": "8px",
                "color": "#ffffff" if is_active else "#6a8a9e",
                "fontSize": "12px",
                "fontWeight": "700" if is_active else "400",
                "padding": "10px 14px", "marginBottom": "3px",
                "cursor": "pointer", "transition": "all .2s ease",
                "letterSpacing": "0.3px",
            }
        ))

    return html.Div([
        html.Div("MODULES", style={
            "color": "#253545", "fontSize": "9px", "fontWeight": "900",
            "letterSpacing": "2px", "padding": "8px 14px 4px",
        }),
        *items,

        # ── Launch Pad footer ─────────────────────────────
        html.Div(style={
            "flex": "1",
        }),
        html.A([
            html.Div([
                html.Span("🚀", style={"fontSize": "14px", "marginRight": "8px"}),
                html.Div([
                    html.Div("MISSION CONTROL", style={
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "8px", "fontWeight": "900",
                        "letterSpacing": "2px", "color": "#00c2ff99",
                        "lineHeight": "1",
                    }),
                    html.Div("Launch Pad ↗", style={
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "11px", "fontWeight": "700",
                        "color": "#00c2ff", "lineHeight": "1.2",
                    }),
                ]),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": f"#00c2ff12",
                "border": f"1px solid #00c2ff35",
                "borderRadius": "8px",
                "padding": "10px 12px",
                "cursor": "pointer",
                "transition": "all .2s ease",
            }),
        ],
        href="http://localhost:9000/",
        target="_blank",
        style={"textDecoration": "none", "display": "block", "margin": "8px 6px 4px"},
        id="launchpad-footer-link",
        ),
    ], style={
        "width": "210px", "minWidth": "210px",
        "background": "#07090c",
        "borderRight": f"1px solid {_BLUE}18",
        "padding": "12px 8px",
        "overflowY": "auto",
        "minHeight": "100vh",
    })

# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _header,
    dcc.Store(id="def-suite-active-tab", data="def-sast"),
    html.Div([
        html.Div(id="def-suite-sidebar", children=_sidebar("def-sast")),
        html.Div(
            id="def-suite-content",
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
    f"          html,body{{margin:0;padding:0;background:{_DARK};"
    "             font-family:'Inter','Segoe UI',sans-serif;}}"
    "          ::-webkit-scrollbar{width:5px;}"
    f"          ::-webkit-scrollbar-track{{background:{_DARK};}}"
    "          ::-webkit-scrollbar-thumb{background:#1a2535;border-radius:3px;}"
    f"          @keyframes def-pulse{{0%,100%{{opacity:1;}}50%{{opacity:0.3;}}}}"
    "          button:hover{background:rgba(0,194,255,0.07)!important;color:#ccc!important;}"
    "        </style>"
    "    </head>"
    "    <body>"
    "        {%app_entry%}"
    "        <footer>{%config%}{%scripts%}{%renderer%}</footer>"
    "    </body>"
    "</html>"
)

# ── Nav routing callback ───────────────────────────────────────────────────────
@callback(
    Output("def-suite-active-tab", "data"),
    Input({"type": "def-suite-nav-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _update_active_tab(_):
    if not ctx.triggered_id:
        return no_update
    return ctx.triggered_id["index"]


@callback(
    Output("def-suite-sidebar",  "children"),
    Output("def-suite-content",  "children"),
    Input("def-suite-active-tab", "data"),
)
def _render_content(active_tab):
    tab = active_tab or "def-sast"
    sidebar = _sidebar(tab)

    _MAP = {
        "def-sast":          lambda: _sast_layout(),
        "def-api":           lambda: ui_api_assessment.layout(),
        "def-container":     lambda: ui_container_security.layout(),
        "def-supply-chain":  lambda: ui_supply_chain.layout(),
        "def-phishing":      lambda: ui_phishing.layout(),
        "def-threat-hunt":   lambda: ui_threat_hunting.layout(),
        "def-oauth":         lambda: ui_oauth_security.layout(),
        "def-ai-hardening":  lambda: ui_ai_hardening.layout(),
        "def-edr-gaps":      lambda: ui_edr_gaps.layout(),
    }

    if tab in _MAP:
        content = _MAP[tab]()
    else:
        content = html.Div(f"Unknown tab: {tab}",
                           style={"color": "#00c2ff", "padding": "40px"})

    return sidebar, html.Div(content, style={"padding": "0"})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis Cyber Defence Suite — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9015, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Cyber Defence Suite  (Standalone)                   ║
╠══════════════════════════════════════════════════════════════════╣
║  URL   →  http://{args.host}:{args.port}/
║  Tabs  →  9 modules (SAST · API · Container · Supply Chain      ║
║           Phishing · Threat Hunt · OAuth · AI Harden · EDR)     ║
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
