#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Digital Forensics & Incident Response Suite  (Standalone)
=================================================================
Runs the complete DIGITAL FORENSICS section as an independent Dash app
on port 9018. Mirrors the DFIR nav-dropdown from the main Ægis SOC.

Included modules:
  🔬 Digital Forensics      ui_forensics   → layout()
  📂 DFIR Case Management   ui_dfir_case   → layout()

Usage:
  python dfir_app.py              # port 9018
  python dfir_app.py --debug      # dev mode
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

# ── Dash ──────────────────────────────────────────────────────────────────────
from dash import Dash, html, dcc, Input, Output, callback, no_update, ALL, ctx
import dash_bootstrap_components as dbc

# ── App FIRST ─────────────────────────────────────────────────────────────────
app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
    ],
    suppress_callback_exceptions=True,
    title="Ægis — Digital Forensics & IR",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#06060f"},
        {"name": "description", "content": "Ægis DFIR — Memory · Disk · Network Artifact Analysis · Case Management"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "dfir-suite-secret-2026")

# ── Import modules AFTER app ──────────────────────────────────────────────────
from cyber_range.moduls.ui_forensics  import layout as layout_forensics   # noqa: E402
from cyber_range.moduls.ui_dfir_case  import layout as layout_dfir_case   # noqa: E402

# ── Tab definitions ───────────────────────────────────────────────────────────
_TABS = [
    ("dfir-forensics", "🔬 Digital Forensics"),
    ("dfir-case",      "📂 DFIR Case Management"),
]

# ── Design tokens ─────────────────────────────────────────────────────────────
_DARK   = "#06060f"
_CARD   = "#0b0b18"
_VIOLET = "#9d4edd"   # Deep forensics violet/purple
_LAVNDR = "#c77dff"

# ── Header ────────────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("🔬", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": _VIOLET, "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  DIGITAL FORENSICS & INCIDENT RESPONSE", style={
            "color": "#3a1a5a", "fontWeight": "700", "fontSize": "11px",
            "letterSpacing": "3px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
        }),
    ]),
    html.Div(style={"flex": "1"}),
    # Evidence chain integrity badge
    html.Div([
        html.Span("⛓", style={"marginRight": "6px", "fontSize": "12px",
                                "color": _LAVNDR}),
        html.Span("EVIDENCE CHAIN INTEGRITY", style={
            "color": _LAVNDR, "fontSize": "9px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": f"{_VIOLET}12",
        "border": f"1px solid {_VIOLET}40",
        "borderRadius": "6px", "padding": "5px 14px",
        "marginRight": "12px",
    }),
    
    html.A([
        html.Span("🚀", style={"fontSize": "13px", "marginRight": "6px"}),
        html.Span("Launch Pad", style={
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1px", "color": "#9d4edd",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#9d4edd10",
        "border": f"1px solid #9d4edd30",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": _VIOLET, "marginRight": "6px",
                               "fontSize": "10px",
                               "animation": "dfir-pulse 2s ease-in-out infinite"}),
        html.Span("STANDALONE  •  PORT 9018", style={
            "color": "#3a1a5a", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#0a0512",
        "border": f"1px solid {_VIOLET}33",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #04030e 0%, #08051a 60%, #04030e 100%)",
    "borderBottom": f"2px solid {_VIOLET}33",
    "padding": "12px 24px",
    "display": "flex", "alignItems": "center", "gap": "14px",
    "position": "sticky", "top": "0", "zIndex": "999",
    "boxShadow": "0 4px 24px rgba(0,0,0,0.8)",
})

# ── Capability pills ──────────────────────────────────────────────────────────
_CAPABILITIES = [
    ("🧠", "Memory Analysis"),
    ("💾", "Disk Forensics"),
    ("🌐", "Network Artifacts"),
    ("🕐", "Timeline Analysis"),
    ("⛓",  "Evidence Chain"),
    ("📋", "Case Management"),
]

# ── Sidebar ───────────────────────────────────────────────────────────────────
def _sidebar(active_tab: str) -> html.Div:
    items = []
    for tab_id, label in _TABS:
        is_active = tab_id == active_tab
        items.append(html.Button(
            label,
            id={"type": "dfir-suite-nav-btn", "index": tab_id},
            n_clicks=0,
            style={
                "display": "block", "width": "100%", "textAlign": "left",
                "background": f"linear-gradient(90deg, {_VIOLET}22, {_VIOLET}08)" if is_active else "transparent",
                "border": f"1px solid {_VIOLET}55" if is_active else "1px solid transparent",
                "borderRadius": "8px",
                "color": "#ffffff" if is_active else "#5a3a7a",
                "fontSize": "12px",
                "fontWeight": "700" if is_active else "400",
                "padding": "10px 14px", "marginBottom": "3px",
                "cursor": "pointer", "transition": "all .2s ease",
            }
        ))

    # Capability pills block
    caps_block = html.Div([
        html.Div("CAPABILITIES", style={
            "color": "#3a1a5a", "fontSize": "9px", "fontWeight": "900",
            "letterSpacing": "2px", "marginBottom": "10px",
        }),
        *[html.Div([
            html.Span(icon, style={"marginRight": "8px", "fontSize": "13px"}),
            html.Span(label, style={"color": "#7a5a9a", "fontSize": "11px", "fontWeight": "600"}),
        ], style={
            "padding": "6px 4px",
            "borderBottom": f"1px solid {_VIOLET}15",
            "display": "flex", "alignItems": "center",
        }) for icon, label in _CAPABILITIES],
    ], style={
        "padding": "16px 10px 8px",
        "marginTop": "20px",
        "borderTop": f"1px solid {_VIOLET}15",
    })

    return html.Div([
        html.Div("MODULES", style={
            "color": "#3a1a5a", "fontSize": "9px", "fontWeight": "900",
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
                        "letterSpacing": "2px", "color": "#9d4edd99",
                        "lineHeight": "1",
                    }),
                    html.Div("Launch Pad ↗", style={
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "11px", "fontWeight": "700",
                        "color": "#9d4edd", "lineHeight": "1.2",
                    }),
                ]),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": f"#9d4edd12",
                "border": f"1px solid #9d4edd35",
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
        caps_block,
    ], style={
        "width": "210px", "minWidth": "210px",
        "background": "#040310",
        "borderRight": f"1px solid {_VIOLET}18",
        "padding": "12px 8px",
        "overflowY": "auto",
        "minHeight": "100vh",
    })

# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _header,
    dcc.Store(id="dfir-suite-active-tab", data="dfir-forensics"),
    html.Div([
        html.Div(id="dfir-suite-sidebar", children=_sidebar("dfir-forensics")),
        html.Div(
            id="dfir-suite-content",
            style={"flex": "1", "overflowY": "auto",
                   "background": _DARK, "padding": "0"},
        ),
    ], style={"display": "flex", "flexDirection": "row",
              "minHeight": "calc(100vh - 60px)"}),
], style={"background": _DARK, "minHeight": "100vh"})

# ── CSS ───────────────────────────────────────────────────────────────────────
app.index_string = (
    "<!DOCTYPE html><html>"
    "    <head>"
    "        {%metas%}<title>{%title%}</title>{%favicon%}{%css%}"
    "        <style>"
    f"          html,body{{margin:0;padding:0;background:{_DARK};"
    "             font-family:'Inter','Segoe UI',sans-serif;}}"
    "          ::-webkit-scrollbar{width:5px;}"
    f"          ::-webkit-scrollbar-track{{background:{_DARK};}}"
    "          ::-webkit-scrollbar-thumb{background:#1a0a2a;border-radius:3px;}"
    "          @keyframes dfir-pulse{0%,100%{opacity:1;}50%{opacity:0.3;}}"
    "          button:hover{background:rgba(157,78,221,0.08)!important;color:#ccc!important;}"
    "        </style>"
    "    </head>"
    "    <body>"
    "        {%app_entry%}"
    "        <footer>{%config%}{%scripts%}{%renderer%}</footer>"
    "    </body>"
    "</html>"
)

# ── Nav routing ───────────────────────────────────────────────────────────────
@callback(
    Output("dfir-suite-active-tab", "data"),
    Input({"type": "dfir-suite-nav-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _update_active_tab(_):
    if not ctx.triggered_id:
        return no_update
    return ctx.triggered_id["index"]


@callback(
    Output("dfir-suite-sidebar", "children"),
    Output("dfir-suite-content", "children"),
    Input("dfir-suite-active-tab", "data"),
)
def _render_content(active_tab):
    tab = active_tab or "dfir-forensics"
    sidebar = _sidebar(tab)

    _MAP = {
        "dfir-forensics": layout_forensics,
        "dfir-case":      layout_dfir_case,
    }

    if tab in _MAP:
        content = _MAP[tab]()
    else:
        content = html.Div(f"Unknown tab: {tab}",
                           style={"color": _VIOLET, "padding": "40px"})

    return sidebar, html.Div(content, style={"padding": "0"})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis DFIR Suite — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9018, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Digital Forensics & IR Suite  (Standalone)          ║
╠══════════════════════════════════════════════════════════════════╣
║  URL          →  http://{args.host}:{args.port}/
║  Modules      →  🔬 Digital Forensics  ·  📂 DFIR Case Mgmt    ║
║  Capabilities →  Memory · Disk · Network · Timeline             ║
║                  Evidence Chain · Case Management               ║
║  Debug        →  {str(args.debug):<50} ║
╚══════════════════════════════════════════════════════════════════╝
""")

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        threaded=True,
    )
