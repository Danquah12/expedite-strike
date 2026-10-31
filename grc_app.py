#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — GRC Suite  (Standalone Application)
============================================
Runs the complete GRC section as an independent Dash app on port 9017.
Mirrors the full GRC nav-dropdown from the main Ægis SOC platform.

Included modules:
  📊 GRC Executive Dashboard   ui_grc_executive   → layout_grc_executive()
  ✅ Compliance & GRC           ui_compliance      → layout()
  🤖 AI Compliance Assistant   ui_compliance_assistant → layout_compliance_assistant()

Usage:
  python grc_app.py              # port 9017
  python grc_app.py --debug      # dev mode
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
    title="Ægis — GRC Suite",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#050d0a"},
        {"name": "description", "content": "Ægis GRC Suite — Governance · Risk · Compliance · AI-Assisted Analysis"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "grc-suite-secret-2026")

# ── Import GRC modules AFTER app is created ───────────────────────────────────
from cyber_range.moduls.ui_grc_executive import layout_grc_executive          # noqa: E402
from cyber_range.moduls.ui_compliance import layout as layout_compliance       # noqa: E402
from cyber_range.moduls.ui_compliance_assistant import (                       # noqa: E402
    layout_compliance_assistant,
)

# ── Tab definitions ───────────────────────────────────────────────────────────
_TABS = [
    # ── Governance & Risk ────────────────────────────────────────────
    ("grc-executive",     "📊 GRC Executive Dashboard"),
    ("grc-compliance",    "✅ Compliance & GRC"),
    # ── AI-Assisted ───────────────────────────────────────────────────
    ("grc-ai-assistant",  "🤖 AI Compliance Assistant"),
]

# ── Design tokens ─────────────────────────────────────────────────────────────
_DARK  = "#060c08"
_CARD  = "#0b1410"
_GREEN = "#00e676"   # GRC emerald-green accent
_TEAL  = "#00bfa5"

# ── Section labels for sidebar ────────────────────────────────────────────────
_SECTION_BEFORE = {
    "grc-executive":    "GOVERNANCE & RISK",
    "grc-ai-assistant": "AI-ASSISTED COMPLIANCE",
}

# ── Framework badges ─────────────────────────────────────────────────────────
_FRAMEWORKS = ["NIST", "ISO 27001", "SOC 2", "PCI-DSS", "HIPAA", "CMMC"]

# ── Header ────────────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("📋", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": _GREEN, "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  GOVERNANCE · RISK · COMPLIANCE", style={
            "color": "#0d3a1f", "fontWeight": "700", "fontSize": "11px",
            "letterSpacing": "3px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
        }),
    ]),
    html.Div(style={"flex": "1"}),
    # Framework badges in header
    html.Div([
        html.Span(fw, style={
            "background": f"{_GREEN}15",
            "border": f"1px solid {_GREEN}30",
            "color": _GREEN,
            "fontSize": "9px", "fontWeight": "700",
            "padding": "2px 7px", "borderRadius": "3px",
            "letterSpacing": "1px", "marginRight": "4px",
        }) for fw in _FRAMEWORKS
    ], style={"display": "flex", "alignItems": "center", "marginRight": "16px",
               "flexWrap": "wrap", "gap": "3px"}),
    
    html.A([
        html.Span("🚀", style={"fontSize": "13px", "marginRight": "6px"}),
        html.Span("Launch Pad", style={
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1px", "color": "#00e676",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#00e67610",
        "border": f"1px solid #00e67630",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": _GREEN, "marginRight": "6px",
                               "fontSize": "10px",
                               "animation": "grc-pulse 2s ease-in-out infinite"}),
        html.Span("STANDALONE  •  PORT 9017", style={
            "color": "#0d3a1f", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#020d05",
        "border": f"1px solid {_GREEN}33",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #020805 0%, #040e08 60%, #020805 100%)",
    "borderBottom": f"2px solid {_GREEN}33",
    "padding": "12px 24px",
    "display": "flex", "alignItems": "center", "gap": "14px",
    "position": "sticky", "top": "0", "zIndex": "999",
    "boxShadow": "0 4px 24px rgba(0,0,0,0.7)",
})

# ── Sidebar nav ───────────────────────────────────────────────────────────────
def _sidebar(active_tab: str) -> html.Div:
    items = []
    for tab_id, label in _TABS:
        if tab_id in _SECTION_BEFORE:
            items.append(html.Div(_SECTION_BEFORE[tab_id], style={
                "color": "#0d3520", "fontSize": "9px", "fontWeight": "900",
                "letterSpacing": "2px", "padding": "12px 14px 4px",
                "borderTop": "1px solid #0d2015",
                "marginTop": "6px",
            }))

        is_active = tab_id == active_tab
        items.append(html.Button(
            label,
            id={"type": "grc-suite-nav-btn", "index": tab_id},
            n_clicks=0,
            style={
                "display": "block", "width": "100%", "textAlign": "left",
                "background": f"linear-gradient(90deg, {_GREEN}1a, {_GREEN}08)" if is_active else "transparent",
                "border": f"1px solid {_GREEN}50" if is_active else "1px solid transparent",
                "borderRadius": "8px",
                "color": "#ffffff" if is_active else "#1a6a35",
                "fontSize": "12px",
                "fontWeight": "700" if is_active else "400",
                "padding": "10px 14px", "marginBottom": "3px",
                "cursor": "pointer", "transition": "all .2s ease",
                "letterSpacing": "0.3px",
            }
        ))

    # Frameworks block in sidebar footer
    fw_block = html.Div([
        html.Div("FRAMEWORKS", style={
            "color": "#0d3520", "fontSize": "9px", "fontWeight": "900",
            "letterSpacing": "2px", "marginBottom": "8px",
        }),
        *[html.Div(fw, style={
            "color": _GREEN, "fontSize": "10px", "fontWeight": "600",
            "padding": "3px 0", "borderBottom": "1px solid #0d2015",
        }) for fw in _FRAMEWORKS],
    ], style={
        "padding": "16px 14px 8px",
        "marginTop": "20px",
        "borderTop": f"1px solid {_GREEN}15",
    })

    return html.Div([
        html.Div("MODULES", style={
            "color": "#0d3520", "fontSize": "9px", "fontWeight": "900",
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
                        "letterSpacing": "2px", "color": "#00e67699",
                        "lineHeight": "1",
                    }),
                    html.Div("Launch Pad ↗", style={
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "11px", "fontWeight": "700",
                        "color": "#00e676", "lineHeight": "1.2",
                    }),
                ]),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": f"#00e67612",
                "border": f"1px solid #00e67635",
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
        fw_block,
    ], style={
        "width": "210px", "minWidth": "210px",
        "background": "#030805",
        "borderRight": f"1px solid {_GREEN}18",
        "padding": "12px 8px",
        "overflowY": "auto",
        "minHeight": "100vh",
    })

# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _header,
    dcc.Store(id="grc-suite-active-tab", data="grc-executive"),
    html.Div([
        html.Div(id="grc-suite-sidebar", children=_sidebar("grc-executive")),
        html.Div(
            id="grc-suite-content",
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
    "          ::-webkit-scrollbar-thumb{background:#0d2015;border-radius:3px;}"
    "          @keyframes grc-pulse{0%,100%{opacity:1;}50%{opacity:0.3;}}"
    "          button:hover{background:rgba(0,230,118,0.07)!important;color:#ccc!important;}"
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
    Output("grc-suite-active-tab", "data"),
    Input({"type": "grc-suite-nav-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _update_active_tab(_):
    if not ctx.triggered_id:
        return no_update
    return ctx.triggered_id["index"]


@callback(
    Output("grc-suite-sidebar",  "children"),
    Output("grc-suite-content",  "children"),
    Input("grc-suite-active-tab", "data"),
)
def _render_content(active_tab):
    tab = active_tab or "grc-executive"
    sidebar = _sidebar(tab)

    _MAP = {
        "grc-executive":    layout_grc_executive,
        "grc-compliance":   layout_compliance,
        "grc-ai-assistant": layout_compliance_assistant,
    }

    if tab in _MAP:
        content = _MAP[tab]()
    else:
        content = html.Div(f"Unknown tab: {tab}",
                           style={"color": _GREEN, "padding": "40px"})

    return sidebar, html.Div(content, style={"padding": "0"})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis GRC Suite — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9017, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  GRC Suite  (Standalone)                             ║
╠══════════════════════════════════════════════════════════════════╣
║  URL        →  http://{args.host}:{args.port}/
║  Modules    →  3  (Executive Dashboard · Compliance · AI)       ║
║  Frameworks →  NIST · ISO 27001 · SOC 2 · PCI-DSS · HIPAA      ║
║  Debug      →  {str(args.debug):<52} ║
╚══════════════════════════════════════════════════════════════════╝
""")

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        threaded=True,
    )
