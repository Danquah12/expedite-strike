#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Specialised Operations Suite  (Standalone Application)
==============================================================
Runs the complete SPECIALISED section as an independent Dash app on port 9016.
Mirrors the full SPECIALISED nav-dropdown from the main Ægis SOC platform.

Included modules:
  ☁️ Cloud Assessment         ui_cloud_security   (AWS · Azure · GCP)
  🏭 IoT / OT Security        ui_iot_security     (ICS · SCADA · Embedded)
  📖 IR Playbooks              ui_ir_playbooks     (Incident response runbooks)
  📱 Mobile Security           ui_mobile_security  (Android · iOS)
  📂 DFIR Case Management      ui_dfir_case        (Evidence · Timeline)

Usage:
  python specialised_app.py              # port 9016
  python specialised_app.py --debug      # dev mode
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
    title="Ægis — Specialised Operations Suite",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#0d1117"},
        {"name": "description", "content": "Ægis Specialised Operations — Cloud · IoT/OT · IR Playbooks · Mobile · DFIR"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "specialised-suite-secret-2026")

# ── Import all Specialised UI modules AFTER app is created ────────────────────
from cyber_range.moduls import ui_cloud_security   # noqa: E402
from cyber_range.moduls import ui_iot_security     # noqa: E402
from cyber_range.moduls import ui_ir_playbooks     # noqa: E402
from cyber_range.moduls import ui_mobile_security  # noqa: E402
from cyber_range.moduls import ui_dfir_case        # noqa: E402

# ── Tab definitions ───────────────────────────────────────────────────────────
_TABS = [
    # ── Cloud & ICS ──────────────────────────────────────────────────
    ("spec-cloud",   "☁️  Cloud Assessment"),
    ("spec-iot",     "🏭 IoT / OT Security"),
    # ── Incident Response ─────────────────────────────────────────────
    ("spec-ir",      "📖 IR Playbooks"),
    # ── Mobile & DFIR ────────────────────────────────────────────────
    ("spec-mobile",  "📱 Mobile Security"),
    ("spec-dfir",    "📂 DFIR Case Mgmt"),
]

# ── Design tokens ─────────────────────────────────────────────────────────────
_DARK   = "#09080d"
_CARD   = "#0f0d18"
_GOLD   = "#ffaa00"   # Ægis Specialised amber/gold accent
_ORANGE = "#ff8800"

# ── Section labels for sidebar ────────────────────────────────────────────────
_SECTION_BEFORE = {
    "spec-cloud":   "CLOUD & ICS",
    "spec-ir":      "INCIDENT RESPONSE",
    "spec-mobile":  "MOBILE & DFIR",
}

# ── Header ────────────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("🏭", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": _GOLD, "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  SPECIALISED OPERATIONS SUITE", style={
            "color": "#4a3a10", "fontWeight": "700", "fontSize": "11px",
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
            "letterSpacing": "1px", "color": "#ffaa00",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#ffaa0010",
        "border": f"1px solid #ffaa0030",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": _GOLD, "marginRight": "6px",
                               "fontSize": "10px",
                               "animation": "spec-pulse 2s ease-in-out infinite"}),
        html.Span("STANDALONE  •  PORT 9016", style={
            "color": "#5a4a10", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#130e00",
        "border": f"1px solid {_GOLD}33",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #0a0800 0%, #100d02 60%, #0a0800 100%)",
    "borderBottom": f"2px solid {_GOLD}33",
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
                "color": "#3a2d05", "fontSize": "9px", "fontWeight": "900",
                "letterSpacing": "2px", "padding": "12px 14px 4px",
                "borderTop": "1px solid #221a05",
                "marginTop": "6px",
            }))

        is_active = tab_id == active_tab
        items.append(html.Button(
            label,
            id={"type": "spec-suite-nav-btn", "index": tab_id},
            n_clicks=0,
            style={
                "display": "block", "width": "100%", "textAlign": "left",
                "background": f"linear-gradient(90deg, {_GOLD}20, {_GOLD}08)" if is_active else "transparent",
                "border": f"1px solid {_GOLD}50" if is_active else "1px solid transparent",
                "borderRadius": "8px",
                "color": "#ffffff" if is_active else "#6a5a20",
                "fontSize": "12px",
                "fontWeight": "700" if is_active else "400",
                "padding": "10px 14px", "marginBottom": "3px",
                "cursor": "pointer", "transition": "all .2s ease",
                "letterSpacing": "0.3px",
            }
        ))

    return html.Div([
        html.Div("MODULES", style={
            "color": "#3a2d05", "fontSize": "9px", "fontWeight": "900",
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
                        "letterSpacing": "2px", "color": "#ffaa0099",
                        "lineHeight": "1",
                    }),
                    html.Div("Launch Pad ↗", style={
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "11px", "fontWeight": "700",
                        "color": "#ffaa00", "lineHeight": "1.2",
                    }),
                ]),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": f"#ffaa0012",
                "border": f"1px solid #ffaa0035",
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
        "background": "#070500",
        "borderRight": f"1px solid {_GOLD}18",
        "padding": "12px 8px",
        "overflowY": "auto",
        "minHeight": "100vh",
    })

# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _header,
    dcc.Store(id="spec-suite-active-tab", data="spec-cloud"),
    html.Div([
        html.Div(id="spec-suite-sidebar", children=_sidebar("spec-cloud")),
        html.Div(
            id="spec-suite-content",
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
    "          ::-webkit-scrollbar-thumb{background:#1a1005;border-radius:3px;}"
    "          @keyframes spec-pulse{0%,100%{opacity:1;}50%{opacity:0.3;}}"
    "          button:hover{background:rgba(255,170,0,0.07)!important;color:#ccc!important;}"
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
    Output("spec-suite-active-tab", "data"),
    Input({"type": "spec-suite-nav-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _update_active_tab(_):
    if not ctx.triggered_id:
        return no_update
    return ctx.triggered_id["index"]


@callback(
    Output("spec-suite-sidebar", "children"),
    Output("spec-suite-content", "children"),
    Input("spec-suite-active-tab", "data"),
)
def _render_content(active_tab):
    tab = active_tab or "spec-cloud"
    sidebar = _sidebar(tab)

    _MAP = {
        "spec-cloud":  lambda: ui_cloud_security.layout(),
        "spec-iot":    lambda: ui_iot_security.layout(),
        "spec-ir":     lambda: ui_ir_playbooks.layout(),
        "spec-mobile": lambda: ui_mobile_security.layout(),
        "spec-dfir":   lambda: ui_dfir_case.layout(),
    }

    if tab in _MAP:
        content = _MAP[tab]()
    else:
        content = html.Div(f"Unknown tab: {tab}",
                           style={"color": _GOLD, "padding": "40px"})

    return sidebar, html.Div(content, style={"padding": "0"})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis Specialised Operations Suite — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9016, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Specialised Operations Suite  (Standalone)          ║
╠══════════════════════════════════════════════════════════════════╣
║  URL   →  http://{args.host}:{args.port}/
║  Tabs  →  5 modules                                             ║
║           ☁️  Cloud · 🏭 IoT/OT · 📖 IR Playbooks              ║
║           📱 Mobile · 📂 DFIR Case                              ║
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
