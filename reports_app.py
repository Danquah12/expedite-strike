#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Reports Suite  (Standalone Application)
================================================
Runs the complete REPORTS section as an independent Dash app on port 9020.
Mirrors the full REPORTS nav-dropdown from the main Ægis SOC platform.

All 14 report types from ui_reporting:
  INCIDENT REPORTS
  ─────────────────
  1️⃣  Executive Summary       reporting_executive_summary()
  2️⃣  Attack Timeline         reporting_attack_timeline()
  3️⃣  Impacted Assets         reporting_impacted_assets()
  4️⃣  User & Identity Impact  reporting_identity_impact()
  5️⃣  Exploitation Analysis   reporting_vulnerability_exploitation()
  6️⃣  Malware & Tooling       reporting_malware_tooling()
  7️⃣  Detection Performance   reporting_detection_performance()

  REPORTING SUITE
  ───────────────
  8️⃣  Data Exfiltration       reporting_data_exposure()
  9️⃣  Lateral Movement        reporting_lateral_movement()
  🔟  Control Failures         reporting_control_failures()
  📋  Remediation & Recovery   reporting_remediation_recovery()
  📜  Compliance Reporting     reporting_compliance_regulatory()
  🕸️  Neo4j Graph Report       reporting_neo4j_intelligence()
  📁  Document Analysis        reporting_shared_drive_analysis()

Usage:
  python reports_app.py              # port 9020
  python reports_app.py --debug      # dev mode
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
    title="Ægis — Reports Suite",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#07060a"},
        {"name": "description", "content": "Ægis Reports Suite — Incident · Timeline · Compliance · Neo4j Intelligence"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "reports-suite-secret-2026")

# ── Import reporting module AFTER app ─────────────────────────────────────────
from cyber_range.moduls.ui_reporting import (                                  # noqa: E402
    reporting_executive_summary,
    reporting_attack_timeline,
    reporting_impacted_assets,
    reporting_identity_impact,
    reporting_vulnerability_exploitation,
    reporting_malware_tooling,
    reporting_detection_performance,
    reporting_data_exposure,
    reporting_lateral_movement,
    reporting_control_failures,
    reporting_remediation_recovery,
    reporting_compliance_regulatory,
    reporting_neo4j_intelligence,
    reporting_shared_drive_analysis,
)
from cyber_range.moduls.ui_fleet_reports import (                              # noqa: E402
    fleet_report_overview,
    fleet_report_external,
    fleet_report_redteam,
    fleet_report_defence,
    fleet_report_specialised,
    fleet_report_grc,
    fleet_report_dfir,
    fleet_report_platform,
)

# ── Tab definitions ───────────────────────────────────────────────────────────
_TABS = [
    # ── Incident Reports ───────────────────────────────────
    ("rep-exec",        "1️⃣  Executive Summary"),
    ("rep-timeline",    "2️⃣  Attack Timeline"),
    ("rep-assets",      "3️⃣  Impacted Assets"),
    ("rep-identity",    "4️⃣  User & Identity"),
    ("rep-exploit",     "5️⃣  Exploitation Analysis"),
    ("rep-malware",     "6️⃣  Malware & Tooling"),
    ("rep-detection",   "7️⃣  Detection Performance"),
    # ── Reporting Suite ──────────────────────────────────
    ("rep-exfil",       "8️⃣  Data Exfiltration"),
    ("rep-lateral",     "9️⃣  Lateral Movement"),
    ("rep-controls",    "🔟 Control Failures"),
    ("rep-remediation", "📋 Remediation & Recovery"),
    ("rep-compliance",  "📜 Compliance Reporting"),
    ("rep-neo4j",       "🕸️  Neo4j Graph Report"),
    ("rep-docs",        "📁 Document Analysis"),
    # ── Fleet Reports ─────────────────────────────────────
    ("rep-fleet-overview",    "🚀 Fleet Overview"),
    ("rep-fleet-external",    "🔭 External Assessment"),
    ("rep-fleet-redteam",     "🔴 Red Team"),
    ("rep-fleet-defence",     "🛡️ Cyber Defence"),
    ("rep-fleet-specialised", "🏗️ Specialised Ops"),
    ("rep-fleet-grc",         "📋 GRC & Compliance"),
    ("rep-fleet-dfir",        "🔬 DFIR & Forensics"),
    ("rep-fleet-platform",    "⚙️ Platform Health"),
]

# ── Layout function map ───────────────────────────────────────────────────────
_LAYOUT_MAP = {
    "rep-exec":        reporting_executive_summary,
    "rep-timeline":    reporting_attack_timeline,
    "rep-assets":      reporting_impacted_assets,
    "rep-identity":    reporting_identity_impact,
    "rep-exploit":     reporting_vulnerability_exploitation,
    "rep-malware":     reporting_malware_tooling,
    "rep-detection":   reporting_detection_performance,
    "rep-exfil":       reporting_data_exposure,
    "rep-lateral":     reporting_lateral_movement,
    "rep-controls":    reporting_control_failures,
    "rep-remediation": reporting_remediation_recovery,
    "rep-compliance":  reporting_compliance_regulatory,
    "rep-neo4j":       reporting_neo4j_intelligence,
    "rep-docs":        reporting_shared_drive_analysis,
    # Fleet reports
    "rep-fleet-overview":    fleet_report_overview,
    "rep-fleet-external":    fleet_report_external,
    "rep-fleet-redteam":     fleet_report_redteam,
    "rep-fleet-defence":     fleet_report_defence,
    "rep-fleet-specialised": fleet_report_specialised,
    "rep-fleet-grc":         fleet_report_grc,
    "rep-fleet-dfir":        fleet_report_dfir,
    "rep-fleet-platform":    fleet_report_platform,
}

# ── Design tokens ─────────────────────────────────────────────────────────────
_DARK   = "#07060a"
_AMBER  = "#e8a020"   # Reports warm amber
_ORANGE = "#f59e0b"

_SECTION_BEFORE = {
    "rep-exec":           "INCIDENT REPORTS",
    "rep-exfil":          "REPORTING SUITE",
    "rep-fleet-overview": "FLEET REPORTS",
}

# ── Header ────────────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("📄", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": _AMBER, "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  SECURITY REPORTS SUITE", style={
            "color": "#3a2a08", "fontWeight": "700", "fontSize": "11px",
            "letterSpacing": "3px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
        }),
    ]),
    html.Div(style={"flex": "1"}),
    # Report count badge
    html.Div([
        html.Span("📋", style={"marginRight": "6px", "fontSize": "12px"}),
        html.Span("14 REPORT TYPES", style={
            "color": _AMBER, "fontSize": "9px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": f"{_AMBER}12",
        "border": f"1px solid {_AMBER}35",
        "borderRadius": "6px", "padding": "5px 14px",
        "marginRight": "12px",
    }),
    
    html.A([
        html.Span("🚀", style={"fontSize": "13px", "marginRight": "6px"}),
        html.Span("Launch Pad", style={
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1px", "color": "#e8a020",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#e8a02010",
        "border": f"1px solid #e8a02030",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": _AMBER, "marginRight": "6px",
                               "fontSize": "10px",
                               "animation": "rep-pulse 2s ease-in-out infinite"}),
        html.Span("STANDALONE  •  PORT 9021", style={
            "color": _AMBER, "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#110900",
        "border": f"1px solid {_AMBER}30",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #080600 0%, #0f0b02 60%, #080600 100%)",
    "borderBottom": f"2px solid {_AMBER}30",
    "padding": "12px 24px",
    "display": "flex", "alignItems": "center", "gap": "14px",
    "position": "sticky", "top": "0", "zIndex": "999",
    "boxShadow": "0 4px 24px rgba(0,0,0,0.8)",
})

# ── Sidebar nav ───────────────────────────────────────────────────────────────
def _sidebar(active_tab: str) -> html.Div:
    items = []
    for tab_id, label in _TABS:
        if tab_id in _SECTION_BEFORE:
            items.append(html.Div(_SECTION_BEFORE[tab_id], style={
                "color": "#3a2a08", "fontSize": "9px", "fontWeight": "900",
                "letterSpacing": "2px", "padding": "12px 14px 4px",
                "borderTop": "1px solid #1a1205",
                "marginTop": "6px",
            }))

        is_active = tab_id == active_tab
        items.append(html.Button(
            label,
            id={"type": "rep-suite-nav-btn", "index": tab_id},
            n_clicks=0,
            style={
                "display": "block", "width": "100%", "textAlign": "left",
                "background": f"linear-gradient(90deg, {_AMBER}20, {_AMBER}08)" if is_active else "transparent",
                "border": f"1px solid {_AMBER}50" if is_active else "1px solid transparent",
                "borderRadius": "8px",
                "color": "#ffffff" if is_active else "#5a4010",
                "fontSize": "11.5px",
                "fontWeight": "700" if is_active else "400",
                "padding": "9px 12px", "marginBottom": "2px",
                "cursor": "pointer", "transition": "all .2s ease",
                "letterSpacing": "0.2px",
            }
        ))

    # Export quick-actions block
    export_block = html.Div([
        html.Div("EXPORT", style={
            "color": "#3a2a08", "fontSize": "9px", "fontWeight": "900",
            "letterSpacing": "2px", "marginBottom": "8px",
        }),
        *[html.Div([
            html.Span(icon, style={"marginRight": "8px", "fontSize": "12px"}),
            html.Span(label, style={"color": "#7a5a20", "fontSize": "10px",
                                    "fontWeight": "600"}),
        ], style={
            "padding": "5px 4px", "borderBottom": f"1px solid {_AMBER}10",
            "display": "flex", "alignItems": "center",
        }) for icon, label in [("📄", "PDF Export"), ("📊", "Excel / CSV"),
                                ("📝", "Word Document"), ("🔗", "Share Link")]],
    ], style={
        "padding": "14px 10px 8px", "marginTop": "20px",
        "borderTop": f"1px solid {_AMBER}12",
    })

    return html.Div([
        html.Div("REPORTS", style={
            "color": "#3a2a08", "fontSize": "9px", "fontWeight": "900",
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
                        "letterSpacing": "2px", "color": "#e8a02099",
                        "lineHeight": "1",
                    }),
                    html.Div("Launch Pad ↗", style={
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "11px", "fontWeight": "700",
                        "color": "#e8a020", "lineHeight": "1.2",
                    }),
                ]),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": f"#e8a02012",
                "border": f"1px solid #e8a02035",
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
        export_block,
    ], style={
        "width": "220px", "minWidth": "220px",
        "background": "#050400",
        "borderRight": f"1px solid {_AMBER}15",
        "padding": "12px 8px",
        "overflowY": "auto",
        "minHeight": "100vh",
    })

# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _header,
    dcc.Store(id="rep-suite-active-tab", data="rep-exec"),
    html.Div([
        html.Div(id="rep-suite-sidebar", children=_sidebar("rep-exec")),
        html.Div(
            id="rep-suite-content",
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
    "          @keyframes rep-pulse{0%,100%{opacity:1;}50%{opacity:0.3;}}"
    "          button:hover{background:rgba(232,160,32,0.07)!important;"
    "                       color:#ccc!important;}"
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
    Output("rep-suite-active-tab", "data"),
    Input({"type": "rep-suite-nav-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _update_active_tab(_):
    if not ctx.triggered_id:
        return no_update
    return ctx.triggered_id["index"]


@callback(
    Output("rep-suite-sidebar", "children"),
    Output("rep-suite-content", "children"),
    Input("rep-suite-active-tab", "data"),
)
def _render_content(active_tab):
    tab = active_tab or "rep-exec"
    sidebar = _sidebar(tab)

    if tab in _LAYOUT_MAP:
        try:
            content = _LAYOUT_MAP[tab]()
        except Exception as e:
            import traceback
            err_msg = traceback.format_exc()
            content = html.Div([
                html.H4("⚠️ Error Rendering Report View", style={"color": "#f87171", "fontFamily": "monospace"}),
                html.P(f"Report module '{tab}' encountered an error during data processing:", style={"color": "#94a3b8"}),
                html.Pre(err_msg, style={
                    "background": "#1e1e2e",
                    "color": "#fca5a5",
                    "padding": "16px",
                    "borderRadius": "8px",
                    "overflowX": "auto",
                    "fontSize": "12px",
                    "fontFamily": "monospace"
                })
            ], style={"padding": "32px"})
    else:
        content = html.Div(f"Unknown tab: {tab}",
                           style={"color": _AMBER, "padding": "40px"})

    return sidebar, html.Div(content, style={"padding": "0"})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis Reports Suite — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9020, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Reports Suite  (Standalone)                         ║
╠══════════════════════════════════════════════════════════════════╣
║  URL     →  http://{args.host}:{args.port}/
║  Reports →  14 types across 2 sections                          ║
║             Incident Reports (7) · Reporting Suite (7)          ║
║  Debug   →  {str(args.debug):<54} ║
╚══════════════════════════════════════════════════════════════════╝
""")

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        threaded=True,
    )
