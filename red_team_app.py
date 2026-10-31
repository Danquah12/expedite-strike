#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Red Team Operations  (Standalone Application)
======================================================
Runs the Red Team Infrastructure & Operations UI independently on port 9013,
completely decoupled from the main Ægis SOC platform.

Features:
  • C2 Framework Manager (Sliver / Havoc / Cobalt Strike / Metasploit)
  • Redirector Setup
  • Payload Generation
  • Campaign Tracker
  • OPSEC Checklist
  • AI Attack Narrative / OPSEC Review / Rules of Engagement

Usage:
  python red_team_app.py              # production
  python red_team_app.py --debug      # dev mode

The main Ægis app (port 9011) is NOT affected by running this service.
"""

import sys
import os
from pathlib import Path

# ── Ensure project root & user local packages are on sys.path ───────────────
_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

_EXTRA = "/home/kali/.local/lib/python3.13/site-packages"
if _EXTRA not in sys.path:
    sys.path.insert(0, _EXTRA)

# ── Load .env ────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(os.path.join(str(_APP_DIR), ".env"), override=True)

# Suppress proxy env vars
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ[_k] = ""

# ── Core Dash imports ────────────────────────────────────────────────────────
from dash import Dash, html, dcc
import dash_bootstrap_components as dbc

# ── Build the standalone Dash app ────────────────────────────────────────────
# NOTE: assets/ folder is auto-served by Dash — picks up external_assessment.css
app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
    ],
    suppress_callback_exceptions=True,
    title="Ægis — Red Team Operations",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#0d1117"},
        {"name": "description", "content": "Ægis Red Team Operations — C2, Payloads, Campaign Tracker, AI Narrative"},
        {"name": "apple-mobile-web-app-capable", "content": "yes"},
        {"name": "apple-mobile-web-app-status-bar-style", "content": "black-translucent"},
    ],
)

server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "red-team-secret-2026-!@#")

# ── Import Red Team UI module AFTER app is created ───────────────────────────
# This registers all @callback decorators against the global Dash callback list.
from cyber_range.moduls import ui_red_team_ops  # noqa: E402

# ── Header bar ───────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("🔴", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": "#ff3355", "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  RED TEAM OPERATIONS", style={
            "color": "#546e8a", "fontWeight": "700", "fontSize": "11px",
            "letterSpacing": "3px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
        }),
    ]),
    html.Div(style={"flex": "1"}),  # spacer
    
    html.A([
        html.Span("🚀", style={"fontSize": "13px", "marginRight": "6px"}),
        html.Span("Launch Pad", style={
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1px", "color": "#ef4444",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#ef444410",
        "border": f"1px solid #ef444430",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": "#ff3355", "marginRight": "6px", "fontSize": "10px"}),
        html.Span("STANDALONE  •  PORT 9013", style={
            "color": "#546e8a", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#1a0a0d", "border": "1px solid #ff335533",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #0d0808 0%, #140a0a 60%, #0d0808 100%)",
    "borderBottom": "2px solid rgba(255,51,85,0.25)",
    "padding": "12px 24px",
    "display": "flex",
    "alignItems": "center",
    "gap": "14px",
    "position": "sticky",
    "top": "0",
    "zIndex": "999",
    "boxShadow": "0 4px 24px rgba(0,0,0,0.6)",
})

# ── App layout ───────────────────────────────────────────────────────────────
app.layout = html.Div([
    # Header
    _header,

    # Red Team Operations UI
    html.Div(
        id="rt-standalone-content",
        children=ui_red_team_ops.layout(),
        style={"padding": "0", "minHeight": "100vh"},
    ),
], style={"background": "#0d0d0d", "minHeight": "100vh"})

# ── Custom index_string — injects red-tinted CSS overrides ───────────────────
_RT_CSS = """
<style>
  html, body { margin: 0; padding: 0; background: #0d0d0d; font-family: 'Inter', 'Segoe UI', sans-serif; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: #0d0d0d; }
  ::-webkit-scrollbar-thumb { background: #1e2230; border-radius: 3px; }
  /* Pulse animation for the red dot indicator */
  @keyframes rt-pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }
  .rt-live-dot { animation: rt-pulse 2s ease-in-out infinite; }
</style>
"""

app.index_string = (
    "<!DOCTYPE html>"
    "<html>"
    "    <head>"
    "        {%metas%}"
    "        <title>{%title%}</title>"
    "        {%favicon%}"
    "        {%css%}"
    + _RT_CSS +
    "    </head>"
    "    <body>"
    "        {%app_entry%}"
    "        <footer>"
    "            {%config%}"
    "            {%scripts%}"
    "            {%renderer%}"
    "        </footer>"
    "    </body>"
    "</html>"
)


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis Red Team Operations — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port",  default=9013, type=int, help="Port (default: 9013)")
    parser.add_argument("--debug", action="store_true",    help="Enable Dash debug mode")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Red Team Operations  (Standalone)                   ║
╠══════════════════════════════════════════════════════════════════╣
║  URL   →  http://{args.host}:{args.port}/                       ║
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
