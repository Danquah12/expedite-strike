#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Home Screen  (Standalone Application — Port 9001)
==========================================================
A clean, premium home screen featuring:
  • Live KPI dashboard (CyberIntel TV feed)
  • Threat intelligence charts (CVSS gauge, severity donut, host bar)
  • AI news anchor broadcast
  • Executive Dashboard button
  • ⚡ Mission Control Launch Pad button → port 9000

No nav tabs. No mega-menu. Pure home experience.
"""

import sys, os
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))
_EXTRA = "/home/kali/.local/lib/python3.13/site-packages"
if _EXTRA not in sys.path:
    sys.path.insert(0, _EXTRA)

from dotenv import load_dotenv
load_dotenv(os.path.join(str(_APP_DIR), ".env"), override=True)
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ[_k] = ""

from dash import Dash, html, dcc, Input, Output, State, callback, no_update
import dash_bootstrap_components as dbc

# ── App first ────────────────────────────────────────────────────────────────
app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&family=Inter:wght@300;400;500;600;700;800;900&display=swap",
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
    ],
    suppress_callback_exceptions=True,
    title="Ægis SOC — Home",
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#04060a"},
        {"name": "description", "content": "Ægis Security Operations Center — Home Screen"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "home-screen-secret-2026")

# ── Import home TV module AFTER app ──────────────────────────────────────────
from cyber_range.moduls.ui_home_tv import generate_home_tv_layout           # noqa: E402

# ── Design tokens ────────────────────────────────────────────────────────────
_BG    = "#04060a"
_SURF  = "#080c12"
_BLUE  = "#00b4ff"
_CYAN  = "#00e8ff"
_GOLD  = "#f59e0b"

# ── Launch Pad button ─────────────────────────────────────────────────────────
_LAUNCHPAD_BTN = html.A(
    href="http://localhost:9000/",
    target="_blank",
    rel="noopener noreferrer",
    children=html.Div([
        # Animated ring
        html.Div(style={
            "position": "absolute", "inset": "-3px",
            "borderRadius": "16px",
            "background": f"linear-gradient(135deg, {_BLUE}, {_CYAN}, {_GOLD}, {_BLUE})",
            "backgroundSize": "300% 300%",
            "animation": "launchpad-ring 3s linear infinite",
            "zIndex": "0", "opacity": "0.7",
        }),
        # Button body
        html.Div([
            html.Span("🚀", style={"fontSize": "22px", "lineHeight": "1"}),
            html.Div([
                html.Div("MISSION CONTROL", style={
                    "fontFamily": "'JetBrains Mono', monospace",
                    "fontSize": "10px", "fontWeight": "800",
                    "letterSpacing": "3px", "color": "#9ad4f5",
                    "lineHeight": "1",
                }),
                html.Div("Launch Pad  ↗", style={
                    "fontFamily": "'JetBrains Mono', monospace",
                    "fontSize": "15px", "fontWeight": "900",
                    "letterSpacing": "1px", "color": "#ffffff",
                    "lineHeight": "1.3",
                }),
            ]),
        ], style={
            "display": "flex", "alignItems": "center", "gap": "14px",
            "position": "relative", "zIndex": "1",
            "background": "linear-gradient(135deg, #04101a, #070e1a)",
            "borderRadius": "13px",
            "padding": "14px 24px",
        }),
    ], style={
        "position": "relative",
        "borderRadius": "16px",
        "overflow": "hidden",
        "cursor": "pointer",
        "transition": "transform .2s ease, filter .2s ease",
    }),
    style={"textDecoration": "none"},
    id="launchpad-link",
)

_EXEC_BTN = html.A(
    href="http://localhost:8050/",
    target="_blank",
    children=html.Div([
        html.Span("📊", style={"fontSize": "16px"}),
        html.Span("Full SOC Platform", style={
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "11px", "fontWeight": "700",
            "letterSpacing": "2px", "color": "#00b4ff",
        }),
    ], style={
        "display": "flex", "alignItems": "center", "gap": "10px",
        "background": "rgba(0,180,255,.08)",
        "border": "1px solid rgba(0,180,255,.25)",
        "borderRadius": "10px", "padding": "11px 20px",
        "cursor": "pointer",
        "transition": "all .2s ease",
    }),
    style={"textDecoration": "none"},
)

_ADMIN_BTN = html.A(
    href="http://localhost:8050/admin/panel",
    target="_blank",
    rel="noopener noreferrer",
    children=html.Div([
        html.Div([
            html.Span("🔐", style={"fontSize": "14px"}),
            html.Span("Admin Portal", style={
                "fontFamily": "'JetBrains Mono', monospace",
                "fontSize": "10px", "fontWeight": "800",
                "letterSpacing": "2px", "color": "#ff6b6b",
            }),
        ], style={
            "display": "flex", "alignItems": "center", "gap": "8px",
        }),
        # live dot
        html.Div([
            html.Span(style={
                "display": "inline-block",
                "width": "5px", "height": "5px",
                "borderRadius": "50%", "background": "#ff4444",
                "animation": "admin-pulse 1.5s ease-in-out infinite",
            }),
            html.Span("LIVE", style={
                "fontFamily": "'JetBrains Mono', monospace",
                "fontSize": "8px", "fontWeight": "700",
                "letterSpacing": "1.5px", "color": "#ff4444",
            }),
        ], style={"display": "flex", "alignItems": "center", "gap": "4px",
                   "marginTop": "2px"}),
    ], style={
        "display": "flex", "flexDirection": "column", "alignItems": "flex-start",
        "background": "rgba(255,60,60,.07)",
        "border": "1px solid rgba(255,60,60,.28)",
        "borderRadius": "10px", "padding": "9px 18px",
        "cursor": "pointer",
        "transition": "all .2s ease",
    }),
    style={"textDecoration": "none"},
    id="admin-portal-btn",
)

# ── Top header bar ────────────────────────────────────────────────────────────
_topbar = html.Div([
    # Left: Shield + wordmark
    html.Div([
        html.Div("🛡️", style={"fontSize": "28px"}),
        html.Div([
            html.Div([
                html.Span("ÆGIS", style={
                    "fontFamily": "'JetBrains Mono', monospace",
                    "fontWeight": "900", "fontSize": "20px",
                    "letterSpacing": "6px", "color": _BLUE,
                }),
            ]),
            html.Div("SECURITY OPERATIONS CENTER", style={
                "fontFamily": "'JetBrains Mono', monospace",
                "fontSize": "8px", "fontWeight": "700",
                "letterSpacing": "4px", "color": "#0d2535",
                "marginTop": "1px",
            }),
        ]),
    ], style={"display": "flex", "alignItems": "center", "gap": "14px"}),

    html.Div(style={"flex": "1"}),

    # Right: buttons
    html.Div([
        _EXEC_BTN,
        _ADMIN_BTN,
        _LAUNCHPAD_BTN,
    ], style={"display": "flex", "alignItems": "center", "gap": "12px"}),

], style={
    "display": "flex", "alignItems": "center",
    "padding": "0 32px",
    "height": "68px",
    "background": f"linear-gradient(90deg, #02080f 0%, #040c18 50%, #02080f 100%)",
    "borderBottom": f"1px solid rgba(0,180,255,.1)",
    "position": "sticky", "top": "0", "zIndex": "1000",
    "backdropFilter": "blur(16px)",
    "boxShadow": "0 4px 40px rgba(0,0,0,.8)",
})

# ── Interval for TV refresh ───────────────────────────────────────────────────
_INTERVAL = dcc.Interval(id="home-refresh-interval", interval=60_000, n_intervals=0)
_TV_STORE  = dcc.Store(id="home-tv-store")

# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _INTERVAL,
    _TV_STORE,
    _topbar,

    # ── Home TV content area ──────────────────────────────────
    html.Div(id="home-tv-content", style={"minHeight": "calc(100vh - 68px)"}),

], style={
    "background": _BG,
    "minHeight": "100vh",
    "fontFamily": "'Inter', sans-serif",
})

# ── CSS ───────────────────────────────────────────────────────────────────────
app.index_string = """<!DOCTYPE html>
<html>
  <head>
    {%metas%}
    <title>{%title%}</title>
    {%favicon%}
    {%css%}
    <style>
      *, *::before, *::after { box-sizing: border-box; }
      html, body { margin: 0; padding: 0; background: #04060a; }

      /* ── Launchpad button rainbow ring ── */
      @keyframes launchpad-ring {
        0%   { background-position: 0%   50%; }
        50%  { background-position: 100% 50%; }
        100% { background-position: 0%   50%; }
      }
      #launchpad-link > div { transition: transform .25s ease, filter .25s ease; }
      #launchpad-link:hover > div { transform: translateY(-2px) scale(1.02); filter: brightness(1.15); }
      #launchpad-link:hover .launch-inner { box-shadow: 0 8px 30px rgba(0,180,255,.3); }

      /* ── Exec btn hover ── */
      a[href*="8050"]:not(#admin-portal-btn) div:hover {
        background: rgba(0,180,255,.15) !important;
        border-color: rgba(0,180,255,.45) !important;
      }
      /* ── Admin btn hover ── */
      #admin-portal-btn div:hover {
        background: rgba(255,60,60,.14) !important;
        border-color: rgba(255,60,60,.5) !important;
      }
      @keyframes admin-pulse { 0%,100%{opacity:1;} 50%{opacity:.2;} }

      /* ── Scrollbar ── */
      ::-webkit-scrollbar { width: 5px; }
      ::-webkit-scrollbar-track { background: #04060a; }
      ::-webkit-scrollbar-thumb { background: #0d1520; border-radius: 3px; }

      /* ── Override any nav tabs from home TV ── */
      .nav-tabs, .nav-link, .mega-nav, #aegis-mega-nav-root { display: none !important; }

      /* ── TV badge glow ── */
      .tv-live { animation: tv-glow 1.5s ease-in-out infinite !important; }
      @keyframes tv-glow {
        0%,100% { opacity:1; color:#ff3333; }
        50%      { opacity:.4; }
      }

      /* ── Scanline overlay ── */
      body::before {
        content: '';
        position: fixed; inset: 0; pointer-events: none; z-index: 0;
        background: repeating-linear-gradient(
          0deg, transparent 0, transparent 3px,
          rgba(0,180,255,.008) 3px, rgba(0,180,255,.008) 4px
        );
      }

      /* ── Fleet ticker animation ── */
      @keyframes fleet-ticker {
        0%   { transform: translateX(0); }
        100% { transform: translateX(-50%); }
      }
      @keyframes tv-live-dot {
        0%,100% { opacity:1; }
        50%      { opacity:.2; }
      }
    </style>
  </head>
  <body>
    {%app_entry%}
    <footer>{%config%}{%scripts%}{%renderer%}</footer>
  </body>
</html>"""

# ── Fleet Intelligence Broadcast section ─────────────────────────────────────
_FLEET = [
    (9000, "🏁", "Mission Control",     "Launch Pad gateway to the entire fleet",          "#00b4ff"),
    (8050, "🏛️", "Ægis SOC Platform",  "Full 68+ module unified platform",                "#00b4ff"),
    (8050, "🔐", "Admin Portal",        "User management · Roles · 2FA",                   "#ef4444", "/admin/panel"),
    (9012, "🔭", "External Assessment", "OSINT · Threat Intel · Dark Web · Ext Pentest",   "#a855f7"),
    (9013, "🎯", "Red Team Ops",        "Web App PT · C2 · Exploitation · Post-Exploit",   "#ef4444"),
    (9014, "🔴", "Red Team Suite",      "AD RedOps · Ægis AD Intel · 12 Modules",         "#f97316"),
    (9015, "🛡️", "Cyber Defence",      "SAST · API · Container · Threat Hunt · EDR",      "#00c2ff"),
    (9016, "🏭", "Specialised Ops",    "Cloud · IoT/OT · IR Playbooks · Mobile · DFIR",   "#ffaa00"),
    (9017, "📋", "GRC Suite",           "NIST · ISO 27001 · SOC 2 · PCI-DSS · HIPAA",     "#00e676"),
    (9018, "🔬", "Digital Forensics",   "Memory · Disk · Network · Evidence Chain",        "#9d4edd"),
    (9019, "⚙️", "Platform Suite",     "System · LLM · AI Chatbot · PhD Research",        "#00ccff"),
    (9020, "📊", "Reports Suite",       "14 Incident Reports + 8 Fleet Reports",           "#e8a020"),
]

def _build_fleet_section():
    import socket

    def _up(port):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.4)
            s.close(); return True
        except: return False

    cards = []
    for entry in _FLEET:
        port  = entry[0]
        icon  = entry[1]
        name  = entry[2]
        desc  = entry[3]
        color = entry[4]
        path  = entry[5] if len(entry) > 5 else "/"
        url   = f"http://localhost:{port}{path}"
        online = _up(port)

        cards.append(html.Div([
            # Status + icon row
            html.Div([
                html.Span(icon, style={"fontSize": "20px"}),
                html.Div(style={"flex": "1"}),
                html.Span("●", style={
                    "color": "#00e676" if online else "#ff5252",
                    "fontSize": "10px",
                    "animation": "tv-live-dot 2s ease-in-out infinite",
                }),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "8px"}),
            # Name
            html.Div(name, style={
                "color": color, "fontWeight": "800", "fontSize": "12px",
                "letterSpacing": ".3px", "marginBottom": "4px",
            }),
            # Port badge
            html.Div(f":{port}{path if path != '/' else ''}", style={
                "fontFamily": "'JetBrains Mono', monospace",
                "fontSize": "9px", "color": "#1a3a4a",
                "marginBottom": "6px",
            }),
            # Description
            html.Div(desc, style={
                "color": "#1a2a3a", "fontSize": "10px", "lineHeight": "1.5",
                "marginBottom": "12px",
            }),
            # Launch button
            html.A("LAUNCH ↗", href=url, target="_blank", style={
                "display": "block", "textAlign": "center",
                "background": f"{color}14",
                "border": f"1px solid {color}35",
                "borderRadius": "6px", "padding": "6px 0",
                "color": color, "fontSize": "9px", "fontWeight": "700",
                "letterSpacing": "1.5px", "textDecoration": "none",
            }),
        ], style={
            "background": "#080c14",
            "border": f"1px solid {color}18",
            "borderTop": f"2px solid {color}55",
            "borderRadius": "10px",
            "padding": "14px 14px 12px",
            "transition": "transform .2s ease, box-shadow .2s ease",
        }))

    news_items = [
        f"🔭 External Assessment (:{_FLEET[3][0]}) scanning OSINT surface",
        f"🔴 Red Team Suite (:{_FLEET[5][0]}) running AD RedOps analysis",
        f"🛡️ Cyber Defence (:{_FLEET[7][0]}) processing SAST findings",
        f"📋 GRC Suite (:{_FLEET[8][0]}) evaluating NIST compliance posture",
        f"🔬 DFIR (:{_FLEET[9][0]}) evidence chain integrity verified",
        f"📊 Reports Suite (:{_FLEET[11][0]}) — 22 report types across all modules",
        f"⚙️ Platform Suite (:{_FLEET[10][0]}) system health nominal",
        f"🏭 Specialised Ops (:{_FLEET[7][0]}) cloud misconfiguration scan active",
    ]
    ticker = "  ·  ".join(news_items) + "  ·  "

    return html.Div([
        # ── Section header ─────────────────────────────────
        html.Div([
            html.Div(style={"height": "1px", "background": "linear-gradient(90deg,transparent,rgba(0,180,255,.15),transparent)", "marginBottom": "24px"}),
            html.Div([
                html.Span("📡", style={"fontSize": "18px", "marginRight": "10px"}),
                html.Span("FLEET INTELLIGENCE BROADCAST", style={
                    "fontFamily": "'JetBrains Mono', monospace",
                    "fontSize": "11px", "fontWeight": "900",
                    "letterSpacing": "4px", "color": "#1a3a5a",
                }),
                html.Span("● LIVE", style={
                    "color": "#00b4ff", "fontSize": "9px", "fontWeight": "700",
                    "letterSpacing": "2px", "marginLeft": "14px",
                    "animation": "tv-glow 1.5s ease-in-out infinite",
                }),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "16px"}),

            # ── News ticker ────────────────────────────────
            html.Div([
                html.Div([
                    html.Span("📡 ÆGIS FLEET INTEL  ", style={
                        "color": "#00b4ff", "fontWeight": "800",
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "10px", "letterSpacing": "2px",
                        "marginRight": "16px", "whiteSpace": "nowrap",
                    }),
                    html.Div(ticker + ticker, style={
                        "display": "inline-block",
                        "color": "#1a4a6a", "fontSize": "10px",
                        "fontFamily": "'JetBrains Mono', monospace",
                        "animation": "fleet-ticker 40s linear infinite",
                        "whiteSpace": "nowrap",
                    }),
                ], style={"display": "flex", "alignItems": "center", "overflow": "hidden"}),
            ], style={
                "background": "#02080e",
                "border": "1px solid rgba(0,180,255,.08)",
                "borderRadius": "6px", "padding": "9px 16px",
                "marginBottom": "20px", "overflow": "hidden",
            }),

            # ── Suite cards grid ───────────────────────────
            html.Div(cards, style={
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fill, minmax(200px, 1fr))",
                "gap": "12px",
            }),

            html.Div([
                html.A("Open Full Reports Suite →", href="http://localhost:9020/",
                       target="_blank", style={
                    "color": "#e8a020", "fontSize": "11px", "fontWeight": "700",
                    "textDecoration": "none", "letterSpacing": "1px",
                }),
                html.Span("  ·  ", style={"color": "#1a2a3a"}),
                html.A("Mission Control Launch Pad →", href="http://localhost:9000/",
                       target="_blank", style={
                    "color": "#00b4ff", "fontSize": "11px", "fontWeight": "700",
                    "textDecoration": "none", "letterSpacing": "1px",
                }),
            ], style={"marginTop": "20px", "textAlign": "center", "padding": "12px"}),
        ], style={"padding": "0 22px 28px"}),
    ], style={"background": "#060810", "borderTop": "1px solid rgba(0,180,255,.06)"})


# ── Render home TV content ────────────────────────────────────────────────────
@callback(
    Output("home-tv-content", "children"),
    Input("home-refresh-interval", "n_intervals"),
)
def _render_home(_):
    try:
        tv_layout = generate_home_tv_layout()
        fleet_section = _build_fleet_section()
        return html.Div([tv_layout, fleet_section])
    except Exception as e:
        return html.Div([
            html.Div("⚠️", style={"fontSize": "48px", "textAlign": "center", "paddingTop": "80px"}),
            html.P(f"Home TV failed to load: {e}",
                   style={"color": "#ff5252", "textAlign": "center", "fontFamily": "monospace"}),
        ])


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ægis Home Screen — Standalone")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9001, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Home Screen  (Standalone)                           ║
╠══════════════════════════════════════════════════════════════════╣
║  URL          →  http://{args.host}:{args.port}/
║  Launch Pad   →  http://localhost:9000/
║  Full SOC     →  http://localhost:8050/
║  Content      →  CyberIntel TV · KPIs · AI Anchors             ║
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
