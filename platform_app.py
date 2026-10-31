#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Platform Suite  (Standalone Application)
=================================================
Runs the PLATFORM section (excluding Assessment Manager) as an independent
Dash app on port 9019.

Included modules:
  🖥️  System Status           — Health checks, services & diagnostics
  🤖  LLM Engine              — Multi-model AI analysis orchestrator (batch)
  💬  AI Chatbot              — Triple-engine threat intelligence assistant
  🎓  PhD AI Comparison       — 10-dim AI capability scoring tool
  🔬  PhD Research Tools      — Monte Carlo, Cohen's d & MCDA toolset
  🚀  Platform Enhancements   — Exec summaries, patch matrix, cypher builder

Usage:
  python platform_app.py              # port 9019
  python platform_app.py --debug      # dev mode
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
from dash import Dash, html, dcc, Input, Output, State, callback, no_update, ALL, ctx
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

# ── App FIRST ─────────────────────────────────────────────────────────────────
app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
    ],
    suppress_callback_exceptions=True,
    title="Ægis — Platform Suite",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#080808"},
        {"name": "description", "content": "Ægis Platform Suite — System Status · LLM Engine · AI Chatbot · PhD Research"},
    ],
)
server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "platform-suite-secret-2026")

# ── Import platform modules AFTER app is created ──────────────────────────────
import psutil                                                                    # noqa: E402
import cyber_range.moduls.ui_platform_enhancements as ui_enh                    # noqa: E402
from cyber_range.moduls import ui_phd_comparison                                # noqa: E402
from cyber_range.moduls import ui_phd_advanced                                  # noqa: E402

# ── Inline System Health layout (self-contained, mirrors app.py) ──────────────
def _system_health_layout() -> html.Div:
    """Real-time system diagnostics — mirrors app.py system_health_layout()."""
    try:
        cpu  = psutil.cpu_percent(interval=0.2)
        mem  = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        net  = psutil.net_io_counters()
        sent_mb = round(net.bytes_sent  / 1024 / 1024, 1)
        recv_mb = round(net.bytes_recv  / 1024 / 1024, 1)
    except Exception:
        cpu = mem = disk = sent_mb = recv_mb = 0

    def _gauge(value, title, color):
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=value,
            title={"text": title, "font": {"color": "#aaa", "size": 13}},
            number={"suffix": "%", "font": {"color": "#fff", "size": 20}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#333"},
                "bar": {"color": color},
                "bgcolor": "#111",
                "steps": [
                    {"range": [0,  60], "color": "#1a1a1a"},
                    {"range": [60, 80], "color": "#2a1a0a"},
                    {"range": [80, 100], "color": "#2a0a0a"},
                ],
                "threshold": {"line": {"color": "red", "width": 2},
                              "thickness": 0.75, "value": 90},
            }
        ))
        fig.update_layout(
            paper_bgcolor="#0d0d0d", plot_bgcolor="#0d0d0d",
            margin=dict(l=10, r=10, t=40, b=10), height=160,
        )
        return dcc.Graph(figure=fig, config={"displayModeBar": False})

    def _stat(icon, label, value, color="#00ccff"):
        return html.Div([
            html.Div(icon, style={"fontSize": "22px", "marginBottom": "4px"}),
            html.Div(label, style={"color": "#555", "fontSize": "10px",
                                   "letterSpacing": "1px", "fontWeight": "700"}),
            html.Div(value, style={"color": color, "fontSize": "18px",
                                   "fontWeight": "900", "fontFamily": "monospace"}),
        ], style={
            "background": "#0d0d0d", "border": "1px solid #1a1a1a",
            "borderRadius": "10px", "padding": "14px 20px",
            "textAlign": "center", "minWidth": "130px",
        })

    # Services status — complete Aegis fleet (Ports 9000, 9011-9021) + Neo4j engine
    _SERVICES = [
        ("Mission Control",      9000, "http"),
        ("Aegis SOC & ASPM",     9011, "http"),
        ("Expedite Strike",      9012, "http"),
        ("Red Team Ops",         9013, "http"),
        ("Cloud Pentest",        9014, "http"),
        ("Cyber Defence",        9015, "http"),
        ("Ransomware Recovery",  9016, "http"),
        ("Unified SOAR & GRC",   9017, "http"),
        ("CERBERUS DFIR",        9018, "http"),
        ("Platform Suite",       9019, "http"),
        ("PenTest Console",      9020, "http"),
        ("Reporting Suite",      9021, "http"),
        ("Neo4j Engine",         7687, "bolt"),
    ]

    def _svc_pill(name, port, proto):
        if proto == "bolt":
            try:
                import socket
                s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                s.close()
                up = True
                label = "UP"
                color = "#00e676"
            except Exception:
                up = True
                label = "MOCK GRAPH"
                color = "#00ccff"
        else:
            try:
                import socket
                s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                s.close()
                up = True
            except Exception:
                up = False
            color = "#00e676" if up else "#ff5252"
            label = "UP" if up else "DOWN"
        return html.Div([
            html.Span("●", style={"color": color, "marginRight": "6px",
                                   "fontSize": "10px"}),
            html.Span(f"{name} :{port}", style={
                "color": "#aaa", "fontSize": "11px", "fontWeight": "600",
            }),
            html.Span(label, style={
                "background": f"{color}20",
                "border": f"1px solid {color}50",
                "color": color, "fontSize": "9px", "fontWeight": "700",
                "padding": "1px 7px", "borderRadius": "4px",
                "marginLeft": "8px", "letterSpacing": "1px",
            }),
        ], style={
            "display": "flex", "alignItems": "center",
            "padding": "7px 12px",
            "borderBottom": "1px solid #111",
        })

    return html.Div([
        html.Div([
            html.H4("🖥️ System Status & Diagnostics",
                    style={"color": "#00ccff", "marginBottom": "4px"}),
            html.P("Live platform health — CPU · Memory · Disk · Network · Services",
                   style={"color": "#444", "fontSize": "12px", "marginBottom": "20px"}),

            # Gauges row
            dbc.Row([
                dbc.Col(_gauge(cpu,  "CPU",    "#00ccff"), md=4),
                dbc.Col(_gauge(mem,  "Memory", "#ff9800"), md=4),
                dbc.Col(_gauge(disk, "Disk",   "#ab47bc"), md=4),
            ], className="mb-3"),

            # Network stats
            dbc.Row([
                dbc.Col(_stat("📤", "SENT",     f"{sent_mb} MB", "#00e676"), width="auto"),
                dbc.Col(_stat("📥", "RECEIVED", f"{recv_mb} MB", "#00e676"), width="auto"),
                dbc.Col(_stat("🔢", "CPU CORES",str(psutil.cpu_count()), "#00ccff"), width="auto"),
                dbc.Col(_stat("💾", "RAM TOTAL",
                              f"{round(psutil.virtual_memory().total/1024**3,1)} GB",
                              "#ff9800"), width="auto"),
            ], className="mb-4 g-3"),

            # Services
            html.Div([
                html.Div("ÆGIS SERVICES", style={
                    "color": "#333", "fontSize": "9px", "fontWeight": "900",
                    "letterSpacing": "2px", "padding": "10px 12px 6px",
                }),
                *[_svc_pill(n, p, t) for n, p, t in _SERVICES],
            ], style={
                "background": "#0a0a0a", "border": "1px solid #1a1a1a",
                "borderRadius": "10px", "overflow": "hidden",
                "maxWidth": "520px",
            }),

            # Refresh button
            html.Div([
                html.Button("⟳  Refresh Status", id="plat-refresh-system",
                            n_clicks=0, style={
                    "background": "#00ccff15", "border": "1px solid #00ccff44",
                    "color": "#00ccff", "borderRadius": "8px",
                    "padding": "8px 20px", "cursor": "pointer",
                    "fontSize": "12px", "fontWeight": "700",
                    "marginTop": "16px",
                }),
            ]),
        ], style={"padding": "28px 32px"}),
    ], style={"background": "#080808", "minHeight": "100vh"})


# ── LLM Engine layout (static Dash layout re-built cleanly) ──────────────────
def _llm_engine_layout() -> html.Div:
    """LLM Batch Analysis interface — mirrors app.py llm_tab."""
    return html.Div([
        dbc.Container([
            html.H3("🧠 LLM Analysis Interface — Batch Mode",
                    className="text-warning mt-3"),
            html.P(
                "Submit up to 20 questions simultaneously to all 3 AI engines. "
                "Neo4j context is fetched once and shared across all questions. "
                "This interface is read-only and does not execute scans or modify data.",
                className="text-muted",
            ),
            html.Hr(style={"borderColor": "#222"}),
            dbc.Row([
                dbc.Col([
                    html.Label("Questions (one per line, max 20):",
                               className="text-secondary fw-bold small"),
                    dcc.Textarea(
                        id="plat-llm-questions",
                        placeholder="Enter each question on a new line…\n\nExample:\nWhat are the top 5 critical CVEs?\nWhich hosts are most exposed?\nSummarise recent threat actors…",
                        style={
                            "width": "100%", "height": "220px",
                            "background": "#0d0d0d", "color": "#eee",
                            "border": "1px solid #2a2a2a", "borderRadius": "8px",
                            "padding": "12px", "fontFamily": "monospace",
                            "fontSize": "12px", "resize": "vertical",
                        },
                    ),
                ], md=8),
                dbc.Col([
                    html.Label("AI Engine:", className="text-secondary fw-bold small"),
                    dcc.Dropdown(
                        id="plat-llm-engine",
                        options=[
                            {"label": "🔗 Deterministic AI (Neo4j)", "value": "neo4j"},
                            {"label": "🤖 ChatGPT (OpenAI)",         "value": "gpt"},
                            {"label": "🧬 Claude Sonnet",            "value": "claude"},
                            {"label": "🔀 All Engines",              "value": "all"},
                        ],
                        value="all",
                        clearable=False,
                        style={"background": "#111", "color": "#eee"},
                    ),
                    html.Br(),
                    html.Label("Max Tokens:", className="text-secondary fw-bold small"),
                    dcc.Slider(id="plat-llm-tokens", min=256, max=4096, step=256,
                               value=1024, marks={256: "256", 1024: "1k",
                                                  2048: "2k", 4096: "4k"}),
                    html.Br(),
                    dbc.Button("🚀  Run Batch Analysis", id="plat-llm-run",
                               color="warning", className="w-100 fw-bold mt-2"),
                    html.Div(id="plat-llm-status", className="text-muted small mt-2"),
                ], md=4),
            ], className="mb-3"),
            html.Div(id="plat-llm-results", style={"marginTop": "16px"}),
        ], fluid=True),
    ], style={"background": "#080808", "minHeight": "100vh"})


# ── AI Chatbot layout ─────────────────────────────────────────────────────────
def _chatbot_layout() -> html.Div:
    """Triple-engine AI chatbot — mirrors app.py chatbot_tab."""
    _PRESETS = [
        "What are my top 10 critical CVEs?",
        "Which hosts have the highest attack surface exposure?",
        "Summarise recent threat actor activity",
        "What MITRE ATT&CK techniques are most relevant to my findings?",
        "Generate an executive risk summary",
        "Which vulnerabilities should I patch first?",
        "Are there any signs of lateral movement in my scan data?",
    ]
    return html.Div([
        dbc.Container([
            html.H3("🛡️ AI Security Analyst Assistant (Triple Engine)",
                    className="text-warning mb-2"),
            html.P(
                "Compare responses across all three AI systems — Deterministic AI (Neo4j), "
                "ChatGPT, and Claude Sonnet — with live graph context.",
                className="text-muted mb-3",
            ),
            # Preset + Input row
            dbc.Row([
                dbc.Col([
                    dcc.Dropdown(
                        id="plat-chatbot-preset",
                        placeholder="💡 Quick question preset…",
                        options=[{"label": q[:60], "value": q} for q in _PRESETS],
                        clearable=True,
                        style={"background": "#111", "color": "#eee"},
                    ),
                ], md=5),
                dbc.Col([
                    dbc.InputGroup([
                        dbc.Input(id="plat-chatbot-input",
                                  placeholder="Ask any security question…",
                                  style={"background": "#111", "color": "#eee",
                                         "border": "1px solid #333"}),
                        dbc.Button("Send", id="plat-chatbot-send",
                                   color="warning", className="fw-bold"),
                    ]),
                ], md=7),
            ], className="mb-4"),
            # Response columns
            dbc.Row([
                dbc.Col([
                    html.Div("🔗 DETERMINISTIC AI", style={
                        "color": "#00ccff", "fontSize": "10px", "fontWeight": "900",
                        "letterSpacing": "2px", "marginBottom": "8px",
                    }),
                    html.Div(id="plat-chatbot-neo4j",
                             style={"background": "#0a0f18",
                                    "border": "1px solid #00ccff22",
                                    "borderRadius": "10px", "padding": "14px",
                                    "minHeight": "200px", "color": "#ccc",
                                    "fontSize": "13px", "lineHeight": "1.6"}),
                ], md=4),
                dbc.Col([
                    html.Div("🤖 CHATGPT", style={
                        "color": "#10a37f", "fontSize": "10px", "fontWeight": "900",
                        "letterSpacing": "2px", "marginBottom": "8px",
                    }),
                    html.Div(id="plat-chatbot-gpt",
                             style={"background": "#0a180f",
                                    "border": "1px solid #10a37f22",
                                    "borderRadius": "10px", "padding": "14px",
                                    "minHeight": "200px", "color": "#ccc",
                                    "fontSize": "13px", "lineHeight": "1.6"}),
                ], md=4),
                dbc.Col([
                    html.Div("🧬 CLAUDE SONNET", style={
                        "color": "#d97706", "fontSize": "10px", "fontWeight": "900",
                        "letterSpacing": "2px", "marginBottom": "8px",
                    }),
                    html.Div(id="plat-chatbot-claude",
                             style={"background": "#18100a",
                                    "border": "1px solid #d9770622",
                                    "borderRadius": "10px", "padding": "14px",
                                    "minHeight": "200px", "color": "#ccc",
                                    "fontSize": "13px", "lineHeight": "1.6"}),
                ], md=4),
            ]),
            # Chat history
            html.Div(id="plat-chatbot-history", className="mt-4"),
        ], fluid=True),
    ], style={"background": "#080808", "minHeight": "100vh"})


# ── Tab definitions ───────────────────────────────────────────────────────────
_TABS = [
    # ── Core Platform ─────────────────────────────────────────────────
    ("plat-system",      "🖥️  System Status"),
    ("plat-llm",         "🤖 LLM Engine"),
    ("plat-chatbot",     "💬 AI Chatbot"),
    # ── AI Research Suite ────────────────────────────────────────────
    ("plat-phd-compare", "🎓 PhD AI Comparison"),
    ("plat-phd-tools",   "🔬 PhD Research Tools"),
    ("plat-enhance",     "🚀 Platform Enhancements"),
]

_SECTION_BEFORE = {
    "plat-system":      "CORE PLATFORM",
    "plat-phd-compare": "AI RESEARCH SUITE",
}

# ── Design tokens ─────────────────────────────────────────────────────────────
_DARK  = "#060606"
_CYAN  = "#00ccff"
_GREY  = "#1a1a1a"

# ── Header ────────────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("⬛", style={"fontSize": "20px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": _CYAN, "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  PLATFORM SUITE", style={
            "color": "#1a3a4a", "fontWeight": "700", "fontSize": "11px",
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
            "letterSpacing": "1px", "color": "#00ccff",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": "#00ccff10",
        "border": "1px solid #00ccff30",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": _CYAN, "marginRight": "6px",
                               "fontSize": "10px",
                               "animation": "plat-pulse 2s ease-in-out infinite"}),
        html.Span("STANDALONE  •  PORT 9019", style={
            "color": "#1a3a4a", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#040f14",
        "border": f"1px solid {_CYAN}33",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #030a0e 0%, #060e14 60%, #030a0e 100%)",
    "borderBottom": f"2px solid {_CYAN}22",
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
                "color": "#1a3a4a", "fontSize": "9px", "fontWeight": "900",
                "letterSpacing": "2px", "padding": "12px 14px 4px",
                "borderTop": "1px solid #111",
                "marginTop": "6px",
            }))
        is_active = tab_id == active_tab
        items.append(html.Button(
            label,
            id={"type": "plat-suite-nav-btn", "index": tab_id},
            n_clicks=0,
            style={
                "display": "block", "width": "100%", "textAlign": "left",
                "background": f"linear-gradient(90deg, {_CYAN}1a, {_CYAN}08)" if is_active else "transparent",
                "border": f"1px solid {_CYAN}44" if is_active else "1px solid transparent",
                "borderRadius": "8px",
                "color": "#ffffff" if is_active else "#2a5a6a",
                "fontSize": "12px",
                "fontWeight": "700" if is_active else "400",
                "padding": "10px 14px", "marginBottom": "3px",
                "cursor": "pointer", "transition": "all .2s ease",
            }
        ))
    return html.Div([
        html.Div("MODULES", style={
            "color": "#1a3a4a", "fontSize": "9px", "fontWeight": "900",
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
                        "letterSpacing": "2px", "color": "#00ccff99",
                        "lineHeight": "1",
                    }),
                    html.Div("Launch Pad ↗", style={
                        "fontFamily": "'JetBrains Mono', monospace",
                        "fontSize": "11px", "fontWeight": "700",
                        "color": "#00ccff", "lineHeight": "1.2",
                    }),
                ]),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": f"#00ccff12",
                "border": f"1px solid #00ccff35",
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
        "background": "#030808",
        "borderRight": f"1px solid {_CYAN}12",
        "padding": "12px 8px",
        "overflowY": "auto",
        "minHeight": "100vh",
    })


# ── App layout ────────────────────────────────────────────────────────────────
app.layout = html.Div([
    _header,
    dcc.Store(id="plat-suite-active-tab", data="plat-system"),
    html.Div([
        html.Div(id="plat-suite-sidebar", children=_sidebar("plat-system")),
        html.Div(
            id="plat-suite-content",
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
    "          ::-webkit-scrollbar-thumb{background:#111;border-radius:3px;}"
    f"          @keyframes plat-pulse{{0%,100%{{opacity:1;}}50%{{opacity:0.3;}}}}"
    "          button:hover{background:rgba(0,204,255,0.07)!important;color:#ccc!important;}"
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
    Output("plat-suite-active-tab", "data"),
    Input({"type": "plat-suite-nav-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _update_active_tab(_):
    if not ctx.triggered_id:
        return no_update
    return ctx.triggered_id["index"]


@callback(
    Output("plat-suite-sidebar", "children"),
    Output("plat-suite-content", "children"),
    Input("plat-suite-active-tab", "data"),
)
def _render_content(active_tab):
    tab = active_tab or "plat-system"
    sidebar = _sidebar(tab)

    _MAP = {
        "plat-system":      _system_health_layout,
        "plat-llm":         _llm_engine_layout,
        "plat-chatbot":     _chatbot_layout,
        "plat-phd-compare": ui_phd_comparison.generate_phd_comparison_layout,
        "plat-phd-tools":   ui_phd_advanced.generate_phd_advanced_layout,
        "plat-enhance":     ui_enh.generate_enhancements_layout,
    }

    if tab in _MAP:
        content = _MAP[tab]()
    else:
        content = html.Div(f"Unknown tab: {tab}",
                           style={"color": _CYAN, "padding": "40px"})

    return sidebar, html.Div(content, style={"padding": "0"})


# ── System refresh callback ───────────────────────────────────────────────────
@callback(
    Output("plat-suite-active-tab", "data", allow_duplicate=True),
    Input("plat-refresh-system", "n_clicks"),
    prevent_initial_call=True,
)
def _refresh_system(n):
    if n:
        return "plat-system"
    return no_update


# ── Chatbot preset → input fill ───────────────────────────────────────────────
@callback(
    Output("plat-chatbot-input", "value"),
    Input("plat-chatbot-preset", "value"),
    prevent_initial_call=True,
)
def _fill_preset(preset):
    return preset or no_update


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis Platform Suite — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9019, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   Ægis  —  Platform Suite  (Standalone)                        ║
╠══════════════════════════════════════════════════════════════════╣
║  URL      →  http://{args.host}:{args.port}/
║  Modules  →  6  (System · LLM · Chatbot · PhD Compare           ║
║               PhD Research · Enhancements)                      ║
║  Debug    →  {str(args.debug):<54} ║
╚══════════════════════════════════════════════════════════════════╝
""")

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        threaded=True,
    )
