from dash import html, dcc
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

# =========================================================
# Premium Colors
# =========================================================
panel_bg = "#0d1117"
card_bg = "#161b22"
border_color = "#30363d"
accent_cyan = "#00f0ff"
accent_orange = "#ff9900"
accent_red = "#ff3333"
accent_purple = "#b533ff"
accent_green = "#00ff66"
text_muted = "#8b949e"

# =========================================================
# Assessment Layout
# =========================================================

control_panel = dbc.Card(
    [
        dbc.CardHeader("🛠 Scanner Control", style={"backgroundColor": card_bg, "borderBottom": f"1px solid {border_color}", "color": accent_orange}),
        dbc.CardBody(
            [
                html.Label("Scanner Engine", style={"color": text_muted, "fontWeight": "bold"}),
                dcc.Dropdown(
                    id="scanner-select",
                    options=[
                        {"label": "Nmap (Network & Service Enumeration)", "value": "nmap"},
                        {"label": "Nuclei (Vulnerability Scanning)", "value": "nuclei"},
                        {"label": "OWASP ZAP (Web Application Scanning)", "value": "zap"},
                        {"label": "Burp Engine (AegisProbe — Full Active Scan)", "value": "burp"},
                        {"label": "AegisProbe (Custom Plugin Framework)", "value": "aegisprobe"},
                    ],
                    placeholder="Select a scanner…",
                    clearable=False,
                    style={"backgroundColor": "#111", "color": "#111", "marginBottom": "10px"},
                ),

                # Scan profile — adapts to all scanners
                html.Label("Scan Profile", id="nmap-profile-label",
                           style={"color": text_muted, "fontWeight": "bold", "display": "block"}),
                dcc.Dropdown(
                    id="nmap-profile-select",
                    options=[
                        # ─── Nmap ───────────────────────────────
                        {"label": "── Nmap ──────────────────────────────", "value": "nmap_sep", "disabled": True},
                        {"label": "⚡  Nmap: Quick (Top 100 ports, no scripts)", "value": "nmap:quick"},
                        {"label": "🔍  Nmap: Standard (vuln + vulners)", "value": "nmap:standard"},
                        {"label": "🔥  Nmap: Full Vuln (All NSE vuln + SSL/SMB/HTTP)", "value": "nmap:full_vuln"},
                        {"label": "🛡️  Nmap: Comprehensive (All ports + UDP + brute)", "value": "nmap:comprehensive"},
                        # ─── Nuclei ─────────────────────────────
                        {"label": "── Nuclei ────────────────────────────", "value": "nuclei_sep", "disabled": True},
                        {"label": "⚡  Nuclei: Light (Info & Network only)", "value": "nuclei:light"},
                        {"label": "🔍  Nuclei: Standard (All community templates)", "value": "nuclei:standard"},
                        {"label": "🎯  Nuclei: CVE-Only (CVEs + Exposures)", "value": "nuclei:cve_only"},
                        {"label": "🔥  Nuclei: Full (All templates + brute + fuzzing)", "value": "nuclei:full"},
                        # ─── ZAP ────────────────────────────────
                        {"label": "── OWASP ZAP ────────────────────────", "value": "zap_sep", "disabled": True},
                        {"label": "👁  ZAP: Passive (Spider + headers only)", "value": "zap:passive"},
                        {"label": "🔍  ZAP: Active Light (XSS, SQLi, Path Traversal)", "value": "zap:active_light"},
                        {"label": "🔥  ZAP: Full Active (All OWASP Top 10)", "value": "zap:full_active"},
                        # ─── AegisProbe / Burp ──────────────────
                        {"label": "── AegisProbe / Burp ────────────────", "value": "aegis_sep", "disabled": True},
                        {"label": "⚡  AegisProbe: Passive (Passive plugins only)", "value": "aegis:passive:low"},
                        {"label": "🔍  AegisProbe: Full (All plugins, medium intensity)", "value": "aegis:full:medium"},
                        {"label": "🔥  AegisProbe: Aggressive (All plugins, max workers)", "value": "aegis:full:aggressive"},
                    ],
                    value="nmap:standard",
                    clearable=False,
                    placeholder="Select a scan profile…",
                    style={"backgroundColor": "#111", "color": "#111", "marginBottom": "15px"},
                ),
                
                html.Label("Scan Targets", style={"color": text_muted, "fontWeight": "bold"}),
                dcc.Textarea(
                    id="target-input",
                    placeholder=(
                        "Enter scan targets (one per line)\n\n"
                        "Examples:\n"
                        "192.168.1.113\n"
                        "10.0.0.0/24\n"
                        "https://app.example.com"
                    ),
                    style={
                        "width": "100%",
                        "height": "160px",
                        "backgroundColor": "#111",
                        "color": "#00ff66",
                        "border": f"1px solid {border_color}",
                        "fontFamily": "monospace",
                        "fontSize": "0.95rem",
                        "padding": "10px",
                        "marginBottom": "20px",
                    },
                ),

                dbc.Row(
                    [
                        dbc.Col(dbc.Button("▶ Run Scan", id="scan-btn", style={"backgroundColor": accent_orange, "borderColor": accent_orange, "color": "#000", "fontWeight": "bold", "width": "100%"}, n_clicks=0), width=4),
                        dbc.Col(dbc.Button("⛔ Cancel", id="cancel-btn", color="danger", style={"fontWeight": "bold", "width": "100%"}, n_clicks=0, disabled=True), width=4),
                        dbc.Col(dbc.Button("📥 Force Ingest", id="ingest-btn", color="success", style={"fontWeight": "bold", "width": "100%"}, n_clicks=0, disabled=True), width=4),
                    ],
                    className="g-2"
                ),
            ]
        )
    ],
    style={"backgroundColor": card_bg, "border": f"1px solid {border_color}", "height": "100%"}
)

terminal_panel = dbc.Card(
    [
        dbc.CardHeader("📜 Live Terminal Output", style={"backgroundColor": card_bg, "borderBottom": f"1px solid {border_color}", "color": accent_cyan}),
        dbc.CardBody(
            [
                html.Div(
                    id="scan-log-output",
                    children="[SYS] Assessment Engine initialized...\n[SYS] Awaiting target execution...",
                    style={
                        "whiteSpace": "pre-wrap",
                        "backgroundColor": "#050505",
                        "color": accent_green,
                        "padding": "15px",
                        "borderRadius": "4px",
                        "height": "320px",
                        "fontFamily": "'Fira Code', monospace",
                        "fontSize": "0.85rem",
                        "border": f"1px solid {border_color}",
                        "overflowY": "auto",
                        "lineHeight": "1.4"
                    },
                )
            ]
        )
    ],
    style={"backgroundColor": card_bg, "border": f"1px solid {border_color}", "height": "100%"}
)

metrics_panel = dbc.Card(
    [
        dbc.CardHeader("📊 Assessment Coverage (Neo4j)", style={"backgroundColor": card_bg, "borderBottom": f"1px solid {border_color}", "color": "#fff"}),
        dbc.CardBody(
            [
                dbc.Row(
                    [
                        dbc.Col(
                            html.Div([
                                html.H6("Assets Assessed", style={"color": text_muted}),
                                html.H3(id="assess-assets", children="0", style={"color": accent_cyan, "fontWeight": "bold"})
                            ], style={"textAlign": "center"}),
                            width=4
                        ),
                        dbc.Col(
                            html.Div([
                                html.H6("Services Assessed", style={"color": text_muted}),
                                html.H3(id="assess-services", children="0", style={"color": accent_purple, "fontWeight": "bold"})
                            ], style={"textAlign": "center", "borderLeft": f"1px solid {border_color}", "borderRight": f"1px solid {border_color}"}),
                            width=4
                        ),
                        dbc.Col(
                            html.Div([
                                html.H6("Vulnerabilities", style={"color": text_muted}),
                                html.H3(id="assess-findings", children="0", style={"color": accent_red, "fontWeight": "bold"})
                            ], style={"textAlign": "center"}),
                            width=4
                        ),
                    ],
                    className="mb-4"
                ),
                dcc.Graph(id="assess-findings-by-source", style={"height": "250px"}),
                html.Div(
                    "ℹ️ Metrics reflect successfully ingested artifact payloads inside Neo4j.",
                    style={"color": text_muted, "fontSize": "0.8rem", "textAlign": "center", "marginTop": "10px"}
                )
            ]
        )
    ],
    style={"backgroundColor": card_bg, "border": f"1px solid {border_color}", "marginTop": "20px"}
)


assessment_layout = dbc.Container(
    [
        dcc.Interval(
            id="scan-log-interval",
            interval=1000,
            n_intervals=0,
            disabled=True,
        ),
        html.H3("🧪 Advanced Vulnerability Assessment", style={"color": "#fff", "fontWeight": "bold", "marginBottom": "5px"}),
        html.P(
            "Execute and monitor distributed network and web vulnerability scans using Nmap, Nuclei, and OWASP ZAP. "
            "Artifacts are stored centrally in /mnt/scans and continuously ingested into the graph database.",
            style={"color": text_muted, "marginBottom": "20px"}
        ),
        
        dbc.Row(
            [
                dbc.Col(control_panel, width=5),
                dbc.Col(terminal_panel, width=7),
            ],
            style={"alignItems": "stretch"}
        ),
        
        # ── Scanner filter bar ────────────────────────────────────────
        html.Div([
            html.Div([
                html.Span("🔎 Filter by Scanner:",
                          style={"color":"#8b949e","fontSize":"12px",
                                 "fontWeight":"600","marginRight":"12px",
                                 "lineHeight":"32px"}),
                dcc.RadioItems(
                    id="scan-source-filter",
                    options=[
                        {"label": "📊 All",              "value": "all"},
                        {"label": "🟢 Nmap",             "value": "nmap"},
                        {"label": "🔴 Nuclei",           "value": "nuclei"},
                        {"label": "🟠 ZAP",              "value": "zap"},
                        {"label": "🟣 AegisProbe",       "value": "AegisProbe"},
                    ],
                    value="all",
                    inline=True,
                    inputStyle={"marginRight":"4px"},
                    labelStyle={
                        "marginRight":"14px",
                        "cursor":"pointer",
                        "fontSize":"12px",
                        "color":"#e6e6e6",
                        "padding":"5px 10px",
                        "borderRadius":"14px",
                        "border":"1px solid #30363d",
                        "backgroundColor":"#161b22",
                    },
                ),
            ], style={"display":"flex","alignItems":"center",
                      "flexWrap":"wrap","gap":"4px"}),
        ], id="scan-filter-bar",
           style={"padding":"10px 14px","background":"#0d1117",
                  "borderRadius":"8px","border":"1px solid #21262d",
                  "marginTop":"12px","marginBottom":"4px"}),

        html.Div(id="assessment-scan-summary", style={"display": "none"}),
        html.Div(id="scan-filtered-summary", style={"marginTop": "0"}),

        html.Div([
            dbc.Button("📄 Export PTES Report", id="assessment-ptes-btn",
                       color="warning", size="sm",
                       style={"fontWeight": "800", "color": "#000",
                              "display": "none"},
                       n_clicks=0),
            dcc.Download(id="assessment-ptes-download"),
            html.Div(id="assessment-ptes-status", style={"display":"inline-block","marginLeft":"10px"}),
        ], style={"marginTop": "8px"}),

        dbc.Row(
            dbc.Col(metrics_panel, width=12)
        )
    ],
    fluid=True,
    style={"padding": "20px"}
)
