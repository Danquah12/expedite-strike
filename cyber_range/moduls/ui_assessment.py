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
                        {"label": "AegisProbe (Custom Plugin Framework)",       "value": "aegisprobe"},
                        {"label": "Burp Suite (Web Application Scanner)",       "value": "burp"},
                        {"label": "Nessus (Tenable Vulnerability Scanner)",     "value": "nessus"},
                        {"label": "Nmap (Network & Service Enumeration)",       "value": "nmap"},
                        {"label": "Nuclei (Vulnerability Scanning)",            "value": "nuclei"},
                        {"label": "OpenVAS (Network Vulnerability Scanner)",    "value": "openvas"},
                        {"label": "OWASP ZAP (Web Application Scanning)",      "value": "zap"},
                        {"label": "SCAP/XCCDF (Security Content Automation)",  "value": "scap_xccdf"},
                        {"label": "STIG CKL (DISA STIG Checklist)",            "value": "stig_ckl"},
                    ],
                    value="scap_xccdf",
                    placeholder="Select a scanner…",
                    clearable=False,
                    persistence=False,
                    style={"backgroundColor": "#111", "color": "#111", "marginBottom": "10px"},
                ),

                # Scan profile — dynamically populated based on scanner selection
                html.Label("Scan Profile", id="nmap-profile-label",
                           style={"color": text_muted, "fontWeight": "bold", "display": "block"}),
                dcc.Dropdown(
                    id="nmap-profile-select",
                    options=[
                        {"label": "🔍 Full Assessment — All SSG Benchmarks",                "value": "scap_xccdf:all"},
                        {"label": "🔍 RHEL 8/9 — DISA STIG + CIS  (1530-1697 rules)",     "value": "scap_xccdf:linux_server"},
                        {"label": "🔍 Ubuntu 22.04/24.04 — CIS + DISA STIG",               "value": "scap_xccdf:linux_desktop"},
                        {"label": "🔍 Debian 12 / AlmaLinux 9 — CIS Benchmark",            "value": "scap_xccdf:network"},
                        {"label": "🔍 Fedora / CentOS 8 — NIST 800-53 + CIS",              "value": "scap_xccdf:applications"},
                        {"label": "🔍 Cloud / Container — OCP4, EKS, CS9/10 (1530 rules)", "value": "scap_xccdf:cloud"},
                        {"label": "🔍 Windows Server — DISA STIG",                         "value": "scap_xccdf:windows_server"},
                        {"label": "🔍 Windows Desktop — CIS Win 10/11",                    "value": "scap_xccdf:windows_desktop"},
                        {"label": "📂 Import Custom XCCDF / DS File (path in Targets)",    "value": "scap_xccdf:import"},
                    ],
                    value="scap_xccdf:all",
                    clearable=False,
                    persistence=False,
                    placeholder="🔍 Select SSG benchmark profile...",
                    style={"backgroundColor": "#111", "color": "#111", "marginBottom": "15px"},
                ),
                
                html.Label("Scan Targets", style={"color": text_muted, "fontWeight": "bold"}),
                dcc.Textarea(
                    id="target-input",
                    value=(
                        "# === VMware Lab Targets (VMnet8 NAT) ===\n"
                        "192.168.195.138    # Windows Server 2012\n"
                        "192.168.195.137    # OWASP BWA / VM-137\n"
                        "192.168.195.128    # pfSense Firewall\n"
                        "192.168.195.0/24   # Full subnet scan\n"
                        "# --- Start these VMs for more targets ---\n"
                        "# Metasploitable2-Linux\n"
                        "# Windows 2019 Server\n"
                        "# Windows 10 x64\n"
                        "# Onion-Security\n"
                        "# Kali Linux 2025.3\n"
                        "# kali-linux-App-install"
                    ),
                    placeholder=(
                        "Enter target (one per line)\n\n"
                        "For LIVE assessment (🔍 profiles):\n"
                        "  192.168.195.137  (OWASP BWA)\n"
                        "  192.168.195.138  (Windows Server)\n"
                        "  https://app.example.com\n\n"
                        "For static import (📂 profile):\n"
                        "  /path/to/result.xml"
                    ),
                    style={
                        "width": "100%",
                        "height": "120px",
                        "backgroundColor": "#111",
                        "color": "#00ff66",
                        "border": f"1px solid {border_color}",
                        "fontFamily": "monospace",
                        "fontSize": "0.95rem",
                        "padding": "10px",
                        "marginBottom": "12px",
                    },
                ),

                # ── SSH Credential Panel ───────────────────────────────
                dbc.Card([
                    dbc.CardHeader([
                        html.Span("🔐 Authentication", style={
                            "color": accent_orange, "fontWeight": "bold", "fontSize": "0.85rem"
                        }),
                        html.Small(
                            " — Required for remote targets | Not needed for localhost",
                            style={"color": text_muted, "fontSize": "0.75rem"}
                        ),
                    ], style={"backgroundColor": "#1a1a1a", "padding": "6px 12px",
                              "cursor": "pointer"},
                       id="scap-auth-collapse-header"),
                    dbc.Collapse(
                        dbc.CardBody([
                            # Info banner
                            html.Div([
                                html.Span("ℹ️ ", style={"fontSize": "1rem"}),
                                html.Span([
                                    html.Strong("localhost / 127.0.0.1: "),
                                    "No credentials needed — oscap runs locally.",
                                    html.Br(),
                                    html.Strong("Remote targets: "),
                                    "SSH key or password required for authenticated scan.",
                                    html.Br(),
                                    html.Strong("Without auth: "),
                                    "Results marked INVALID — no DB write.",
                                ], style={"fontSize": "0.78rem", "color": "#aaa"}),
                            ], style={
                                "background": "#0d1a0d", "border": "1px solid #1a3a1a",
                                "borderRadius": "4px", "padding": "8px 10px", "marginBottom": "10px"
                            }),
                            dbc.Row([
                                dbc.Col([
                                    html.Label("SSH User", style={"color": text_muted,
                                               "fontSize": "0.78rem", "marginBottom": "2px"}),
                                    dbc.Input(
                                        id="scap-ssh-user",
                                        placeholder="root",
                                        value="",
                                        type="text",
                                        size="sm",
                                        style={"backgroundColor": "#111", "color": "#fff",
                                               "border": f"1px solid {border_color}",
                                               "fontFamily": "monospace"},
                                    ),
                                ], width=4),
                                dbc.Col([
                                    html.Label("SSH Key Path", style={"color": text_muted,
                                               "fontSize": "0.78rem", "marginBottom": "2px"}),
                                    dbc.Input(
                                        id="scap-ssh-key",
                                        placeholder="~/.ssh/id_rsa",
                                        value="",
                                        type="text",
                                        size="sm",
                                        style={"backgroundColor": "#111", "color": "#fff",
                                               "border": f"1px solid {border_color}",
                                               "fontFamily": "monospace"},
                                    ),
                                ], width=4),
                                dbc.Col([
                                    html.Label("SSH Password", style={"color": text_muted,
                                               "fontSize": "0.78rem", "marginBottom": "2px"}),
                                    dbc.Input(
                                        id="scap-ssh-password",
                                        placeholder="(leave empty if using key)",
                                        value="",
                                        type="password",
                                        size="sm",
                                        style={"backgroundColor": "#111", "color": "#fff",
                                               "border": f"1px solid {border_color}"},
                                    ),
                                ], width=4),
                            ], className="g-2"),
                            html.Div(
                                "🔒 Credentials used only for this scan session. "
                                "Store long-term creds in Vault (SCAP_SSH_KEY env var).",
                                style={"color": text_muted, "fontSize": "0.72rem", "marginTop": "6px"}
                            ),
                        ], style={"padding": "10px", "backgroundColor": "#111"}),
                        id="scap-auth-collapse",
                        is_open=True,
                    ),
                ], style={"border": f"1px solid {border_color}", "marginBottom": "12px",
                          "backgroundColor": "#111"}),

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
        
        html.Div([
            # ── Row 1: Scanner filter ──────────────────────────────────────
            html.Div([
                html.Span("🔎 Filter by Scanner:",
                          style={"color":"#8b949e","fontSize":"12px",
                                 "fontWeight":"600","marginRight":"12px",
                                 "lineHeight":"32px"}),
                dcc.Checklist(
                    id="scan-source-filter",
                    options=[
                        {"label": "📊 All",              "value": "all"},
                        {"label": "🟢 Nmap",             "value": "nmap"},
                        {"label": "🔴 Nuclei",           "value": "nuclei"},
                        {"label": "🟠 ZAP",              "value": "zap"},
                        {"label": "🟣 AegisProbe",       "value": "AegisProbe"},
                        {"label": "🟤 OpenVAS",          "value": "openvas"},
                        {"label": "🔵 Nessus",           "value": "nessus"},
                        {"label": "⚔️ STIG",             "value": "stig_ckl"},
                        {"label": "🛡️ SCAP",             "value": "scap_xccdf"},
                    ],
                    value=["all"],
                    inline=True,
                    inputStyle={"marginRight":"4px"},
                    labelStyle={
                        "marginRight":"8px",
                        "cursor":"pointer",
                        "fontSize":"12px",
                        "color":"#e6e6e6",
                        "padding":"5px 10px",
                        "borderRadius":"14px",
                        "border":"1px solid #30363d",
                        "backgroundColor":"#161b22",
                        "userSelect":"none",
                    },
                ),
            ], style={"display":"flex","alignItems":"center",
                      "flexWrap":"wrap","gap":"4px","marginBottom":"10px"}),

            # ── Row 2: Test Type / Scope filter ────────────────────────────
            html.Div([
                html.Span("🎯 Test Type:",
                          style={"color":"#8b949e","fontSize":"12px",
                                 "fontWeight":"600","marginRight":"12px",
                                 "lineHeight":"32px","whiteSpace":"nowrap"}),
                dcc.RadioItems(
                    id="scan-test-type-filter",
                    options=[
                        {"label": "🌐 All",              "value": "all"},
                        {"label": "🕸️ Web Testing",      "value": "web"},
                        {"label": "⚙️ API Testing",      "value": "api"},
                        {"label": "🖥️ Network / OS-IP",  "value": "network"},
                        {"label": "🔒 SAT / Compliance", "value": "sat"},
                    ],
                    value="all",
                    inline=True,
                    inputStyle={"marginRight":"4px"},
                    labelStyle={
                        "marginRight":"8px",
                        "cursor":"pointer",
                        "fontSize":"12px",
                        "color":"#e6e6e6",
                        "padding":"5px 12px",
                        "borderRadius":"14px",
                        "border":"1px solid #30363d",
                        "backgroundColor":"#161b22",
                    },
                ),
                html.Span(id="scan-test-type-label",
                          style={"color":"#8b949e","fontSize":"11px",
                                 "marginLeft":"12px","fontStyle":"italic"}),
            ], style={"display":"flex","alignItems":"center",
                      "flexWrap":"wrap","gap":"4px","marginBottom":"10px"}),

            # ── Row 3: Date range filter ───────────────────────────────────
            html.Div([
                html.Span("📅 Date Filter:",
                          style={"color":"#8b949e","fontSize":"12px",
                                 "fontWeight":"600","marginRight":"12px",
                                 "lineHeight":"32px","whiteSpace":"nowrap"}),
                # Quick-select buttons
                html.Div([
                    dbc.Button("Today",     id="scan-date-today-btn",   size="sm", color="secondary",
                               outline=True, n_clicks=0,
                               style={"fontSize":"11px","padding":"3px 10px","marginRight":"4px"}),
                    dbc.Button("This Week", id="scan-date-week-btn",    size="sm", color="secondary",
                               outline=True, n_clicks=0,
                               style={"fontSize":"11px","padding":"3px 10px","marginRight":"4px"}),
                    dbc.Button("This Month",id="scan-date-month-btn",   size="sm", color="secondary",
                               outline=True, n_clicks=0,
                               style={"fontSize":"11px","padding":"3px 10px","marginRight":"4px"}),
                    dbc.Button("All Time",  id="scan-date-all-btn",     size="sm", color="primary",
                               outline=True, n_clicks=0,
                               style={"fontSize":"11px","padding":"3px 10px","marginRight":"12px"}),
                ], style={"display":"inline-flex","alignItems":"center"}),
                # Date range picker
                dcc.DatePickerRange(
                    id="scan-date-range",
                    display_format="YYYY-MM-DD",
                    start_date=None,
                    end_date=None,
                    clearable=True,
                    with_portal=False,
                    style={"fontSize":"12px"},
                    className="dark-date-picker",
                ),
                html.Span(id="scan-date-range-label",
                          style={"color":"#8b949e","fontSize":"11px",
                                 "marginLeft":"12px","fontStyle":"italic"}),
            ], style={"display":"flex","alignItems":"center","flexWrap":"wrap","gap":"4px"}),

            # Store carries test-type into pipeline callback
            dcc.Store(id="scan-date-filter-store",  data={"start": None, "end": None}),
            dcc.Store(id="scan-test-type-store",    data="all"),
        ], id="scan-filter-bar",
           style={"padding":"12px 14px","background":"#0d1117",
                  "borderRadius":"8px","border":"1px solid #21262d",
                  "marginTop":"12px","marginBottom":"4px"}),

        # ── Pipeline: Send to Enumeration ────────────────────────────
        html.Div([
            html.Div([
                html.Span("🔗 Attack Pipeline", style={
                    "color": accent_orange, "fontSize": "13px",
                    "fontWeight": "700", "marginRight": "16px"}),
                html.Span("Send scan results for exploit discovery →", style={
                    "color": "#8b949e", "fontSize": "11px"}),
                # Live badge showing the active test-type scope
                html.Span(id="pipeline-test-type-badge",
                          style={"marginLeft":"12px","fontSize":"11px",
                                 "fontWeight":"600","color":"#58a6ff",
                                 "padding":"2px 10px","borderRadius":"10px",
                                 "border":"1px solid #1f6feb","backgroundColor":"#0d1117"}),
            ], style={"flex": "1"}),
            html.Div([
                dbc.Button(
                    "🎯 Send to Enumeration →",
                    id="pipeline-send-to-enum-btn",
                    color="danger", size="sm",
                    style={"fontWeight": "700", "letterSpacing": "0.5px",
                           "padding": "8px 20px", "fontSize": "12px",
                           "border": "1px solid #ff4444",
                           "boxShadow": "0 0 12px rgba(255,68,68,0.3)"},
                    className="me-2",
                ),
                dbc.Button(
                    "📋 Send Latest Scan →",
                    id="pipeline-send-latest-scan-btn",
                    color="warning", size="sm", outline=True,
                    style={"fontWeight": "600", "fontSize": "11px"},
                ),
            ]),
        ], style={
            "display": "flex", "alignItems": "center",
            "justifyContent": "space-between",
            "padding": "12px 16px", "marginTop": "10px", "marginBottom": "10px",
            "backgroundColor": "#1a1020", "borderRadius": "8px",
            "border": "1px solid #ff444433",
        }),

        # Pipeline status feedback (shows count or 'no data' warning)
        html.Div(id="pipeline-status-msg",
                 style={"fontSize":"11px","color":"#8b949e","marginBottom":"4px",
                        "minHeight":"18px"}),

        # Hidden store to hold host list for the pipeline callback
        dcc.Store(id="pipeline-host-options", data=[]),

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
