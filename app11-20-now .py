#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Towson University — AI-Augmented Vulnerability Intelligence Dashboard
Fully integrated version (Batches 1–3 merged)
"""

# ==========================================================
#  IMPORTS & CONFIGURATION
# ==========================================================
import os
import sqlite3
import psutil
import pandas as pd
import plotly.express as px
import subprocess
import time
import requests
from pathlib import Path
from datetime import datetime

# --- Dash Framework ---
from dash import Dash, html, dcc, Input, Output, State, no_update, dash_table
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

# --- Neo4j Integration ---
from neo4j import GraphDatabase
from neo4j_integration import import_nmap_hosts_to_neo4j, enrich_cves_from_nvd
from neo4j_integration import run_full_pipeline
# Add sound/animation components
import dash_daq as daq
from dash_extensions import EventListener



# =====================================================================
#  GRAPH TYPES & CYPHER QUERIES  (OPTION A - 7 CATEGORIES • 20 TYPES)
# =====================================================================

# =====================================================================
#  GRAPH TYPES & CYPHER QUERIES  (OPTION A - 7 CATEGORIES • 20 TYPES)
# =====================================================================

GRAPH_TYPES = {

    # ----------------------------------------------------------
    # 1) CORE RELATIONSHIP GRAPHS
    # ----------------------------------------------------------
    "Core Relationship Graphs": [
        {"label": "Asset ↔ Service Mapping", "value": "core_asset_service"},
        {"label": "Asset ↔ Vulnerability Mapping", "value": "core_asset_vuln"},
        {"label": "Service ↔ Vulnerabilities", "value": "core_service_vuln"},
        {"label": "Asset ↔ Dependencies", "value": "core_asset_dependency"},
    ],

    # ----------------------------------------------------------
    # 2) VULNERABILITY GRAPHS
    # ----------------------------------------------------------
    "Vulnerability Graphs": [
        {"label": "All Vulnerabilities Overview", "value": "vuln_all"},
        {"label": "CVSS Severity Tiers", "value": "vuln_cvss_tiers"},
        {"label": "Exploitable Vulnerabilities", "value": "vuln_exploitable"},
        {"label": "Vulnerability Attack Surface", "value": "vuln_attack_surface"},
    ],

    # ----------------------------------------------------------
    # 3) THREAT INTELLIGENCE
    # ----------------------------------------------------------
    "Threat Intelligence Graphs": [
        {"label": "ThreatActor → Exploit → Vulnerability", "value": "ti_actor_exploit_vuln"},
        {"label": "Exploit ↔ Vulnerability Mapping", "value": "ti_exploit_vuln"},
        {"label": "MITRE ATT&CK Techniques", "value": "ti_attack_techniques"},
    ],

    # ----------------------------------------------------------
    # 4) ATTACK PATH
    # ----------------------------------------------------------
    "Attack Path Graphs": [
        {"label": "Shortest Attack Path → Crown Jewel", "value": "ap_shortest_to_cj"},
        {"label": "Privilege Escalation Paths", "value": "ap_privilege_escalation"},
        {"label": "User → Asset → Vulnerability Chain", "value": "ap_user_asset_vuln"},
        {"label": "Lateral Movement Chains", "value": "ap_lateral_movement"},
    ],

    # ----------------------------------------------------------
    # 5) NETWORK
    # ----------------------------------------------------------
    "Network Graphs": [
        {"label": "Network Segments ↔ Assets", "value": "net_segments_assets"},
        {"label": "Firewall Allowed Paths", "value": "net_firewall_paths"},
        {"label": "Inbound / Outbound Exposure Graph", "value": "net_exposure"},
    ],

    # ----------------------------------------------------------
    # 6) COMPLIANCE
    # ----------------------------------------------------------
    "Compliance Graphs": [
        {"label": "Control → Gap → POAM", "value": "comp_control_gap_poam"},
        {"label": "Control Family Overview", "value": "comp_control_families"},
        {"label": "Control Coverage Map", "value": "comp_coverage"},
    ],

    # ----------------------------------------------------------
    # 7) CLOUD SECURITY
    # ----------------------------------------------------------
    "Cloud Security Graphs": [
        {"label": "CloudAsset ↔ SecurityGroup", "value": "cloud_asset_sg"},
        {"label": "IAM Role Assignments", "value": "cloud_iam_paths"},
        {"label": "Cloud Misconfigurations", "value": "cloud_misconfigs"},
    ],
}


# ==========================================================
#  ENVIRONMENT SETUP
# ==========================================================
PROJECT_ROOT = "/root/vuln_intel"
DB_PATH = f"{PROJECT_ROOT}/vuln_intel.db"
STATUS_LOG = f"{PROJECT_ROOT}/app/status.log"

# Create or clear the status log file on startup
Path(STATUS_LOG).write_text("=== Dashboard initialized ===\n")

# OpenAI API (if used in other modules)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-4o"

print(f"[+] DB path: {DB_PATH}")
print("[+] Environment initialized successfully.")

# ==========================================================
#  DASH INITIALIZATION
# ==========================================================
external_stylesheets = [dbc.themes.DARKLY]
app = Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=external_stylesheets)
app.title = "Towson Vulnerability Intelligence Dashboard"
server = app.server

print(f"[+] DB path: {DB_PATH}")
print("[+] Environment initialized successfully.")

# ==========================================================
#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    """Load vulnerability data from SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings LIMIT 1000", conn)
        conn.close()
        return df
    except Exception as e:
        print("Error loading findings:", e)
        return pd.DataFrame(columns=["id", "host", "severity", "cvss", "source"])

def call_llm(prompt):
    """Query OpenAI GPT model for natural language analysis."""
    if not OPENAI_API_KEY:
        return "⚠️ OPENAI_API_KEY not configured."
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={"model": OPENAI_MODEL, "messages": [{"role": "user", "content": prompt}]},
            timeout=20,
        )
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"LLM error: {e}"

# ==========================================================
#  TAB 1: SYSTEM HEALTH
# ==========================================================
def system_health_layout():
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent

    health_df = pd.DataFrame({
        "Metric": ["CPU Usage", "Memory Usage", "Disk Usage"],
        "Value": [cpu, mem, disk]
    })
    fig = px.bar(health_df, x="Metric", y="Value", text="Value", color="Value",
                 color_continuous_scale="inferno", title="System Resource Utilization (%)")

    return dbc.Container([
        html.H3("🖥️ System Health Overview", className="text-warning mb-3"),
        dcc.Graph(figure=fig),
        html.Div(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 style={"textAlign": "center", "color": "#bbb"})
    ])

# ==========================================================
#  IMPORTS & CONFIGURATION
# ==========================================================
import os
import sqlite3
import psutil
import pandas as pd
import plotly.express as px
import subprocess
import time
import requests
from pathlib import Path
from datetime import datetime

# --- Dash Framework ---
from dash import Dash, html, dcc, Input, Output, State, no_update, dash_table
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

# --- Neo4j Integration ---
from neo4j import GraphDatabase
from neo4j_integration import import_nmap_hosts_to_neo4j, enrich_cves_from_nvd

# ==========================================================
#  ENVIRONMENT SETUP
# ==========================================================
PROJECT_ROOT = "/root/vuln_intel"
DB_PATH = f"{PROJECT_ROOT}/vuln_intel.db"
STATUS_LOG = f"{PROJECT_ROOT}/app/status.log"

# Create or clear status log file
Path(STATUS_LOG).write_text("=== Dashboard initialized ===\n")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-4o"

print(f"[+] DB path: {DB_PATH}")
print("[+] Environment initialized successfully.")


# ==========================================================
#  DASH INITIALIZATION
# ==========================================================
external_stylesheets = [dbc.themes.DARKLY]
app = Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=external_stylesheets)
app.title = "Towson Vulnerability Intelligence Dashboard"
server = app.server


# ==========================================================
#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    """Example helper for loading vulnerability data from SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings", conn)
        conn.close()
        print(f"[+] Loaded {len(df)} findings from {DB_PATH}")
        return df
    except Exception as e:
        print(f"[!] Could not load findings: {e}")
        return pd.DataFrame()


# ==========================================================
#  TAB 2: VULNERABILITY DASHBOARD
# ==========================================================
def vulnerability_tab():
    return dbc.Container([
        html.H3("📊 Vulnerability Dashboard", className="text-warning mb-3"),

        # Refresh Button
        html.Div([
            dbc.Button("🔄 Refresh Dashboard", id="nessus-refresh", color="warning", className="mb-3")
        ]),

        # --- Summary Metrics ---
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardHeader("Total Assets"),
                dbc.CardBody(html.H3(id="metric-assets", className="text-center"))
            ], color="dark", inverse=True), width=3),

            dbc.Col(dbc.Card([
                dbc.CardHeader("Total Services"),
                dbc.CardBody(html.H3(id="metric-services", className="text-center"))
            ], color="secondary", inverse=True), width=3),

            dbc.Col(dbc.Card([
                dbc.CardHeader("Total Vulnerabilities"),
                dbc.CardBody(html.H3(id="metric-vulns", className="text-center"))
            ], color="danger", inverse=True), width=3),
        ], className="mb-4"),

        # --- Graph Visualization ---
        html.H5("Attack Surface Graph", className="text-light mt-4"),
        cyto.Cytoscape(
            id="vuln-graph",
            layout={'name': 'cose'},
            style={'width': '100%', 'height': '500px', 'backgroundColor': '#1b1b1b'},
            elements=[],
            stylesheet=[
                {'selector': 'node[label="Asset"]', 'style': {
                    'background-color': '#28a745', 'label': 'data(id)', 'font-size': '10px', 'color': '#fff'}},
                {'selector': 'node[label="Service"]', 'style': {
                    'background-color': '#007bff', 'label': 'data(id)', 'font-size': '9px', 'color': '#fff'}},
                {'selector': 'node[label="Vulnerability"]', 'style': {
                    'background-color': '#dc3545', 'label': 'data(id)', 'font-size': '8px', 'color': '#fff'}},
                {'selector': 'edge', 'style': {'line-color': '#999'}}
            ]
        ),

        html.Br(),

        # --- CVSS Severity Heatmap Section ---
        html.H5("CVSS Severity Heatmap", className="text-light"),
        dcc.Graph(id="cvss-heatmap", style={"height": "350px"}),

        html.Div([
            html.Span("🟥 Critical", style={"color": "#ff073a", "padding": "10px"}),
            html.Span("🟧 High", style={"color": "#ff8800", "padding": "10px"}),
            html.Span("🟨 Medium", style={"color": "#ffc107", "padding": "10px"}),
            html.Span("🟩 Low", style={"color": "#28a745", "padding": "10px"})
        ], style={"textAlign": "center", "fontSize": "18px"}),

        html.Br(),

        # --- Data Table ---
        html.H5("Asset & Service Summary", className="text-light mt-3"),
        dash_table.DataTable(
            id="vuln-table",
            columns=[
                {"name": "Asset", "id": "Asset"},
                {"name": "Service", "id": "Service"},
                {"name": "Port", "id": "Port"},
                {"name": "Vulnerability", "id": "Vulnerability", "presentation": "markdown"},
            ],
            markdown_options={"html": True},
            style_table={"overflowX": "auto", "backgroundColor": "#111"},
            style_header={
                "backgroundColor": "#EAAA00",
                "color": "black",
                "fontWeight": "bold"
            },
            style_cell={
                "backgroundColor": "#222",
                "color": "white",
                "padding": "6px"
            },
            style_cell_conditional=[
                {
                    "if": {"column_id": "Vulnerability"},
                    "whiteSpace": "normal",
                    "textAlign": "left"
                }
            ],
            page_size=10
        ),

        # --- Auto Refresh & Alerts ---
        dcc.Interval(id="interval-refresh", interval=30 * 1000, n_intervals=0),
        html.Audio(id="audio-alert", src=None, autoPlay=True, controls=False, style={"display": "none"}),
        html.Div(id="alert-banner"),

        # --- Last Updated Timestamp ---
        html.Div(id="last-updated", style={"textAlign": "center", "color": "#bbb", "marginTop": "10px"})
    ], fluid=True)


# ==========================================================
#  CALLBACK: UPDATE DASHBOARD FROM NEO4J (CVSS + ALERTS + TIMESTAMP)
# ==========================================================
@app.callback(
    [Output("metric-assets", "children"),
     Output("metric-services", "children"),
     Output("metric-vulns", "children"),
     Output("vuln-graph", "elements"),
     Output("vuln-table", "data"),
     Output("cvss-heatmap", "figure"),
     Output("audio-alert", "src"),
     Output("alert-banner", "children"),
     Output("last-updated", "children")],
    [Input("interval-refresh", "n_intervals"),
     Input("nessus-refresh", "n_clicks")],
    prevent_initial_call=False
)
def update_vuln_dashboard(_, refresh_clicks):
    from neo4j import GraphDatabase
    import plotly.express as px
    import pandas as pd
    from datetime import datetime
    from neo4j_integration import enrich_cves_from_nvd

    print("[+] Updating Vulnerability Dashboard...")

    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "Adomaa12@"

    assets, services, vulns = set(), set(), set()
    nodes, edges, table_data, heatmap_data = [], [], [], []
    new_critical_high = []  # for alert triggers

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            q = """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a.host AS asset, s.name AS service, s.port AS port,
                   v.id AS vuln, v.cvss AS cvss
            """
            data = list(session.run(q))

            # --- Self-Healing CVSS ---
            missing_cvss = [rec["vuln"] for rec in data if rec["vuln"] and rec["cvss"] is None]
            if missing_cvss:
                print(f"[!] Missing CVSS for {len(missing_cvss)} vulnerabilities — enriching...")
                try:
                    enrich_cves_from_nvd(limit=50)
                    data = list(session.run(q))  # reload after enrichment
                except Exception as e:
                    print(f"[!] CVSS enrichment failed: {e}")

            # --- Process Results ---
            for rec in data:
                a, s, p, v, cvss = (
                    rec["asset"], rec["service"], rec["port"], rec["vuln"], rec["cvss"]
                )

                # Metrics
                if a: assets.add(a)
                if s: services.add(s)
                if v: vulns.add(v)

                # Nodes & edges
                if a:
                    nodes.append({"data": {"id": a, "label": "Asset"}})
                if s:
                    sid = f"{s}:{p}"
                    nodes.append({"data": {"id": sid, "label": "Service"}})
                    edges.append({"data": {"source": a, "target": sid}})
                if v:
                    nodes.append({"data": {"id": v, "label": "Vulnerability"}})
                    edges.append({"data": {"source": f"{s}:{p}", "target": v}})

                # Clickable CVE link
                if v and v.startswith("CVE-"):
                    nvd_link = f"[{v}](https://nvd.nist.gov/vuln/detail/{v})"
                else:
                    nvd_link = v or "None"

                # Severity formatting
                severity_label = (
                    f"{nvd_link} (Critical)" if cvss and cvss >= 9.0 else
                    f"{nvd_link} (High)" if cvss and cvss >= 7.0 else
                    f"{nvd_link} (Medium)" if cvss and cvss >= 4.0 else
                    f"{nvd_link} (Low)" if cvss and cvss > 0 else
                    f"{nvd_link} (Informational)"
                )

                # Add to table
                table_data.append({
                    "Asset": a or "",
                    "Service": s or "",
                    "Port": p or "",
                    "Vulnerability": severity_label
                })

                # Track for alert
                if cvss and cvss >= 7.0:
                    new_critical_high.append(v)

                # Add to heatmap
                if v and cvss is not None:
                    heatmap_data.append({"Vulnerability": v, "CVSS": float(cvss)})

        driver.close()

    except Exception as e:
        print(f"[!] Neo4j connection or query failed: {e}")
        empty_fig = px.scatter(title="⚠️ Error loading data")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return "0", "0", "0", [], [], empty_fig, None, html.Div("⚠️ Error connecting to Neo4j"), f"Last updated: {now}"

    # --- Deduplicate nodes ---
    seen = {}
    for n in nodes:
        nid = n["data"]["id"]
        if nid not in seen:
            seen[nid] = n
    elements = list(seen.values()) + edges

    # --- Handle empty case ---
    if not elements:
        print("[!] No data found in Neo4j graph.")
        fig = px.scatter(title="No vulnerability data available")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return "0", "0", "0", [], [], fig, None, html.Div("No vulnerabilities found"), f"Last updated: {now}"

    # --- CVSS Heatmap ---
    if heatmap_data:
        df_heatmap = pd.DataFrame(heatmap_data)
        fig = px.density_heatmap(
            df_heatmap,
            x="Vulnerability",
            y="CVSS",
            color_continuous_scale="RdYlGn_r",
            title="CVSS Severity Distribution",
            nbinsy=10
        )
        fig.update_layout(
            plot_bgcolor="#111",
            paper_bgcolor="#111",
            font_color="#fff",
            margin=dict(l=30, r=30, t=50, b=50)
        )
    else:
        fig = px.scatter(title="No CVSS data available")

    # --- Audio & Visual Alerts ---
    audio_src, alert_banner = None, ""
    if new_critical_high:
        audio_src = "/assets/alert.mp3"
        alert_banner = html.Div(
            f"🚨 {len(new_critical_high)} High or Critical Vulnerabilities Detected!",
            style={
                "backgroundColor": "#ff073a",
                "color": "white",
                "padding": "12px",
                "fontWeight": "bold",
                "textAlign": "center",
                "animation": "flash 1s infinite"
            }
        )

    # --- Last Updated Timestamp ---
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[+] Dashboard updated: {len(assets)} assets, {len(services)} services, {len(vulns)} vulnerabilities.")

    return (
        str(len(assets)),
        str(len(services)),
        str(len(vulns)),
        elements,
        table_data,
        fig,
        audio_src,
        alert_banner,
        f"Last updated: {now}"
    )


# ==========================================================
#  TAB 3: LLM REQUEST
# ==========================================================
llm_tab = html.Div([
    html.H3("🧠 LLM Request Interface", className="text-warning mb-3"),
    html.P("Summarize or analyze findings using OpenAI GPT-4o."),
    dcc.Textarea(id="llm-prompt", placeholder="Ask about vulnerabilities...", style={"width": "100%", "height": "150px"}),
    html.Br(),
    dbc.Button("Run LLM Analysis", id="llm-btn", color="warning"),
    html.Div(id="llm-output", style={"whiteSpace": "pre-wrap", "marginTop": "10px", "color": "#EAAA00"})
])

@app.callback(Output("llm-output", "children"), Input("llm-btn", "n_clicks"), State("llm-prompt", "value"), prevent_initial_call=True)
def process_llm(n, text):
    if not text:
        raise dash.exceptions.PreventUpdate
    return call_llm(text)

# ==========================================================
#  TAB 4: CHATBOT (Placeholder)
# ==========================================================
chatbot_tab = html.Div([
    html.H3("💬 Chatbot", className="text-warning mb-3"),
    html.P("Conversational interface under development.")
])

# ==========================================================
#  TAB 5: ASSESSMENT
# ==========================================================
assessment_tab = html.Div([
    html.H3("🧪 Automated Vulnerability Scanning", className="text-warning mb-3"),
    html.P("Select a scanner and specify targets for assessment."),
    dcc.Dropdown(
        id="scanner-select",
        options=[
            {"label": "Nmap (Network Discovery)", "value": "nmap"},
            {"label": "OpenVAS (Vulnerability Scan)", "value": "openvas"},
            {"label": "Nessus", "value": "nessus"},
            {"label": "Burp Suite (Web App Scan)", "value": "burp"},
        ],
        placeholder="Select scanner",
        style={"width": "50%"}
    ),
    dcc.Input(id="target-ip", type="text", placeholder="Enter target IP or upload file", style={"width": "50%"}),
    html.Br(), html.Br(),
    dbc.Button("Run Scan", id="scan-btn", color="warning"),
    html.Div(id="scan-status", style={"marginTop": "15px", "color": "#EAAA00"})
])

@app.callback(Output("scan-status", "children"), Input("scan-btn", "n_clicks"), State("scanner-select", "value"), State("target-ip", "value"), prevent_initial_call=True)
def trigger_scan(n, scanner, target):
    if not scanner or not target:
        return "⚠️ Please select a scanner and provide target(s)."
    if scanner == "nmap":
        cmd = ["nmap", "-sV", "-O", "-v", target]
        subprocess.Popen(cmd)
        return f"🔍 Running Nmap scan on {target}..."
    return f"Triggered {scanner} scan for {target}."

# ==========================================================
#  PLACEHOLDER TABS (Reporting, Voice, Attack)
# ==========================================================
reporting_tab = html.Div([html.H3("📄 Reporting (Under Development)")])
voice_tab = html.Div([html.H3("🎙️ Voice Assistant (Under Development)")])
attack_tab = html.Div([html.H3("🕸️ Attack Path Analysis (Neo4j Integration)")])

# ======================================================================
#  TAB 8 — NEO4J GRAPH VISUALIZATION (STANDARD VERSION — CLEAN & FAST)
# ======================================================================
import dash_cytoscape as cyto
cyto.load_extra_layouts()

def neo4j_graphs_tab():
    return html.Div(
        [
            # ==========================================================
            # TITLE
            # ==========================================================
            html.H3("🧠 Neo4j Graph Visualizations", className="text-warning mb-4"),

            # ==========================================================
            # GRAPH CATEGORY
            # ==========================================================
            html.Label("Graph Category:", className="text-light"),
            dcc.Dropdown(
                id="graph-category",
                options=[{"label": c, "value": c} for c in GRAPH_TYPES.keys()],
                value="Core Relationship Graphs",
                clearable=False,
                style={"width": "60%", "marginBottom": "20px"},
            ),

            # ==========================================================
            # GRAPH TYPE
            # ==========================================================
            html.Label("Graph Type:", className="text-light"),
            dcc.Dropdown(
                id="graph-type",
                placeholder="Select Graph Type",
                options=[],
                style={"width": "60%", "marginBottom": "30px"},
            ),

            html.Hr(style={"borderColor": "#EAAA00"}),
            html.Div(id="graph-title", className="text-warning text-center mb-3"),

            # ==========================================================
            # CYTOSCAPE GRAPH
            # ==========================================================
            cyto.Cytoscape(
                id="neo4j-graph",
                layout={"name": "cose"},
                style={"width": "100%", "height": "600px", "backgroundColor": "#111"},
                elements=[],

                # CLEAN stylesheet
                stylesheet=[
                    # ------------------------------- GENERAL NODE STYLE
                    {
                        "selector": "node",
                        "style": {
                            "label": "data(label)",
                            "font-size": "12px",
                            "color": "white",
                            "background-color": "#666",
                            "width": "40px",
                            "height": "40px",
                            "text-outline-width": 1,
                            "text-outline-color": "#222",
                        },
                    },

                    # ------------------------------- ASSET
                    {
                        "selector": "node[type='Asset']",
                        "style": {"background-color": "#00A8E8", "shape": "round-rectangle"},
                    },

                    # ------------------------------- SERVICE
                    {
                        "selector": "node[type='Service']",
                        "style": {"background-color": "#007BFF", "shape": "hexagon"},
                    },

                    # ------------------------------- VULNERABILITY (CVSS COLORS)
                    {"selector": "node[type='Vulnerability'][cvss < 4]", "style": {"background-color": "#2ECC71"}},
                    {"selector": "node[type='Vulnerability'][cvss >= 4][cvss < 7]", "style": {"background-color": "#F1C40F"}},
                    {"selector": "node[type='Vulnerability'][cvss >= 7][cvss < 9]", "style": {"background-color": "#E67E22"}},
                    {"selector": "node[type='Vulnerability'][cvss >= 9]", "style": {"background-color": "#C0392B"}},

                    # ------------------------------- EXPLOIT
                    {
                        "selector": "node[type='Exploit']",
                        "style": {"background-color": "#8E44AD", "shape": "diamond"},
                    },

                    # ------------------------------- THREAT ACTOR
                    {
                        "selector": "node[type='ThreatActor']",
                        "style": {"background-color": "#FF5733", "shape": "octagon"},
                    },

                    # ------------------------------- USER / PRIVILEGE
                    {"selector": "node[type='User']", "style": {"background-color": "#1ABC9C"}},
                    {"selector": "node[type='Privilege']", "style": {"background-color": "#27AE60"}},

                    # ------------------------------- CROWN JEWEL
                    {"selector": "node[type='CrownJewel']", "style": {"background-color": "#F39C12", "shape": "star"}},

                    # ------------------------------- NETWORK ZONE
                    {"selector": "node[type='NetworkZone']", "style": {"background-color": "#34495E"}},

                    # ------------------------------- COMPLIANCE
                    {"selector": "node[type='Control']", "style": {"background-color": "#2980B9"}},
                    {"selector": "node[type='Gap']", "style": {"background-color": "#E74C3C"}},
                    {"selector": "node[type='POAM']", "style": {"background-color": "#F39C12"}},

                    # ------------------------------- CLOUD
                    {"selector": "node[type='CloudAsset']", "style": {"background-color": "#9B59B6"}},
                    {"selector": "node[type='SecurityGroup']", "style": {"background-color": "#E74C3C"}},
                    {"selector": "node[type='Role']", "style": {"background-color": "#1ABC9C"}},
                    {"selector": "node[type='Misconfiguration']", "style": {"background-color": "#D35400"}},

                    # ------------------------------- EDGES
                    {
                        "selector": "edge",
                        "style": {
                            "line-color": "#EAAA00",
                            "width": 2,
                            "target-arrow-shape": "triangle",
                            "target-arrow-color": "#EAAA00",
                            "curve-style": "bezier",
                        },
                    },

                    # ------------------------------- SELECTED NODE
                    {"selector": "node:selected", "style": {"border-width": 3, "border-color": "white"}},
                ],
            ),

            # ==========================================================
            # NODE INFO PANEL
            # ==========================================================
            html.Div(
                id="node-info-panel",
                className="text-light mt-4 p-3",
                style={
                    "backgroundColor": "#222",
                    "border": "1px solid #444",
                    "borderRadius": "8px",
                    "display": "none",
                    "whiteSpace": "pre-wrap",
                },
            ),

            # ==========================================================
            # LAYOUT SELECTOR
            # ==========================================================
            html.Div(
                [
                    html.Label("Graph Layout:", className="text-light mt-4"),
                    dcc.Dropdown(
                        id="layout-selector",
                        options=[
                            {"label": "CoSE", "value": "cose"},
                            {"label": "Circle", "value": "circle"},
                            {"label": "Grid", "value": "grid"},
                            {"label": "Concentric", "value": "concentric"},
                            {"label": "Breadth First", "value": "breadthfirst"},
                        ],
                        value="cose",
                        clearable=False,
                        style={"width": "40%", "color": "#000"},
                    ),
                ],
                className="mt-4",
            ),

            # ==========================================================
            # SEARCH BAR
            # ==========================================================
            html.Div(
                [
                    html.Label("Search Graph:", className="text-light mt-4"),
                    dcc.Input(
                        id="graph-search-input",
                        type="text",
                        debounce=True,
                        placeholder="Search by label, type, CVE...",
                        style={"width": "60%", "padding": "8px", "color": "#000"},
                    ),
                ],
                className="mb-4",
            ),

            # ==========================================================
            # ATTACK PATH CONTROLS (BASIC)
            # ==========================================================
            html.Div(
                [
                    html.H4("⚔ Attack Path Analysis", className="text-warning mt-4"),
                    dcc.Dropdown(
                        id="attack-start-node",
                        placeholder="Start Node",
                        options=[],
                        style={"width": "50%", "marginBottom": "10px"},
                    ),
                    dcc.Dropdown(
                        id="attack-target-node",
                        placeholder="Target Node (e.g., Crown Jewel)",
                        options=[],
                        style={"width": "50%", "marginBottom": "10px"},
                    ),
                    html.Button(
                        "🚀 Trace Attack Path",
                        id="attack-path-btn",
                        className="btn btn-danger",
                        n_clicks=0,
                    ),
                ]
            ),

            html.Div(
                id="attack-path-panel",
                className="text-light mt-4 p-3",
                style={
                    "backgroundColor": "#111",
                    "border": "1px solid #444",
                    "borderRadius": "8px",
                    "whiteSpace": "pre-wrap",
                },
            ),

            # ==========================================================
            # EXPORT BUTTONS
            # ==========================================================
            html.Div(
                [
                    html.Button("📄 Export JSON", id="export-json-btn",
                                className="btn btn-primary me-3"),
                    html.Button("📊 Export CSV", id="export-csv-btn",
                                className="btn btn-success"),
                    dcc.Download(id="neo4j-export-download"),
                ],
                className="mt-5",
            ),

            # ==========================================================
            # DATA STORES
            # ==========================================================
            dcc.Store(id="right-click-node"),
            dcc.Store(id="original-elements"),
            dcc.Store(id="last-attack-path"),
        ]
    )

 

# ======================================================================
#   CALLBACK: Populate graph types when category changes
# ======================================================================
@app.callback(
    Output("graph-type", "options"),
    Input("graph-category", "value"),
)
def update_graph_type_dropdown(category):
    return GRAPH_TYPES.get(category, [])


# ======================================================================
#   CALLBACK: Load Graph From Neo4j
# ======================================================================
@app.callback(
    [
        Output("neo4j-graph", "elements"),
        Output("graph-title", "children"),
        Output("original-elements", "data"),
        Output("attack-start-node", "options"),
        Output("attack-target-node", "options"),
    ],
    [
        Input("graph-type", "value"),
        Input("graph-category", "value"),
    ],
)
def load_graph(graph_type, category):

    if not graph_type:
        return [], "", [], [], []

    query = GRAPH_QUERIES.get(graph_type)

    if not query:
        return [], f"⚠ No query mapped for: {graph_type}", [], [], []

    try:
        driver = get_driver()
        with driver.session() as session:

            results = session.run(query)

            nodes = {}
            edges = []

            for record in results:
                path = record["p"]
                for node in path.nodes:
                    nid = str(node.id)
                    if nid not in nodes:
                        nodes[nid] = {
                            "data": {
                                "id": nid,
                                "label": node.get("name") or node.get("id"),
                                "type": list(node.labels)[0],
                                **node._properties,
                            }
                        }

                for rel in path.relationships:
                    edges.append({
                        "data": {
                            "id": str(rel.id),
                            "source": str(rel.start_node.id),
                            "target": str(rel.end_node.id),
                            "label": rel.type,
                        }
                    })

            elements = list(nodes.values()) + edges

            select_options = [{"label": n["data"]["label"], "value": n["data"]["id"]} for n in nodes.values()]

            return (
                elements,
                f"📊 {graph_type}",
                elements,
                select_options,
                select_options,
            )

    except Exception as e:
        return [], f"❌ Neo4j Query Error: {e}", [], [], []


# ======================================================================
#   CALLBACK: Show Node Info Panel
# ======================================================================
@app.callback(
    Output("node-info-panel", "children"),
    Output("node-info-panel", "style"),
    Input("neo4j-graph", "tapNodeData"),
)
def show_node_info(data):
    if not data:
        return "", {"display": "none"}

    info = "\n".join([f"{k}: {v}" for k, v in data.items()])

    return info, {
        "display": "block",
        "backgroundColor": "#222",
        "border": "1px solid #444",
        "borderRadius": "8px",
        "padding": "10px",
    }


# ======================================================================
#   CALLBACK: Switch Graph Layout
# ======================================================================
@app.callback(
    Output("neo4j-graph", "layout"),
    Input("layout-selector", "value"),
)
def update_layout(layout):
    return {"name": layout}


# ======================================================================
#   CALLBACK: Search Highlight
# ======================================================================
@app.callback(
    Output("neo4j-graph", "stylesheet"),
    Input("graph-search-input", "value"),
    State("neo4j-graph", "stylesheet"),
)
def update_search(query, stylesheet):
    if not query:
        return stylesheet

    new_style = stylesheet + [
        {
            "selector": f"[label *= '{query}']",
            "style": {
                "background-color": "#FFFF00",
                "border-width": 3,
                "border-color": "black",
            }
        }
    ]

    return new_style


# ======================================================================
#   CLIENTSIDE CALLBACK — Right-click Context Menu Popup
# ======================================================================
app.clientside_callback(
    """
    function(event) {
        if (!event) return window.dash_clientside.no_update;

        const posX = event.position.x;
        const posY = event.position.y;

        const menu = document.getElementById("context-menu");
        menu.style.left = posX + "px";
        menu.style.top = posY + "px";
        menu.style.display = "block";

        return event.data.id;
    }
    """,
    Output("right-click-node", "data"),
    Input("neo4j-graph", "cxttapNodeData"),
)


# ======================================================================
#   CALLBACK: Hide, Isolate, Reset Graph
# ======================================================================
@app.callback(
    Output("neo4j-graph", "elements"),
    [
        Input("ctx-hide", "n_clicks"),
        Input("ctx-reset", "n_clicks"),
        Input("ctx-neighbors", "n_clicks"),
        Input("ctx-isolate", "n_clicks"),
    ],
    [
        State("right-click-node", "data"),
        State("original-elements", "data"),
        State("neo4j-graph", "elements"),
    ],
)
def right_click_actions(hide, reset, neighbors, isolate, node_id, original, current):

    triggered = ctx.triggered_id

    if not triggered or not node_id:
        return current

    if triggered == "ctx-reset":
        return original

    if triggered == "ctx-hide":
        return [el for el in current if el["data"].get("id") != node_id]

    if triggered == "ctx-isolate":
        return [el for el in current if el["data"].get("id") == node_id]

    if triggered == "ctx-neighbors":
        neighbor_ids = set()
        for edge in current:
            if "source" in edge["data"]:
                if edge["data"]["source"] == node_id:
                    neighbor_ids.add(edge["data"]["target"])
                if edge["data"]["target"] == node_id:
                    neighbor_ids.add(edge["data"]["source"])

        return [
            el for el in current
            if el["data"].get("id") in neighbor_ids or
               el["data"].get("id") == node_id or
               (
                   "source" in el["data"] and
                   (el["data"]["source"] == node_id or el["data"]["target"] == node_id)
               )
        ]

    return current


# ======================================================================
#   CALLBACK: Trace Attack Path (from GRAPH_QUERIES)
# ======================================================================
@app.callback(
    Output("attack-path-panel", "children"),
    Output("neo4j-graph", "elements"),
    Output("last-attack-path", "data"),
    Input("attack-path-btn", "n_clicks"),
    [
        State("attack-start-node", "value"),
        State("attack-target-node", "value"),
        State("original-elements", "data"),
    ]
)
def trace_attack(n, start_node, target_node, original):

    if not n or not start_node or not target_node:
        return "", original, []

    q = GRAPH_QUERIES["Attack Path: Lateral Movement"].replace(
        "$START", start_node).replace("$END", target_node)

    try:
        driver = get_driver()
        with driver.session() as session:
            results = session.run(q)

            paths = []
            nodes = []
            edges = []

            for r in results:
                p = r["p"]
                paths.append(p)
                for node in p.nodes:
                    nodes.append({
                        "data": {
                            "id": str(node.id),
                            "label": node.get("name") or "",
                            "type": list(node.labels)[0]
                        }
                    })
                for rel in p.relationships:
                    edges.append({
                        "data": {
                            "id": str(rel.id),
                            "source": str(rel.start_node.id),
                            "target": str(rel.end_node.id),
                            "label": rel.type,
                        }
                    })

            elements = nodes + edges
            summary = f"Found {len(paths)} attack path(s)."

            return summary, elements, elements

    except Exception as e:
        return f"Error: {e}", original, []


# ======================================================================
#   CALLBACK: Export JSON / CSV / PNG
# ======================================================================
@app.callback(
    Output("neo4j-export-download", "data"),
    [
        Input("export-json-btn", "n_clicks"),
        Input("export-csv-btn", "n_clicks"),
    ],
    State("neo4j-graph", "elements"),
    prevent_initial_call=True
)
def export_graph(json_btn, csv_btn, elements):

    triggered = ctx.triggered_id

    if triggered == "export-json-btn":
        return dict(content=json.dumps(elements, indent=2), filename="neo4j_graph.json")

    if triggered == "export-csv-btn":
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["id", "label", "type", "source", "target"])

        for el in elements:
            d = el["data"]
            writer.writerow([
                d.get("id"),
                d.get("label"),
                d.get("type"),
                d.get("source"),
                d.get("target")
            ])

        return dict(content=output.getvalue(), filename="neo4j_graph.csv")

    return None



# ==========================================================
#  LAUNCH DASHBOARD
# ==========================================================
if __name__ == "__main__":
    print("✅ Dashboard ready on http://127.0.0.1:8050")
    app.run(host="0.0.0.0", port=8050, debug=True)
