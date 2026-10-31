#!/usr/bin/env python3

# -*- coding: utf-8 -*-
"""
Towson University — AI-Augmented Vulnerability Intelligence Dashboard
Fully integrated version (Batches 1–3 merged)
"""
# ==========================================================
#  IMPORTS & CONFIGURATION
# ==========================================================

import time
import requests
from pathlib import Path
from datetime import datetime
import os
import psutil
import pandas as pd
import plotly.express as px

# Dash Framework
import dash
from dash import Dash, html, dcc, Input, Output, State, no_update, dash_table
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

# Neo4j Integration
from neo4j import GraphDatabase
from neo4j_integration import (
    import_nmap_hosts_to_neo4j,
    enrich_cves_from_nvd,
    run_full_pipeline
)

# Audio / UX
import dash_daq as daq
from dash_extensions import EventListener

import base64
import xml.etree.ElementTree as ET
import json

# MITRE Loader
from mitre_loader import run_full_mitre_loader

# ==========================================================
# CYBER RANGE SERVICE IMPORTS
# ==========================================================
from cyber_range.services.neo4j_engine import Neo4jEngine
from cyber_range.services.killchain import KillChainGenerator
from cyber_range.services.digital_twin import DigitalTwin
from cyber_range.services.honeypot import HoneypotEngine
from cyber_range.services.exploit_ai import ExploitModeler
from cyber_range.services.wargame_ai import WargameAI
from cyber_range.services.ti_feed import ThreatIntelFeed
from cyber_range.services.remediation_ai import RemediationAI

# ==========================================================
# CYBER RANGE UI IMPORTS
# ==========================================================
from cyber_range.moduls.ui_killchain import killchain_tab, register_callbacks as kc_callbacks
from cyber_range.moduls.ui_digital_twin import digital_twin_tab, register_callbacks as dt_callbacks
from cyber_range.moduls.ui_honeypot import honeypot_tab, register_callbacks as hp_callbacks
from cyber_range.moduls.ui_exploit_ai import exploit_ai_tab, register_callbacks as exp_callbacks
from cyber_range.moduls.ui_wargame_ai import wargame_tab, register_callbacks as wg_callbacks
from cyber_range.moduls.ui_ti_feed import ti_feed_tab, register_callbacks as ti_callbacks
from cyber_range.moduls.ui_remediation import remediation_tab, register_callbacks as rm_callbacks


# ==========================================================
#  NEO4J CONFIGURATION (GLOBAL - REQUIRE THIS)
# ==========================================================
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"



# Automatically rebuild MITRE ATT&CK graph on startup
print("[APP] Running MITRE Enterprise Loader (STRICT)…")
run_full_mitre_loader()

DB_PATH = "/root/vuln_intel/vuln_intel.db"

def insert_finding(row):
    """
    Insert parsed finding into SQLite using your exact schema.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    sql = """
    INSERT INTO findings (
        asset_id, host, port, service, title, severity,
        cvss, cve_id, description, evidence, remediation,
        vuln_name, path, source, import_date, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    cur.execute(sql, row)
    conn.commit()
    conn.close()


def parse_nmap_xml(content):
    """
    Parse Nmap XML content → list of DB rows.
    """
    rows = []
    root = ET.fromstring(content)

    for host in root.findall("host"):
        addr = host.find("address").attrib["addr"]

        for port in host.findall(".//port"):
            portid = port.attrib.get("portid")
            service_el = port.find("service")

            service_name = service_el.attrib.get("name") if service_el is not None else "unknown"

            row = [
                None,                        # asset_id
                addr,                        # host
                portid,                      # port
                service_name,                # service
                f"{service_name} detected",  # title
                "info",                      # severity
                None,                        # cvss
                None,                        # cve_id
                None,                        # description
                None,                        # evidence
                None,                        # remediation
                service_name,                # vuln_name
                None,                        # path
                "nmap",                      # source
                datetime.now().strftime("%Y-%m-%d"),
                datetime.now().strftime("%H:%M:%S")
            ]
            rows.append(row)

    return rows


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

# ======================================================================
#   NEO4J GRAPH QUERIES FOR GRAPH INTELLIGENCE
# ======================================================================

GRAPH_QUERIES = {

    # ----------------------------------------------------------
    # 1) CORE RELATIONSHIP GRAPH QUERIES
    # ----------------------------------------------------------
    "Core Relationship Graphs": {

        "core_asset_service": """
            MATCH (a:Asset)-[r:HAS_SERVICE]->(s:Service)
            RETURN a, r, s
        """,

        "core_asset_vuln": """
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, v
        """,

        "core_service_vuln": """
            MATCH (s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN s, v
        """,

        "core_asset_dependency": """
            MATCH (a:Asset)-[r:DEPENDS_ON]->(b:Asset)
            RETURN a, r, b
        """,
    },

    # ----------------------------------------------------------
    # 2) VULNERABILITY GRAPH QUERIES
    # ----------------------------------------------------------
    "Vulnerability Graphs": {

        "vuln_all": """
            MATCH (v:Vulnerability)
            RETURN v
        """,

        "vuln_cvss_tiers": """
            MATCH (v:Vulnerability)
            RETURN v
        """,

        "vuln_exploitable": """
            MATCH (v:Vulnerability {exploitable: true})
            RETURN v
        """,

        "vuln_attack_surface": """
            MATCH p = (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN p
        """,
    },

    # ----------------------------------------------------------
    # 3) THREAT INTELLIGENCE GRAPH QUERIES
    # ----------------------------------------------------------
    "Threat Intelligence Graphs": {

        "ti_actor_exploit_vuln": """
            MATCH p = (ta:ThreatActor)-[:USES_EXPLOIT]->(e:Exploit)
                        -[:TARGETS]->(v:Vulnerability)
            RETURN p
        """,

        "ti_exploit_vuln": """
            MATCH (e:Exploit)-[:TARGETS]->(v:Vulnerability)
            RETURN e, v
        """,

        "ti_attack_techniques": """
            MATCH (tech:Technique)
            RETURN tech
        """,
    },

    # ----------------------------------------------------------
    # 4) ATTACK PATH GRAPH QUERIES
    # ----------------------------------------------------------
    "Attack Path Graphs": {

        "ap_shortest_to_cj": """
            MATCH (cj:CrownJewel)
            MATCH p = shortestPath((a:Asset)-[:HAS_VULNERABILITY*..5]->(cj))
            RETURN p
        """,

        "ap_privilege_escalation": """
            MATCH p = (u:User)-[:HAS_ACCESS]->(a:Asset)
                      -[:HAS_VULNERABILITY]->(v:Vulnerability)
                      -[:ALLOWS_PRIV_ESC]->(tech:Technique)
            RETURN p
        """,

        "ap_user_asset_vuln": """
            MATCH p = (u:User)-[:USES]->(a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN p
        """,

        "ap_lateral_movement": """
            MATCH p = (a1:Asset)-[:LATERAL_MOVE]->(a2:Asset)
            RETURN p
        """,
    },

    # ----------------------------------------------------------
    # 5) NETWORK GRAPH QUERIES
    # ----------------------------------------------------------
    "Network Graphs": {

        "net_segments_assets": """
            MATCH (n:NetworkSegment)-[:CONTAINS]->(a:Asset)
            RETURN n, a
        """,

        "net_firewall_paths": """
            MATCH p = (src:Asset)-[:ALLOWED_BY_FW*1..3]->(dst:Asset)
            RETURN p
        """,

        "net_exposure": """
            MATCH p = (a:Asset)-[:EXPOSED_TO]->(i:Internet)
            RETURN p
        """,
    },

    # ----------------------------------------------------------
    # 6) COMPLIANCE GRAPH QUERIES
    # ----------------------------------------------------------
    "Compliance Graphs": {

        "comp_control_gap_poam": """
            MATCH p = (c:Control)-[:HAS_GAP]->(g:Gap)-[:GENERATES_POAM]->(p:POAM)
            RETURN p
        """,

        "comp_control_families": """
            MATCH (cf:ControlFamily)-[:CONTAINS]->(c:Control)
            RETURN cf, c
        """,

        "comp_coverage": """
            MATCH (c:Control)-[:COVERED_BY]->(e:Evidence)
            RETURN c, e
        """,
    },

    # ----------------------------------------------------------
    # 7) CLOUD SECURITY GRAPH QUERIES
    # ----------------------------------------------------------
    "Cloud Security Graphs": {

        "cloud_asset_sg": """
            MATCH (ca:CloudAsset)-[:ASSIGNED_TO]->(sg:SecurityGroup)
            RETURN ca, sg
        """,

        "cloud_iam_paths": """
            MATCH p = (u:CloudUser)-[:ASSUMES_ROLE]->(r:Role)-[:PERMITS]->(a:CloudAsset)
            RETURN p
        """,

        "cloud_misconfigs": """
            MATCH (m:Misconfiguration)-[:AFFECTS]->(ca:CloudAsset)
            RETURN m, ca
        """,
    },
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

#def call_llm(prompt):
 #  # """Query OpenAI GPT model for natural language analysis."""
  #  if not OPENAI_API_KEY:
   #     return "⚠️ OPENAI_API_KEY not configured."
   # try:
    #    resp = requests.post(
     #       "https://api.openai.com/v1/chat/completions",
      #      headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
       #     json={"model": OPENAI_MODEL, "messages": [{"role": "user", "content": prompt}]},
        #    timeout=20,
       # )
       # data = resp.json()
       # return data["choices"][0]["message"]["content"]
   # except Exception as e:
    #    return f"LLM error: {e}"

from openai import OpenAI
client = OpenAI()

def call_llm(prompt):
    """Query OpenAI GPT model using the new Responses API."""
    try:
        response = client.responses.create(
            model="gpt-4o-mini",
            input=prompt
        )
        return response.output_text
    except Exception as e:
        return f"LLM error: {e}"


# ==========================================================
#  DASH LAYOUT WITH ALL TABS (SYSTEM → NEO4J → MITRE)
# ==========================================================
app.layout = dbc.Container(
    [
        html.H2(
            "Towson University — Vulnerability Intelligence Dashboard",
            className="text-warning mt-3 mb-4"
        ),

        dbc.Tabs(
            id="tabs",
            active_tab="system",
            children=[
                dbc.Tab(label="System", tab_id="system"),
                dbc.Tab(label="Vulnerabilities", tab_id="vuln"),
                dbc.Tab(label="LLM", tab_id="llm"),
                dbc.Tab(label="Chatbot", tab_id="chatbot"),
                dbc.Tab(label="Assessment", tab_id="assessment"),
                dbc.Tab(label="Reporting", tab_id="reporting"),
                dbc.Tab(label="Voice", tab_id="voice"),

                # NEW — Tab 8
                dbc.Tab(label="Neo4j Graph Intelligence", tab_id="neo4j"),

                # NEW — Tab 9
                dbc.Tab(label="MITRE ATT&CK Intelligence", tab_id="mitre"),
            ],
        ),

        html.Div(id="tab-content", className="mt-4")
    ],
    fluid=True
)

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
#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    ...


# ==========================================================
#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    ...



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

@app.callback(
    Output("llm-output", "children"),
    Input("llm-btn", "n_clicks"),
    State("llm-prompt", "value"),
    prevent_initial_call=True
)
def process_llm(n, text):
    if not text:
        raise dash.exceptions.PreventUpdate

    # -------------------------------------------------------------
    # 1. LOAD SCAN FINDINGS FROM SQLITE
    # -------------------------------------------------------------
    try:
        df = load_findings()  # your existing function
        findings_summary = df.to_string(index=False) if not df.empty else "No findings in SQLite."
    except Exception as e:
        findings_summary = f"SQLite Error: {e}"

    # -------------------------------------------------------------
    # 2. LOAD ATTACK GRAPH FROM NEO4J
    # -------------------------------------------------------------
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
        with driver.session() as session:
            q = """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a.host AS asset, s.name AS service, s.port AS port, v.id AS vuln, v.cvss AS cvss
            """
            graph_data = list(session.run(q))
            neo4j_context = "\n".join(str(r) for r in graph_data) if graph_data else "No Neo4j attack graph data."
        driver.close()
    except Exception as e:
        neo4j_context = f"Neo4j Error: {e}"

    # -------------------------------------------------------------
    # 3. LOAD RAW XML SNIPPETS (OPTIONAL CONTEXT)
    # -------------------------------------------------------------
    xml_context = ""
    try:
        xml_dir = "/root/vuln_intel/xml"
        if os.path.exists(xml_dir):
            files = [f for f in os.listdir(xml_dir) if f.endswith(".xml")]
            for f in files[:3]:  # only include first 3 XML files for context
                path = os.path.join(xml_dir, f)
                snippet = Path(path).read_text(errors="ignore")[:3000]  # limit size
                xml_context += f"\n--- XML: {f} ---\n{snippet}\n"
        else:
            xml_context = "No XML directory found."
    except Exception as e:
        xml_context = f"XML Error: {e}"

    # -------------------------------------------------------------
    # 4. COMBINE EVERYTHING INTO A SUPER-PROMPT
    # -------------------------------------------------------------
    full_context = f"""
You are an expert cybersecurity analyst. Answer ONLY using the data below.

========================
📌 USER QUESTION
========================
{text}

========================
📦 SQLite Vulnerability Findings
========================
{findings_summary}

========================
🕸 Neo4j Attack Graph Data
========================
{neo4j_context}

========================
📄 XML Scan Snippets (Nmap, Nessus, OpenVAS, ZAP)
========================
{xml_context}

Provide:
- A clean summary
- Important risks
- Top threats
- A remediation plan (if relevant)
"""

    # -------------------------------------------------------------
    # 5. SEND THE FULL CONTEXT TO GPT-4o
    # -------------------------------------------------------------
    return call_llm(full_context)




#@app.callback(Output("llm-output", "children"), Input("llm-btn", "n_clicks"), State("llm-prompt", "value"), prevent_initial_call=True)
#def process_llm(n, text):
 #   if not text:
  #      raise dash.exceptions.PreventUpdate
   # return call_llm(text)

# ==========================================================
#  TAB 4: CHATBOT (Placeholder)
# ==========================================================

chatbot_tab = html.Div([
    html.H3("🛡️ AI Security Analyst Assistant", className="text-warning mb-3"),

    # Chat display
    html.Div(id="chatbot-history", style={
        "height": "420px",
        "overflowY": "scroll",
        "border": "1px solid #444",
        "padding": "10px",
        "backgroundColor": "#111",
        "color": "white",
        "borderRadius": "8px"
    }),

    html.Br(),

    # Input + send
    dcc.Input(
        id="chatbot-input",
        type="text",
        placeholder="Ask a security question or issue a command...",
        style={"width": "70%", "padding": "10px"}
    ),
    dbc.Button("Send", id="chatbot-send", color="warning",
               style={"marginLeft": "10px"}),

    html.Br(), html.Br(),

    # File Upload Box
    dcc.Upload(
        id="chatbot-upload",
        children=html.Div(["Drag & Drop or Select Scan Files (XML)"]),
        style={
            "width": "90%", "height": "70px",
            "lineHeight": "70px",
            "borderWidth": "1px",
            "borderStyle": "dashed",
            "borderRadius": "5px",
            "textAlign": "center",
            "backgroundColor": "#222",
            "color": "white"
        },
        accept=".xml"
    ),

    html.Div(id="upload-status", className="text-info mt-2"),

], className="p-3")


# ==========================================================
#  TAB 5: ASSESSMENT
# ==========================================================

# ==========================================================
#  TAB: ADVANCED ASSESSMENT PIPELINE
# ==========================================================

assessment_tab = dbc.Container([

    html.H3("🧪 Automated Vulnerability Assessment", className="text-warning mb-3"),

    html.P("Select scanner or upload result files."),

    # Scanner selection
    dcc.Dropdown(
        id="scanner-select",
        options=[
            {"label": "Nmap (Network Discovery)", "value": "nmap"},
            {"label": "OpenVAS (Vulnerability Scan)", "value": "openvas"},
            {"label": "ZAP (Web Application Scan)", "value": "zap"},
            {"label": "Full Pipeline (Run Everything)", "value": "pipeline"},
        ],
        placeholder="Select scanner...",
        style={"width": "50%"}
    ),

    # Target input
    dcc.Input(
        id="target-ip",
        type="text",
        placeholder="Enter IP, hostname, or range (e.g., 192.168.1.0/24)",
        style={"width": "50%", "marginTop": "10px"}
    ),

    html.Br(), html.Br(),

    # Run scan
    dbc.Button("Run Scan", id="scan-btn", color="warning"),

    html.Br(), html.Br(),

    # File upload for XML / JSON
    html.H5("📁 Upload Scan Files (Nmap, Nessus, OpenVAS, ZAP)"),
    dcc.Upload(
        id="upload-scan-file",
        children=html.Div(["Drag & Drop or Select Scan File"]),
        style={
            "width": "70%", "height": "80px",
            "lineHeight": "80px", "borderWidth": "2px",
            "borderStyle": "dashed",
            "borderRadius": "5px", "textAlign": "center",
            "margin": "10px"
        },
        multiple=False
    ),


    html.Hr(),

    # Live log panel
    html.H4("📜 Scan Log Output", className="text-warning"),
    html.Div(
        id="scan-log",
        style={
            "backgroundColor": "#111", "color": "#EAAA00",
            "padding": "10px", "height": "300px",
            "overflowY": "scroll", "border": "1px solid #444"
        }
    ),

    html.Hr(),

    html.H4("⬇ Export Processed Results"),

    dbc.Button("Export JSON", id="export-json", color="primary", className="m-1"),
    dbc.Button("Export CSV", id="export-csv", color="secondary", className="m-1"),

    dcc.Download(id="download-json"),
    dcc.Download(id="download-csv"),

], fluid=True)

# ==========================================================
#  PLACEHOLDER TABS (Reporting, Voice, Attack)
# ==========================================================
reporting_tab = html.Div([html.H3("📄 Reporting (Under Development)")])
voice_tab = html.Div([html.H3("🎙️ Voice Assistant (Under Development)")])
attack_tab = html.Div([html.H3("🕸️ Attack Path Analysis (Neo4j Integration)")])


# ==========================================================
#  REPORTING TAB — Fully Functional
# ==========================================================
reporting_tab = html.Div([
    html.H3("📄 Automated Reporting", className="text-warning mb-3"),

    html.P("Generate compliance-ready reports based on parsed Nmap, Nessus, OpenVAS, and ZAP findings.",
           className="text-light"),

    # ----------------------------------------
    # PDF Report
    # ----------------------------------------
    html.H4("📘 Security Assessment Report", className="text-warning mt-4"),
    dbc.Button("Generate PDF Report", id="pdf-btn", color="warning", className="mb-3"),
    dcc.Download(id="pdf-download"),

    html.Hr(style={"borderColor": "#444"}),

    # ----------------------------------------
    # POA&M
    # ----------------------------------------
    html.H4("📝 POA&M (Plan of Action & Milestones)", className="text-warning mt-4"),
    dbc.Button("Generate POA&M CSV", id="poam-btn", color="danger", className="mb-3"),
    dcc.Download(id="poam-download"),

    html.Hr(style={"borderColor": "#444"}),

    # ----------------------------------------
    # NIST Mapping
    # ----------------------------------------
    html.H4("📚 NIST 800-53 Control Mapping", className="text-warning mt-4"),
    dbc.Button("Generate NIST Mapping", id="nist-btn", color="info", className="mb-3"),
    dcc.Download(id="nist-download"),

], className="p-4")


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

 

def neo4j_preset_graphs_tab():
    return dbc.Container([

        html.H2("Neo4j Graph Presets", className="mt-3 mb-4 text-info"),

        dbc.Row([
            # -------- LEFT SIDE BUTTONS ----------
            dbc.Col([

                dbc.Button("Show Asset Graph", id="btn-assets",
                           color="primary", className="mb-2 w-100"),

                dbc.Button("Show Vulnerability Graph", id="btn-vuln",
                           color="secondary", className="mb-2 w-100"),

                dbc.Button("Show Technique → Tactic", id="btn-tech-tac",
                           color="warning", className="mb-2 w-100"),

                dbc.Button("Show Techniques → Subtechniques", id="btn-subtech",
                           color="dark", className="mb-2 w-100"),

                dbc.Button("Show Attack Paths (Asset → Vuln → Technique → Tactic)",
                           id="btn-attack-path", color="danger", className="mb-2 w-100"),

                # ---------- LEGEND ----------
                html.Div([
                    html.H4("Legend", className="text-info mt-4"),
                    html.Div([
                        html.Div("🟦 Asset", style={"color": "#4A90E2", "font-size": "18px"}),
                        html.Div("🔴 Vulnerability", style={"color": "#D0021B", "font-size": "18px"}),
                        html.Div("🟧 Technique", style={"color": "#F5A623", "font-size": "18px"}),
                        html.Div("🟨 SubTechnique", style={"color": "#F8E71C", "font-size": "18px"}),
                        html.Div("🟪 Tactic", style={"color": "#9013FE", "font-size": "18px"}),
                        html.Div("➡ Relationship", style={"color": "#CCCCCC", "font-size": "18px"}),
                    ])
                ], className="mt-4 p-3 rounded", style={"background-color": "#1c1c1c"}),

            ], width=3),

            # ---------- RIGHT SIDE GRAPH ----------
            dbc.Col([

                # Tooltip Div (hidden by default)
                html.Div(id="cy-tooltip", style={
                    "position": "absolute",
                    "zIndex": 999,
                    "padding": "6px 10px",
                    "background": "#222",
                    "color": "white",
                    "border": "1px solid #555",
                    "borderRadius": "4px",
                    "display": "none",
                }),

                cyto.Cytoscape(
                    id="neo4j-preset-graph",
                    style={"height": "780px", "backgroundColor": "#111111"},
                    layout={"name": "cose", "animate": True},
                    elements=[],

                    stylesheet=[

                        # ----- GLOBAL NODE STYLE -----
                        {
                            "selector": "node",
                            "style": {
                                "label": "data(label)",
                                "font-size": "17px",
                                "color": "#FFFFFF",
                                "text-outline-width": 2,
                                "text-outline-color": "#333333",
                                "background-color": "#4A90E2",
                                "width": 50,
                                "height": 50,
                            }
                        },

                        {"selector": "[type='Asset']",
                         "style": {"background-color": "#4A90E2"}},

                        {"selector": "[type='Vulnerability']",
                         "style": {"background-color": "#D0021B"}},

                        {"selector": "[type='Technique']",
                         "style": {"background-color": "#F5A623"}},

                        {"selector": "[type='SubTechnique']",
                         "style": {"background-color": "#F8E71C", "color": "#000"}},

                        {"selector": "[type='Tactic']",
                         "style": {"background-color": "#9013FE"}},

                        # ----- EDGES -----
                        {
                            "selector": "edge",
                            "style": {
                                "width": 3,
                                "line-color": "#BBBBBB",
                                "target-arrow-color": "#BBBBBB",
                                "target-arrow-shape": "triangle",
                                "curve-style": "bezier",
                            }
                        },

                        # ----- SELECTED -----
                        {
                            "selector": ":selected",
                            "style": {
                                "border-width": 4,
                                "border-color": "#FFD700",
                                "background-color": "#FFF176",
                                "color": "#000",
                            }
                        }
                    ]
                )
            ], width=9)
        ])
    ], fluid=True)


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
# CALLBACK: Load Neo4j Graph Intelligence (Main Graph)
# ======================================================================

@app.callback(
    [
        Output("neo4j-graph", "elements"),
        Output("graph-title", "children", allow_duplicate=True)

    ],
    [
        Input("graph-category", "value"),
        Input("graph-type", "value")
    ],
    prevent_initial_call=True
)
def load_neo4j_graph(category, graph_type):
    from neo4j import GraphDatabase

    if not category or not graph_type:
        return [], "⚠ Select a graph type"

    # Get Cypher for selected graph
    cypher_query = GRAPH_QUERIES.get(category, {}).get(graph_type)
    if not cypher_query:
        return [], f"⚠ No query found for: {graph_type}"

    # Connect
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(uri, auth=("neo4j", "Adomaa12@"))

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            result = session.run(cypher_query)

            for record in result:
                # Path-based results
                if "p" in record:
                    path = record["p"]

                    for node in path.nodes:
                        nid = str(node.id)
                        if nid not in nodes:
                            nodes[nid] = {"data": {
                                "id": nid,
                                "label": node.get("name") or node.get("id") or list(node.labels)[0],
                                "type": list(node.labels)[0]
                            }}

                    for rel in path.relationships:
                        edges.append({"data": {
                            "source": str(rel.start_node.id),
                            "target": str(rel.end_node.id),
                            "label": rel.type
                        }})

                # Direct node/rel
                else:
                    for key, val in record.items():
                        if hasattr(val, "labels"):
                            nid = str(val.id)
                            nodes[nid] = {"data": {
                                "id": nid,
                                "label": val.get("name") or nid,
                                "type": list(val.labels)[0]
                            }}
                        if hasattr(val, "type"):
                            start, end = val.nodes
                            edges.append({"data": {
                                "source": str(start.id),
                                "target": str(end.id),
                            }})

    except Exception as e:
        return [], f"❌ Neo4j Error: {e}"

    finally:
        driver.close()

    return list(nodes.values()) + edges, f"📊 Graph View: {graph_type}"



# ======================================================================
#   CALLBACK: Load Neo4j Graph Elements Based on Graph Type
# ======================================================================

@app.callback(
    Output("neo4j-preset-graph", "elements"),
    [
        Input("btn-assets", "n_clicks"),
        Input("btn-vuln", "n_clicks"),
        Input("btn-tech-tac", "n_clicks"),
        Input("btn-subtech", "n_clicks"),
        Input("btn-attack-path", "n_clicks"),
    ],
     prevent_initial_call=True
)
def load_preset_graph(btn_assets, btn_vuln, btn_tech_tac, btn_subtech, btn_attack_path):

    # Determine which button fired
    ctx = dash.callback_context
    if not ctx.triggered:
        return []

    clicked = ctx.triggered[0]["prop_id"].split(".")[0]

    # Neo4j driver using your new constants
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # PRESET CYPHER QUERIES
    cypher_queries = {
        "btn-assets": """
            MATCH (a:Asset)-[r]->(b)
            RETURN a, r, b
        """,

        "btn-vuln": """
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, v
        """,

        "btn-tech-tac": """
            MATCH (tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN tech, tac
        """,

        "btn-subtech": """
            MATCH (p:Technique)-[:HAS_SUBTECHNIQUE]->(c:SubTechnique)
            RETURN p, c
        """,

        "btn-attack-path": """
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN a, v, tech, tac
        """,
    }

    query = cypher_queries.get(clicked)
    if not query:
        return []

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            results = session.run(query)

            for row in results:
                for key, val in row.items():

                    # Node
                    if hasattr(val, "labels"):
                        node_id = str(val.id)
                        label = list(val.labels)[0]
                        name = val.get("name") or val.get("id") or label

                        nodes[node_id] = {"data": {"id": node_id, "label": name}}

                    # Relationship
                    if hasattr(val, "type"):
                        start, end = val.nodes
                        edges.append({
                            "data": {
                                "source": str(start.id),
                                "target": str(end.id)
                            }
                        })

        driver.close()
        return list(nodes.values()) + edges

    except Exception as e:
        driver.close()
        print(f"[Preset Graph Error] {e}")
        return []

@app.callback(
    Output("cy-tooltip", "style"),
    Output("cy-tooltip", "children"),
    Input("neo4j-preset-graph", "mouseoverNodeData"),
    Input("neo4j-preset-graph", "mouseoverEdgeData"),
)
def show_tooltip(node, edge):

    # ----- Node Hover -----
    if node:
        return (
            {
                "position": "absolute",
                "zIndex": 999,
                "top": "20px",
                "left": "20px",
                "padding": "6px 10px",
                "background": "#222",
                "color": "white",
                "border": "1px solid #555",
                "borderRadius": "4px",
                "display": "block",
            },
            f"Node: {node.get('label', 'Unknown')}"
        )

    # ----- Edge Hover -----
    if edge:
        return (
            {
                "position": "absolute",
                "zIndex": 999,
                "top": "20px",
                "left": "20px",
                "padding": "6px 10px",
                "background": "#222",
                "color": "white",
                "border": "1px solid #555",
                "borderRadius": "4px",
                "display": "block",
            },
            f"Edge: {edge.get('label', 'relationship')}"
        )

    # ----- Nothing Hovered -----
    return {"display": "none"}, ""


    # --------------------------------------
    # 1. Map graph_type → Cypher query
    # --------------------------------------
    CYPHER_MAP = {

        # ---------------- CORE GRAPHS ----------------
        "core_asset_service": """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            RETURN a, s
        """,

        "core_asset_vuln": """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, s, v
        """,

        "core_service_vuln": """
            MATCH (s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN s, v
        """,

        # ---------------- VULN GRAPHS ----------------
        "vuln_all": """
            MATCH (v:Vulnerability)
            RETURN v
        """,

        "vuln_attack_surface": """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, s, v
        """,

        # ---------------- ATTACK PATH ----------------
        "ap_user_asset_vuln": """
            MATCH (u:User)-[:ACCESS]->(a:Asset)
            MATCH (a)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN u, a, s, v
        """,

        "ap_shortest_to_cj": """
            MATCH (cj:CrownJewel)
            MATCH p = shortestPath(
                (a:Asset)-[*..6]->(cj)
            )
            RETURN p
        """,

        # ---------------- THREAT INTEL ----------------
        "ti_attack_techniques": """
            MATCH (t:Tactic)<-[:PART_OF]-(tech:Technique)
            OPTIONAL MATCH (tech)<-[:MAPS_TO_TECHNIQUE]-(v:Vulnerability)
            RETURN t, tech, v
        """,
    }

    if graph_type not in CYPHER_MAP:
        return [], f"⚠ No query defined for graph type: {graph_type}"

    cypher_query = CYPHER_MAP[graph_type]

    # --------------------------------------
    # 2. Connect to Neo4j
    # --------------------------------------
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "Adomaa12@"

    driver = GraphDatabase.driver(uri, auth=(user, password))

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            result = session.run(cypher_query)

            # --------------------------------------
            # 3. Process Neo4j records → Nodes + Edges
            # --------------------------------------
            for record in result:

                # Case A: query returns a PATH
                if "p" in record.keys():
                    path = record["p"]
                    for node in path.nodes:
                        nid = str(node.id)
                        if nid not in nodes:
                            nodes[nid] = {
                                "data": {
                                    "id": nid,
                                    "label": node.get("host") or node.get("name") or node.get("id"),
                                    "type": list(node.labels)[0]
                                }
                            }

                    for rel in path.relationships:
                        edges.append({
                            "data": {
                                "source": str(rel.start_node.id),
                                "target": str(rel.end_node.id),
                                "label": rel.type
                            }
                        })

                # Case B: individual nodes
                else:
                    for key in record.keys():
                        node = record[key]
                        if hasattr(node, "id"):
                            nid = str(node.id)
                            if nid not in nodes:
                                nodes[nid] = {
                                    "data": {
                                        "id": nid,
                                        "label": node.get("host") or node.get("name") or node.get("id"),
                                        "type": list(node.labels)[0]
                                    }
                                }

            elements = list(nodes.values()) + edges

            return elements, f"📊 Graph View: {graph_type}"

    except Exception as e:
        return [], f"❌ Neo4j Error: {e}"

    finally:
        driver.close()



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
    function(data) {
        if (!data) return window.dash_clientside.no_update;

        // Fallback position values since context tap is unavailable
        const menu = document.getElementById("context-menu");
        menu.style.left = "200px";   // static/fixed position
        menu.style.top = "200px";
        menu.style.display = "block";

        return data.id;
    }
    """,
    Output("right-click-node", "data"),
    Input("neo4j-graph", "tapNodeData")
)


# ======================================================================
#   CALLBACK: Hide, Isolate, Reset Graph
# ======================================================================
#@app.callback(
 #   Output("neo4j-graph", "elements"),
  #  [
   #     Input("ctx-hide", "n_clicks"),
    #    Input("ctx-reset", "n_clicks"),
     #   Input("ctx-neighbors", "n_clicks"),
      #  Input("ctx-isolate", "n_clicks"),
   # ],
   # [
    #    State("right-click-node", "data"),
     #   State("original-elements", "data"),
      #  State("neo4j-graph", "elements"),
   # ],
#)

@app.callback(
    Output("neo4j-graph", "elements", allow_duplicate=True),
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
    prevent_initial_call=True
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
#  FINAL APP LAYOUT (REQUIRED)
# ==========================================================

#app.layout = dbc.Container(
 #   [
  #      dbc.Tabs(
   #         id="tabs",
    #        active_tab="system",

     #       children=[
      #          dbc.Tab(system_health_layout(), label="System", tab_id="system"),
       #         dbc.Tab(vulnerability_tab(), label="Vulnerabilities", tab_id="vuln"),
        #        dbc.Tab(llm_tab, label="LLM", tab_id="llm"),
         #       dbc.Tab(chatbot_tab, label="Chatbot", tab_id="chatbot"),
          #      dbc.Tab(assessment_tab, label="Assessment", tab_id="assessment"),
           #     dbc.Tab(reporting_tab, label="Reporting", tab_id="reporting"),
            #    dbc.Tab(voice_tab, label="Voice", tab_id="voice"),
             #   dbc.Tab(neo4j_graphs_tab(), label="Neo4j Graph Intelligence", tab_id="neo4j"),

                # NEW MITRE TAB (placeholder for now)
              #  dbc.Tab(
               #     html.Div(id="mitre-tab-content", className="p-3 text-light"),
                #    label="MITRE ATT&CK Intelligence",
                 #   tab_id="mitre"
               # ),
           # ],
       # ),

        #html.Div(id="tabs-content", className="p-4")
    #],
    #fluid=True,
#)


# ======================================================================
#  BATCH 8 — MITRE ATT&CK INTELLIGENCE TAB (UI LAYOUT)
# ======================================================================

def mitre_tab_layout():
    return dbc.Container([

        html.H2("MITRE ATT&CK Intelligence", className="text-info mt-3 mb-4"),



        # ===============================
        # TOP SEARCH + FILTER BAR
        # ===============================
        dbc.Row([
            dbc.Col([
                html.Label("Search Technique / Tactic"),
                dcc.Input(
                    id="mitre-search-box",
                    type="text",
                    placeholder="Example: T1059, Discovery, WMI, Privilege Escalation…",
                    debounce=True,
                    className="form-control"
                )
            ], width=6),

            dbc.Col([
                html.Label("Filter by Tactic"),
                dcc.Dropdown(
                    id="mitre-tactic-dropdown",
                    options=[],
                    placeholder="Choose Tactic (TAxxxx)",
                    clearable=True
                )
            ], width=6),
        ], className="mb-4"),

        html.Hr(),

        # ===============================
        # GRAPHS + DETAILS PANEL
        # ===============================
        dbc.Row([
            dbc.Col([
                html.H4("Technique–Tactic Graph"),
                cyto.Cytoscape(
                    id="mitre-cytoscape",
                    layout={"name": "cose"},
                    style={"height": "700px"},
                    elements=[],
                    stylesheet=[
                        {"selector": ".tactic", "style": {"background-color": "#ffbf00", "label": "data(label)"}},
                        {"selector": ".technique", "style": {"background-color": "#00aaff", "label": "data(label)"}},
                        {"selector": ".subtech", "style": {"background-color": "#7f00ff", "label": "data(label)"}},
                    ]
                ),
            ], width=8),

            dbc.Col([
                html.H4("ATT&CK Item Details"),
                dbc.Card([
                    dbc.CardBody([
                        html.H5(id="mitre-detail-title", className="text-warning"),
                        html.Div(id="mitre-detail-body", className="mt-2")
                    ])
                ])
            ], width=4),
        ]),

        html.Hr(className="mt-5"),

        # ===============================
        # 3 NEW PANELS: HEATMAP + CVE MAPPING + ATTACK PATHS
        # ===============================
        dbc.Row([
            dbc.Col([
                html.H4("🔥 ATT&CK Technique Heatmap (Counts by Tactic)"),
                dcc.Graph(id="mitre-heatmap")
            ], width=6),

            dbc.Col([
                html.H4("🔗 CVE → MITRE Technique Mapping"),
                dcc.Input(
                    id="mitre-cve-box",
                    type="text",
                    placeholder="Example: CVE-2021-44228",
                    debounce=True,
                    className="form-control"
                ),
                html.Div(id="mitre-cve-results", className="mt-3")
            ], width=6),
        ], className="mt-4"),

        html.Hr(),

        dbc.Row([
            dbc.Col([
                html.H4("🚀 Attack Path Simulation"),
                html.P("Map: Asset → Vulnerability → Technique → Tactic"),
                dcc.Input(
                    id="mitre-attack-path-asset",
                    type="text",
                    placeholder="Hostname, IP, or Asset ID",
                    debounce=True,
                    className="form-control"
                ),
                dcc.Graph(id="mitre-attack-path-graph")
            ], width=12)
        ])
    ], fluid=True)


# ==========================================================
#  TAB ROUTER — Load Content Based on Active Tab
# ==========================================================
#@app.callback(
 #   Output("tabs-content", "children"),
  #  Input("tabs", "active_tab")
#)
#def render_tab_content(active_tab):

 #   if active_tab == "system":
  #      return system_health_layout()

   # elif active_tab == "vuln":
    #    return vulnerability_tab()

    #elif active_tab == "llm":
     #   return llm_tab

    #elif active_tab == "chatbot":
     #   return chatbot_tab

    #elif active_tab == "assessment":
     #   return assessment_tab

    #elif active_tab == "reporting":
     #   return reporting_tab

   # elif active_tab == "voice":
    #    return voice_tab

    #elif active_tab == "neo4j":
     #   return neo4j_graphs_tab()

    #elif active_tab == "mitre":
      #  return html.Div(
       #     [
        #        html.H3("MITRE ATT&CK Intelligence (Coming Soon)", className="text-warning"),
         #       html.P("This tab will show techniques, sub-techniques, heatmaps, mappings to assets, and attack paths.")
          #  ],
           # className="p-4"
#        )

 #   return html.Div("Tab not found.", className="text-danger")


# ==========================================================
#  BATCH 1 — MITRE ATT&CK DEFINITIONS (TACTICS & TECHNIQUES)
# ==========================================================

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
}

# --------------------------------------------------------------
# MITRE TECHNIQUES (subset, expandable)
# --------------------------------------------------------------
MITRE_TECHNIQUES = {
    "T1003": "OS Credential Dumping",
    "T1059": "Command and Scripting Interpreter",
    "T1046": "Network Service Scanning",
    "T1021": "Remote Services",
    "T1069": "Permission Groups Discovery",
    "T1078": "Valid Accounts",
    "T1105": "Ingress Tool Transfer",
    "T1204": "User Execution",
    "T1566": "Phishing",
    "T1486": "Data Encrypted for Impact",
}

# --------------------------------------------------------------
# TECHNIQUE → TACTIC MAPPING
# --------------------------------------------------------------
MITRE_TECHNIQUE_TO_TACTIC = {
    "T1003": "TA0006",  # Credential Access
    "T1059": "TA0002",  # Execution
    "T1046": "TA0007",  # Discovery
    "T1021": "TA0008",  # Lateral Movement
    "T1069": "TA0007",  # Discovery
    "T1078": "TA0001",  # Initial Access
    "T1105": "TA0002",  # Execution
    "T1204": "TA0002",  # Execution
    "T1566": "TA0001",  # Initial Access
    "T1486": "TA0010",  # Exfiltration / Impact
}

# --------------------------------------------------------------
# TECHNIQUE DETAILS / LONG DESCRIPTION
# --------------------------------------------------------------
MITRE_TECHNIQUE_DETAILS = {
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries dump credentials from operating systems using LSASS, SAM, or other sources.",
        "link": "https://attack.mitre.org/techniques/T1003/"
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Attackers run commands via PowerShell, Bash, Python, or other CLI interfaces.",
        "link": "https://attack.mitre.org/techniques/T1059/"
    },
    "T1046": {
        "name": "Network Service Scanning",
        "description": "Attackers scan ports, services, and network endpoints to map attack surfaces.",
        "link": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1021": {
        "name": "Remote Services",
        "description": "Adversaries laterally move using SMB, SSH, WinRM, etc.",
        "link": "https://attack.mitre.org/techniques/T1021/"
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "description": "Attackers enumerate user groups and permissions.",
        "link": "https://attack.mitre.org/techniques/T1069/"
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Attackers use legitimate credentials to evade defenses.",
        "link": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "description": "Malware, payloads, or tools transferred into environment.",
        "link": "https://attack.mitre.org/techniques/T1105/"
    },
    "T1204": {
        "name": "User Execution",
        "description": "Execution triggered by a user action such as opening an attachment.",
        "link": "https://attack.mitre.org/techniques/T1204/"
    },
    "T1566": {
        "name": "Phishing",
        "description": "Adversaries send malicious emails to users.",
        "link": "https://attack.mitre.org/techniques/T1566/"
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "description": "Ransomware encrypts files or systems to disrupt availability.",
        "link": "https://attack.mitre.org/techniques/T1486/"
    },
}


# ==========================================================
#  BATCH 2 — MITRE DATA LAYER (NEO4J CORRELATION ENGINE)
# ==========================================================

def insert_mitre_into_neo4j():
    """
    Populates Neo4j with MITRE Tactic + Technique nodes
    and links techniques to their parent tactic.
    This only needs to run once, but is safe to run multiple times.
    """
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687",
                                      auth=("neo4j", "Adomaa12@"))

        with driver.session() as session:

            # ---------------------------
            # Create MITRE Tactic Nodes
            # ---------------------------
            for tid, tname in MITRE_TACTICS.items():
                session.run("""
                    MERGE (t:Tactic {id: $id})
                    SET t.name = $name
                """, id=tid, name=tname)

            # ---------------------------
            # Create MITRE Technique Nodes
            # ---------------------------
            for tech_id, tech_name in MITRE_TECHNIQUES.items():
                detail = MITRE_TECHNIQUE_DETAILS.get(tech_id, {})
                session.run("""
                    MERGE (x:Technique {id: $id})
                    SET x.name = $name,
                        x.description = $desc,
                        x.link = $link
                """, id=tech_id,
                     name=tech_name,
                     desc=detail.get("description", ""),
                     link=detail.get("link", ""))

            # ---------------------------
            # Link Technique → Tactic
            # ---------------------------
            for tech, tactic in MITRE_TECHNIQUE_TO_TACTIC.items():
                session.run("""
                    MATCH (tech:Technique {id: $tech})
                    MATCH (tac:Tactic {id: $tactic})
                    MERGE (tech)-[:PART_OF]->(tac)
                """, tech=tech, tactic=tactic)

        driver.close()
        print("✅ MITRE data inserted into Neo4j")

    except Exception as e:
        print(f"❌ MITRE insertion error: {e}")


def correlate_cves_to_mitre():
    import requests
    import json

    print("[+] Downloading MITRE CVE → ATT&CK mapping...")

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/relationships.json"

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        raw_text = resp.text.strip()

        # ---------------------------------------------------------
        # FIX: The MITRE file is NDJSON (each line is a JSON object)
        # ---------------------------------------------------------
        relationships = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                relationships.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # Ignore malformed lines

        print(f"[+] Parsed {len(relationships)} MITRE relationships.")

    except Exception as e:
        print("[!] MITRE correlation failed while downloading:", e)
        return

    # ---------------------------------------------------------
    # Insert MITRE → CVE relationships into Neo4j
    # ---------------------------------------------------------
    try:
        driver = get_driver()
        with driver.session() as session:

            for rel in relationships:
                src = rel.get("source_ref")
                dst = rel.get("target_ref")

                if not src or not dst:
                    continue

                # Only handle Technique → CVE mappings
                if src.startswith("attack-pattern") and "cve" in dst.lower():
                    session.run("""
                        MATCH (tech:Technique {id:$tech})
                        MATCH (v:Vulnerability {id:$cve})
                        MERGE (v)-[:MAPS_TO_TECHNIQUE]->(tech)
                    """, tech=src, cve=dst.upper())

        print("[+] MITRE CVE correlation successfully saved to Neo4j.")

    except Exception as e:
        print("[!] MITRE correlation failed:", e)


# ======================================================================
#  BATCH 3 — TAB 9: MITRE ATT&CK INTELLIGENCE LAYOUT (UI PANEL)
# ======================================================================

def mitre_tab_layout():
    return html.Div(
        [
            # ----------------------------------------------------------
            # TITLE & DESCRIPTION
            # ----------------------------------------------------------
            html.H2("🧩 MITRE ATT&CK Intelligence Portal",
                    className="text-warning mb-2",
                    style={"fontWeight": "bold"}),

            html.P(
                "Explore tactics, techniques, sub-techniques, and their mapped vulnerabilities "
                "directly from your Neo4j knowledge graph.",
                className="text-light",
                style={"opacity": "0.85", "fontSize": "18px"}
            ),

            html.Hr(style={"borderColor": "#444"}),

            # ----------------------------------------------------------
            # DROPDOWNS FOR TACTIC → TECHNIQUE
            # ----------------------------------------------------------
            html.Div(
                [
                    html.Label("Select MITRE Tactic:", className="text-warning"),
                    dcc.Dropdown(
                        id="mitre-tactic",
                        options=[{"label": MITRE_TACTICS[k], "value": k} for k in MITRE_TACTICS],
                        placeholder="TA0001 – TA0011",
                        style={"width": "60%", "color": "black", "marginBottom": "20px"},
                        clearable=True,
                    ),

                    html.Label("Select Technique (Optional):", className="text-warning"),
                    dcc.Dropdown(
                        id="mitre-technique",
                        options=[],  # Filled dynamically
                        placeholder="Technique (e.g., T1059)",
                        style={"width": "60%", "color": "black", "marginBottom": "20px"},
                        clearable=True,
                    ),

                    dbc.Button(
                        "🔍 Load MITRE Graph",
                        id="mitre-load-btn",
                        color="warning",
                        className="mt-2 mb-4",
                    ),
                ]
            ),

            # ----------------------------------------------------------
            # GRAPH TITLE
            # ----------------------------------------------------------
            html.Div(
                id="mitre-graph-title",
                className="text-warning mb-3",
                style={"fontSize": "22px", "fontWeight": "bold"},
            ),

            # ----------------------------------------------------------
            # MITRE GRAPH PANEL
            # ----------------------------------------------------------
            cyto.Cytoscape(
                id="mitre-graph",
                layout={"name": "cose"},
                style={
                    "width": "100%",
                    "height": "650px",
                    "backgroundColor": "#0d0d0d",
                    "border": "1px solid #333",
                    "borderRadius": "10px",
                },
                elements=[],
                stylesheet=[
                    # General node style
                    {
                        "selector": "node",
                        "style": {
                            "label": "data(label)",
                            "font-size": "12px",
                            "color": "white",
                            "background-color": "#666",
                            "text-outline-color": "#222",
                            "text-outline-width": 1,
                        },
                    },
                    {"selector": "node[type='Tactic']", "style": {"background-color": "#FF5733"}},
                    {"selector": "node[type='Technique']", "style": {"background-color": "#8E44AD"}},
                    {"selector": "node[type='SubTechnique']", "style": {"background-color": "#3498DB"}},
                    {"selector": "node[type='Vulnerability']", "style": {"background-color": "#C0392B"}},
                    {
                        "selector": "edge",
                        "style": {
                            "line-color": "#EAAA00",
                            "width": 2,
                            "target-arrow-shape": "triangle",
                            "target-arrow-color": "#EAAA00",
                        },
                    },
                ],
            ),

            html.Br(),

            # ----------------------------------------------------------
            # RAW JSON (OPTIONAL)
            # ----------------------------------------------------------
            html.Div(
                [
                    html.H4("🗂 Raw MITRE Data (Debugging)", className="text-warning"),
                    html.Pre(
                        id="mitre-raw-json",
                        style={
                            "whiteSpace": "pre-wrap",
                            "backgroundColor": "#111",
                            "color": "#EAAA00",
                            "padding": "10px",
                            "border": "1px solid #333",
                            "borderRadius": "6px",
                            "fontSize": "12px",
                            "display": "none",  # Hidden by default
                        },
                    ),
                ],
                className="mt-4",
            ),
        ],
        style={"padding": "20px"},
    )






# ======================================================================
# FIXED MITRE CALLBACKS — NO get_driver(), NO invalid queries
# ======================================================================

def neo_driver():
    return GraphDatabase.driver("bolt://localhost:7687",
                                auth=("neo4j", "Adomaa12@"))

@app.callback(
    Output("mitre-technique", "options"),
    Input("mitre-tactic", "value"),
)
def update_mitre_techniques_fixed(tactic_id):

    if not tactic_id:
        return []

    try:
        driver = neo_driver()
        with driver.session() as session:
            q = """
            MATCH (tech:Technique)-[:PART_OF]->(t:Tactic {id:$id})
            RETURN tech.id AS id, tech.name AS name
            ORDER BY id
            """
            result = session.run(q, id=tactic_id)
            return [{"label": r["name"], "value": r["id"]} for r in result]

    except Exception as e:
        print("[MITRE] Technique load error:", e)
        return []


@app.callback(
    Output("mitre-graph", "elements"),
    [
        Input("mitre-load-btn", "n_clicks"),
        State("mitre-tactic", "value"),
        State("mitre-technique", "value"),
    ],
    prevent_initial_call=True,
)
def load_mitre_graph_fixed(n_clicks, tactic_id, technique_id):

    if not tactic_id and not technique_id:
        return []

    driver = neo_driver()

    if tactic_id and technique_id:
        cypher = """
        MATCH (t:Tactic {id:$tac})
        MATCH (tech:Technique {id:$tech})-[:PART_OF]->(t)
        OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
        RETURN t, tech, v
        """
    elif tactic_id:
        cypher = """
        MATCH (t:Tactic {id:$tac})
        MATCH (tech:Technique)-[:PART_OF]->(t)
        RETURN t, tech
        """
    else:
        cypher = """
        MATCH (tech:Technique {id:$tech})
        OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
        RETURN tech, v
        """

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            rows = session.run(cypher, tac=tactic_id, tech=technique_id)

            for rec in rows:
                for k in rec.keys():
                    node = rec[k]
                    if not node:
                        continue

                    nid = str(node.id)
                    if nid not in nodes:
                        nodes[nid] = {
                            "data": {
                                "id": nid,
                                "label": node.get("name") or node.get("id"),   # FIXED
                                "type": list(node.labels)[0],
                            }
                        }

            # Relationship fetch
            if tactic_id and technique_id:
                rel_query = """
                MATCH p=(tech:Technique {id:$tech})-[:PART_OF]->(t:Tactic {id:$tac})
                OPTIONAL MATCH p2=(v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
                RETURN p, p2
                """
            elif tactic_id:
                rel_query = """
                MATCH p=(tech:Technique)-[:PART_OF]->(t:Tactic {id:$tac})
                RETURN p
                """
            else:
                rel_query = """
                MATCH p=(tech:Technique {id:$tech})
                OPTIONAL MATCH p2=(v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
                RETURN p, p2
                """

            rels = session.run(rel_query, tac=tactic_id, tech=technique_id)

            for rec in rels:
                for key in rec.keys():
                    if rec[key] is None:
                        continue
                    path = rec[key]
                    for rel in path.relationships:
                        edges.append({
                            "data": {
                                "id": str(rel.id),
                                "source": str(rel.start_node.id),
                                "target": str(rel.end_node.id),
                                "label": rel.type
                            }
                        })

        return list(nodes.values()) + edges

    except Exception as e:
        print("[MITRE ERROR FIXED]", e)
        return []

    finally:
        driver.close()



# ======================================================================
#  BATCH 5 — MITRE ↔ CVE ↔ Neo4j Correlation Engine
# ======================================================================

def correlate_cves_to_mitre():
    """
    Connects existing Nmap/OpenVAS/ZAP/Burp CVEs inside Neo4j
    to MITRE Techniques (Txxxx) using public CVE → MITRE mappings.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "Adomaa12@")
        )

        # -------------------------------------------------------------
        # 1) Pull MITRE CVE → Technique mapping from official source
        # -------------------------------------------------------------
        print("[+] Downloading MITRE CVE → ATT&CK mapping...")
        mapping_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-mapping.json"

        mapping_json = requests.get(mapping_url, timeout=20).json()

        # Each entry: {"cve": "CVE-XXXX-YYYY", "techniqueID": "T####"}
        cve_map = mapping_json.get("CVE_mappings", [])

        print(f"[+] Loaded {len(cve_map)} MITRE mappings.")

        # -------------------------------------------------------------
        # 2) Insert relationships into Neo4j
        # -------------------------------------------------------------
        with driver.session() as session:
            for entry in cve_map:
                cve = entry.get("cve")
                technique = entry.get("techniqueID")

                if not cve or not technique:
                    continue

                session.run(
                    """
                    MATCH (v:Vulnerability {id: $cve})
                    MATCH (t:Technique {id: $tech})
                    MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
                    """,
                    cve=cve,
                    tech=technique
                )

        print("[+] CVE ↔ MITRE technique correlation completed.")

    except Exception as e:
        print("[!] MITRE correlation failed:", e)



# ======================================================================
#  BATCH 5B — Insert MITRE ATT&CK Ontology into Neo4j
# ======================================================================

def insert_mitre_into_neo4j():
    """
    Loads MITRE ATT&CK tactics, techniques, and sub-techniques into Neo4j.
    ONLY needs to be run once.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "Adomaa12@")
        )

        print("[+] Loading MITRE ATT&CK Data into Neo4j...")

        # ---------------------------------------------------------
        # Download the official MITRE ATT&CK Enterprise STIX dataset
        # ---------------------------------------------------------
        mitre_url = (
            "https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json"
        )
        data = requests.get(mitre_url, timeout=20).json()
        objects = data.get("objects", [])

        with driver.session() as session:

            for obj in objects:
                stix_type = obj.get("type")
                stix_id = obj.get("id")
                name = obj.get("name")

                # =============================
                # TACTIC
                # =============================
                if stix_type == "x-mitre-tactic":
                    session.run(
                        """
                        MERGE (t:Tactic {id: $id})
                        SET t.label = $name
                        """,
                        id=obj["external_references"][0]["external_id"],
                        name=name,
                    )

                # =============================
                # TECHNIQUE
                # =============================
                if stix_type == "attack-pattern":
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id")
                            session.run(
                                """
                                MERGE (t:Technique {id: $id})
                                SET t.label = $name
                                """,
                                id=tech_id,
                                name=name,
                            )

                # =============================
                # SUB-TECHNIQUE (T####.###)
                # =============================
                # Format contains a dot when it's a sub-technique
                if stix_type == "attack-pattern":
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tid = ref.get("external_id")
                            if "." in tid:
                                sub_tid = tid
                                parent_tid = tid.split(".")[0]
                                session.run(
                                    """
                                    MATCH (parent:Technique {id: $parent})
                                    MERGE (s:SubTechnique {id: $child})
                                    SET s.label = $name
                                    MERGE (parent)-[:HAS_SUBTECHNIQUE]->(s)
                                    """,
                                    parent=parent_tid,
                                    child=sub_tid,
                                    name=name,
                                )

        print("[+] MITRE ATT&CK data imported successfully!")

    except Exception as e:
        print("[!] Failed to insert MITRE ATT&CK data:", e)


# ======================================================================
#  BATCH 6 — MITRE ATT&CK ANALYTICS ENGINE (PhD Research Version)
# ======================================================================

def mitre_get_techniques_by_tactic(tactic_id):
    """
    Returns all Techniques belonging to a given MITRE Tactic (TA000X).
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH (ta:Tactic {id: $tactic})<-[:BELONGS_TO]-(tech:Technique)
                RETURN tech.id AS id, tech.label AS name
                ORDER BY tech.id
                """,
                tactic=tactic_id
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE tactic lookup error:", e)
        return []


def mitre_get_cves_for_technique(tech_id):
    """
    Returns all CVEs mapped to a MITRE Technique.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t:Technique {id: $tech})
                RETURN v.id AS cve, v.cvss AS cvss
                ORDER BY v.id
                """,
                tech=tech_id
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE CVE lookup error:", e)
        return []


def mitre_get_attack_chains(target_asset=None):
    """
    Returns likely attack chains based on MITRE + CVE + Graph Structure.
    Used for lateral movement, privilege escalation, and kill chain modeling.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )

        with driver.session() as session:

            # ===============================================
            # GENERAL ATTACK CHAIN QUERY
            # ===============================================
            query = """
            MATCH p=(u:User)-[:ACCESS]->(a:Asset)-[:RUNS_SERVICE]->(s:Service)
                  -[:HAS_VULNERABILITY]->(v:Vulnerability)
                  -[:MAPS_TO_TECHNIQUE]->(t:Technique)
            RETURN p LIMIT 25
            """

            if target_asset:
                query = query.replace(
                    "RETURN p LIMIT 25",
                    "WHERE a.host = $asset RETURN p LIMIT 25"
                )

            results = session.run(query, asset=target_asset)

            chains = []
            for record in results:
                path = record["p"]
                chain = []
                for node in path.nodes:
                    chain.append({
                        "id": node.get("id") or node.get("name"),
                        "type": list(node.labels)[0]
                    })
                chains.append(chain)

            return chains

    except Exception as e:
        print("[!] Attack chain inference failed:", e)
        return []


def mitre_frequency_heatmap():
    """
    Produces a MITRE Technique frequency map:
    Technique → number of CVEs mapped.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
                RETURN t.id AS id, t.label AS name, COUNT(v) AS cve_count
                ORDER BY cve_count DESC
                LIMIT 50
                """
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE frequency error:", e)
        return []


def mitre_privilege_escalation_paths():
    """
    Query to identify Privilege Escalation patterns:
    Vulnerability → Technique → Target Privilege
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH p=(v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->
                         (t:Technique)-[:HAS_SUBTECHNIQUE*0..1]->
                         (st:SubTechnique)
                WHERE t.id STARTS WITH 'T' AND st.id STARTS WITH 'T'
                RETURN DISTINCT t.id AS technique,
                       t.label AS name,
                       COLLECT(DISTINCT v.id)[0..10] AS sample_cves
                LIMIT 40
                """
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE PrivEsc error:", e)
        return []


# ======================================================================
#  BATCH 7 — MITRE AI CALLBACK ENGINE (PhD-Level)
# ======================================================================

@app.callback(
    [
        Output("mitre-techniques-table", "data"),
        Output("mitre-cve-table", "data"),
        Output("mitre-ai-output", "children"),
    ],
    [
        Input("mitre-tactic-dropdown", "value"),
        Input("mitre-technique-dropdown", "value"),
        Input("mitre-ai-btn", "n_clicks"),
    ],
    [
        State("mitre-analysis-input", "value"),
    ],
    prevent_initial_call=True
)
def mitre_ai_workflow(tactic_id, technique_id, ai_click, user_prompt):

    triggered = ctx.triggered_id

    # ------------------------------------------------------
    # 1) USER SELECTED A MITRE TACTIC
    # ------------------------------------------------------
    if triggered == "mitre-tactic-dropdown":
        if not tactic_id:
            return [], [], ""
        techniques = mitre_get_techniques_by_tactic(tactic_id)
        return techniques, [], ""

    # ------------------------------------------------------
    # 2) USER SELECTED A TECHNIQUE
    # ------------------------------------------------------
    if triggered == "mitre-technique-dropdown":
        if not technique_id:
            return [], [], ""
        cves = mitre_get_cves_for_technique(technique_id)
        return no_update, cves, ""

    # ------------------------------------------------------
    # 3) RUN FULL AI ANALYSIS
    # ------------------------------------------------------
    if triggered == "mitre-ai-btn":
        if not user_prompt:
            return no_update, no_update, "⚠ Please enter a question."

        # --------------------------------------------------
        # 3.1 — GPT-4o
        # --------------------------------------------------
        gpt_answer = call_llm(
            f"MITRE ATT&CK Analysis Request:\n"
            f"Tactic: {tactic_id}\n"
            f"Technique: {technique_id}\n"
            f"Question: {user_prompt}\n"
        )

        # --------------------------------------------------
        # 3.2 — Vulners API
        # --------------------------------------------------
        try:
            vulners_resp = requests.get(
                "https://vulners.com/api/v3/search/lucene/",
                params={"query": user_prompt, "size": 5},
                headers={"X-Api-Key": os.getenv("VULNERS_API_KEY")},
                timeout=10
            ).json()
            vulners_text = json.dumps(vulners_resp, indent=2)
        except:
            vulners_text = "⚠ Vulners API unavailable."

        # --------------------------------------------------
        # 3.3 — Exploit-DB (searchsploit)
        # --------------------------------------------------
        try:
            proc = subprocess.run(
                ["searchsploit", user_prompt, "--json"],
                capture_output=True,
                text=True,
            )
            exploit_text = proc.stdout
        except:
            exploit_text = "⚠ searchsploit unavailable."

        # --------------------------------------------------
        # 3.4 — Build Unified Output Panel
        # --------------------------------------------------
        ai_panel = html.Div([
            html.H4("🧠 GPT-4o Analysis", className="text-warning"),
            html.Pre(gpt_answer, style=_mitre_panel_style()),

            html.H4("📘 Vulners Intelligence", className="text-primary mt-4"),
            html.Pre(vulners_text, style=_mitre_panel_style()),

            html.H4("💥 Exploit-DB Results", className="text-danger mt-4"),
            html.Pre(exploit_text, style=_mitre_panel_style()),
        ])

        return no_update, no_update, ai_panel

    return no_update, no_update, ""

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

@app.callback(
    Output("pdf-download", "data"),
    Input("pdf-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_pdf_report(n_clicks):

    df = load_findings()
    findings_summary = df.to_string(index=False) if not df.empty else "No findings available."

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Security Assessment Report", styles["Title"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
    story.append(Paragraph(
        "This document summarizes vulnerabilities identified across Nmap, Nessus, "
        "OpenVAS, and ZAP scans.", styles["BodyText"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Findings Summary</b>", styles["Heading2"]))
    story.append(Paragraph(findings_summary.replace("\n", "<br/>"), styles["Code"]))

    pdf_path = "/tmp/security_report.pdf"
    pdf = SimpleDocTemplate(pdf_path, pagesize=letter)
    pdf.build(story)

    return dcc.send_file(pdf_path)


import csv
import io
from datetime import datetime, timedelta

@app.callback(
    Output("poam-download", "data"),
    Input("poam-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_poam(n):
    df = load_findings()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Weakness ID", "Description", "Source", "Severity", "Recommended Fix", "Due Date"])

    for _, row in df.iterrows():
        due_date = (datetime.today() + timedelta(days=30)).strftime("%Y-%m-%d")
        mitigation = f"Apply vendor patch for {row['id']} and implement system hardening."

        writer.writerow([
            row["id"],
            row["source"],
            row["source"],
            row.get("cvss", "N/A"),
            mitigation,
            due_date
        ])

    return dict(
        content=output.getvalue(),
        filename="POAM.csv"
    )



NIST_MAP = {
    "tls": ["SC-13", "SC-23"],
    "http": ["SC-7", "AC-4"],
    "ftp": ["AC-4", "CM-7"],
    "cve": ["RA-5", "SI-2"],
    "outdated": ["CM-2", "CM-6"],
    "weak": ["SC-12", "SC-28"]
}

@app.callback(
    Output("nist-download", "data"),
    Input("nist-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_nist_mapping(n):

    df = load_findings()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Finding", "Source", "Mapped NIST Controls"])

    for _, row in df.iterrows():

        text = str(row["id"]).lower()
        controls = []

        for keyword, control_list in NIST_MAP.items():
            if keyword in text:
                controls.extend(control_list)

        if not controls:
            controls = ["RA-5"]  # Default vulnerability management control

        writer.writerow([
            row["id"],
            row["source"],
            "; ".join(controls)
        ])

    return dict(
        content=output.getvalue(),
        filename="nist_mapping.csv"
    )



@app.callback(
    Output("chatbot-history", "children"),
    Input("chatbot-send", "n_clicks"),
    State("chatbot-input", "value"),
    State("chatbot-history", "children"),
    prevent_initial_call=True
)
def security_chatbot(n_clicks, user_msg, history):

    if not user_msg:
        raise dash.exceptions.PreventUpdate

    # --------------------------------------
    # 1. Load SQLite Findings
    # --------------------------------------
    try:
        df = load_findings()
        sqlite_summary = df.to_string(index=False) if not df.empty else "No findings."
    except Exception as e:
        sqlite_summary = f"SQLite Error: {e}"

    # --------------------------------------
    # 2. Load Neo4j Attack Graph
    # --------------------------------------
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
        with driver.session() as session:
            q = """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a.host AS asset, s.name AS service, s.port AS port,
                   v.id AS vuln, v.cvss AS cvss, v.source AS source
            """
            records = list(session.run(q))
            graph_summary = "\n".join(str(r) for r in records) if records else "No graph data."
        driver.close()
    except Exception as e:
        graph_summary = f"Neo4j Error: {e}"

    # --------------------------------------
    # 3. Load XML Scan Snippets
    # --------------------------------------
    xml_context = ""
    try:
        xml_dir = "/root/vuln_intel/xml"
        if os.path.exists(xml_dir):
            for f in os.listdir(xml_dir)[:3]:  # limit to 3
                if f.endswith(".xml"):
                    path = os.path.join(xml_dir, f)
                    snippet = Path(path).read_text(errors="ignore")[:3000]
                    xml_context += f"\n--- {f} ---\n{snippet}\n"
        else:
            xml_context = "XML directory missing."
    except Exception as e:
        xml_context = f"XML Error: {e}"

    # --------------------------------------
    # 4. Build Security-Aware LLM Prompt
    # --------------------------------------
    full_context = f"""
You are an AI cybersecurity analyst. Use ONLY the data provided below:

====================
USER QUESTION
====================
{user_msg}

====================
SQLITE FINDINGS (Parsed Nmap/Nessus/OpenVAS/ZAP)
====================
{sqlite_summary}

====================
NEO4J ATTACK GRAPH (Assets → Services → Vulnerabilities)
====================
{graph_summary}

====================
RAW XML SNIPPETS
====================
{xml_context}

TASKS:
- Answer the question accurately.
- Use real assets, ports, CVEs, severities, and relationships.
- Provide MITRE ATT&CK techniques if relevant.
- Provide risk analysis.
- Provide recommended remediations.
- Never hallucinate information not found in the datasets.
"""

    ai_response = call_llm(full_context)

    # Format message history
    history = history or []
    history += [
        html.Div(f"👤 You: {user_msg}", style={"marginTop": "8px"}),
        html.Div(f"🛡️ AI: {ai_response}", style={"marginTop": "8px", "color": "#EAAA00"})
    ]

    return history




# ======================================================================
# Helper: Panel style for AI output
# ======================================================================
def _mitre_panel_style():
    return {
        "whiteSpace": "pre-wrap",
        "backgroundColor": "#000",
        "padding": "10px",
        "border": "1px solid #333",
        "borderRadius": "6px",
        "fontSize": "12px",
        "color": "#EAAA00",
        "maxHeight": "450px",
        "overflowY": "scroll",
    }



@app.callback(
    Output("upload-status", "children"),
    Input("upload-scan-file", "contents"),
    State("upload-scan-file", "filename"),
    prevent_initial_call=True
)
def process_uploaded_file(contents, filename):
    if not contents:
        return "No file uploaded."

    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)

    try:
        if filename.endswith(".xml"):
            rows = parse_nmap_xml(decoded)
            for r in rows:
                insert_finding(r)
            return f"Imported {len(rows)} items from {filename}"

        return "Unsupported file type."

    except Exception as e:
        return f"Error processing file: {e}"


@app.callback(
    Output("scan-log", "children"),
    Input("scan-btn", "n_clicks"),
    State("scanner-select", "value"),
    State("target-ip", "value"),
    prevent_initial_call=True
)
def run_scan_pipeline(n, scanner, target):
    log = ""

    if not scanner:
        return "⚠ Select a scanner."

    if scanner == "nmap":
        cmd = ["nmap", "-sV", "-O", "-oX", "nmap_output.xml", target]
        log += "Running Nmap...\n"
        subprocess.run(cmd)
        with open("nmap_output.xml") as f:
            rows = parse_nmap_xml(f.read())
            for r in rows:
                insert_finding(r)
        log += f"Inserted {len(rows)} Nmap findings.\n"

    elif scanner == "pipeline":
        log += "🔥 Running FULL ASSESSMENT PIPELINE...\n"

        # 1. Nmap
        cmd = ["nmap", "-sV", "-O", "-oX", "nmap_output.xml", target]
        subprocess.run(cmd)
        with open("nmap_output.xml") as f:
            rows = parse_nmap_xml(f.read())
            for r in rows:
                insert_finding(r)
        log += f"✔ Nmap: {len(rows)} items inserted.\n"

        # Add OpenVAS + ZAP triggers here when you want

    else:
        log += "Scanner not implemented yet."

    return log


@app.callback(
    Output("download-json", "data"),
    Input("export-json", "n_clicks"),
    prevent_initial_call=True
)
def export_json(n):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM findings", conn)
    conn.close()
    return dict(content=df.to_json(orient="records"), filename="findings.json")

@app.callback(
    Output("download-csv", "data"),
    Input("export-csv", "n_clicks"),
    prevent_initial_call=True
)
def export_csv(n):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM findings", conn)
    conn.close()
    return dict(content=df.to_csv(index=False), filename="findings.csv")



[{"label": "T1059 (Technique)", "value": "T1059"}, ...]


@app.callback(
    Output("mitre-attack-path-graph", "figure"),
    Input("mitre-attack-path-asset", "value")
)
def mitre_attack_path(asset):

    if not asset:
        return go.Figure()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    q = """
    MATCH (a:Asset {name:$x})-[:HAS_VULN]->(v:Vulnerability)
    OPTIONAL MATCH (v)-[:EXPLOITS]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
    RETURN a, v, tech, tac
    """

    rows = []
    with driver.session() as session:
        rows = [r.data() for r in session.run(q, x=asset)]

    edges = []
    nodes = set()

    for r in rows:
        a = r["a"]["name"]
        v = r["v"]["id"]
        tech = r["tech"]["id"] if r["tech"] else None
        tac = r["tac"]["id"] if r["tac"] else None

        nodes.add(a)
        nodes.add(v)

        edges.append((a, v))

        if tech:
            nodes.add(tech)
            edges.append((v, tech))

        if tac:
            nodes.add(tac)
            edges.append((tech, tac))

    # Build networkx graph → plotly
    import networkx as nx
    G = nx.DiGraph()
    for n in nodes: G.add_node(n)
    for e in edges: G.add_edge(e[0], e[1])

    pos = nx.spring_layout(G)

    # create figure
    fig = go.Figure()

    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            mode='lines',
            line=dict(width=2, color='gray')
        ))

    for node in G.nodes():
        x, y = pos[node]
        fig.add_trace(go.Scatter(
            x=[x], y=[y], mode='markers+text',
            text=node, textposition="top center",
            marker=dict(size=12)
        ))

    fig.update_layout(title=f"Attack Path for Asset: {asset}")

    return fig

    # PRESET NEO4J QUERIES
    cypher = {
        "btn-assets": """
            MATCH (a:Asset)-[r]->(b)
            RETURN a, r, b
        """,
        "btn-vuln": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            RETURN a, v
        """,
        "btn-tech-tac": """
            MATCH (tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN tech, tac
        """,
        "btn-subtech": """
            MATCH (p:Technique)-[:HAS_SUBTECHNIQUE]->(c:SubTechnique)
            RETURN p, c
        """,
        "btn-attack-path": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:EXPLOITS]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN a, v, tech, tac
        """
    }[clicked]

    nodes = {}
    edges = []

    with driver.session() as session:
        results = session.run(cypher)

        for row in results:
            for key, val in row.items():

                # Skip null values
                if val is None:
                    continue

                # Handle nodes safely
                if hasattr(val, "labels"):
                    nid = val.id
                    label = list(val.labels)[0] if val.labels else "Node"
                    text = val.get("name") or val.get("id") or label

                    nodes[nid] = {"data": {"id": nid, "label": text}}

                # Handle relationships safely
                elif hasattr(val, "type") and hasattr(val, "nodes"):
                    try:
                        n1, n2 = val.nodes
                        if n1 and n2:
                            edges.append({
                                "data": {"source": n1.id, "target": n2.id}
                            })
                    except:
                        pass  # skip broken relationships

    # Return EMPTY list if no graph
    elements = list(nodes.values()) + edges
    return elements if elements else []


def load_preset_graph(btn_assets, btn_vuln, btn_tech_tac, btn_subtech, btn_attack_path):

    from dash import callback_context
    ctx = callback_context


def load_preset_graph(btn_assets, btn_vuln, btn_tech_tac, btn_subtech, btn_attack_path):

    from dash import callback_context
    ctx = callback_context
    if not ctx.triggered:
        return []

    clicked = ctx.triggered[0]["prop_id"].split(".")[0]

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # All preset Cypher queries
    cypher_queries = {
        "btn-assets": """
            MATCH (a:Asset)-[r]->(b)
            RETURN a, r, b
        """,

        "btn-vuln": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            RETURN a, v
        """,

        "btn-tech-tac": """
            MATCH (tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN tech, tac
        """,

        "btn-subtech": """
            MATCH (p:Technique)-[:HAS_SUBTECHNIQUE]->(c:SubTechnique)
            RETURN p, c
        """,

        "btn-attack-path": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:EXPLOITS]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN a, v, tech, tac
        """,
    }

    query = cypher_queries[clicked]

    nodes = {}
    edges = []

    with driver.session() as session:
        results = session.run(query)
        for row in results:
            for key, val in row.items():

                if hasattr(val, "labels"):   # Node
                    nid = val.id
                    label = list(val.labels)[0]
                    text = val.get("name") or val.get("id") or label

                    nodes[nid] = {"data": {"id": nid, "label": text}}

                if hasattr(val, "type"):     # Relationship
                    start, end = val.nodes
                    edges.append({"data": {"source": start.id, "target": end.id}})

    return list(nodes.values()) + edges


# ==========================================================
#  TAB — ATTACK CHAIN SIMULATOR
# ==========================================================

def attack_chain_simulator_tab():
    return html.Div(
        [
            html.H3("⚔️ Attack Chain Simulator", className="text-warning mb-3"),

            html.P(
                "Simulate attacker movement using real graph data (Assets → Services → Vulnerabilities → Techniques).",
                className="text-light"
            ),

            html.Hr(),

            # Start node
            html.Label("Start Asset / Node:", className="text-light"),
            dcc.Dropdown(
                id="acs-start",
                placeholder="Select start node...",
                options=[],
                style={"width": "60%", "marginBottom": "20px"},
            ),

            # Target node
            html.Label("Target Node (e.g., Crown Jewel):", className="text-light"),
            dcc.Dropdown(
                id="acs-target",
                placeholder="Select target node...",
                options=[],
                style={"width": "60%", "marginBottom": "20px"},
            ),

            dbc.Button(
                "🚀 Simulate Attack Path",
                id="acs-run",
                color="danger",
                className="mt-3 mb-4"
            ),

            html.Div(
                id="acs-output",
                style={
                    "whiteSpace": "pre-wrap",
                    "backgroundColor": "#111",
                    "padding": "15px",
                    "border": "1px solid #333",
                    "borderRadius": "6px",
                    "color": "#EAAA00",
                }
            ),
        ],
        className="p-4"
    )



# ======================================================================
# CALLBACK: Populate Attack Chain Simulator Node Dropdowns
# ======================================================================

@app.callback(
    [
        Output("attack-start-node", "options"),
        Output("attack-target-node", "options")
    ],
    Input("neo4j-graph", "elements"),
    prevent_initial_call=False
)
def populate_attack_nodes(elements):

    # If graph is empty → no node options
    if not elements:
        return [], []

    # Collect nodes from graph elements
    node_options = []
    seen = set()

    for el in elements:
        if "data" in el and "id" in el["data"]:
            nid = el["data"]["id"]
            label = el["data"].get("label", nid)

            if nid not in seen:
                seen.add(nid)
                node_options.append({
                    "label": label,
                    "value": nid
                })

    # Use the same node list for both dropdowns
    return node_options, node_options

# === CYBER RANGE CALLBACK REGISTRATIONS ===
kc_callbacks(app)
dt_callbacks(app)
hp_callbacks(app)
exp_callbacks(app)
wg_callbacks(app)
ti_callbacks(app)
rm_callbacks(app)



# ==========================================================
# FINAL CLEAN DASHBOARD LAYOUT (NO DUPLICATES ANYWHERE)
# ==========================================================

app.layout = dbc.Container(
    [
        html.H2(
            "Towson University — Vulnerability Intelligence Dashboard",
            className="text-warning mt-3 mb-4"
        ),

        dbc.Tabs(
            id="tabs",
            active_tab="system",

            children=[
                # -------------------------------------------------
                # 1. System
                # -------------------------------------------------
                dbc.Tab(system_health_layout(), label="System", tab_id="system"),

                # -------------------------------------------------
                # 2. Assessment
                # -------------------------------------------------
                dbc.Tab(assessment_tab, label="Assessment", tab_id="assessment"),

                # -------------------------------------------------
                # 3. Vulnerabilities
                # -------------------------------------------------
                dbc.Tab(vulnerability_tab(), label="Vulnerabilities", tab_id="vuln"),

                # -------------------------------------------------
                # 4. LLM
                # -------------------------------------------------
                dbc.Tab(llm_tab, label="LLM", tab_id="llm"),

                # -------------------------------------------------
                # 5. Chatbot
                # -------------------------------------------------
                dbc.Tab(chatbot_tab, label="Chatbot", tab_id="chatbot"),

                # -------------------------------------------------
                # 6. Neo4j Graph Intelligence
                # -------------------------------------------------
                dbc.Tab(neo4j_graphs_tab(), label="Neo4j Graph Intelligence", tab_id="neo4j"),

                # -------------------------------------------------
                # 7. Neo4j Graph Presets
                # -------------------------------------------------
                dbc.Tab(
                    neo4j_preset_graphs_tab(),
                    label="Neo4j Graph Presets",
                    tab_id="neo4j_presets"
                ),

                # -------------------------------------------------
                # 8. MITRE ATT&CK Intelligence
                # -------------------------------------------------
                dbc.Tab(
                    mitre_tab_layout(),
                    label="MITRE ATT&CK Intelligence",
                    tab_id="mitre"
                ),

                # -------------------------------------------------
                # 9. Attack Chain Simulator
                # -------------------------------------------------
                dbc.Tab(
                    attack_chain_simulator_tab(),
                    label="Attack Chain Simulator",
                    tab_id="attack_sim"
                ),

                # =====================================================
                # 10. CYBER-RANGE ADVANCED MODULES
                # =====================================================

                dbc.Tab(killchain_tab(),      label="Kill Chain",       tab_id="killchain"),
                dbc.Tab(digital_twin_tab(),   label="Digital Twin",     tab_id="digital_twin"),
                dbc.Tab(honeypot_tab(),       label="Honeypots",        tab_id="honeypots"),
                dbc.Tab(exploit_ai_tab(),     label="Exploit AI",       tab_id="exploit_ai"),
                dbc.Tab(wargame_tab(),        label="Wargame AI",       tab_id="wargame"),
                dbc.Tab(ti_feed_tab(),        label="Threat Intelligence", tab_id="ti_feed"),
                dbc.Tab(remediation_tab(),    label="Remediation AI",   tab_id="rem_ai"),

                # -------------------------------------------------
                # 17. Reporting
                # -------------------------------------------------
                dbc.Tab(reporting_tab, label="Reporting", tab_id="reporting"),

                # -------------------------------------------------
                # 18. Voice
                # -------------------------------------------------
                dbc.Tab(voice_tab, label="Voice", tab_id="voice"),
            ],
        ),

        html.Div(id="tabs-content"),
    ],
    fluid=True,
)

# ============================================
# AI Narrative Callback (FIXED & RESTORED)
# ============================================
from openai import OpenAI
client = OpenAI()

@app.callback(
    Output("ai-narrative", "children"),
    [
        Input("metric-vulns", "children"),
        Input("metric-assets", "children"),
        Input("metric-services", "children"),
    ],
    prevent_initial_call=False
)
def update_ai_narrative(vuln_count, asset_count, service_count):
    try:
        summary = f"""
        Vulnerabilities: {vuln_count}
        Assets: {asset_count}
        Services: {service_count}
        """

        prompt = f"""
        Based on this environment summary, generate a concise cybersecurity narrative:
        {summary}

        Focus on:
        - Likely attack paths
        - Business impact
        - Urgency
        - Recommended immediate actions
        """

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        # Correct OpenAI SDK usage
        narrative = response.choices[0].message.content
        return narrative

    except Exception as e:
        return f"[AI Narrative Error] {str(e)}"



# ==========================================================
#  LAUNCH DASHBOARD
# ==========================================================
if __name__ == "__main__":
    print("✅ Dashboard ready on http://127.0.0.1:8050")
# ================================================
# ON-BOOT: Load MITRE + Correlate CVEs + Ensure Graph
# ================================================
#try:
 #   print("🚀 Initializing MITRE + CVE correlation...")
  #  insert_mitre_into_neo4j()
   # correlate_cves_to_mitre()
    #print("✅ MITRE and CVE correlation completed.")
#except Exception as e:
 #   print("❌ MITRE Initialization failed:", e)

    
    app.run(host="0.0.0.0", port=8050, debug=True)


