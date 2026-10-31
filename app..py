#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Towson University — Unified Vulnerability Intelligence Dashboard
---------------------------------------------------------------
Tabs:
  1. Vulnerability Dashboard
  2. LLM Request
  3. Natural Language
  4. Chatbot
  5. Assessment (Nessus, OpenVAS, Nmap, Burp)
  6. Reporting
  7. Voice Assistant
  8. System Health
---------------------------------------------------------------
Author: Consolidated for research use (Towson University)
"""

# ==========================================================
#  Imports and Environment Setup
# ==========================================================
import os, sys, json, base64, sqlite3, subprocess, time, threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests, pandas as pd, plotly.express as px, dash_bootstrap_components as dbc
from fpdf import FPDF
import psutil

from dash import Dash, dcc, html, Input, Output, State, ctx, no_update, dash_table
from dash.exceptions import PreventUpdate

# --- Local Neo4j Integration ---
from neo4j_integration import (
    parse_nmap_xml,
    import_nmap_hosts_to_neo4j,
    enrich_cves_from_nvd,
)

# ==========================================================
#  Configuration
# ==========================================================
PROJECT_ROOT = "/root/vuln_intel"
DB_PATH = f"{PROJECT_ROOT}/app/data/findings.db"
REPORT_DIR = Path(f"{PROJECT_ROOT}/app/data/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Neo4j configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"

# OpenAI configuration
OPENAI_KEY = os.getenv(
    "OPENAI_API_KEY",
    "your-openai-api-key-here"
)
OPENAI_MODEL = "gpt-4o"

# Whitelisted lab network ranges
SCAN_WHITELIST = [
    "192.168.", "10.", "172.16."
]

# Status log initialization
STATUS_LOG = f"{PROJECT_ROOT}/app/status.log"
Path(STATUS_LOG).write_text("")

def append_status(line: str):
    """Write timestamped log entry."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(STATUS_LOG, "a") as f:
        f.write(f"[{timestamp}] {line}\n")

# ==========================================================
#  Database Helpers
# ==========================================================
def load_findings():
    """Load all findings from SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings", conn)
        conn.close()
        if df.empty:
            append_status("No records found in findings.db")
        return df
    except Exception as e:
        append_status(f"DB load failed: {e}")
        return pd.DataFrame()

def save_findings_to_csv():
    """Export findings to CSV for offline review."""
    df = load_findings()
    if df.empty:
        return None
    csv_path = REPORT_DIR / f"findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(csv_path, index=False)
    append_status(f"CSV exported to {csv_path}")
    return csv_path

# ==========================================================
#  Neo4j Helpers
# ==========================================================
from neo4j import GraphDatabase

def connect_neo4j():
    """Create Neo4j driver instance."""
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        append_status("✅ Connected to Neo4j successfully.")
        return driver
    except Exception as e:
        append_status(f"❌ Neo4j connection failed: {e}")
        return None

def push_to_neo4j():
    """Push SQLite findings to Neo4j graph DB."""
    df = load_findings()
    if df.empty:
        append_status("⚠️ No data to push to Neo4j.")
        return "No data"
    driver = connect_neo4j()
    if not driver:
        return "Neo4j connection failed"

    with driver.session() as session:
        for _, row in df.iterrows():
            query = """
            MERGE (a:Asset {host:$host})
            MERGE (v:Vulnerability {cve:$cve})
            SET v.severity=$severity, v.cvss=$cvss, v.source=$source
            MERGE (a)-[:HAS_VULNERABILITY]->(v)
            """
            session.run(
                query,
                host=row.get("host"),
                cve=row.get("cve_id", "N/A"),
                severity=row.get("severity", "unknown"),
                cvss=row.get("cvss", 0),
                source=row.get("source", "unknown")
            )
    append_status("Pushed findings to Neo4j.")
    return "Pushed to Neo4j"

# ==========================================================
#  OpenAI Helper
# ==========================================================
import openai
openai.api_key = OPENAI_KEY

def call_openai(prompt: str) -> str:
    """Call OpenAI GPT model for analysis."""
    try:
        completion = openai.ChatCompletion.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4
        )
        response = completion.choices[0].message.content.strip()
        append_status("OpenAI call succeeded.")
        return response
    except Exception as e:
        append_status(f"OpenAI call failed: {e}")
        return f"OpenAI error: {e}"

# ==========================================================
#  Flask + Dash Initialization
# ==========================================================
app = Dash(__name__, suppress_callback_exceptions=True, assets_folder="assets", external_stylesheets=[dbc.themes.DARKLY])
server = app.server
append_status("[+] Dashboard initialized successfully.")

print(f"[+] DB path: {DB_PATH}")
print("[+] OpenAI key loaded (GPT-4o active).")
print("[+] Neo4j connection ready.")

# ==========================================================
#  TAB LAYOUTS (Towson Theme)
# ==========================================================

# -------------------------
# Vulnerability Dashboard
# -------------------------
vuln_tab = dbc.Container(
    [
        html.H3("Vulnerability Dashboard", className="text-warning mb-4"),

        dbc.Row([
            dbc.Col(
                dcc.Dropdown(
                    id="source-filter",
                    placeholder="Filter by Source (Nmap, OpenVAS, Burp, ZAP)",
                    multi=True,
                    style={"color": "#000", "borderRadius": "6px"}
                ), width=3
            ),
            dbc.Col(
                dcc.Dropdown(
                    id="severity-filter",
                    placeholder="Filter by Severity (Critical, High, Medium, Low, Info)",
                    multi=True,
                    style={"color": "#000", "borderRadius": "6px"}
                ), width=3
            ),
            dbc.Col(
                dcc.Dropdown(
                    id="ip-filter",
                    placeholder="Filter by IP/Host",
                    multi=True,
                    style={"color": "#000", "borderRadius": "6px"}
                ), width=3
            ),
            dbc.Col(
                dbc.Button("Refresh Data", id="refresh-btn", color="warning", className="w-100"),
                width=3
            )
        ], className="mb-4"),

        # CVSS Distribution Graph
        dcc.Graph(id="cvss-distribution", style={"height": "350px"}),

        html.Hr(),

        # Findings Table
        dash_table.DataTable(
            id="findings-table",
            columns=[
                {"name": c, "id": c} for c in [
                    "id", "host", "port", "service", "severity",
                    "cvss", "cve_id", "source", "description"
                ]
            ],
            style_header={"backgroundColor": "#EAAA00", "color": "black", "fontWeight": "bold"},
            style_data={
                "backgroundColor": "#1E1E1E",
                "color": "#FFFFFF",
                "whiteSpace": "normal",
                "height": "auto",
            },
            style_table={"overflowX": "auto", "border": "1px solid #EAAA00"},
            page_size=10,
        )
    ], fluid=True
)

# -------------------------
# LLM Request Tab
# -------------------------
llm_tab = dbc.Container([
    html.H3("LLM Request Interface", className="text-warning mb-4"),
    dcc.Textarea(
        id="llm-input",
        placeholder="Enter your prompt or question (e.g. summarize all critical vulnerabilities)...",
        style={"width": "100%", "height": "180px", "color": "#000"}
    ),
    html.Br(),
    dbc.Button("Submit Request", id="llm-submit", color="warning", className="mt-2"),
    html.Hr(),
    html.H4("Response:", className="text-info mt-3"),
    html.Pre(id="llm-response", style={"whiteSpace": "pre-wrap", "color": "#EAEAEA", "fontSize": "16px"})
], fluid=True)

# -------------------------
# Natural Language Tab
# -------------------------
natural_language_tab = dbc.Container([
    html.H3("Natural Language Query Processor", className="text-warning mb-4"),
    dcc.Input(
        id="nl-query",
        placeholder="Ask something like: show all hosts with CVSS > 7...",
        type="text",
        style={"width": "80%", "color": "#000"}
    ),
    dbc.Button("Run Query", id="nl-run", color="warning", className="ms-2"),
    html.Hr(),
    html.Div(id="nl-results", style={"whiteSpace": "pre-wrap", "color": "#EAEAEA"})
], fluid=True)

# -------------------------
# Chatbot Tab
# -------------------------
chatbot_tab = dbc.Container([
    html.H3("Vulnerability Chatbot", className="text-warning mb-4"),
    dcc.Textarea(
        id="chatbot-input",
        placeholder="Chat with VulnBot (e.g. list top 10 CVEs)...",
        style={"width": "100%", "height": "150px", "color": "#000"}
    ),
    dbc.Button("Send", id="chatbot-send", color="warning", className="mt-2"),
    html.Hr(),
    html.Div(id="chatbot-output", style={"whiteSpace": "pre-wrap", "color": "#EAEAEA", "fontSize": "16px"})
], fluid=True)

# -------------------------
# Assessment Tab
# -------------------------
assessment_tab = dbc.Container([
    html.H3("Security Assessment Suite", className="text-warning mb-4"),
    html.P("Select a scanner or upload a target list:", className="text-light"),
    dbc.Row([
        dbc.Col(
            dcc.Dropdown(
                id="scanner-select",
                options=[
                    {"label": "Nmap", "value": "nmap"},
                    {"label": "OpenVAS", "value": "openvas"},
                    {"label": "Nessus", "value": "nessus"},
                    {"label": "Burp Suite", "value": "burp"}
                ],
                placeholder="Select a scanner",
                style={"color": "#000"}
            ), width=3
        ),
        dbc.Col(dcc.Input(id="scan-target", placeholder="Target IP(s), e.g. 192.168.1.0/24", type="text", style={"color":"#000"}), width=6),
        dbc.Col(dcc.Upload(id="upload-targets", children=html.Div(["📁 Upload target.txt"]), multiple=False), width=3),
    ]),
    html.Br(),
    dbc.Button("Start Scan", id="start-scan-btn", color="warning"),
    html.Hr(),
    html.H5("Scan Log:", className="text-info"),
    html.Pre(id="scan-log", style={"backgroundColor": "#111", "color": "#EEE", "height": "300px", "overflowY": "scroll"})
], fluid=True)

# -------------------------
# Reporting Tab
# -------------------------
reporting_tab = dbc.Container([
    html.H3("Automated Report Generator", className="text-warning mb-4"),
    html.P("Export data and generate PDF reports for selected assets.", className="text-light"),
    dbc.Button("Generate PDF Report", id="generate-pdf", color="warning"),
    html.Br(), html.Br(),
    html.Div(id="report-status", className="text-info")
], fluid=True)

# -------------------------
# Voice Assistant Tab
# -------------------------
voice_tab = dbc.Container([
    html.H3("Voice Assistant (Browser-based)", className="text-warning mb-4"),
    html.Div([
        html.Button("🎤 Start Listening", id="start-voice", n_clicks=0),
        html.Button("🛑 Stop", id="stop-voice", n_clicks=0, style={"marginLeft": "10px"})
    ]),
    html.Br(),
    html.Div(id="voice-status", className="text-info mt-2"),
    html.Pre(id="voice-output", style={"whiteSpace": "pre-wrap", "color": "#EAEAEA"})
], fluid=True)

# -------------------------
# System Health Tab
# -------------------------
system_health_tab = dbc.Container([
    html.H3("System Health Monitor", className="text-warning mb-4"),
    html.Div(id="system-health-content", className="text-light")
], fluid=True)

# -------------------------
# Tabs Layout Wrapper
# -------------------------
app.layout = html.Div([
    html.Div(
        className="header-container",
        children=[
            html.H2("Towson University — Vuln Intel Unified Dashboard", className="header-title text-warning text-center mt-2")
        ]
    ),
    dcc.Tabs(
        id="tabs", value="tab1", className="custom-tabs",
        children=[
            dcc.Tab(label="Vulnerability Dashboard", value="tab1", className='tab', selected_className='tab--selected'),
            dcc.Tab(label="LLM Request", value="tab2", className='tab', selected_className='tab--selected'),
            dcc.Tab(label="Natural Language", value="tab3", className='tab', selected_className='tab--selected'),
            dcc.Tab(label="Chatbot", value="tab4", className='tab', selected_className='tab--selected'),
            dcc.Tab(label="Assessment", value="tab5", className='tab', selected_className='tab--selected'),
            dcc.Tab(label="Reporting", value="tab6", className='tab', selected_className='tab--selected'),
            dcc.Tab(label="Voice Assistant", value="tab7", className='tab', selected_className='tab--selected'),
            dcc.Tab(label="System Health", value="tab8", className='tab', selected_className='tab--selected')
        ]
    ),
    html.Div(id="tabs-content", className="mt-4")
])


# ==========================================================
#  CALLBACKS & FUNCTIONAL LOGIC
# ==========================================================

# ---------- Vulnerability Dashboard ----------
@app.callback(
    [
        Output("cvss-distribution", "figure"),
        Output("findings-table", "data"),
        Output("source-filter", "options"),
        Output("severity-filter", "options"),
        Output("ip-filter", "options")
    ],
    Input("refresh-btn", "n_clicks"),
)
def update_vuln_dashboard(n_clicks):
    df = load_findings()
    if df.empty:
        fig = px.bar(title="No Data Found")
        return fig, [], [], [], []

    # Prepare dropdown options
    sources = [{"label": s, "value": s} for s in sorted(df["source"].dropna().unique())]
    severities = [{"label": s, "value": s} for s in sorted(df["severity"].dropna().unique())]
    hosts = [{"label": h, "value": h} for h in sorted(df["host"].dropna().unique())]

    # CVSS distribution
    cvss_series = pd.to_numeric(df["cvss"], errors="coerce").dropna()
    if len(cvss_series) > 0:
        fig = px.histogram(df, x="cvss", nbins=10, title="CVSS Score Distribution", color="severity")
        fig.update_layout(
            plot_bgcolor="#111", paper_bgcolor="#111", font_color="#EAEAEA",
            xaxis_title="CVSS", yaxis_title="Count"
        )
    else:
        fig = px.bar(title="No CVSS data available")

    return fig, df.to_dict("records"), sources, severities, hosts


# ---------- LLM Request ----------
@app.callback(
    Output("llm-response", "children"),
    Input("llm-submit", "n_clicks"),
    State("llm-input", "value"),
    prevent_initial_call=True
)
def handle_llm_request(n_clicks, prompt):
    if not prompt:
        raise PreventUpdate
    response = call_openai(f"Analyze vulnerability data:\n{prompt}")
    return response


# ---------- Natural Language ----------
@app.callback(
    Output("nl-results", "children"),
    Input("nl-run", "n_clicks"),
    State("nl-query", "value"),
    prevent_initial_call=True
)
def handle_nl_query(n_clicks, query):
    df = load_findings()
    if df.empty:
        return "No findings available."

    if "cvss" in query.lower():
        try:
            value = float(query.split(">")[-1])
            filtered = df[pd.to_numeric(df["cvss"], errors="coerce") > value]
            return filtered.to_string(index=False)
        except Exception:
            return "Could not parse CVSS threshold."
    else:
        return df.head(10).to_string(index=False)


# ---------- Chatbot ----------
@app.callback(
    Output("chatbot-output", "children"),
    Input("chatbot-send", "n_clicks"),
    State("chatbot-input", "value"),
    prevent_initial_call=True
)
def handle_chatbot(n_clicks, query):
    if not query:
        raise PreventUpdate
    response = call_openai(f"You are a cybersecurity analyst. {query}")
    return response


# ---------- Assessment (Scanning) ----------
@app.callback(
    Output("scan-log", "children"),
    Input("start-scan-btn", "n_clicks"),
    State("scanner-select", "value"),
    State("scan-target", "value"),
    prevent_initial_call=True
)
def trigger_scan(n_clicks, scanner, targets):
    if not scanner or not targets:
        return "Select a scanner and target first."

    if not any(targets.startswith(prefix) for prefix in SCAN_WHITELIST):
        return f"⚠️ Target '{targets}' not in whitelist {SCAN_WHITELIST}"

    append_status(f"Initiating {scanner.upper()} scan on {targets}...")

    try:
        if scanner == "nmap":
            cmd = ["nmap", "-sV", "-T4", "-p-", "-v", targets]
        elif scanner == "openvas":
            cmd = ["gvm-cli", "socket", "--xml", f"<create_target><name>{targets}</name></create_target>"]
        elif scanner == "nessus":
            cmd = ["nessuscli", "scan", "start", targets]
        elif scanner == "burp":
            cmd = ["java", "-jar", "burpsuite.jar"]
        else:
            return "Unknown scanner selected."

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output_lines = []
        for line in iter(process.stdout.readline, ""):
            output_lines.append(line)
            sys.stdout.write(line)
        process.wait()
        append_status(f"{scanner.upper()} scan completed for {targets}")
        return "".join(output_lines)
    except Exception as e:
        append_status(f"Scan failed: {e}")
        return f"Scan error: {e}"


# ---------- Reporting ----------
@app.callback(
    Output("report-status", "children"),
    Input("generate-pdf", "n_clicks"),
    prevent_initial_call=True
)
def generate_report(n_clicks):
    df = load_findings()
    if df.empty:
        return "No findings available for report."

    pdf_path = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Towson University Vulnerability Report", ln=True, align="C")

    pdf.set_font("Arial", size=10)
    for _, row in df.iterrows():
        pdf.multi_cell(0, 8, f"{row.get('host', '')} | {row.get('severity', '')} | {row.get('cve_id', '')}")

    pdf.output(str(pdf_path))
    append_status(f"PDF report generated: {pdf_path}")
    return f"✅ PDF report created at {pdf_path}"


# ---------- System Health ----------
@app.callback(
    Output("system-health-content", "children"),
    Input("tabs", "value")
)
def update_system_health(tab):
    if tab != "tab8":
        raise PreventUpdate

    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime = time.strftime("%H:%M:%S", time.gmtime(time.time() - psutil.boot_time()))

    return html.Div([
        html.P(f"🧠 CPU Usage: {cpu}%"),
        html.P(f"💾 Memory: {mem.percent}% used"),
        html.P(f"📦 Disk: {disk.percent}% used"),
        html.P(f"⏱️ Uptime: {uptime}"),
    ], style={"fontSize": "18px"})


# ---------- Tab Router ----------
@app.callback(Output("tabs-content", "children"), Input("tabs", "value"))
def render_tab(tab):
    if tab == "tab1": return vuln_tab
    elif tab == "tab2": return llm_tab
    elif tab == "tab3": return natural_language_tab
    elif tab == "tab4": return chatbot_tab
    elif tab == "tab5": return assessment_tab
    elif tab == "tab6": return reporting_tab
    elif tab == "tab7": return voice_tab
    elif tab == "tab8": return system_health_tab
    return html.Div("Unknown tab selected.")


# ==========================================================
#  SERVER ENTRYPOINT
# ==========================================================
if __name__ == "__main__":
    append_status("Dashboard starting up...")
    app.run(host="0.0.0.0", port=8050, debug=True)

