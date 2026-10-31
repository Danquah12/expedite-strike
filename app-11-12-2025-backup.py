#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Vuln-Intel Dashboard (merged)
Tabs:
  - Vulnerability Dashboard
  - LLM Request
  - Natural Language
  - Chatbot
  - Assessment (Nessus, OpenVAS, Nmap, Burp)
  - Reporting
  - Voice Assistant (browser speech fallback)
Author: Merged for user (authorized scanning only)
"""

import os
import sys
import json
import base64
import sqlite3
import subprocess
import time
from datetime import datetime
from pathlib import Path

import requests
import pandas as pd
import plotly.express as px
from fpdf import FPDF

from dash import Dash, dcc, html, Input, Output, State, ctx, no_update
import dash_bootstrap_components as dbc
import dash_table
from neo4j_integration import assessment_nmap_import_step, enrich_cves_from_nvd

# ==========================================================
#  VULNERABILITY DASHBOARD TAB (Towson Themed and Functional)
# ==========================================================
import dash
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc

# Vulnerability Dashboard Layout
vuln_tab = dbc.Container(
    [
        html.H3("Vulnerability Dashboard", className="text-info mb-3"),

        # === FILTER DROPDOWNS ===
        dbc.Row([
            dbc.Col(
                dcc.Dropdown(
                    id="source-filter",
                    placeholder="Filter by Source (e.g., Nmap, OpenVAS, Burp, ZAP)",
                    multi=True,
                    style={"color": "#000000", "borderRadius": "8px"}
                ),
                width=3
            ),
            dbc.Col(
                dcc.Dropdown(
                    id="severity-filter",
                    placeholder="Filter by Severity (e.g., High, Medium, Low)",
                    multi=True,
                    style={"color": "#000000", "borderRadius": "8px"}
                ),
                width=3
            ),
            dbc.Col(
                dcc.Dropdown(
                    id="ip-filter",
                    placeholder="Filter by Host/IP Address",
                    multi=True,
                    style={"color": "#000000", "borderRadius": "8px"}
                ),
                width=3
            ),
        ], className="mb-4"),

        # === CVSS SCORE CHART ===
        dcc.Graph(
            id="cvss-distribution",
            figure={
                "layout": {
                    "paper_bgcolor": "#1C1C1C",
                    "plot_bgcolor": "#1C1C1C",
                    "font": {"color": "#FFFFFF"},
                }
            },
            config={"displaylogo": False}
        ),

        # === FINDINGS TABLE ===
        html.Div(
            [
                dash_table.DataTable(
                    id="findings-table",
                    columns=[
                        {"name": "id", "id": "id"},
                        {"name": "asset_id", "id": "asset_id"},
                        {"name": "host", "id": "host"},
                        {"name": "port", "id": "port"},
                        {"name": "service", "id": "service"},
                        {"name": "title", "id": "title"},
                        {"name": "severity", "id": "severity"},
                        {"name": "cvss", "id": "cvss"},
                        {"name": "cve_id", "id": "cve_id"},
                        {"name": "description", "id": "description"},
                        {"name": "source", "id": "source"},
                        {"name": "import_date", "id": "import_date"},
                        {"name": "timestamp", "id": "timestamp"},
                    ],
                    data=[],  # dynamically loaded by callback
                    page_size=10,
                    style_table={
                        "overflowX": "auto",
                        "backgroundColor": "#121212",
                        "padding": "10px",
                        "borderRadius": "10px",
                    },
                    style_cell={
                        "fontFamily": "Segoe UI, sans-serif",
                        "fontSize": "14px",
                        "padding": "8px",
                        "textAlign": "left",
                        "backgroundColor": "#1E1E1E",
                        "color": "#FFFFFF",
                        "border": "1px solid #444",
                    },
                    style_header={
                        "backgroundColor": "#EAAA00",   # Towson Gold
                        "color": "#000000",
                        "fontWeight": "bold",
                        "border": "1px solid #555",
                        "textAlign": "center",
                    },
                    style_data_conditional=[
                        {
                            "if": {"row_index": "odd"},
                            "backgroundColor": "#252525",  # zebra stripe
                        },
                        {
                            "if": {"state": "active"},
                            "backgroundColor": "#333333",
                            "color": "#FFD700",
                            "border": "1px solid #FFD700",
                        },
                    ],
                    style_as_list_view=True,
                    filter_action="native",
                    sort_action="native",
                    sort_mode="multi",
                    row_selectable="multi",
                    selected_rows=[],
                    export_format="csv",
                    export_headers="display",
                ),
            ],
            className="mt-4",
        ),
    ],
    fluid=True,
)

# -------------------- Config & Env --------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")  # default model requested
DB_PATH = os.getenv("DB_PATH", "/root/vuln_intel/app/data/findings.db")
REPORT_DIR = Path(os.getenv("REPORT_DIR", "/root/vuln_intel/app/data/reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Scanner envs
NESSUS_URL = os.getenv("NESSUS_URL")
NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY")
NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY")
NESSUS_TEMPLATE_UUID = os.getenv("NESSUS_TEMPLATE_UUID")

OPENVAS_URL = os.getenv("OPENVAS_URL")
OPENVAS_TOKEN = os.getenv("OPENVAS_TOKEN")

BURP_URL = os.getenv("BURP_URL")
BURP_API_KEY = os.getenv("BURP_API_KEY")

# safety
AUTHORIZED_ONLY_MSG = "⚠️ You must confirm you have written authorization to scan these targets."

# -------------------- Helpers --------------------
def load_findings_df():
    """Load findings table into DataFrame (safe fallback to empty DF)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings", conn)
        conn.close()
        # Normalize columns if missing
        expected_cols = ['id','asset_id','host','port','service','title','severity','cvss','cve_id',
                         'description','evidence','remediation','vuln_name','path','source','import_date','timestamp']
        for c in expected_cols:
            if c not in df.columns:
                df[c] = None
        return df
    except Exception as e:
        print(f"[!] DB load error: {e}")
        return pd.DataFrame(columns=['id','asset_id','host','port','service','title','severity','cvss','cve_id',
                                     'description','evidence','remediation','vuln_name','path','source','import_date','timestamp'])

def openai_chat(prompt: str, system: str = "You are a helpful cyber security assistant.") -> str:
    """Call OpenAI chat completions via REST (requests)."""
    if not OPENAI_API_KEY:
        return "OpenAI API key not configured. Set OPENAI_API_KEY in environment."
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1024,
        "temperature": 0.2
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        # Defensive extraction
        text = ""
        if "choices" in data and len(data["choices"]) > 0:
            # For chat, message may be nested
            choice = data["choices"][0]
            if "message" in choice:
                text = choice["message"].get("content", "")
            else:
                text = choice.get("text", "")
        return text or "(no content returned)"
    except Exception as e:
        return f"OpenAI request failed: {e}"

# -------------------- Scanner helpers --------------------
def nessus_headers():
    if not (NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY):
        return None
    return {"X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY}", "Content-Type": "application/json"}

def nessus_create_and_launch_scan(name: str, targets: str, template_uuid: str = None):
    """Create and launch a Nessus scan via REST API. Returns dict."""
    if not NESSUS_URL:
        return {"error": "NESSUS_URL not configured."}
    headers = nessus_headers()
    if not headers:
        return {"error": "Missing NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY."}
    uuid = template_uuid or NESSUS_TEMPLATE_UUID
    if not uuid:
        return {"error": "No Nessus template UUID configured. Set NESSUS_TEMPLATE_UUID env var."}
    payload = {
        "uuid": uuid,
        "settings": {"name": name, "text_targets": targets}
    }
    try:
        create_url = f"{NESSUS_URL.rstrip('/')}/scans"
        r = requests.post(create_url, headers=headers, json=payload, timeout=30, verify=True)
        if r.status_code not in (200,201):
            return {"error": f"Nessus create failed: {r.status_code} {r.text}"}
        resp = r.json()
        scan_id = resp.get("scan", {}).get("id") or resp.get("id")
        if scan_id:
            launch_url = f"{NESSUS_URL.rstrip('/')}/scans/{scan_id}/launch"
            r2 = requests.post(launch_url, headers=headers, timeout=30, verify=True)
            if r2.status_code not in (200,201):
                return {"scan_id": scan_id, "launch_error": f"{r2.status_code} {r2.text}"}
            return {"scan_id": scan_id, "launch": r2.json()}
        return {"error": "No scan id from create."}
    except Exception as e:
        return {"error": f"Nessus API error: {e}"}

def nessus_get_scan_status(scan_id: int):
    if not NESSUS_URL:
        return {"error": "NESSUS_URL not configured."}
    headers = nessus_headers()
    if not headers:
        return {"error": "Missing Nessus credentials."}
    try:
        r = requests.get(f"{NESSUS_URL.rstrip('/')}/scans/{scan_id}", headers=headers, timeout=20, verify=True)
        if r.status_code != 200:
            return {"error": f"Nessus fetch failed: {r.status_code} {r.text}"}
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def trigger_openvas_scan(name: str, targets: str):
    """Trigger OpenVAS/Greenbone scan via its REST API — requires OPENVAS_TOKEN and OPENVAS_URL."""
    if not OPENVAS_URL:
        return {"error": "OPENVAS_URL not set."}
    if not OPENVAS_TOKEN:
        return {"error": "OPENVAS_TOKEN not set."}
    headers = {"Authorization": f"Bearer {OPENVAS_TOKEN}", "Content-Type": "application/json"}
    payload = {"name": name, "targets": targets}
    try:
        r = requests.post(f"{OPENVAS_URL.rstrip('/')}/api/tasks", headers=headers, json=payload, timeout=30, verify=True)
        if r.status_code not in (200,201):
            return {"error": f"OpenVAS create failed: {r.status_code} {r.text}"}
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def trigger_burp_scan(name: str, targets: str):
    """Trigger Burp Enterprise scan (needs BURP_URL and BURP_API_KEY)."""
    if not BURP_URL:
        return {"error": "BURP_URL not set."}
    if not BURP_API_KEY:
        return {"error": "BURP_API_KEY not set."}
    headers = {"Authorization": BURP_API_KEY", "Content-Type": "application/json"}
    payload = {"scan_config_name": "Default", "name": name, "urls": [t.strip() for t in targets.split(",") if t.strip()]}
    try:
        r = requests.post(f"{BURP_URL.rstrip('/')}/api/v1/scans", headers=headers, json=payload, timeout=30, verify=True)
        if r.status_code not in (200,201):
            return {"error": f"Burp create failed: {r.status_code} {r.text}"}
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def trigger_nmap_scan_async(name: str, targets: str):
    """Launch local nmap as a background process. Writes XML into REPORT_DIR/nmap/<name>.xml"""
    try:
        out_dir = REPORT_DIR / "nmap"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_name = "".join(ch for ch in name if ch.isalnum() or ch in ("-", "_")).strip()
        out_file = out_dir / f"{safe_name}.xml"
        # Build command: -sV (service/version) -O (OS detect) --script vuln
        target_list = [t for t in [x.strip() for x in targets.replace("\n",",").split(",")] if t]
        cmd = ["nmap", "-sV", "-O", "--script", "vuln", "-oX", str(out_file)] + target_list
        subprocess.Popen(cmd)
        return {"message": f"Nmap launched; output: {out_file}", "path": str(out_file)}
    except Exception as e:
        return {"error": str(e)}

# -------------------- Reporting helper --------------------
def export_findings_to_pdf(selected_ids, out_path):
    """Generate a simple PDF of findings (one host per page)."""
    df = load_findings_df()
    df_sel = df[df['id'].isin(selected_ids)] if selected_ids else df
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)
    for _, row in df_sel.iterrows():
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 8, f"Host: {row.get('host', '')}", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 6, f"Port: {row.get('port','')}\nService: {row.get('service','')}\nSeverity: {row.get('severity','')}\nCVSS: {row.get('cvss','')}\nCVE: {row.get('cve_id','')}")
        pdf.ln(4)
        pdf.multi_cell(0, 6, f"Title: {row.get('title','')}\n\nDescription:\n{row.get('description','')}\n\nRemediation:\n{row.get('remediation','')}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out_path))
    return str(out_path)

# -------------------- Dash App Layout --------------------
app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY], suppress_callback_exceptions=True)
server = app.server
app.title = "Vuln Intel Dashboard"

# top header + tabs (Towson theme colours)
header = dbc.Row([
    dbc.Col(html.Img(src="/assets/towson_logo.png", style={"height":"48px"}), width="auto"),
    dbc.Col(html.H3("Towson University — Vulnerability Intelligence Dashboard", style={"color":"#EAAA00", "marginLeft":"12px"}))
], align="center", style={"padding":"6px 12px"})

tabs = dcc.Tabs(id="tabs", value="vuln_dashboard", children=[
    dcc.Tab(label="Vulnerability Dashboard", value="vuln_dashboard"),
    dcc.Tab(label="LLM Request", value="llm_request"),
    dcc.Tab(label="Natural Language", value="natural_language"),
    dcc.Tab(label="Chatbot", value="chatbot"),
    dcc.Tab(label="Assessment", value="assessment"),
    dcc.Tab(label="Reporting", value="reporting"),
    dcc.Tab(label="Voice Assistant", value="voice_assistant"),
])

# vulnerability tab components (will be returned into layout on demand)
def build_vuln_tab():
    df = load_findings_df()
    src_options = [{"label": s, "value": s} for s in sorted(df['source'].dropna().unique())]
    sev_options = [{"label": s, "value": s} for s in sorted(df['severity'].dropna().unique())]
    host_options = [{"label": h, "value": h} for h in sorted(df['host'].dropna().unique())]
    return dbc.Container([
        dbc.Row([
            dbc.Col([
                html.Label("Source"),
                dcc.Dropdown(id="source-filter", options=src_options, placeholder="All sources", multi=True)
            ], md=4),
            dbc.Col([
                html.Label("Severity"),
                dcc.Dropdown(id="severity-filter", options=sev_options, placeholder="All severities", multi=True)
            ], md=4),
            dbc.Col([
                html.Label("Host / IP"),
                dcc.Dropdown(id="ip-filter", options=host_options, placeholder="All hosts", multi=True)
            ], md=4),
        ], className="mb-2"),
        dbc.Row([
            dbc.Col(dcc.Graph(id="cvss-distribution"), md=6),
            dbc.Col(dash_table.DataTable(
                id="findings-table",
                columns=[{"name": c, "id": c} for c in ["id","host","port","service","title","severity","cvss","cve_id","source"]],
                data=df.to_dict("records"),
                page_size=10,
                style_table={"overflowX":"auto"},
                filter_action="native",
                sort_action="native",
                row_selectable="multi",
            ), md=6)
        ])
    ], fluid=True)

# LLM request tab
llm_tab = dbc.Container([
    html.H4("LLM Request"),
    dcc.Textarea(id="llm-prompt", placeholder="Ask the model (e.g., 'Summarize all high severity CVEs')", style={"width":"100%","height":"140px"}),
    html.Br(),
    dbc.Button("Send to LLM", id="llm-send", color="warning"),
    html.Div(id="llm-output", style={"whiteSpace":"pre-wrap", "marginTop":"10px"})
], fluid=True)

# Natural Language tab (structured simple queries)
natural_tab = dbc.Container([
    html.H4("Natural Language Query Processor"),
    dcc.Textarea(id="nl-prompt", placeholder="e.g., 'Show me all critical vulns on 192.168.174.0/24'", style={"width":"100%","height":"120px"}),
    html.Br(),
    dbc.Button("Run NL Query", id="nl-run", color="warning"),
    html.Div(id="nl-output", style={"whiteSpace":"pre-wrap", "marginTop":"10px"})
es], fluid=True)

# Chatbot tab
chatbot_tab = dbc.Container([
    html.H4("Chatbot (ask about the data)"),
    dcc.Textarea(id="chat-msg", placeholder="Ask: 'Summarize all high CVEs from openvas'", style={"width":"100%","height":"120px"}),
    html.Br(),
    dbc.Button("Ask Chatbot", id="chat-send", color="primary"),
    html.Div(id="chat-output", style={"whiteSpace":"pre-wrap","marginTop":"10px"})
], fluid=True)

# Assessment tab (includes scanner selection + targets + confirm)
# === Assessment tab layout (replace the old block) ===
assessment_tab = dbc.Container([
    html.H4("Assessment — Scan Orchestration"),
    html.Div("Select scanner and provide targets. Only scan authorized systems.", style={"color":"#f4f4b4"}),
    html.Br(),
    dcc.Dropdown(id="scanner-select", options=[
        {"label":"Nessus", "value":"nessus"},
        {"label":"OpenVAS", "value":"openvas"},
        {"label":"Nmap (local)", "value":"nmap"},
        {"label":"Burp Enterprise", "value":"burp"}], placeholder="Choose a scanner"),
    html.Br(),
    dcc.Textarea(id="nessus-targets", placeholder="Enter targets (comma/newline separated)", style={"width":"100%","height":"100px"}),
    dcc.Upload(id="nessus-upload", children=html.Div(["Drag & drop or click to upload targets.txt"]), multiple=False),
    html.Br(),
    dbc.Input(id="nessus-name", placeholder="Scan name (optional)"),
    html.Br(),
    dcc.Checklist(id="nessus-confirm", options=[{"label":"I confirm I have written authorization to scan these targets", "value":"confirmed"}], value=[]),
    html.Br(),
    dbc.Button("Create & Launch Scan", id="nessus-launch", color="danger"),
    html.Button("Refresh Scan Status", id="nessus-refresh", n_clicks=0, style={"marginLeft":"8px"}),
    html.Pre(id="nessus-status", style={"whiteSpace":"pre-wrap", "color":"#bfe", "marginTop":"8px"})
], fluid=True)


# === Callback: launch scans and integrate Nmap -> Neo4j -> NVD enrichment ===
# Add/ensure these imports exist near the top of your app.py:
#
# from dash import html, dcc, Input, Output, State
# from dash.exceptions import PreventUpdate
# import os, subprocess, time
# from neo4j_integration import assessment_nmap_import_step, enrich_cves_from_nvd
#
# (If you already imported similar packages, skip duplicates.)

@app.callback(
    Output("nessus-status", "children"),
    Input("nessus-launch", "n_clicks"),
    State("scanner-select", "value"),
    State("nessus-targets", "value"),
    State("nessus-confirm", "value"),
    prevent_initial_call=True
)
def launch_assessment(n_clicks, scanner, targets, confirm):
    """
    Unified scan orchestration callback.
    - Validates authorization checkbox
    - Runs scanner selected (uses existing run_nmap_scan if present, else subprocess fallback)
    - For Nmap: after scan, imports into Neo4j and enriches CVEs via NVD
    """

    if not n_clicks:
        raise PreventUpdate

    # Basic validation
    if not confirm or "confirmed" not in confirm:
        return "❗ Please confirm you have written authorization to scan these targets."

    if not targets:
        return "⚠️ No targets provided. Please enter target IPs or hostnames."

    # Normalize targets list (comma or newline separated)
    targets_list = [t.strip() for t in targets.replace("\n", ",").split(",") if t.strip()]
    if not targets_list:
        return "⚠️ No valid targets found after parsing."

    # Build app_config for neo4j integration
    neo_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo_user = os.getenv("NEO4J_USER", "neo4j")
    neo_pass = os.getenv("NEO4J_PASS", "neo4j")
    scan_file = os.getenv("NMAP_XML_PATH", "/root/vuln_intel/app/data/nmap_scan.xml")
    gds_project_name = os.getenv("GDS_PROJECT", "nmapGraph")

    app_config = {
        "nmap_xml_path": scan_file,
        "neo4j_uri": neo_uri,
        "neo4j_user": neo_user,
        "neo4j_pass": neo_pass,
        "gds_project": gds_project_name
    }

    # --- NMAP flow ---------------------------------------------------------
    if scanner == "nmap":
        # If your project already has run_nmap_scan(targets, output_path) use it.
        run_local_nmap = None
        try:
            # try to use an existing helper if defined elsewhere in app
            run_local_nmap = globals().get("run_nmap_scan", None) or globals().get("run_nmap", None)
        except Exception:
            run_local_nmap = None

        # Ensure output directory exists
        out_dir = os.path.dirname(scan_file)
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            pass

        # Run Nmap (prefer user-defined helper)
        try:
            if callable(run_local_nmap):
                # Expecting function signature: run_nmap_scan(targets:list, xml_out_path:str)
                run_local_nmap(targets_list, scan_file)
            else:
                # Fallback: subprocess call to nmap
                # NOTE: this synchronous call may take time depending on targets.
                cmd = [
                    "nmap", "-sS", "-sV", "-p-", "--open", "--reason",
                    "--script", "vuln or default",
                    "-oX", scan_file
                ] + targets_list
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
                if proc.returncode != 0:
                    # return stderr so user sees what failed
                    return f"❌ Nmap failed (rc={proc.returncode}):\n{proc.stderr}"
        except subprocess.TimeoutExpired:
            return "⏱️ Nmap timed out. Try fewer targets or increase timeout."
        except FileNotFoundError:
            return "⚠️ Nmap executable not found on PATH. Install nmap or provide a run_nmap_scan helper."
        except Exception as e:
            return f"⚠️ Nmap execution error: {e}"

        # Verify xml exists
        if not os.path.exists(scan_file):
            return f"❌ Expected scan output not found at {scan_file}."

        # Step 1: Import Nmap scan results into Neo4j
        try:
            assessment_nmap_import_step(app_config)
        except Exception as e:
            return f"❌ Error importing Nmap results into Neo4j: {e}"

        # Step 2: Enrich CVEs via NVD API (batch)
        try:
            # batch_limit and delay are tuneable via env or hardcode
            batch_limit = int(os.getenv("NVD_BATCH_LIMIT", "50"))
            delay = float(os.getenv("NVD_DELAY", "1.2"))
            enrich_cves_from_nvd(
                neo4j_uri=app_config["neo4j_uri"],
                user=app_config["neo4j_user"],
                password=app_config["neo4j_pass"],
                batch_limit=batch_limit,
                delay=delay
            )
        except Exception as e:
            # Enrichment failures should not erase successful import; inform user but continue
            return f"✅ Nmap import succeeded — but NVD enrichment failed: {e}"

        return f"✅ Nmap scan completed, results imported into Neo4j, and CVEs enriched. Targets: {', '.join(targets_list)}"

    # --- NESSUS / OPENVAS / BURP branches: keep existing flows or placeholder text ----
    elif scanner == "nessus":
        # If you have existing Nessus orchestration code, call it here.
        # Replace the next line with your existing Nessus scan invocation.
        return "🚀 (Placeholder) Nessus scan started — integrate your existing Nessus workflow here."

    elif scanner == "openvas":
        # Replace with your OpenVAS orchestration call
        return "🚀 (Placeholder) OpenVAS scan started — integrate your existing OpenVAS workflow here."

    elif scanner == "burp":
        # Replace with your Burp Enterprise orchestration call
        return "🚀 (Placeholder) Burp Enterprise scan started — integrate your existing Burp workflow here."

    else:
        return "⚠️ Unknown scanner selected. Choose a scanner and try again."

# Reporting tab
reporting_tab = dbc.Container([
    html.H4("Reporting"),
    html.Div("Select rows in Vulnerability Dashboard table and export to PDF."),
    html.Br(),
    dbc.Button("Export selected findings to PDF", id="export-pdf", color="secondary"),
    html.Div(id="export-output", style={"marginTop":"10px", "color":"#bfe"})
], fluid=True)

# Voice assistant tab (lightweight/browser speech fallback)
voice_tab = dbc.Container([
    html.H4("Voice Assistant (Browser speech API)"),
    html.Div("Click Start/Stop in your browser. Requires assets/voice.js to be installed in app/assets."),
    html.Button("Start Voice", id="start-voice"),
    html.Button("Stop Voice", id="stop-voice", style={"marginLeft":"8px"}),
    dcc.Checklist(id="tts-check", options=[{"label":"Speak replies (browser TTS)", "value":"tts"}], value=[]),
    html.Div(id="recognized-text", style={"whiteSpace":"pre-wrap","marginTop":"8px","color":"#bfe"}),
    html.Div(id="llm-voice-response", style={"whiteSpace":"pre-wrap","marginTop":"8px","color":"#ffd"})
], fluid=True)

app.layout = dbc.Container([
    header,
    tabs,
    html.Hr(),
    html.Div(id="tab-content")
], fluid=True)

# -------------------- Callbacks --------------------

# Render selected tab
@app.callback(Output("tab-content", "children"), Input("tabs", "value"))
def render_tab(tab):
    if tab == "vuln_dashboard":
        return build_vuln_tab()
    elif tab == "llm_request":
        return llm_tab
    elif tab == "natural_language":
        return natural_tab
    elif tab == "chatbot":
        return chatbot_tab
    elif tab == "assessment":
        return assessment_tab
    elif tab == "reporting":
        return reporting_tab
    elif tab == "voice_assistant":
        return voice_tab
    return html.Div("Unknown tab")

# Update vuln dashboard visuals when filters change
@app.callback(
    Output("cvss-distribution", "figure"),
    Output("findings-table", "data"),
    Input("source-filter", "value"),
    Input("severity-filter", "value"),
    Input("ip-filter", "value"),
)
def update_vuln_visuals(sources, severities, ips):
    df = load_findings_df()
    # apply filters
    if sources:
        df = df[df['source'].isin(sources)]
    if severities:
        df = df[df['severity'].isin(severities)]
    if ips:
        df = df[df['host'].isin(ips)]
    # ensure cvss numeric
    df['cvss_num'] = pd.to_numeric(df['cvss'], errors='coerce')
    # build histogram / distribution
    if not df.empty and df['cvss_num'].notnull().any():
        fig = px.histogram(df.dropna(subset=['cvss_num']), x='cvss_num', nbins=10, title="CVSS Score Distribution", labels={"cvss_num":"CVSS"})
    else:
        # empty placeholder
        fig = px.histogram(pd.DataFrame({"cvss_num":[]}), x='cvss_num', title="CVSS Score Distribution")
        fig.update_layout(xaxis={"visible": False}, yaxis={"visible": False}, annotations=[{"text":"No CVSS data available","xref":"paper","yref":"paper","x":0.5,"y":0.5,"showarrow":False}])
    # table data return
    table_data = df[["id","host","port","service","title","severity","cvss","cve_id","source"]].to_dict("records")
    return fig, table_data

# LLM request handler
@app.callback(Output("llm-output", "children"), Input("llm-send", "n_clicks"), State("llm-prompt", "value"), prevent_initial_call=True)
def run_llm_request(n, prompt):
    if not prompt:
        return "Please enter a prompt."
    out = openai_chat(prompt)
    return out

# Natural language processor (calls the LLM for parsing then runs local query)
@app.callback(Output("nl-output", "children"), Input("nl-run", "n_clicks"), State("nl-prompt", "value"), prevent_initial_call=True)
def run_nl_query(n, prompt):
    if not prompt:
        return "Enter a natural language query."
    # Ask LLM to translate NL query to a SQL-ish filter (simple prompt)
    system = "You are a helpful assistant that translates a user's short natural language query into a SQL WHERE clause over a table with columns host, port, severity, cvss, source, cve_id. Return only JSON: {\"where\":\"...\"}"
    reply = openai_chat(prompt, system=system)
    try:
        parsed = json.loads(reply)
        where = parsed.get("where","")
    except Exception:
        return f"Failed to parse LLM response. Raw: {reply}"
    # very simple and dangerous to run arbitrary SQL. We'll only support a few keywords mapping.
    df = load_findings_df()
    # naive: filter by keywords present
    q = where.lower()
    if "severity =" in q or "severity in" in q:
        # crude extraction
        import re
        vals = re.findall(r"severity\s*(?:=|in)\s*\(?['\"]?([a-zA-Z, ]+)['\"]?\)?", q)
        if vals:
            sev_list = [s.strip() for s in vals[0].split(",")]
            df = df[df['severity'].str.lower().isin([s.lower() for s in sev_list])]
    # return top 20 rows
    return df.head(20).to_string(index=False)

# Chatbot handler (question about dataset)
@app.callback(Output("chat-output", "children"), Input("chat-send", "n_clicks"), State("chat-msg", "value"), prevent_initial_call=True)
def run_chatbot(n, msg):
    if not msg:
        return "Please ask something."
    # we can provide dataset summary + call LLM
    df = load_findings_df()
    # create short context for LLM
    ctx_summary = f"Dataset: {len(df)} findings. Sources: {', '.join(sorted(df['source'].dropna().unique()))}."
    prompt = f"{ctx_summary}\nUser: {msg}\nAnswer concisely."
    return openai_chat(prompt)

# Assessment: create/launch scans (single unified callback)
@app.callback(
    Output("nessus-status", "children"),
    [Input("nessus-launch", "n_clicks"), Input("nessus-refresh", "n_clicks")],
    [State("scanner-select","value"),
     State("nessus-targets","value"),
     State("nessus-upload","contents"),
     State("nessus-name","value"),
     State("nessus-confirm","value"),
     State("nessus-status","children")],
    prevent_initial_call=True
)
def assessment_action(launch_clicks, refresh_clicks, scanner, targets_text, upload_contents, scan_name, confirm, current_status):
    trigger_id = ctx.triggered_id
    # require authorization
    if not confirm or "confirmed" not in confirm:
        return AUTHORIZED_ONLY_MSG
    # determine targets (upload overrides)
    targets = ""
    if upload_contents:
        try:
            header, b64 = upload_contents.split(",",1)
            raw = base64.b64decode(b64).decode("utf-8", errors="ignore")
            targets = ",".join([line.strip() for line in raw.splitlines() if line.strip()])
        except Exception as e:
            return f"Failed to parse upload: {e}"
    elif targets_text:
        targets = ",".join([t.strip() for t in targets_text.replace("\n",",").split(",") if t.strip()])
    if not targets:
        return "No targets specified."
    name = scan_name or f"AutoScan-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}"
    # dispatch
    if trigger_id == "nessus-launch":
        if scanner == "nessus":
            res = nessus_create_and_launch_scan(name, targets)
            return json.dumps(res, indent=2)
        elif scanner == "openvas":
            res = trigger_openvas_scan(name, targets)
            return json.dumps(res, indent=2)
        elif scanner == "nmap":
            res = trigger_nmap_scan_async(name, targets)
            return json.dumps(res, indent=2)
        elif scanner == "burp":
            res = trigger_burp_scan(name, targets)
            return json.dumps(res, indent=2)
        else:
            return "Select a scanner."
    elif trigger_id == "nessus-refresh":
        # try to extract "scan_id" from current_status text
        import re
        if not current_status:
            return "No previous run found to refresh. Create a scan first."
        m = re.search(r"scan_id\"?\s*[:=]?\s*\"?(\d+)\"?", str(current_status))
        if m:
            scan_id = m.group(1)
            # try Nessus first
            status = nessus_get_scan_status(scan_id)
            return json.dumps(status, indent=2)
        return "No scan id found in status text."

# Reporting: export selected table rows to PDF
@app.callback(
    Output("export-output", "children"),
    Input("export-pdf", "n_clicks"),
    State("findings-table", "derived_virtual_selected_rows"),
    State("findings-table", "data"),
    prevent_initial_call=True
)
def export_pdf(n, selected_rows, table_data):
    df_table = pd.DataFrame(table_data or [])
    if selected_rows:
        selected_ids = [df_table.loc[i, "id"] for i in selected_rows if "id" in df_table.columns and i < len(df_table)]
    else:
        selected_ids = df_table["id"].tolist() if not df_table.empty and "id" in df_table.columns else []
    out_file = REPORT_DIR / f"findings_report_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.pdf"
    export_findings_to_pdf(selected_ids, out_file)
    return f"Exported PDF to: {out_file}"

# Voice Assistant JS integration (assets/voice.js must exist) -> the JS will put recognized text into 'recognized-text' element or call fetch.
@app.callback(Output("llm-voice-response", "children"), Input("start-voice","n_clicks"), prevent_initial_call=True)
def voice_start(n):
    # This callback is primarily placeholder; real voice logic handled in client JS
    return "Voice started (use browser console/voice.js)."

# -------------------- Start server --------------------
if __name__ == "__main__":
    print(f"[+] DB path: {DB_PATH}")
    print(f"[+] OpenAI configured: {'yes' if OPENAI_API_KEY else 'no'}")
    # Use new run API if necessary
    try:
        # For Dash v2+, run() is recommended
        app.run(host="0.0.0.0", port=8050, debug=True)
    except Exception:
        # fallback
        app.run_server(host="0.0.0.0", port=8050, debug=True)
