#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master app.py — Towson University Vulnerability Intelligence Dashboard
Merged, sanitized, ready-to-paste.
- 7 tabs: Vulnerability Dashboard, LLM Request, Natural Language, Chatbot, Assessment, Reporting, Voice Assistant
- DB: /root/vuln_intel/app/data/findings.db
- OpenAI: via OPENAI_API_KEY environment variable (no hard-coded key)
"""

import os
import sys
import json
import sqlite3
import subprocess
import ipaddress
import base64
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
import requests
import pandas as pd
import plotly.express as px

from flask import request, jsonify
from dash import Dash, dcc, html, Input, Output, State, dash_table, no_update
import dash_bootstrap_components as dbc

# -----------------------
# Configuration
# -----------------------
PROJECT_ROOT = "/root/vuln_intel"
DB_PATH = f"{PROJECT_ROOT}/app/data/findings.db"
REPORT_DIR = Path(f"{PROJECT_ROOT}/app/data/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# Optional scanner endpoints (set env vars if you want to enable remote APIs)
NESSUS_URL = os.getenv("NESSUS_URL")       # e.g. https://nessus.example
NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY")
NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY")
OPENVAS_URL = os.getenv("OPENVAS_URL")
OPENVAS_TOKEN = os.getenv("OPENVAS_TOKEN")
BURP_URL = os.getenv("BURP_URL")
BURP_API_KEY = os.getenv("BURP_API_KEY")

# Whitelist ranges — lab-only (change as needed)
WHITELIST_CIDRS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# -----------------------
# Helper functions
# -----------------------
def db_exists_and_has_table(path, tbl="findings"):
    if not Path(path).exists():
        return False
    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (tbl,))
        r = cur.fetchone()
        conn.close()
        return bool(r)
    except Exception:
        return False

def load_findings_df():
    # returns pandas DataFrame (safe when DB missing)
    if not db_exists_and_has_table(DB_PATH, "findings"):
        cols = ["id","asset_id","host","port","service","title","severity","cvss","cve_id","description","evidence","remediation","vuln_name","path","source","import_date","timestamp"]
        return pd.DataFrame(columns=cols)
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM findings", conn)
    conn.close()
    return df

def openai_chat(prompt: str):
    if not OPENAI_API_KEY:
        return "OpenAI API key not set in environment."
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {"model": OPENAI_MODEL, "messages": [{"role": "user", "content": prompt}], "max_tokens": 800}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"OpenAI call failed: {e}"

def validate_targets_in_whitelist(targets: str):
    # Accepts comma/newline separated ip or cidr entries. Returns (ok, message)
    try:
        entries = [e.strip() for e in targets.replace("\n", ",").split(",") if e.strip()]
        for ent in entries:
            if "/" in ent:  # network
                net = ipaddress.ip_network(ent, strict=False)
                if not any(net.subnet_of(w) for w in WHITELIST_CIDRS):
                    return False, f"{ent} not in authorized lab ranges"
            else:
                addr = ipaddress.ip_address(ent)
                if not any(addr in w for w in WHITELIST_CIDRS):
                    return False, f"{ent} not in authorized lab ranges"
        return True, "ok"
    except Exception as e:
        return False, str(e)

def export_findings_to_csv():
    df = load_findings_df()
    out = REPORT_DIR / f"findings_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(out, index=False)
    return str(out)

def import_csv_from_bytes(b64payload):
    try:
        data = base64.b64decode(b64payload)
        tmp = REPORT_DIR / f"import_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        tmp.write_bytes(data)
        df = pd.read_csv(tmp)
        conn = sqlite3.connect(DB_PATH)
        df.to_sql("findings", conn, if_exists="append", index=False)
        conn.close()
        return f"Imported {len(df)} rows"
    except Exception as e:
        return f"CSV import failed: {e}"

def parse_nmap_xml_file(xml_path):
    """
    Parse nmap XML and append to findings table.
    This is minimal parser — improves as needed.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        for host in root.findall("host"):
            addr_elem = host.find("address")
            if addr_elem is None:
                continue
            addr = addr_elem.get("addr")
            for port in host.findall(".//port"):
                portid = port.get("portid")
                svc_elem = port.find("service")
                service_name = svc_elem.get("name") if svc_elem is not None else None
                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else None
                title = f"Service {service_name or state} on {addr}:{portid}"
                cur.execute("""INSERT INTO findings (host,port,service,title,severity,cvss,source,import_date,timestamp)
                            VALUES (?,?,?,?,?,?,?,?,?)""",
                            (addr, portid, service_name, title, "info", None, "nmap", datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return f"Parsed {xml_path}"
    except Exception as e:
        return f"Nmap XML parse error: {e}"

# Nmap runner (verbose). Only run local nmap binary.
def run_nmap_verbose(targets: str, out_basename: str = None):
    if not targets:
        return "No targets provided."
    out_dir = REPORT_DIR / "nmap"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_basename = out_basename or f"nmap_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    out_xml = out_dir / f"{out_basename}.xml"
    # prepare cmd list: use -vvv for verbosity, -sV -O --script vuln for version+OS+vuln scripts
    targets_list = [t.strip() for t in targets.replace("\n", ",").split(",") if t.strip()]
    cmd = ["nmap", "-vvv", "-sV", "-O", "--script", "vuln", "-oX", str(out_xml)] + targets_list
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        # write stdout to a log file for review
        (out_dir / f"{out_basename}.log").write_text(proc.stdout + "\n\nSTDERR:\n" + proc.stderr)
        # attempt parse xml
        if out_xml.exists():
            parse_nmap_xml_file(str(out_xml))
        return f"Nmap finished. XML: {out_xml}"
    except Exception as e:
        return f"Nmap run failed: {e}"

# Minimalness: list of scanner configs (placeholders)
def list_nessus_templates():
    if not (NESSUS_URL and NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY):
        return []
    try:
        resp = requests.get(f"{NESSUS_URL.rstrip('/')}/editor/scan/templates",
                            headers={"X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY}"},
                            timeout=10, verify=False)
        return [{"label": t.get("name"), "value": t.get("uuid")} for t in resp.json().get("templates", [])]
    except Exception:
        return []

def list_openvas_configs():
    if not (OPENVAS_URL and OPENVAS_TOKEN):
        return []
    try:
        resp = requests.get(f"{OPENVAS_URL.rstrip('/')}/api/configs",
                            headers={"Authorization": f"Bearer {OPENVAS_TOKEN}"}, timeout=10, verify=False)
        return [{"label": c.get("name"), "value": c.get("id")} for c in resp.json().get("configs", [])]
    except Exception:
        return []

def list_burp_configs():
    if not (BURP_URL and BURP_API_KEY):
        return []
    try:
        resp = requests.get(f"{BURP_URL.rstrip('/')}/api/v1/scan_configurations",
                            headers={"Authorization": BURP_API_KEY"}, timeout=10, verify=False)
        return [{"label": c.get("name"), "value": c.get("uuid")} for c in resp.json().get("items", [])]
    except Exception:
        return []

# Minimal placeholders for starting remote scans (implement per vendor docs when enabling)
def start_nessus_scan(template_uuid, targets):
    return {"status": "started", "id": None, "message": "Nessus integration not configured or response was empty."}

def start_openvas_task(config_id, targets):
    return {"status": "started", "id": None, "message": "OpenVAS integration not configured or response was empty."}

def start_burp_scan(template_id, urls):
    return {"status": "started", "id": None, "message": "Burp integration not configured or response was empty."}

# -----------------------
# Dash app / layout
# -----------------------
app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY], suppress_callback_exceptions=True)
server = app.server

# small style blocks used for readability
table_style = {
    "style_header": {"backgroundColor": "#111", "color": "#EAAA00", "fontWeight": "bold"},
    "style_cell": {"backgroundColor": "#1C1C1C", "color": "#E0E0E0", "whiteSpace": "normal", "height": "auto"},
    "style_table": {"overflowX": "auto"}
}

# === Tab content generators ===
def vulnerability_dashboard_layout():
    df = load_findings_df()
    # aggregated CVSS distribution (cvss numeric), but many rows may have None -> convert
    fig_cvss = px.histogram(df, x="severity", y="cvss", histfunc="avg", title="CVSS distribution by severity") if not df.empty and "cvss" in df.columns else {}
    # host counts per source
    src_options = [{"label": s, "value": s} for s in sorted(df["source"].dropna().unique())] if not df.empty else []
    severity_options = [{"label": s, "value": s} for s in sorted(df["severity"].dropna().unique())] if not df.empty else []
    hosts = sorted(df["host"].dropna().unique().tolist()) if not df.empty else []

    return dbc.Container([
        html.H4("Vulnerability Dashboard", style={"color":"#EAAA00"}),
        dbc.Row([
            dbc.Col(dcc.Dropdown(id="source-filter", options=src_options, placeholder="Filter by Source"), md=4),
            dbc.Col(dcc.Dropdown(id="severity-filter", options=severity_options, placeholder="Filter by Severity"), md=4),
            dbc.Col(dcc.Dropdown(id="host-filter", options=[{"label":h,"value":h} for h in hosts], placeholder="Filter by IP"), md=4),
        ], className="mb-3"),
        dbc.Row([
            dbc.Col(dcc.Graph(id="sev-bar", figure=px.bar(df, x="severity", title="Vulnerabilities by severity") if not df.empty else {}), md=6),
            dbc.Col(dcc.Graph(id="cvss-distribution", figure=fig_cvss if fig_cvss else {}), md=6)
        ]),
        html.Hr(),
        dash_table.DataTable(
            id="findings-table",
            columns=[{"name": c, "id": c} for c in df.columns] if not df.empty else [{"name":"id","id":"id"}],
            data=df.to_dict("records"),
            page_size=12,
            filter_action="native",
            sort_action="native",
            row_selectable="multi",
            **table_style
        )
    ], fluid=True)

def llm_request_layout():
    return dbc.Container([
        html.H4("LLM Request", style={"color":"#EAAA00"}),
        dcc.Textarea(id="llm-prompt", placeholder="Enter your prompt (e.g. 'Summarize all high severity vulnerabilities')", style={"width":"100%","height":"160px"}),
        dbc.Button("Run LLM Analysis", id="run-llm", color="warning", className="mt-2"),
        html.Br(), html.Br(),
        dbc.Alert(id="llm-result", is_open=True, color="light", style={"whiteSpace":"pre-wrap","color":"#000","background":"#fff"})
    ], fluid=True)

def natural_language_layout():
    return dbc.Container([
        html.H4("Natural Language Query Processor", style={"color":"#EAAA00"}),
        dcc.Textarea(id="nlq-prompt", placeholder="Ask something about your findings (e.g., 'Which hosts have FTP services?')", style={"width":"100%","height":"100px"}),
        dbc.Button("Run Query", id="nlq-run", color="success", className="mt-2"),
        html.Br(), html.Br(),
        html.Pre(id="nlq-result", style={"whiteSpace":"pre-wrap","color":"#bfe"})
    ], fluid=True)

def chatbot_layout():
    return dbc.Container([
        html.H4("Chatbot (ask the dataset / LLM)", style={"color":"#EAAA00"}),
        dcc.Textarea(id="chat-input", placeholder="Ask the chatbot (e.g., 'Summarize all high CVEs from openvas')", style={"width":"100%","height":"120px"}),
        dbc.Button("Ask", id="chat-ask", color="primary", className="mt-2"),
        html.Br(), html.Br(),
        dbc.Alert(id="chat-response", color="dark", style={"whiteSpace":"pre-wrap","color":"#fff","background":"#222"})
    ], fluid=True)

def assessment_layout():
    # scanner dropdown and template dropdown are populated via callbacks
    return dbc.Container([
        html.H4("Assessment — Launch Scans", style={"color":"#EAAA00"}),
        dbc.Row([
            dbc.Col(dcc.Dropdown(id="scanner-select", options=[
                {"label":"Nmap (local verbose)","value":"nmap"},
                {"label":"Nessus","value":"nessus"},
                {"label":"OpenVAS","value":"openvas"},
                {"label":"Burp Suite","value":"burp"},
            ], placeholder="Select scanner"), md=4),
            dbc.Col(dcc.Dropdown(id="scanner-template", placeholder="Select template / config"), md=4),
            dbc.Col(dbc.Button("Refresh templates", id="refresh-templates", color="secondary"), md=4)
        ], className="mb-2"),
        dcc.Textarea(id="scan-targets", placeholder="Targets (comma or newline separated)", style={"width":"100%","height":"100px"}),
        dbc.Checklist(id="confirm-auth", options=[{"label":"I confirm these targets are authorized for my lab", "value":"ok"}], value=[]),
        dbc.Button("Launch Scan", id="launch-scan", color="danger", className="mt-2"),
        html.Br(), html.Br(),
        dbc.Progress(id="scan-progress", value=0, striped=True, animated=True),
        html.Pre(id="scan-log", style={"whiteSpace":"pre-wrap","color":"#bfe","marginTop":"10px"})
    ], fluid=True)

def reporting_layout():
    return dbc.Container([
        html.H4("Reporting & Data Management", style={"color":"#EAAA00"}),
        dbc.Row([
            dbc.Col(dbc.Button("Export Findings CSV", id="btn-export-csv", color="info"), md=3),
            dbc.Col(dcc.Upload(id="upload-csv", children=html.Div(["Drag and drop CSV here or click to upload"]), multiple=False,
                               style={"width":"100%","height":"60px","lineHeight":"60px","borderWidth":"1px","borderStyle":"dashed","borderRadius":"5px","textAlign":"center"}), md=6),
            dbc.Col(dbc.Button("Reparse Nmap XML directory", id="btn-parse-nmap", color="secondary"), md=3)
        ]),
        html.Br(),
        html.Div(id="report-status", style={"color":"#bfe"})
    ], fluid=True)

def voice_assistant_layout():
    # This tab expects assets/voice.js to implement browser Speech API and post to /llm_voice
    return dbc.Container([
        html.H4("Voice Assistant (Browser Speech API)", style={"color":"#EAAA00"}),
        html.Div([
            dbc.Button("Start Voice (browser)", id="voice-start", color="primary"),
            dbc.Button("Stop Voice", id="voice-stop", color="secondary", style={"marginLeft":"8px"}),
            dcc.Checklist(id="voice-tts", options=[{"label":"Speak replies (browser TTS)", "value":"tts"}], value=[])
        ], className="mb-2"),
        html.Div(id="voice-status", children="Status: idle", style={"color":"#bfe"}),
        html.Br(),
        html.Div(id="voice-recognized", style={"color":"#bfe","whiteSpace":"pre-wrap"}),
        html.Div(id="voice-llm-reply", style={"color":"#ffd","whiteSpace":"pre-wrap"})
    ], fluid=True)

# -------------------------
# Main layout with 7 tabs
# -------------------------
app.layout = dbc.Container([
    dbc.Row(dbc.Col(html.H2("Towson University — Vulnerability Intelligence Dashboard", style={"textAlign":"center","color":"#EAAA00"}))),
    dcc.Tabs(id="main-tabs", value="dashboard", children=[
        dcc.Tab(label="Vulnerability Dashboard", value="dashboard"),
        dcc.Tab(label="LLM Request", value="llm"),
        dcc.Tab(label="Natural Language", value="natural"),
        dcc.Tab(label="Chatbot", value="chatbot"),
        dcc.Tab(label="Assessment", value="assessment"),
        dcc.Tab(label="Reporting", value="reporting"),
        dcc.Tab(label="Voice Assistant", value="voice")
    ]),
    html.Div(id="tab-content", style={"marginTop":"12px"})
], fluid=True)

# -------------------------
# Callbacks: Tab routing
# -------------------------
@app.callback(Output("tab-content", "children"), Input("main-tabs", "value"))
def render_tab(tab_value):
    if tab_value == "dashboard":
        return vulnerability_dashboard_layout()
    elif tab_value == "llm":
        return llm_request_layout()
    elif tab_value == "natural":
        return natural_language_layout()
    elif tab_value == "chatbot":
        return chatbot_layout()
    elif tab_value == "assessment":
        return assessment_layout()
    elif tab_value == "reporting":
        return reporting_layout()
    elif tab_value == "voice":
        return voice_assistant_layout()
    return html.Div("Unknown tab")

# -------------------------
# Callbacks: LLM request
# -------------------------
@app.callback(
    Output("llm-result", "children"),
    Input("run-llm", "n_clicks"),
    State("llm-prompt", "value"),
    prevent_initial_call=True
)
def handle_llm(n, prompt):
    if not prompt:
        return "Please enter a prompt."
    resp = openai_chat(prompt)
    return resp

# -------------------------
# Callbacks: Natural Language Query
# -------------------------
@app.callback(
    Output("nlq-result", "children"),
    Input("nlq-run", "n_clicks"),
    State("nlq-prompt", "value"),
    prevent_initial_call=True
)
def handle_nlq(n, prompt):
    if not prompt:
        return "Enter a query."
    # Simple local engine: search findings and produce short answer, then optionally call LLM for summary
    df = load_findings_df()
    if df.empty:
        return "No findings available."
    # basic filters: naive phrase searches
    matched = df[df.apply(lambda r: prompt.lower() in " ".join([str(x).lower() for x in r.fillna("")]), axis=1)]
    if matched.empty:
        # fallback to LLM summarization of entire dataset
        text = "No matched rows. Provide a summary of the dataset."
        return openai_chat(f"{prompt}\n\nDataset summary:\n{df.head(50).to_csv(index=False)}")
    return matched.to_string(index=False)

# -------------------------
# Callbacks: Chatbot
# -------------------------
@app.callback(
    Output("chat-response", "children"),
    Input("chat-ask", "n_clicks"),
    State("chat-input", "value"),
    prevent_initial_call=True
)
def handle_chat(n, text):
    if not text:
        return "Enter a question."
    # first attempt: local dataset query
    df = load_findings_df()
    # if question refers to 'summarize' or wants synthesis, call OpenAI
    if any(k in text.lower() for k in ["summarize","overall","top","explain","what are"]):
        prompt = f"User query: {text}\n\nDataset (top 100 rows):\n{df.head(100).to_csv(index=False)}\n\nPlease answer based on dataset and mention any CVEs, hosts, severities."
        return openai_chat(prompt)
    # otherwise do a local filter
    matched = df[df.apply(lambda r: text.lower() in " ".join([str(x).lower() for x in r.fillna("")]), axis=1)]
    if matched.empty:
        return openai_chat(f"No direct matches in dataset for: {text}\nPlease provide a short answer.")
    return matched.head(20).to_string(index=False)

# -------------------------
# Callbacks: Assessment tab templates + launch
# -------------------------
@app.callback(
    Output("scanner-template", "options"),
    Input("scanner-select", "value")
)
def populate_templates(scanner):
    if scanner == "nessus":
        return list_nessus_templates()
    if scanner == "openvas":
        return list_openvas_configs()
    if scanner == "burp":
        return list_burp_configs()
    return []

@app.callback(
    Output("scan-log", "children"),
    Output("scan-progress", "value"),
    Input("launch-scan", "n_clicks"),
    State("scanner-select", "value"),
    State("scanner-template", "value"),
    State("scan-targets", "value"),
    State("confirm-auth", "value"),
    prevent_initial_call=True
)
def launch_scan(n, scanner, template, targets, confirm):
    if not n:
        return no_update, no_update
    if not confirm or "ok" not in confirm:
        return "You must confirm authorization for these targets.", 0
    ok, msg = validate_targets_in_whitelist(targets or "")
    if not ok:
        return f"Whitelist error: {msg}", 0
    if scanner == "nmap":
        res = run_nmap_verbose(targets, out_basename=f"nmap_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
        return res, 100
    elif scanner == "nessus":
        r = start_nessus_scan(template, targets)
        return json.dumps(r), 1
    elif scanner == "openvas":
        r = start_openvas_task(template, targets)
        return json.dumps(r), 1
    elif scanner == "burp":
        r = start_burp_scan(template, targets)
        return json.dumps(r), 1
    return "Unknown scanner.", 0

# -------------------------
# Callbacks: Reporting tab (import/export/parse nmap)
# -------------------------
@app.callback(
    Output("report-status", "children"),
    Input("btn-export-csv", "n_clicks"),
    Input("upload-csv", "contents"),
    Input("btn-parse-nmap", "n_clicks"),
    prevent_initial_call=True
)
def handle_reporting(export_clicks, upload_contents, parse_clicks):
    ctx = dash.callback_context
    if not ctx.triggered:
        return no_update
    triggered = ctx.triggered[0]["prop_id"].split(".")[0]
    if triggered == "btn-export-csv":
        out = export_findings_to_csv()
        return f"Exported to {out}"
    if triggered == "upload-csv" and upload_contents:
        # upload_contents is data:<mime>;base64,<b64>
        try:
            header, b64 = upload_contents.split(",",1)
            return import_csv_from_bytes(b64)
        except Exception as e:
            return f"Upload parse error: {e}"
    if triggered == "btn-parse-nmap":
        # parse all xml files in REPORT_DIR/nmap
        out_dir = REPORT_DIR / "nmap"
        if not out_dir.exists():
            return "No nmap outputs found."
        msgs = []
        for f in out_dir.glob("*.xml"):
            msgs.append(parse_nmap_xml_file(str(f)))
        return "\n".join(msgs)
    return "No action."

# -------------------------
# Voice assistant / LLM endpoint (browser JS -> POST)
# -------------------------
@server.route("/llm_voice", methods=["POST"])
def llm_voice_route():
    data = request.json or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error":"no text"}), 400
    reply = openai_chat(text)
    return jsonify({"reply": reply})

# -------------------------
# Safety: if DB missing, ensure created with findings schema
# -------------------------
def ensure_findings_table():
    if not Path(DB_PATH).exists():
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            host TEXT,
            port TEXT,
            service TEXT,
            title TEXT,
            severity TEXT,
            cvss REAL,
            cve_id TEXT,
            description TEXT,
            evidence TEXT,
            remediation TEXT,
            vuln_name TEXT,
            path TEXT,
            source TEXT,
            import_date TEXT,
            timestamp TEXT
        );""")
        conn.commit()
        conn.close()
    else:
        # verify schema exists; if not, create
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings';")
        if not cur.fetchone():
            cur.execute("""CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER,
                        host TEXT, port TEXT, service TEXT, title TEXT, severity TEXT, cvss REAL, cve_id TEXT,
                        description TEXT, evidence TEXT, remediation TEXT, vuln_name TEXT, path TEXT, source TEXT,
                        import_date TEXT, timestamp TEXT);""")
            conn.commit()
        conn.close()

# -------------------------
# Start up tasks
# -------------------------
ensure_findings_table()

# -------------------------
# Run the app
# -------------------------
if __name__ == "__main__":
    print(f"[+] DB path: {DB_PATH}")
    if OPENAI_API_KEY:
        print("[+] OpenAI key present (loaded from environment).")
    else:
        print("[!] OpenAI key NOT set. LLM features will show warnings.")
    # Run with app.run() (modern Dash)
    # choose host/port as you need; default 0.0.0.0:8050
    try:
        app.run(host="0.0.0.0", port=8050, debug=True)
    except TypeError:
        # fallback if older dash expects run_server
        app.run_server(host="0.0.0.0", port=8050, debug=True)
