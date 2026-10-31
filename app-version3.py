#!/usr/bin/env python3
# ==========================================================
#  Vulnerability Intelligence Dashboard (Patched, full app.py)
#  - Restores the working dashboard behavior (loads DB, populates filters & table)
#  - Adds robust OpenAI initialization (new SDK first, legacy fallback)
#  - Provides LLM, Natural Language, Chatbot, Assessment (MITRE placeholder), Reporting, Voice tabs
#  - Ready to copy/replace /root/vuln_intel/app/app.py
# ==========================================================

import os
import sys
import subprocess
import datetime
import sqlite3
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
from fpdf import FPDF

from dash import Dash, dcc, html, Input, Output, State, dash_table
import dash_bootstrap_components as dbc

# ---------------------------
# Configuration (edit if needed)
# ---------------------------
PROJECT_ROOT = "/root/vuln_intel"
DB_PATH = f"{PROJECT_ROOT}/app/data/findings.db"
REPORT_DIR = f"{PROJECT_ROOT}/app/data/reports"
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")  # default model
Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

# ---------------------------
# Robust OpenAI Initialization (new SDK then legacy fallback)
# ---------------------------
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
_openai_diag = ""
_send_chat = None

if not OPENAI_KEY:
    print("[!] OPENAI_API_KEY not set. LLM features will be disabled until you export your key.")
    client = None
else:
    # Try new SDK
    try:
        from openai import OpenAI as OpenAIClient  # new-style SDK
        client = OpenAIClient()  # typically reads key from env
        # optional light connectivity check (non-blocking)
        try:
            _ = client.models.list()
        except Exception:
            pass

        def _send_chat(messages, model=OPENAI_MODEL, max_tokens=600):
            resp = client.chat.completions.create(model=model, messages=messages, max_tokens=max_tokens)
            return resp.choices[0].message.content.strip()

        _openai_diag = "new OpenAI SDK initialized"
        print("[+] New OpenAI SDK initialized.")
    except Exception as exc_new:
        print(f"[!] New OpenAI SDK init failed: {exc_new!s}")
        # Fallback to legacy openai package
        try:
            import openai as legacy_openai
            legacy_openai.api_key = OPENAI_KEY
            client = legacy_openai

            def _send_chat(messages, model=OPENAI_MODEL, max_tokens=600):
                resp = legacy_openai.ChatCompletion.create(model=model, messages=messages, max_tokens=max_tokens)
                return resp["choices"][0]["message"]["content"].strip()

            _openai_diag = "legacy openai.ChatCompletion initialized"
            print("[+] Fallback legacy openai.ChatCompletion initialized.")
        except Exception as exc_legacy:
            client = None
            _openai_diag = f"both new and legacy OpenAI init failed: {exc_legacy!s}"
            print(f"[!] OpenAI fallback failed: {exc_legacy!s}")


def ai_response(prompt: str, df: pd.DataFrame = None, model: str = None, max_tokens: int = 600) -> str:
    """
    Unified AI response wrapper. If no working OpenAI backend is available, returns a clear message.
    """
    if _send_chat is None:
        return ("🚫 OpenAI client not available. Verify OPENAI_API_KEY and package compatibility. "
                "See startup logs for details.")
    model = model or OPENAI_MODEL
    messages = [{"role": "system", "content": "You are a cybersecurity analyst summarizing vulnerability data."}]
    messages.append({"role": "user", "content": prompt})
    # attach small sample for context
    try:
        if df is not None and not df.empty:
            sample = df.head(8).to_dict(orient="records")
            messages.append({"role": "user", "content": f"Context sample: {json.dumps(sample, default=str)}"})
    except Exception:
        messages.append({"role": "user", "content": "Context omitted due to serialization error."})
    try:
        return _send_chat(messages, model=model, max_tokens=max_tokens)
    except Exception as e:
        return f"❌ OpenAI call error: {e!s}"

# ---------------------------
# Database loader / normalizer
# ---------------------------
def load_findings() -> pd.DataFrame:
    """Load findings table from DB_PATH and normalize columns for UI consumption."""
    if not Path(DB_PATH).exists():
        print(f"[!] Database not found at {DB_PATH}")
        return pd.DataFrame()

    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings", conn)
        conn.close()
    except Exception as e:
        print(f"[!] Error reading DB: {e!s}")
        return pd.DataFrame()

    expected_cols = [
        "id","asset_id","host","port","service","title","severity","cvss","cve_id",
        "description","evidence","remediation","vuln_name","path","source","import_date","timestamp"
    ]
    for c in expected_cols:
        if c not in df.columns:
            df[c] = None

    # Basic cleaning/typing
    df["source"] = df["source"].fillna("unknown").astype(str)
    df["severity"] = df["severity"].fillna("information").astype(str).str.lower()
    df["host"] = df["host"].fillna("unknown").astype(str)
    df["port"] = df["port"].fillna("").astype(str)
    df["service"] = df["service"].fillna("").astype(str)
    df["title"] = df["title"].fillna("").astype(str)
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce")
    return df

# ---------------------------
# Dash app setup
# ---------------------------
app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
server = app.server
app.title = "Vuln Intel Dashboard (Towson U)"
app.config.suppress_callback_exceptions = True

# ---------------------------
# Vulnerability Dashboard tab layout
# ---------------------------
vuln_tab = dbc.Container([
    html.H4("Vulnerability Dashboard", style={"color": "#00BFFF"}),
    dbc.Row([
        dbc.Col(dcc.Dropdown(id="source-filter", placeholder="Filter by Source", multi=True), md=4),
        dbc.Col(dcc.Dropdown(id="severity-filter", placeholder="Filter by Severity", multi=True), md=4),
        dbc.Col(dcc.Dropdown(id="ip-filter", placeholder="Filter by IP", multi=True), md=4),
    ], className="mb-3"),
    dbc.Row([
        dbc.Col(dcc.Graph(id="cvss-distribution", style={"height":"420px"}), md=12)
    ], className="mb-3"),
    dbc.Row([
        dash_table.DataTable(
            id="findings-table",
            columns=[{"name": i, "id": i} for i in [
                "id","asset_id","host","port","service","title","severity","cvss","cve_id",
                "description","evidence","remediation","vuln_name","path","source","import_date","timestamp"
            ]],
            page_size=10,
            style_header={"backgroundColor":"#111","color":"#00BFFF"},
            style_cell={"backgroundColor":"#1E1E1E","color":"#E6E6E6","whiteSpace":"normal","height":"auto"},
            filter_action="native",
            sort_action="native",
        )
    ])
], fluid=True)

# ---------------------------
# LLM Request tab layout
# ---------------------------
llm_tab = dbc.Container([
    html.H4("LLM Request", style={"color": "#FFA500"}),
    dcc.Textarea(id="llm-prompt",
                 placeholder="Ask something like: 'Summarize high severity findings from Burp and OpenVAS'",
                 style={"width":"100%","height":"140px"}),
    dbc.Button("Run LLM Analysis", id="llm-submit", color="warning", className="mt-2"),
    html.Div(id="llm-output", style={"whiteSpace":"pre-wrap","paddingTop":"10px"})
], fluid=True)

# ---------------------------
# Natural Language tab layout
# ---------------------------
nl_tab = dbc.Container([
    html.H4("Natural Language Query Processor", style={"color": "#00FF00"}),
    dcc.Input(id="nl-query", type="text", placeholder="e.g., 'Show high CVSS by host'", style={"width":"80%"}),
    dbc.Button("Run", id="nl-submit", color="success", className="ms-2"),
    html.Div(id="nl-output", style={"whiteSpace":"pre-wrap","marginTop":"10px"})
], fluid=True)

# ---------------------------
# Chatbot tab layout
# ---------------------------
chat_tab = dbc.Container([
    html.H4("Chatbot", style={"color":"#FFFF33"}),
    dcc.Textarea(id="chat-input", placeholder="Ask the chatbot about vulnerabilities...", style={"width":"100%","height":"120px"}),
    dbc.Button("Ask", id="chat-submit", color="info", className="mt-2"),
    html.Div(id="chat-output", style={"whiteSpace":"pre-wrap","marginTop":"10px"})
], fluid=True)

# ---------------------------
# Assessment tab layout (MITRE placeholder)
# ---------------------------
assess_tab = dbc.Container([
    html.H4("Assessment (MITRE mapping)", style={"color":"#FF4444"}),
    dbc.Checkbox(id="mitre-enable", value=True, label="Include MITRE mapping"),
    dbc.Button("Run Assessment", id="assess-btn", color="danger", className="ms-2"),
    html.Div(id="assess-output", style={"whiteSpace":"pre-wrap","marginTop":"10px"})
], fluid=True)

# ---------------------------
# Reporting tab layout
# ---------------------------
report_tab = dbc.Container([
    html.H4("Reporting", style={"color":"#33B5E5"}),
    dbc.Button("Generate PDF", id="report-btn", color="primary"),
    html.Div(id="report-output", style={"whiteSpace":"pre-wrap","marginTop":"10px"})
], fluid=True)

# ---------------------------
# Voice tab layout (fallback)
# ---------------------------
voice_tab = dbc.Container([
    html.H4("Voice Assistant (Fallback)", style={"color":"#FF00FF"}),
    html.P("Voice mode requires dash-webrtc + pyaudio. If not present, this will fallback to text input."),
    dbc.Button("Activate Voice (Fallback -> Text)", id="voice-btn", color="secondary"),
    html.Div(id="voice-output", style={"whiteSpace":"pre-wrap","marginTop":"10px"})
], fluid=True)

# ---------------------------
# Main layout with tabs
# ---------------------------
app.layout = dbc.Container([
    html.H3("Towson University — Vulnerability Intelligence Dashboard", className="text-center text-light my-3"),
    dcc.Tabs(id="tabs", value="vuln_tab", children=[
        dcc.Tab(label="Vulnerability Dashboard", value="vuln_tab"),
        dcc.Tab(label="LLM Request", value="llm_tab"),
        dcc.Tab(label="Natural Language", value="nl_tab"),
        dcc.Tab(label="Chatbot", value="chat_tab"),
        dcc.Tab(label="Assessment", value="assess_tab"),
        dcc.Tab(label="Reporting", value="report_tab"),
        dcc.Tab(label="Voice Assistant", value="voice_tab"),
    ]),
    html.Div(id="tabs-content")
], fluid=True)

# ---------------------------
# Tab renderer
# ---------------------------
@app.callback(Output("tabs-content", "children"), Input("tabs", "value"))
def render_tab(tab_value):
    return {
        "vuln_tab": vuln_tab,
        "llm_tab": llm_tab,
        "nl_tab": nl_tab,
        "chat_tab": chat_tab,
        "assess_tab": assess_tab,
        "report_tab": report_tab,
        "voice_tab": voice_tab
    }.get(tab_value, html.Div("Unknown tab"))

# ---------------------------
# Populate filter dropdown options
# ---------------------------
@app.callback(
    [Output("source-filter", "options"),
     Output("severity-filter", "options"),
     Output("ip-filter", "options")],
    Input("tabs", "value")
)
def populate_filters(_tabs_value):
    df = load_findings()
    if df.empty:
        return [], [], []
    sources = sorted(df["source"].fillna("unknown").unique().tolist())
    severities = sorted(df["severity"].fillna("information").unique().tolist())
    ips = sorted(df["host"].fillna("unknown").unique().tolist())
    return (
        [{"label": s, "value": s} for s in sources],
        [{"label": s, "value": s} for s in severities],
        [{"label": i, "value": i} for i in ips]
    )

# ---------------------------
# Update CVSS distribution and findings table
# ---------------------------
@app.callback(
    [Output("cvss-distribution", "figure"),
     Output("findings-table", "data")],
    [Input("source-filter", "value"),
     Input("severity-filter", "value"),
     Input("ip-filter", "value")]
)
def update_dashboard(source_vals, severity_vals, ip_vals):
    df = load_findings()
    if df.empty:
        fig = px.bar(title="No data available")
        return fig, []

    # apply filters
    if source_vals:
        df = df[df["source"].isin(source_vals)]
    if severity_vals:
        df = df[df["severity"].isin(severity_vals)]
    if ip_vals:
        df = df[df["host"].isin(ip_vals)]

    if df.empty:
        fig = px.bar(title="No results for selected filters")
        return fig, []

    # Ensure numeric cvss for plotting; fillna -> 0.0 (so plotting works even if missing)
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce").fillna(0.0)

    fig = px.bar(
        df,
        x="severity",
        y="cvss",
        color="source",
        barmode="group",
        title="CVSS Score Distribution",
        labels={"cvss": "CVSS", "severity": "Severity"}
    )
    return fig, df.to_dict("records")

# ---------------------------
# LLM Request callback
# ---------------------------
@app.callback(
    Output("llm-output", "children"),
    Input("llm-submit", "n_clicks"),
    State("llm-prompt", "value"),
    prevent_initial_call=True
)
def process_llm_request(n_clicks, prompt):
    if not prompt or str(prompt).strip() == "":
        return "⚠️ Please enter a valid prompt."
    df = load_findings()
    return ai_response(f"User request: {prompt}", df=df)

# ---------------------------
# Natural Language callback
# ---------------------------
@app.callback(
    Output("nl-output", "children"),
    Input("nl-submit", "n_clicks"),
    State("nl-query", "value"),
    prevent_initial_call=True
)
def process_nl(n_clicks, query):
    if not query or str(query).strip() == "":
        return "⚠️ Please enter a natural language query."
    df = load_findings()
    return ai_response(f"Interpret and answer this query about the vulnerability dataset: {query}", df=df)

# ---------------------------
# Chatbot callback
# ---------------------------
@app.callback(
    Output("chat-output", "children"),
    Input("chat-submit", "n_clicks"),
    State("chat-input", "value"),
    prevent_initial_call=True
)
def process_chat(n_clicks, question):
    if not question or str(question).strip() == "":
        return "⚠️ Enter a question for the chatbot."
    return ai_response(f"As a cybersecurity chatbot, answer: {question}")

# ---------------------------
# Assessment callback (MITRE placeholder)
# ---------------------------
@app.callback(
    Output("assess-output", "children"),
    Input("assess-btn", "n_clicks"),
    State("mitre-enable", "value"),
    prevent_initial_call=True
)
def run_assessment(n_clicks, mitre_enable):
    df = load_findings()
    if df.empty:
        return "⚠️ No vulnerability data available for assessment."
    prompt = f"Perform a vulnerability assessment over {len(df)} findings. Include MITRE mapping: {bool(mitre_enable)}. Provide prioritized remediation."
    return ai_response(prompt, df=df)

# ---------------------------
# Reporting callback (PDF)
# ---------------------------
@app.callback(
    Output("report-output", "children"),
    Input("report-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_report(n_clicks):
    df = load_findings()
    if df.empty:
        return "⚠️ No data to generate a report."
    filename = f"{REPORT_DIR}/report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=10)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, "Vulnerability Report", ln=True, align="C")
    pdf.ln(4)
    for idx, row in df.iterrows():
        try:
            pdf.multi_cell(0, 6, txt=str(row.to_dict()))
            pdf.ln(2)
        except Exception:
            continue
    try:
        pdf.output(filename)
        return f"✅ Report generated: {filename}"
    except Exception as e:
        return f"❌ Failed to write PDF: {e!s}"

# ---------------------------
# Voice fallback callback
# ---------------------------
@app.callback(
    Output("voice-output", "children"),
    Input("voice-btn", "n_clicks"),
    prevent_initial_call=True
)
def voice_fallback(n_clicks):
    return "🎤 Voice assistant in fallback (text) mode. Install dash-webrtc + pyaudio for true voice."

# ---------------------------
# Run server
# ---------------------------
if __name__ == "__main__":
    print(f"[+] DB path: {DB_PATH}")
    print(f"[+] OpenAI status: {_openai_diag}")
    # best-effort free port
    try:
        subprocess.run(["fuser", "-k", "8050/tcp"], check=False)
    except Exception:
        pass
   # new — Dash current API
# new — Dash current API
# replace: app.run(host="0.0.0.0", port=8050, debug=True)
app.run(host="0.0.0.0", port=8050, debug=False, use_reloader=False)

