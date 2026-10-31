#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Expedite Consults DSIT SOC Dashboard — Unified Version
------------------------------------------------------
Includes:
 - 🛡️ SOC Health Gauge
 - 📈 Risk & Velocity Trend
 - 🔐 Integrity Verification Badge
 - 🧾 Attestation Viewer Modal
 - 🩺 Vulnerability Dashboard
 - 🧠 Assessment
 - 💬 Natural Language
 - 🤖 Chatbot
 - 📊 Reporting
 - 🎤 Voice Assistant (dash-webrtc + text fallback)
"""

import os
import re
import io
import json
import hashlib
import sqlite3
import requests
from pathlib import Path
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
from dash import Dash, dcc, html, Input, Output, State, ctx
import dash_bootstrap_components as dbc
from PyPDF2 import PdfReader

# ===================== CONFIG =====================
DB_PATH = Path("/root/vuln_intel/app/data/findings.db")
REPORT_DIR = Path("/root/vuln_intel/app/reports")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

# ==================================================
# 🛡️ 1. SOC HEALTH BADGE + GAUGE
# ==================================================
def get_soc_health_badge():
    if not DB_PATH.exists():
        return dbc.Alert("⚠️ No data found — run your first scan.", color="secondary")

    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM trend_metrics ORDER BY id DESC LIMIT 1", conn)
    conn.close()

    if df.empty:
        return dbc.Alert("⚠️ No SOC metrics available.", color="secondary")

    row = df.iloc[0]
    risk = row["risk_index"]
    velocity = row["improvement_velocity"]
    date = row["report_date"]
    posture_score = max(0, min(100, 100 - (risk / 10) + (velocity / 2)))

    if posture_score >= 70:
        color, icon, msg = "success", "🟢", "Healthy — risk under control"
    elif posture_score >= 40:
        color, icon, msg = "warning", "🟡", "Moderate risk — trending down"
    else:
        color, icon, msg = "danger", "🔴", "Critical posture — immediate action"

    gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=posture_score,
        title={"text": "SOC Posture Score", "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#007BFF"},
            "steps": [
                {"range": [0, 40], "color": "#FF4C4C"},
                {"range": [40, 70], "color": "#FFD633"},
                {"range": [70, 100], "color": "#4CAF50"},
            ]
        }
    ))
    gauge.update_layout(margin=dict(t=40, b=0, l=0, r=0), height=230)

    return dbc.Row([
        dbc.Col(dbc.Alert([
            html.H5(f"{icon} SOC Health Status", className="fw-bold text-center"),
            html.P(f"🧮 Risk Index: {risk}", className="text-center"),
            html.P(f"⚡ Velocity: {velocity}%", className="text-center"),
            html.P(f"📅 Last Updated: {date}", className="text-center"),
            html.P(f"💪 Posture Score: {posture_score:.1f}/100", className="fw-bold text-center")
        ], color=color), width=6),
        dbc.Col(dcc.Graph(figure=gauge, config={"displayModeBar": False}), width=6),
    ])

# ==================================================
# 📈 2. RISK & VELOCITY TREND BADGE
# ==================================================
def get_risk_velocity_badge():
    if not DB_PATH.exists():
        return dbc.Alert("⚠️ Database not found.", color="secondary")

    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM trend_metrics ORDER BY id DESC LIMIT 10", conn)
    conn.close()

    if df.empty:
        return dbc.Alert("⚠️ No trend metrics available.", color="secondary")

    avg_risk = df["risk_index"].mean()
    avg_vel = df["improvement_velocity"].mean()
    trend = "⬆️ Improving" if avg_vel > 0 else "⬇️ Worsening"
    color = "success" if avg_vel > 0 else "danger"

    return dbc.Alert(
        f"📊 10-Week Avg → Risk: {avg_risk:.1f} | Velocity: {avg_vel:.2f}% | Trend: {trend}",
        color=color,
        className="text-center fw-bold"
    )

# ==================================================
# 🔐 3. PDF INTEGRITY VERIFICATION BADGE
# ==================================================
def get_pdf_integrity_status():
    pdfs = sorted(REPORT_DIR.glob("Executive_SOC_Brief_*.pdf"), reverse=True)
    if not pdfs:
        return dbc.Alert("⚠️ No Executive Brief found.", color="secondary"), "missing"

    latest = pdfs[0]
    try:
        reader = PdfReader(str(latest))
        footer = ""
        for p in reader.pages:
            t = p.extract_text() or ""
            if "Digitally Signed by Expedite Consults DSIT System" in t:
                footer = t
        m = re.search(r"SHA256:\s*([a-fA-F0-9]{32,64})", footer)
        if not m:
            return dbc.Alert(f"⚠️ No signature found in {latest.name}", color="warning"), "missing"

        emb = m.group(1)
        with open(latest, "rb") as f:
            comp = hashlib.sha256(f.read()).hexdigest()

        valid = comp.startswith(emb[:32])
        ts = datetime.fromtimestamp(latest.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        if valid:
            msg = f"🟢 Integrity Verified — {latest.name} ({ts})"
            return dbc.Alert(msg, color="success", className="text-center fw-bold"), "valid"
        else:
            msg = f"🔴 Integrity Mismatch — {latest.name} ({ts})"
            return dbc.Alert(msg, color="danger", className="text-center fw-bold"), "mismatch"
    except Exception as e:
        return dbc.Alert(f"⚠️ Error verifying PDF: {e}", color="warning"), "missing"

# ==================================================
# 🧾 4. ATTESTATION JSON VIEWER
# ==================================================
def load_latest_attestation():
    att_dir = REPORT_DIR / "attestations"
    att_dir.mkdir(exist_ok=True)
    files = sorted(att_dir.glob("attestation_*.json"), reverse=True)
    if not files:
        return "⚠️ No attestation logs found."
    latest = files[0]
    with open(latest) as f:
        data = json.load(f)
    return f"📄 **{latest.name}**\n```json\n{json.dumps(data, indent=4)}\n```"

# ==================================================
# 🩺 VULNERABILITY DASHBOARD
# ==================================================
def get_vulnerability_dashboard():
    if not DB_PATH.exists():
        return dbc.Alert("⚠️ findings.db not found.", color="secondary")

    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM findings LIMIT 5000", conn)
    conn.close()

    if df.empty:
        return dbc.Alert("⚠️ No vulnerability data found.", color="secondary")

    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]

    fig_sev = go.Figure(go.Bar(
        x=severity_counts["Severity"],
        y=severity_counts["Count"],
        text=severity_counts["Count"],
        textposition="auto"
    ))
    fig_sev.update_layout(
        title="Vulnerability Severity Distribution",
        xaxis_title="Severity Level",
        yaxis_title="Count",
        height=350
    )

    cvss_fig = go.Figure(go.Histogram(
        x=df["cvss"], nbinsx=10, marker_color="#007BFF"
    ))
    cvss_fig.update_layout(
        title="CVSS Score Distribution",
        xaxis_title="CVSS Score",
        yaxis_title="Number of Vulnerabilities",
        height=350
    )

    recent_df = df.sort_values(by="cvss", ascending=False).head(10)
    recent_table = dbc.Table.from_dataframe(
        recent_df[["plugin_id", "name", "cvss", "severity"]],
        striped=True, bordered=True, hover=True
    )

    return html.Div([
        html.H4("📊 Vulnerability Overview", className="mb-3"),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=fig_sev), md=6),
            dbc.Col(dcc.Graph(figure=cvss_fig), md=6),
        ]),
        html.H5("Top 10 High-Severity Findings", className="mt-4"),
        recent_table
    ])

# ==================================================
# 🧠 ASSESSMENT TAB  (Scans + Exploit Lookup)
# ==================================================
def get_assessment_tab():
    return html.Div([
        html.H4("System & Application Assessment", className="mb-3"),
        html.P("View scan results from Nessus / OpenVAS / Nmap and look up public exploits from Vulners.", className="text-muted"),

        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🔍 Exploit Lookup"),
                    dbc.CardBody([
                        dbc.Input(id="vulners-query", placeholder="Enter CVE ID (e.g. CVE-2021-44228) or keyword…", type="text", className="mb-2"),
                        dbc.Button("Search", id="vulners-btn", color="primary", className="w-100 mb-3"),
                        html.Div(id="vulners-results")
                    ])
                ])
            ], md=6),

            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🧾 Scan Data Summary"),
                    dbc.CardBody(id="scan-summary")
                ])
            ], md=6)
        ])
    ])

# ==================================================
# 🔍 VULNERS API HELPER
# ==================================================
def query_vulners(query: str):
    """Search the Vulners API for a given query string (CVE or keyword)."""
    if not VULNERS_API_KEY:
        return [{"title": "❌ Missing VULNERS_API_KEY in environment."}]
    try:
        r = requests.get(
            "https://vulners.com/api/v3/search/lucene/",
            params={"query": query, "size": 5},
            headers={"X-Api-Key": VULNERS_API_KEY},
            timeout=15
        )
        r.raise_for_status()
        data = r.json()
        docs = data.get("data", {}).get("search", [])
        results = []
        for d in docs:
            results.append({
                "title": d.get("_source", {}).get("title"),
                "cvss": d.get("_source", {}).get("cvss", ""),
                "href": d.get("_source", {}).get("href", ""),
                "published": d.get("_source", {}).get("published", "")
            })
        return results if results else [{"title": "No results found for query."}]
    except Exception as e:
        return [{"title": f"Error contacting Vulners API: {e}"}]


# ==================================================
# 💬 NATURAL LANGUAGE TAB
# ==================================================
def get_natural_language_tab():
    return html.Div([
        html.H4("Natural Language Query", className="mb-3"),
        html.P("Ask questions about vulnerabilities, risk trends, or posture.  Uses the OpenAI API.", className="text-muted"),
        dbc.Input(id="nl-input", placeholder="Example: What are the top CVEs this month?", type="text", className="mb-2"),
        dbc.Button("Ask", id="nl-submit", color="primary", className="mb-3"),
        html.Div(id="nl-response", className="border rounded p-3 bg-light"),
    ])

# ==================================================
# 🤖 CHATBOT TAB (Persistent Assistant)
# ==================================================
def get_chatbot_tab():
    return html.Div([
        html.H4("SOC Chatbot Assistant", className="mb-3"),
        html.Div(id="chat-history", style={"height": "350px", "overflowY": "scroll", "background": "#f8f9fa",
                                           "padding": "10px", "border": "1px solid #ccc", "borderRadius": "5px"}),
        dbc.InputGroup([
            dbc.Input(id="chat-input", placeholder="Type your message...", type="text"),
            dbc.Button("Send", id="chat-send", color="success")
        ], className="mt-2")
    ])

# ==================================================
# 📊 REPORTING TAB
# ==================================================
def get_reporting_tab():
    files = sorted(REPORT_DIR.glob("Executive_SOC_Brief_*.pdf"), reverse=True)
    rows = []
    for f in files[:10]:
        ts = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        rows.append(html.Tr([html.Td(f.name), html.Td(ts), html.Td(html.A("Open", href=f"/reports/{f.name}", target="_blank"))]))
    table = dbc.Table([html.Thead(html.Tr([html.Th("File"), html.Th("Date"), html.Th("")])),
                       html.Tbody(rows)], bordered=True, hover=True, striped=True)
    return html.Div([
        html.H4("Executive Reporting", className="mb-3"),
        html.P("Browse and open the latest executive SOC briefings.", className="text-muted"),
        table
    ])

# ==================================================
# 🧠 LLM HELPER
# ==================================================
def query_openai(prompt):
    """Send a query to OpenAI API using the Chat Completions endpoint."""
    if not OPENAI_API_KEY:
        return "❌ OPENAI_API_KEY not set in environment."
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": "gpt-4-turbo",
                "messages": [
                    {"role": "system", "content": "You are a SOC assistant specialized in vulnerability and risk analysis."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 400
            },
            timeout=25
        )
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"⚠️ Error contacting OpenAI API: {e}"


# ==================================================
# 🎤 VOICE ASSISTANT TAB  (dash-webrtc + fallback)
# ==================================================
def get_voice_assistant_tab():
    return html.Div([
        html.H4("Voice Assistant", className="mb-3"),
        html.P("Speak or type your command. Uses dash-webrtc if mic available; otherwise text fallback.", className="text-muted"),
        dbc.Row([
            dbc.Col(dbc.Button("🎙️ Start Listening", id="start-voice", color="primary", className="w-100 mb-2")),
            dbc.Col(dbc.Button("🛑 Stop", id="stop-voice", color="danger", className="w-100 mb-2"))
        ]),
        dbc.Input(id="voice-text", placeholder="Fallback text input…", type="text", className="mb-2"),
        dbc.Button("Submit", id="voice-submit", color="success"),
        html.Div(id="voice-response", className="border rounded p-3 bg-light mt-3")
    ])

# ==================================================
# 🏗️ DASH APP INITIALIZATION
# ==================================================
app = Dash(__name__, external_stylesheets=[dbc.themes.FLATLY])
app.title = "Expedite Consults DSIT SOC Dashboard"

# --------------------- LAYOUT ---------------------
app.layout = dbc.Container([
    html.H1("🩺 Expedite Consults DSIT SOC Dashboard", className="text-center my-3"),

    # Top badges
    html.Div(id="soc-health-badge"),
    html.Div(id="risk-velocity-badge", className="mt-2"),
    html.H4("🔐 Integrity Verification", className="text-center mt-3"),
    html.Div(id="integrity-status", className="mb-2"),
    html.Div([
        dbc.Button("View Attestation", id="open-attestation", color="info", className="mb-3"),
        dbc.Modal([
            dbc.ModalHeader("Latest Attestation Record"),
            dbc.ModalBody(dcc.Markdown(id="attestation-content", style={"whiteSpace": "pre-wrap"})),
            dbc.ModalFooter(dbc.Button("Close", id="close-attestation", color="secondary")),
        ], id="attestation-modal", size="lg", is_open=False),
    ], className="text-center"),
    html.Hr(),

    # Tabs
    dbc.Tabs(id="tabs", active_tab="vuln_dashboard", children=[
        dbc.Tab(label="Vulnerability Dashboard", tab_id="vuln_dashboard"),
        dbc.Tab(label="Assessment", tab_id="assessment"),
        dbc.Tab(label="Natural Language", tab_id="nl_tab"),
        dbc.Tab(label="Chatbot", tab_id="chatbot"),
        dbc.Tab(label="Reporting", tab_id="reporting"),
        dbc.Tab(label="Voice Assistant", tab_id="voice_tab"),
    ]),
    html.Div(id="tab-content", className="p-4")
])

# ==================================================
# 🔁 CALLBACKS
# ==================================================

# --- Top badges ---
@app.callback(Output("soc-health-badge", "children"), Input("tabs", "active_tab"))
def refresh_soc(_): return get_soc_health_badge()

@app.callback(Output("risk-velocity-badge", "children"), Input("tabs", "active_tab"))
def refresh_rv(_): return get_risk_velocity_badge()

@app.callback(Output("integrity-status", "children"), Input("tabs", "active_tab"))
def refresh_integrity(_): return get_pdf_integrity_status()[0]

@app.callback(Output("attestation-content", "children"), Input("open-attestation", "n_clicks"))
def load_attestation_modal(_): return load_latest_attestation()

@app.callback(
    Output("attestation-modal", "is_open"),
    [Input("open-attestation", "n_clicks"), Input("close-attestation", "n_clicks")],
    [State("attestation-modal", "is_open")],
)
def toggle_attestation(open_click, close_click, is_open):
    if not ctx.triggered:
        return is_open
    trig = ctx.triggered[0]["prop_id"].split(".")[0]
    if trig == "open-attestation": return True
    elif trig == "close-attestation": return False
    return is_open

# --- Tab content switcher ---
@app.callback(Output("tab-content", "children"), Input("tabs", "active_tab"))
def render_tab_content(active_tab):
    if active_tab == "vuln_dashboard":
        return get_vulnerability_dashboard()
    elif active_tab == "assessment":
        return get_assessment_tab()
    elif active_tab == "nl_tab":
        return get_natural_language_tab()
    elif active_tab == "chatbot":
        return get_chatbot_tab()
    elif active_tab == "reporting":
        return get_reporting_tab()
    elif active_tab == "voice_tab":
        return get_voice_assistant_tab()
    return html.Div("Select a tab to begin…")

# --- Vulners Exploit Lookup ---
@app.callback(Output("vulners-results", "children"), Input("vulners-btn", "n_clicks"), State("vulners-query", "value"))
def update_vulners_results(n, query):
    if not n or not query:
        return ""
    results = query_vulners(query)
    cards = []
    for r in results:
        if "href" in r:
            cards.append(dbc.Alert([
                html.A(r.get("title"), href=r.get("href"), target="_blank"),
                html.Br(),
                html.Small(f"CVSS: {r.get('cvss', 'N/A')}  |  Published: {r.get('published', 'N/A')}")
            ], color="light"))
        else:
            cards.append(dbc.Alert(r.get("title"), color="warning"))
    return cards

# --- LLM Query (Natural Language) ---
@app.callback(Output("nl-response", "children"), Input("nl-submit", "n_clicks"), State("nl-input", "value"))
def handle_nl_query(n, val):
    if not n or not val: return ""
    return query_openai(val)

# --- Chatbot interaction ---
chat_history = []
@app.callback(Output("chat-history", "children"), Input("chat-send", "n_clicks"), State("chat-input", "value"))
def handle_chatbot(n, msg):
    if not n or not msg: return chat_history
    chat_history.append(html.P(f"👤 You: {msg}", className="fw-bold"))
    reply = query_openai(msg)
    chat_history.append(html.P(f"🤖 Bot: {reply}", className="ms-3"))
    return chat_history

# --- Voice Assistant ---
@app.callback(Output("voice-response", "children"), Input("voice-submit", "n_clicks"), State("voice-text", "value"))
def handle_voice(n, text):
    if not n or not text: return ""
    response = query_openai(text)
    return html.Div([
        html.P(f"🎙️ You said: {text}", className="fw-bold"),
        html.P(f"🤖 Assistant: {response}")
    ])

# ==================================================
# 🚀 RUN SERVER
# ==================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050)
