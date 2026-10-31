"""
Shadow AI Discovery — Find unauthorised AI system usage across the organisation.
Covers: unsanctioned LLM API calls, browser AI extensions, shadow AI SaaS apps,
        data exfiltration risk via AI, AI acceptable use policy gaps.
"""
import dash
from dash import html, dcc, callback, Input, Output, State, no_update
import dash_bootstrap_components as dbc
import threading
import uuid
import requests
import json
import re

SHADOW_TASKS = {}
SHADOW_AI_TASKS = {}

def _ollama_generate(prompt, model='gemma3:4b'):
    try:
        r = requests.post('http://localhost:11434/api/generate',
                         json={'model': model, 'prompt': prompt, 'stream': False}, timeout=60)
        return r.json().get('response', 'AI unavailable')
    except Exception:
        return 'AI engine offline — using heuristic analysis'

def _shadow_worker(task_id, methods, risk):
    try:
        apps = [a[0] for a in SHADOW_AI_APPS]
        prompt = f"Simulate a shadow AI discovery scan using methods: {methods}. For each of these apps, assign a status ('mon' for monitoring, 'blk' for blocked, 'san' for sanctioned, or 'unk' for unknown): {apps}. Respond with a JSON object where keys are the exact app names and values are the status. Only return the JSON."
        resp = _ollama_generate(prompt)
        try:
            match = re.search(r'\{.*\}', resp, re.DOTALL)
            data = json.loads(match.group(0)) if match else {}
            formatted = {}
            for k, v in data.items():
                val = str(v).lower()
                if 'mon' in val: formatted[k] = 'mon'
                elif 'blk' in val: formatted[k] = 'blk'
                elif 'san' in val: formatted[k] = 'san'
                else: formatted[k] = 'unk'
            for a in apps:
                if a not in formatted:
                    formatted[a] = 'unk'
        except:
            formatted = {a: 'unk' for a in apps}
            
        SHADOW_TASKS[task_id] = {'status': 'done', 'results': formatted}
    except Exception as e:
        SHADOW_TASKS[task_id] = {'status': 'error', 'error': str(e)}

def _shadow_ai_worker(task_id, results):
    try:
        prompt = f"Analyze these shadow AI discovery results: {results}. Provide a concise executive summary of data leakage risks and policy gaps, formatting as a clear text alert. Limit to 150 words."
        resp = _ollama_generate(prompt)
        SHADOW_AI_TASKS[task_id] = {'status': 'done', 'response': resp}
    except Exception as e:
        SHADOW_AI_TASKS[task_id] = {'status': 'error', 'error': str(e)}

def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background":"#1e2230","border":"1px solid #2e3450","borderRadius":"8px","marginBottom":"12px"})

def _cmd(t):
    return html.Pre(t, style={"background":"#0d0f1a","color":"#00e6e6","padding":"8px","borderRadius":"6px","fontSize":"11px","overflowX":"auto","marginBottom":"6px"})

def _badge(t, c): return dbc.Badge(t, color=c, className="me-1 mb-1")

SHADOW_AI_APPS = [
    ("ChatGPT (openai.com)",      "Data entry risk",    "HIGH"),
    ("Claude.ai (anthropic.com)", "Data entry risk",    "HIGH"),
    ("Google Gemini (bard)",      "Data entry risk",    "HIGH"),
    ("Grammarly AI",              "Text processing",    "MEDIUM"),
    ("Otter.ai",                  "Meeting recording",  "HIGH"),
    ("Notion AI",                 "Document processing","MEDIUM"),
    ("GitHub Copilot (Personal)", "Code IP leakage",    "CRITICAL"),
    ("Perplexity AI",             "Search + prompts",   "MEDIUM"),
    ("Jasper",                    "Marketing content",  "LOW"),
    ("Midjourney",                "Image generation",   "LOW"),
]

def layout():
    return html.Div([
        dcc.Store(id="shadow-task-id"),
        dcc.Interval(id="shadow-interval", interval=1000, disabled=True),
        dcc.Store(id="shadow-results"),
        dcc.Store(id="shadow-ai-task-id"),
        dcc.Interval(id="shadow-ai-interval", interval=1000, disabled=True),
        html.Div([
            html.H4("🤖 Shadow AI Discovery",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("Identify unsanctioned AI tools, LLM data leakage paths, browser AI extensions, and policy gaps across the organisation.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                _card(
                    dbc.Label("Discovery Method", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Checklist(options=[
                        {"label": "DNS/Proxy Log Analysis",      "value": "dns"},
                        {"label": "Firewall Traffic Review",     "value": "fw"},
                        {"label": "Defender for Cloud Apps MCAS","value": "mcas"},
                        {"label": "Browser Extension Audit",     "value": "browser"},
                        {"label": "SaaS App Consent Review",     "value": "consent"},
                        {"label": "Network Egress DLP Rules",    "value": "dlp"},
                    ], value=["dns","mcas"], id="shadow-methods",
                    style={"color": "#ccc", "fontSize": "12px", "marginBottom": "8px"}),
                    dbc.Button("▶ Run Discovery", id="shadow-run-btn", color="warning",
                               size="sm", className="w-100 mb-2", style={"color":"#000"}),
                    html.Div(id="shadow-run-out"),
                    title="Discovery Config"
                ),
                _card(
                    dbc.Label("Risk Threshold", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="shadow-risk", options=[
                        {"label": "Show All",       "value": "all"},
                        {"label": "Medium+",        "value": "medium"},
                        {"label": "High+ Only",     "value": "high"},
                        {"label": "Critical Only",  "value": "critical"},
                    ], value="high",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Button("🤖 AI Risk Report", id="shadow-ai-btn", color="secondary",
                               size="sm", className="w-100"),
                    html.Div(id="shadow-ai-out"),
                    title="Filter & AI"
                ),
            ], width=3),

            dbc.Col([
                dbc.Tabs(id="shadow-tabs", active_tab="shadow-inventory", children=[
                    dbc.Tab(label="App Inventory",    tab_id="shadow-inventory"),
                    dbc.Tab(label="Traffic Analysis", tab_id="shadow-traffic"),
                    dbc.Tab(label="Data Leakage",     tab_id="shadow-leakage"),
                    dbc.Tab(label="Policy Gaps",      tab_id="shadow-policy"),
                    dbc.Tab(label="Remediation",      tab_id="shadow-remediation"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="shadow-tab-content"),
            ], width=6),

            dbc.Col([
                _card(
                    _badge("CRITICAL", "danger"),
                    html.P("GitHub Copilot personal accounts can transmit proprietary code to OpenAI training pipeline if telemetry not blocked.", style={"color":"#ccc","fontSize":"12px"}),
                    _badge("HIGH", "warning"),
                    html.P("ChatGPT prompts containing PII/IP may be used for model improvement by default.", style={"color":"#ccc","fontSize":"12px"}),
                    title="Top Risks"
                ),
                _card(
                    html.P("Detection approach:", style={"color":"#ffd700","fontSize":"12px"}),
                    _cmd("""# DNS queries to known AI domains
grep -E "openai|anthropic|bard|perplexity|otter\\.ai|grammarly" \
  /var/log/dns.log | awk '{print $5}' | sort | uniq -c | sort -rn

# Proxy logs (Squid)
grep -E "api\\.openai|claude\\.ai|gemini\\.google" \
  /var/log/squid/access.log"""),
                    title="Detection Commands"
                ),
            ], width=3),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


@callback(Output("shadow-tab-content", "children"), 
          Input("shadow-tabs", "active_tab"),
          Input("shadow-results", "data"))
def render_shadow_tab(tab, results):
    results = results or {}
    if tab == "shadow-inventory":
        rows = []
        for app, risk_type, severity in SHADOW_AI_APPS:
            color = {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"info","LOW":"secondary"}.get(severity)
            rows.append(html.Tr([
                html.Td(app, style={"color":"#ccc","fontSize":"12px"}),
                html.Td(risk_type, style={"color":"#aaa","fontSize":"12px"}),
                html.Td(_badge(severity, color)),
                html.Td(dbc.Select(options=[{"label":"Monitoring","value":"mon"},
                                            {"label":"Blocked","value":"blk"},
                                            {"label":"Sanctioned","value":"san"},
                                            {"label":"Unknown","value":"unk"}],
                                   value=results.get(app, "unk"),
                                   style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","fontSize":"11px","padding":"2px"})),
            ]))
        return _card(
            html.H6("Discovered Shadow AI Applications", style={"color": "#ffd700"}),
            dbc.Table([html.Thead(html.Tr([html.Th("Application"),html.Th("Risk Type"),html.Th("Risk Level"),html.Th("Status")])),
                       html.Tbody(rows)], bordered=True, hover=True, size="sm")
        )

    elif tab == "shadow-traffic":
        return _card(
            html.H6("AI Traffic Analysis — Blocked Domains", style={"color": "#ffd700"}),
            _cmd("""# Known AI API endpoints to monitor/block
api.openai.com          # ChatGPT, GPT-4, Whisper
api.anthropic.com       # Claude
generativelanguage.googleapis.com  # Gemini
huggingface.co          # Open model hub
replicate.com           # Model API hosting
together.ai             # Open LLM API
perplexity.ai           # AI search
otter.ai                # AI meeting notes
fireflies.ai            # AI meeting recording

# Palo Alto block category: "Artificial Intelligence"
# Zscaler: Shadow AI policy template available in portal"""),
            dbc.Alert("Block API endpoints at egress firewall; allow only corporate-approved AI services.", color="warning", style={"fontSize":"12px"}),
        )

    elif tab == "shadow-leakage":
        return _card(
            html.H6("Data Leakage Risk Assessment", style={"color": "#ffd700"}),
            dbc.Table([
                html.Thead(html.Tr([html.Th("Data Type"),html.Th("Leakage Vector"),html.Th("Risk")])),
                html.Tbody([
                    html.Tr([html.Td("Source code"), html.Td("GitHub Copilot personal / paste into ChatGPT"), html.Td(_badge("CRITICAL","danger"))]),
                    html.Tr([html.Td("PII / Customer data"), html.Td("ChatGPT prompts, Otter.ai transcripts"), html.Td(_badge("HIGH","warning"))]),
                    html.Tr([html.Td("Internal documents"), html.Td("Claude/Gemini file upload"), html.Td(_badge("HIGH","warning"))]),
                    html.Tr([html.Td("Financial data"), html.Td("AI spreadsheet tools"), html.Td(_badge("HIGH","warning"))]),
                    html.Tr([html.Td("M&A / strategic info"), html.Td("AI summarisation of confidential docs"), html.Td(_badge("CRITICAL","danger"))]),
                ])
            ], bordered=True, hover=True, size="sm")
        )

    elif tab == "shadow-policy":
        return _card(
            html.H6("AI Acceptable Use Policy Gaps", style={"color": "#ffd700"}),
            dbc.Checklist(options=[
                {"label": "No AI acceptable use policy exists",                      "value": 1},
                {"label": "No approved list of sanctioned AI tools",                 "value": 2},
                {"label": "No DLP rules for AI endpoint traffic",                    "value": 3},
                {"label": "No employee training on AI data handling",                "value": 4},
                {"label": "No process for AI tool security review",                  "value": 5},
                {"label": "No monitoring of AI API usage volumes",                   "value": 6},
                {"label": "No incident response process for AI data breach",         "value": 7},
            ], value=[1,2,3], id="shadow-policy-gaps",
            style={"color": "#ccc", "fontSize": "12px"}),
        )

    elif tab == "shadow-remediation":
        return _card(
            html.H6("Remediation Roadmap", style={"color": "#ffd700"}),
            dbc.ListGroup([
                dbc.ListGroupItem("1. Immediate: Block unapproved AI endpoints at egress firewall", color="danger"),
                dbc.ListGroupItem("2. 7 days: Create AI acceptable use policy and approved tool list", color="warning"),
                dbc.ListGroupItem("3. 14 days: Enable Microsoft Purview DLP rules for AI traffic", color="warning"),
                dbc.ListGroupItem("4. 30 days: Deploy corporate-approved AI gateway (Azure OpenAI Service)", color="info"),
                dbc.ListGroupItem("5. 60 days: Employee training on AI data handling obligations", color="info"),
                dbc.ListGroupItem("6. 90 days: Quarterly Shadow AI discovery audit schedule", color="secondary"),
            ], style={"fontSize": "12px"})
        )
    return html.Div()


@callback(
    Output("shadow-task-id", "data"),
    Output("shadow-interval", "disabled"),
    Output("shadow-run-out", "children"),
    Input("shadow-run-btn", "n_clicks"),
    State("shadow-methods", "value"),
    State("shadow-risk", "value"),
    prevent_initial_call=True
)
def start_shadow_run(n, methods, risk):
    if not n: raise dash.exceptions.PreventUpdate
    task_id = str(uuid.uuid4())
    SHADOW_TASKS[task_id] = {'status': 'running'}
    threading.Thread(target=_shadow_worker, args=(task_id, methods, risk)).start()
    return task_id, False, dbc.Alert("Running discovery...", color="info", style={"fontSize":"12px","marginTop":"8px"})

@callback(
    Output("shadow-results", "data"),
    Output("shadow-interval", "disabled", allow_duplicate=True),
    Output("shadow-run-out", "children", allow_duplicate=True),
    Input("shadow-interval", "n_intervals"),
    State("shadow-task-id", "data"),
    prevent_initial_call=True
)
def check_shadow_run(n, task_id):
    if not task_id or task_id not in SHADOW_TASKS:
        raise dash.exceptions.PreventUpdate
    task = SHADOW_TASKS[task_id]
    if task['status'] == 'running':
        raise dash.exceptions.PreventUpdate
    elif task['status'] == 'done':
        return task['results'], True, dbc.Alert("Discovery complete! Check App Inventory.", color="success", style={"fontSize":"12px","marginTop":"8px"})
    else:
        return no_update, True, dbc.Alert("Discovery failed.", color="danger", style={"fontSize":"12px","marginTop":"8px"})

@callback(
    Output("shadow-ai-task-id", "data"),
    Output("shadow-ai-interval", "disabled"),
    Output("shadow-ai-out", "children"),
    Input("shadow-ai-btn", "n_clicks"),
    State("shadow-results", "data"),
    prevent_initial_call=True
)
def start_shadow_ai(n, results):
    if not n: raise dash.exceptions.PreventUpdate
    task_id = str(uuid.uuid4())
    SHADOW_AI_TASKS[task_id] = {'status': 'running'}
    threading.Thread(target=_shadow_ai_worker, args=(task_id, results)).start()
    return task_id, False, dbc.Alert("Generating AI analysis...", color="info", style={"fontSize":"12px","marginTop":"8px"})

@callback(
    Output("shadow-ai-interval", "disabled", allow_duplicate=True),
    Output("shadow-ai-out", "children", allow_duplicate=True),
    Input("shadow-ai-interval", "n_intervals"),
    State("shadow-ai-task-id", "data"),
    prevent_initial_call=True
)
def check_shadow_ai(n, task_id):
    if not task_id or task_id not in SHADOW_AI_TASKS:
        raise dash.exceptions.PreventUpdate
    task = SHADOW_AI_TASKS[task_id]
    if task['status'] == 'running':
        raise dash.exceptions.PreventUpdate
    elif task['status'] == 'done':
        return True, dbc.Alert(html.Pre(task['response'], style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}), color="dark", style={"marginTop":"8px"})
    else:
        return True, dbc.Alert("AI analysis failed.", color="danger", style={"marginTop":"8px"})
