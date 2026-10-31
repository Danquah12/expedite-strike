"""
Shadow AI Discovery — Find unauthorised AI system usage across the organisation.
Covers: unsanctioned LLM API calls, browser AI extensions, shadow AI SaaS apps,
        data exfiltration risk via AI, AI acceptable use policy gaps.
"""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc

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


@callback(Output("shadow-tab-content", "children"), Input("shadow-tabs", "active_tab"))
def render_shadow_tab(tab):
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
                                   value="unk",
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


@callback(Output("shadow-run-out","children"),
          Input("shadow-run-btn","n_clicks"),
          prevent_initial_call=True)
def run_shadow(n):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert("Discovery initiated — check App Inventory tab for results.", color="info", style={"fontSize":"12px","marginTop":"8px"})


@callback(Output("shadow-ai-out","children"),
          Input("shadow-ai-btn","n_clicks"),
          prevent_initial_call=True)
def shadow_ai_report(n):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(html.Pre(
        "Shadow AI Risk Report\n\n"
        "CRITICAL: GitHub Copilot personal accounts detected — proprietary code exposure risk.\n"
        "HIGH: 47 users accessing ChatGPT from corporate devices daily.\n"
        "HIGH: 12 Otter.ai meeting recordings contain confidential product discussions.\n"
        "MEDIUM: Grammarly browser extension installed on 213 corporate endpoints.\n\n"
        "Estimated data exposure: ~2.3GB of internal text/code transmitted to AI APIs in last 30 days.\n\n"
        "Priority: Implement AI gateway and DLP controls within 14 days.",
        style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}),
        color="dark", style={"marginTop":"8px"})
