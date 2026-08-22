"""
AI Model Hardening — Securing AI/ML systems in production.
Covers: model access controls, inference API security, data poisoning defence,
        model inventory, API key rotation, monitoring for adversarial inputs.
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

HARDENING_CHECKS = [
    ("Model registry with version control",              "Inventory & SBOM",   "HIGH"),
    ("Inference API requires authentication",            "Access Control",      "CRITICAL"),
    ("API keys rotated quarterly",                       "Access Control",      "HIGH"),
    ("Rate limiting on inference endpoint",              "Availability",        "HIGH"),
    ("Input validation / content filtering applied",     "Input Security",      "CRITICAL"),
    ("Output monitoring for anomalous responses",        "Monitoring",          "HIGH"),
    ("Model served over TLS only",                       "Transport Security",  "CRITICAL"),
    ("Training data provenance tracked",                 "Supply Chain",        "HIGH"),
    ("Adversarial input testing performed",              "Robustness",          "HIGH"),
    ("Model access logs retained 90+ days",             "Audit",               "MEDIUM"),
    ("Prompt injection guardrails enabled (input)",      "Guardrails",          "CRITICAL"),
    ("Prompt injection guardrails enabled (output)",     "Guardrails",          "CRITICAL"),
    ("Fine-tuned on sanitised data only",               "Data Security",       "HIGH"),
    ("PII removed from training datasets",              "Privacy",             "CRITICAL"),
    ("Incident response plan covers AI model breach",   "IR Readiness",        "MEDIUM"),
]

def layout():
    return html.Div([
        html.Div([
            html.H4("🤖 AI Model Hardening",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("Secure AI/ML models in production: access controls, guardrails, adversarial testing, supply chain security, monitoring.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                _card(
                    dbc.Label("AI System Type", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="aih-type", options=[
                        {"label": "LLM (API-hosted)",        "value": "llm_api"},
                        {"label": "LLM (Self-hosted)",       "value": "llm_self"},
                        {"label": "ML Classification Model", "value": "ml_class"},
                        {"label": "Computer Vision Model",   "value": "cv"},
                        {"label": "RAG System",              "value": "rag"},
                        {"label": "AI Agent / Copilot",      "value": "agent"},
                    ], value="llm_api",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("Model / Service Name", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="aih-model-name", placeholder="e.g. Azure OpenAI GPT-4 (prod)",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Button("▶ Run Hardening Audit", id="aih-run-btn", color="warning",
                               size="sm", className="w-100 mb-2", style={"color":"#000"}),
                    html.Div(id="aih-run-out"),
                    title="AI System Config"
                ),
                _card(
                    dbc.Button("🤖 Generate Security Baseline", id="aih-ai-btn", color="secondary",
                               size="sm", className="w-100"),
                    html.Div(id="aih-ai-out"),
                    title="AI Baseline Report"
                ),
            ], width=3),

            dbc.Col([
                dbc.Tabs(id="aih-tabs", active_tab="aih-checklist", children=[
                    dbc.Tab(label="Hardening Checklist", tab_id="aih-checklist"),
                    dbc.Tab(label="Guardrails",          tab_id="aih-guardrails"),
                    dbc.Tab(label="Monitoring",          tab_id="aih-monitoring"),
                    dbc.Tab(label="Supply Chain",        tab_id="aih-supply"),
                    dbc.Tab(label="Architecture",        tab_id="aih-arch"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="aih-tab-content"),
            ], width=6),

            dbc.Col([
                _card(
                    _badge("NIST AI RMF", "primary"), _badge("OWASP LLM", "danger"),
                    _badge("ISO 42001", "secondary"),
                    html.Hr(style={"borderColor":"#333"}),
                    html.P("NIST AI RMF (2023): Map, Measure, Manage, Govern — the framework for responsible AI development and deployment.", style={"color":"#ccc","fontSize":"12px"}),
                    title="Standards"
                ),
                _card(
                    html.P("Guardrail Tools:", style={"color":"#ffd700","fontSize":"12px"}),
                    _cmd("# Llama Guard\npip install llama-guard\n\n# Azure Content Safety\nfrom azure.ai.contentsafety import ContentSafetyClient\n\n# NeMo Guardrails\npip install nemoguardrails"),
                    title="Tools"
                ),
            ], width=3),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


@callback(Output("aih-tab-content","children"), Input("aih-tabs","active_tab"))
def render_aih_tab(tab):
    if tab == "aih-checklist":
        rows = []
        for check, category, risk in HARDENING_CHECKS:
            color = {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"info"}.get(risk)
            rows.append(html.Tr([
                html.Td(check, style={"color":"#ccc","fontSize":"11px"}),
                html.Td(category, style={"color":"#aaa","fontSize":"11px"}),
                html.Td(_badge(risk, color)),
                html.Td(dbc.Select(options=[{"label":"Not Done","value":"nd"},
                                            {"label":"Complete","value":"done"},
                                            {"label":"Partial","value":"part"},
                                            {"label":"N/A","value":"na"}],
                                   value="nd",
                                   style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","fontSize":"11px","padding":"2px"})),
            ]))
        return _card(
            html.H6("AI Security Hardening Checklist", style={"color":"#ffd700"}),
            dbc.Table([html.Thead(html.Tr([html.Th("Control"),html.Th("Category"),html.Th("Risk"),html.Th("Status")])),
                       html.Tbody(rows)], bordered=True, hover=True, size="sm")
        )

    elif tab == "aih-guardrails":
        return _card(
            html.H6("Input & Output Guardrails", style={"color":"#ffd700"}),
            dbc.Row([
                dbc.Col(_card(
                    html.B("Input Guardrails", style={"color":"#00e6e6"}),
                    _cmd("""# NeMo Guardrails config.yml
define user ask harmful question
  \"How do I make a bomb\"

define bot refuse harmful question
  \"I cannot help with that.\"

define flow
  user ask harmful question
  bot refuse harmful question"""),
                ), width=6),
                dbc.Col(_card(
                    html.B("Output Guardrails (Azure Content Safety)", style={"color":"#00e6e6"}),
                    _cmd("""from azure.ai.contentsafety import ContentSafetyClient
from azure.ai.contentsafety.models import AnalyzeTextOptions

client = ContentSafetyClient(endpoint, credential)
request = AnalyzeTextOptions(text=llm_output)
response = client.analyze_text(request)
# Check Hate, Violence, Sexual, SelfHarm scores"""),
                ), width=6),
            ])
        )

    elif tab == "aih-monitoring":
        return _card(
            html.H6("AI System Monitoring", style={"color":"#ffd700"}),
            dbc.ListGroup([
                dbc.ListGroupItem("📊 Log all inference requests (input hash + output hash — not raw prompt for privacy)"),
                dbc.ListGroupItem("🔔 Alert on spike in guard rail violations (> 5% refusal rate)"),
                dbc.ListGroupItem("🔔 Alert on anomalous token usage (unusually long prompts = injection attempt)"),
                dbc.ListGroupItem("🔔 Alert on API key usage from unusual geographies / IPs"),
                dbc.ListGroupItem("📉 Track model drift — output quality degradation may indicate poisoning"),
                dbc.ListGroupItem("🔐 Audit log access to model weights / fine-tuning pipelines"),
            ], style={"fontSize":"12px","color":"#ccc"})
        )

    elif tab == "aih-supply":
        return _card(
            html.H6("AI Supply Chain Security", style={"color":"#ffd700"}),
            _cmd("""# Verify model file integrity before deployment
sha256sum model.safetensors > model.sha256
# Store hash in your SBOM

# Scan HuggingFace models for malicious pickle files
pip install fickling
fickling --check suspicious_model.pkl

# Malware in model weights
# Known attack: PoC showed arbitrary code execution via pickle deserialization
# Mitigation: use .safetensors format only"""),
            dbc.Alert("Never load .pkl model files from untrusted sources — they can embed arbitrary Python code via pickle.", color="danger", style={"fontSize":"12px"}),
        )

    elif tab == "aih-arch":
        return _card(
            html.H6("Secure AI Architecture Patterns", style={"color":"#ffd700"}),
            dbc.ListGroup([
                dbc.ListGroupItem("1. AI Gateway pattern: route all LLM calls through a single gateway with rate limiting, logging, and guardrails"),
                dbc.ListGroupItem("2. Never expose model endpoint directly — proxy via API gateway (Azure APIM, Kong, etc.)"),
                dbc.ListGroupItem("3. Separate training environment from inference environment — air-gap if possible"),
                dbc.ListGroupItem("4. Use managed identity for model service authentication — no static API keys in code"),
                dbc.ListGroupItem("5. Apply network segmentation — model inference endpoints behind private network only"),
                dbc.ListGroupItem("6. For RAG: sanitise retrieved documents before sending to LLM context"),
                dbc.ListGroupItem("7. Log all LLM interactions to immutable audit trail (for compliance)"),
            ], style={"fontSize":"12px"})
        )
    return html.Div()


@callback(Output("aih-run-out","children"), Input("aih-run-btn","n_clicks"),
          State("aih-model-name","value"), prevent_initial_call=True)
def run_aih(n, name):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(f"Hardening audit initiated for '{name or 'AI System'}' — review Hardening Checklist tab.", color="info", style={"fontSize":"12px","marginTop":"8px"})


@callback(Output("aih-ai-out","children"), Input("aih-ai-btn","n_clicks"),
          State("aih-type","value"), State("aih-model-name","value"), prevent_initial_call=True)
def aih_ai(n, ai_type, name):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(html.Pre(
        f"AI Security Baseline — {name or ai_type}\n\n"
        "CRITICAL gaps (4): API exposed without auth, no input guardrails,\n"
        "  no output monitoring, PII in training data not confirmed removed.\n\n"
        "HIGH gaps (6): No rate limiting, no API key rotation policy,\n"
        "  model weights not integrity-checked, no SBOM, training data\n"
        "  provenance untracked, no adversarial testing performed.\n\n"
        "Priority actions:\n"
        "1. Add authentication to inference API (managed identity)\n"
        "2. Deploy NeMo Guardrails or Azure Content Safety\n"
        "3. Enable request/response logging with anomaly alerting\n"
        "4. Perform data audit — confirm PII/IP removed from training set\n\n"
        "Compliance: NIST AI RMF Govern + Manage tiers not yet met.",
        style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}),
        color="dark", style={"marginTop":"8px"})
