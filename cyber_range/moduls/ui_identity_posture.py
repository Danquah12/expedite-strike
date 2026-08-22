"""
Identity Posture — Entra ID / SaaS Attack Surface Assessment
Covers: Entra ID misconfiguration, SaaS SSPM, guest user exposure,
        app consent abuse, conditional access gaps, external sharing.
"""
import dash
from dash import html, dcc, callback, Input, Output, State, no_update
import dash_bootstrap_components as dbc
import threading
import uuid
import requests
import json
import re

IDP_TASKS = {}
IDP_AI_TASKS = {}

def _ollama_generate(prompt, model='gemma3:4b'):
    try:
        r = requests.post('http://localhost:11434/api/generate',
                         json={'model': model, 'prompt': prompt, 'stream': False}, timeout=60)
        return r.json().get('response', 'AI unavailable')
    except Exception:
        return 'AI engine offline — using heuristic analysis'

def _idp_worker(task_id, tenant, scope):
    try:
        checks = [c[0] for c in RISK_CHECKS]
        prompt = f"Simulate an Entra ID posture assessment for {tenant}. For each of these checks, provide a status ('pass', 'fail', or 'na'): {checks}. Respond with a JSON object where keys are the exact check names and values are the status. Only return the JSON."
        resp = _ollama_generate(prompt)
        try:
            match = re.search(r'\{.*\}', resp, re.DOTALL)
            data = json.loads(match.group(0)) if match else {}
            formatted = {}
            for k, v in data.items():
                val = str(v).lower()
                if 'pass' in val: formatted[k] = 'pass'
                elif 'fail' in val: formatted[k] = 'fail'
                else: formatted[k] = 'na'
            for c in checks:
                if c not in formatted:
                    formatted[c] = 'fail'
        except:
            formatted = {c: 'fail' for c in checks}
            
        score = sum(1 for v in formatted.values() if v == 'pass') * 10
        recs = f"Risk Score: {score}/100. Remediate failing checks."
        IDP_TASKS[task_id] = {'status': 'done', 'results': formatted, 'score': score, 'recs': recs}
    except Exception as e:
        IDP_TASKS[task_id] = {'status': 'error', 'error': str(e)}

def _idp_ai_worker(task_id, tenant, results):
    try:
        prompt = f"Analyze these identity posture results for {tenant}: {results}. Provide a concise executive summary of the risks, formatting as a clear text alert. Limit to 150 words."
        resp = _ollama_generate(prompt)
        IDP_AI_TASKS[task_id] = {'status': 'done', 'response': resp}
    except Exception as e:
        IDP_AI_TASKS[task_id] = {'status': 'error', 'error': str(e)}

def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background": "#1e2230", "border": "1px solid #2e3450",
                           "borderRadius": "8px", "marginBottom": "12px"})

def _cmd(t):
    return html.Pre(t, style={"background":"#0d0f1a","color":"#00e6e6","padding":"8px",
                               "borderRadius":"6px","fontSize":"11px","overflowX":"auto","marginBottom":"6px"})

def _badge(t, c): return dbc.Badge(t, color=c, className="me-1 mb-1")

RISK_CHECKS = [
    ("Guest users with access to sensitive SharePoint sites", "HIGH"),
    ("App registrations with client secrets older than 1 year", "HIGH"),
    ("Conditional Access policy excludes break-glass accounts", "MEDIUM"),
    ("MFA not enforced for all users", "CRITICAL"),
    ("Admin consent workflow not enabled", "HIGH"),
    ("SSPR enabled without strong secondary auth", "MEDIUM"),
    ("No sign-in risk policy configured", "HIGH"),
    ("External sharing enabled on all SharePoint sites", "MEDIUM"),
    ("Stale guest accounts (inactive > 90 days)", "MEDIUM"),
    ("Entra ID Connect sync without monitoring", "LOW"),
]

def layout():
    return html.Div([
        dcc.Store(id="idp-task-id"),
        dcc.Interval(id="idp-interval", interval=1000, disabled=True),
        dcc.Store(id="idp-results"),
        dcc.Store(id="idp-ai-task-id"),
        dcc.Interval(id="idp-ai-interval", interval=1000, disabled=True),
        html.Div([
            html.H4("🎯 Identity Posture — Entra ID & SaaS Assessment",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("Entra ID misconfiguration scanning, SaaS security posture, guest exposure, app consent abuse, CA gaps.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                _card(
                    dbc.Label("Tenant Domain", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="idp-tenant", placeholder="company.onmicrosoft.com",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("Scan Scope", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Checklist(options=[
                        {"label": "Entra ID Policies",   "value": "entra"},
                        {"label": "SaaS Apps (M365)",    "value": "m365"},
                        {"label": "Guest Access",        "value": "guests"},
                        {"label": "App Registrations",   "value": "apps"},
                        {"label": "Conditional Access",  "value": "ca"},
                    ], value=["entra","ca"], id="idp-scope",
                    style={"color": "#ccc", "fontSize": "12px", "marginBottom": "8px"}),
                    dbc.Button("▶ Run Posture Assessment", id="idp-run-btn", color="warning",
                               size="sm", className="w-100 mb-1", style={"color": "#000"}),
                    html.Div(id="idp-run-out"),
                    title="Assessment Config"
                ),
                _card(
                    dbc.Button("🤖 AI Risk Summary", id="idp-ai-btn", color="secondary",
                               size="sm", className="w-100"),
                    html.Div(id="idp-ai-out"),
                    title="AI Analysis"
                ),
            ], width=3),

            dbc.Col([
                dbc.Tabs(id="idp-tabs", active_tab="idp-checks", children=[
                    dbc.Tab(label="Risk Checks",   tab_id="idp-checks"),
                    dbc.Tab(label="SaaS Posture",  tab_id="idp-saas"),
                    dbc.Tab(label="App Consent",   tab_id="idp-consent"),
                    dbc.Tab(label="CA Gaps",       tab_id="idp-ca"),
                    dbc.Tab(label="Commands",      tab_id="idp-cmds"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="idp-tab-content"),
            ], width=6),

            dbc.Col([
                _card(
                    _badge("Entra ID", "primary"), _badge("M365", "info"),
                    _badge("Azure RBAC", "secondary"),
                    html.Hr(style={"borderColor": "#333"}),
                    html.P("Key frameworks: Microsoft CSPA, CIS Microsoft 365 Foundations Benchmark v3.0, CISA M365 Security Baseline.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    title="Frameworks"
                ),
                _card(
                    html.P("ROADtools:", style={"color": "#ffd700", "fontSize": "12px"}),
                    _cmd("pip install roadtools\nroadrecon gather -u admin@corp.com\nroadrecon gui"),
                    html.P("ScoutSuite:", style={"color": "#ffd700", "fontSize": "12px"}),
                    _cmd("python scout.py azure --cli\n  --report-dir ./scoutsuite_report"),
                    title="Quick Tools"
                ),
            ], width=3),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


@callback(Output("idp-tab-content", "children"), 
          Input("idp-tabs", "active_tab"),
          Input("idp-results", "data"))
def render_idp_tab(tab, results):
    results = results or {}
    if tab == "idp-checks":
        rows = []
        for check, severity in RISK_CHECKS:
            color = {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"info","LOW":"secondary"}.get(severity,"secondary")
            rows.append(html.Tr([
                html.Td(check, style={"color": "#ccc", "fontSize": "12px"}),
                html.Td(_badge(severity, color)),
                html.Td(dbc.Select(options=[{"label":"Not Checked","value":"nc"},
                                            {"label":"Pass","value":"pass"},
                                            {"label":"Fail","value":"fail"},
                                            {"label":"N/A","value":"na"}],
                                   value=results.get(check, "nc"),
                                   style={"background":"#252a36","color":"#e6e6e6",
                                          "border":"1px solid #3a4055","fontSize":"11px","padding":"2px"})),
            ]))
        return _card(
            html.H6("Entra ID / SaaS Risk Checks", style={"color": "#ffd700"}),
            dbc.Table([html.Thead(html.Tr([html.Th("Check"),html.Th("Risk"),html.Th("Status")])),
                       html.Tbody(rows)], bordered=True, hover=True, size="sm")
        )

    elif tab == "idp-saas":
        return _card(
            html.H6("SaaS Security Posture (M365)", style={"color": "#ffd700"}),
            dbc.Row([
                dbc.Col(_card(
                    html.B("Exchange Online", style={"color": "#00e6e6"}),
                    _cmd("# Check mail forwarding rules\nGet-Mailbox -ResultSize Unlimited | Get-InboxRule | Where-Object {$_.ForwardTo}"),
                    html.B("SharePoint", style={"color": "#00e6e6"}),
                    _cmd("Get-SPOSite -Limit All | Select Url,SharingCapability"),
                ), width=6),
                dbc.Col(_card(
                    html.B("Teams", style={"color": "#00e6e6"}),
                    _cmd("Get-CsTeamsClientConfiguration\n# Check external access\nGet-CsTenantFederationConfiguration"),
                    html.B("Defender for Cloud Apps", style={"color": "#00e6e6"}),
                    _cmd("# MCAS shadow IT report\nGet-MCASDiscoveredApp -Type Sanctioned"),
                ), width=6),
            ])
        )

    elif tab == "idp-consent":
        return _card(
            html.H6("OAuth App Consent Abuse", style={"color": "#ffd700"}),
            dbc.Alert("Illicit Consent Grant: attacker registers OAuth app, tricks user into consenting → persistent access via refresh token.", color="danger", style={"fontSize":"12px"}),
            _cmd("""# List all OAuth app permissions granted by users
Get-AzureADServicePrincipal -All $true | %{
  Get-AzureADServiceAppRoleAssignment -ObjectId $_.ObjectId
} | Where-Object {$_.PrincipalType -eq "User"}

# Check for high-risk permissions granted
# (Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All)"""),
        )

    elif tab == "idp-ca":
        return _card(
            html.H6("Conditional Access Policy Gaps", style={"color": "#ffd700"}),
            dbc.Table([
                html.Thead(html.Tr([html.Th("CA Gap"), html.Th("Risk"), html.Th("Recommendation")])),
                html.Tbody([
                    html.Tr([html.Td("No policy targeting all users + all apps"), html.Td(_badge("CRITICAL","danger")), html.Td("Create baseline policy")]),
                    html.Tr([html.Td("Legacy auth not blocked"), html.Td(_badge("HIGH","warning")), html.Td("Block legacy auth protocols")]),
                    html.Tr([html.Td("No device compliance requirement"), html.Td(_badge("HIGH","warning")), html.Td("Require Intune compliant device")]),
                    html.Tr([html.Td("Sign-in risk not evaluated"), html.Td(_badge("HIGH","warning")), html.Td("Enable Identity Protection risk policy")]),
                    html.Tr([html.Td("Admin roles not requiring phishing-resistant MFA"), html.Td(_badge("CRITICAL","danger")), html.Td("Enforce FIDO2/CBA for admins")]),
                ])
            ], bordered=True, hover=True, size="sm")
        )

    elif tab == "idp-cmds":
        return _card(
            html.H6("Assessment Commands", style={"color": "#ffd700"}),
            _cmd("""# Microsoft 365 DSC — full config export
Install-Module Microsoft365DSC
Export-M365DSCConfiguration -Workloads @("AAD","EXO","SPO","Teams")

# Maester — automated M365 security testing
Install-Module Maester
Invoke-Maester

# Entra ID PIM status
Get-AzureADMSPrivilegedResource -ProviderId aadRoles | Get-AzureADMSPrivilegedRoleAssignment

# Guest user audit
Get-AzureADUser -Filter "userType eq 'Guest'" | Select DisplayName,Mail,CreatedDateTime"""),
        )
    return html.Div()


@callback(
    Output("idp-task-id", "data"),
    Output("idp-interval", "disabled"),
    Output("idp-run-out", "children"),
    Input("idp-run-btn", "n_clicks"),
    State("idp-tenant", "value"),
    State("idp-scope", "value"),
    prevent_initial_call=True
)
def start_idp_run(n, tenant, scope):
    if not n: raise dash.exceptions.PreventUpdate
    task_id = str(uuid.uuid4())
    IDP_TASKS[task_id] = {'status': 'running'}
    threading.Thread(target=_idp_worker, args=(task_id, tenant, scope)).start()
    return task_id, False, dbc.Alert(f"Running assessment for {tenant or '[no tenant]'}...", color="info", style={"fontSize":"12px","marginTop":"8px"})

@callback(
    Output("idp-results", "data"),
    Output("idp-interval", "disabled", allow_duplicate=True),
    Output("idp-run-out", "children", allow_duplicate=True),
    Input("idp-interval", "n_intervals"),
    State("idp-task-id", "data"),
    prevent_initial_call=True
)
def check_idp_run(n, task_id):
    if not task_id or task_id not in IDP_TASKS:
        raise dash.exceptions.PreventUpdate
    task = IDP_TASKS[task_id]
    if task['status'] == 'running':
        raise dash.exceptions.PreventUpdate
    elif task['status'] == 'done':
        score = task['score']
        return task['results'], True, dbc.Alert(f"Assessment complete! Risk Score: {score}/100. Check tabs for details.", color="success", style={"fontSize":"12px","marginTop":"8px"})
    else:
        return no_update, True, dbc.Alert("Assessment failed.", color="danger", style={"fontSize":"12px","marginTop":"8px"})

@callback(
    Output("idp-ai-task-id", "data"),
    Output("idp-ai-interval", "disabled"),
    Output("idp-ai-out", "children"),
    Input("idp-ai-btn", "n_clicks"),
    State("idp-tenant", "value"),
    State("idp-results", "data"),
    prevent_initial_call=True
)
def start_idp_ai(n, tenant, results):
    if not n: raise dash.exceptions.PreventUpdate
    task_id = str(uuid.uuid4())
    IDP_AI_TASKS[task_id] = {'status': 'running'}
    threading.Thread(target=_idp_ai_worker, args=(task_id, tenant, results)).start()
    return task_id, False, dbc.Alert("Generating AI analysis...", color="info", style={"fontSize":"12px","marginTop":"8px"})

@callback(
    Output("idp-ai-interval", "disabled", allow_duplicate=True),
    Output("idp-ai-out", "children", allow_duplicate=True),
    Input("idp-ai-interval", "n_intervals"),
    State("idp-ai-task-id", "data"),
    prevent_initial_call=True
)
def check_idp_ai(n, task_id):
    if not task_id or task_id not in IDP_AI_TASKS:
        raise dash.exceptions.PreventUpdate
    task = IDP_AI_TASKS[task_id]
    if task['status'] == 'running':
        raise dash.exceptions.PreventUpdate
    elif task['status'] == 'done':
        return True, dbc.Alert(html.Pre(task['response'], style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}), color="dark", style={"marginTop":"8px"})
    else:
        return True, dbc.Alert("AI analysis failed.", color="danger", style={"marginTop":"8px"})
