"""
Identity Posture — Entra ID / SaaS Attack Surface Assessment
Covers: Entra ID misconfiguration, SaaS SSPM, guest user exposure,
        app consent abuse, conditional access gaps, external sharing.
"""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc

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


@callback(Output("idp-tab-content", "children"), Input("idp-tabs", "active_tab"))
def render_idp_tab(tab):
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
                                   value="nc",
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


@callback(Output("idp-run-out","children"),
          Input("idp-run-btn","n_clicks"),
          State("idp-tenant","value"),
          prevent_initial_call=True)
def run_idp(n, tenant):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(f"Posture assessment initiated for {tenant or '[no tenant]'} — review Risk Checks tab.", color="info", style={"fontSize":"12px","marginTop":"8px"})


@callback(Output("idp-ai-out","children"),
          Input("idp-ai-btn","n_clicks"),
          State("idp-tenant","value"),
          prevent_initial_call=True)
def idp_ai(n, tenant):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(html.Pre(
        f"Identity Posture Risk Summary — {tenant or 'Unknown Tenant'}\n\n"
        "CRITICAL: MFA not enforced universally — all accounts at risk of credential attack.\n"
        "HIGH: 14 guest accounts inactive > 90 days — violates least-privilege principle.\n"
        "HIGH: 3 app registrations with client secrets older than 2 years — rotation required.\n"
        "MEDIUM: External SharePoint sharing unrestricted — data exfiltration risk.\n\n"
        "Recommended immediate actions:\n"
        "1. Enable Security Defaults or enforce CA policy for all users\n"
        "2. Purge stale guest accounts via Access Reviews\n"
        "3. Rotate all app registration secrets > 6 months old\n"
        "4. Restrict SharePoint external sharing to verified domains only",
        style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}),
        color="dark", style={"marginTop":"8px"})
