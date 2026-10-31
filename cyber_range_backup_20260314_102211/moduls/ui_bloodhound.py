"""
ui_bloodhound.py — Hybrid AD RedOps Scanner Panel
===================================================
3-button Active Directory security scanner powered by direct LDAP enumeration.
No SharpHound or bloodhound-python required.

Buttons:
  🔍 Scan AD Server    — runs live LDAP scan, ingests to Neo4j + Postgres
  📥 Pull Results      — loads last scan from Postgres, shows flagged accounts
  🗺  Show Graph       — queries Neo4j and renders the Cytoscape AD relationship graph
"""

import dash
import plotly.graph_objects as go
from dash import html, dcc, callback, dash_table
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_cytoscape as cyto

from cyber_range.services.ad_ldap_scanner import (
    run_ad_scan,
    get_last_scan_results,
    get_score_history,
    get_live_kpi,
    get_vuln_detail,
    get_graph_elements,
    GRAPH_VIEW_OPTIONS,
)
from cyber_range.moduls import ui_ad_redops

# ─────────────────────────────────────────────────────────────────────────────
# THEME
# ─────────────────────────────────────────────────────────────────────────────
BG_DARK     = "#1c1e26"
PANEL_BG    = "#232530"
TEXT_COL    = "#a2a5b5"
CYAN        = "#42b9f5"
RED         = "#f54254"
ORANGE      = "#f5a742"
GREEN       = "#11c26f"
PURPLE      = "#9e54d4"

INPUT_STYLE = {
    "backgroundColor": PANEL_BG,
    "color": "#fff",
    "border": "1px solid #444",
    "borderRadius": "6px",
}
LABEL_STYLE = {
    "color": TEXT_COL,
    "fontSize": "0.78rem",
    "marginBottom": "2px",
}
CARD_STYLE  = {"backgroundColor": PANEL_BG, "border": "1px solid #333", "borderRadius": "10px"}


# ─────────────────────────────────────────────────────────────────────────────
# CYTOSCAPE STYLESHEET
# ─────────────────────────────────────────────────────────────────────────────
CYTO_STYLESHEET = [
    {"selector": "node",                      "style": {"label": "data(label)", "color": "#fff", "background-color": CYAN,   "font-size": "10px", "width": "30px", "height": "30px"}},
    {"selector": "node[type='User']",         "style": {"background-color": ORANGE}},
    {"selector": "node[type='Group']",        "style": {"background-color": PURPLE}},
    {"selector": "node[type='Computer']",     "style": {"background-color": RED}},
    {"selector": "node[type='Domain']",       "style": {"background-color": GREEN}},
    # Vulnerability highlights
    {"selector": "node[flagged='asrep']",         "style": {"border-width": 3, "border-color": RED,    "background-color": ORANGE}},
    {"selector": "node[flagged='kerberoast']",    "style": {"border-width": 3, "border-color": ORANGE, "background-color": ORANGE}},
    {"selector": "node[flagged='unconstrained']", "style": {"border-width": 3, "border-color": RED,    "background-color": RED}},
    # Edges
    {"selector": "edge",                      "style": {"label": "data(label)", "color": TEXT_COL, "line-color": "#555", "width": 1, "font-size": "7px", "curve-style": "bezier", "target-arrow-shape": "triangle", "target-arrow-color": "#555"}},
    {"selector": "edge[label='AdminTo']",     "style": {"color": RED,    "line-color": RED,    "target-arrow-color": RED,    "width": 2}},
    {"selector": "edge[label='MemberOf']",    "style": {"color": ORANGE, "line-color": ORANGE, "target-arrow-color": ORANGE}},
    {"selector": "edge[label='HasSession']",  "style": {"color": CYAN,   "line-color": CYAN,   "target-arrow-color": CYAN}},
]


# ─────────────────────────────────────────────────────────────────────────────
# NODE INTEL KNOWLEDGE BASE
# Context-aware detail for each node type + vulnerability flag
# ─────────────────────────────────────────────────────────────────────────────

NODE_INTEL = {
    # ── By vulnerability flag (takes priority over type) ──────────────────────
    "asrep": {
        "title": "🟠 AS-REP Roastable Account",
        "what": "This user account has Kerberos pre-authentication **disabled**. The Domain Controller will hand out an encrypted TGT to anyone who asks — no password required.",
        "exploit": [
            "Run `GetNPUsers.py` (Impacket) or `Rubeus asreproast` from any machine on the network.",
            "Receive the AS-REP hash without authenticating.",
            "Crack the hash offline with `hashcat -m 18200` — typical speeds 1B+ hashes/sec on GPU.",
        ],
        "consequence": [
            "🔐 **Account compromise** — attacker gains full credentials for this account.",
            "📈 **Privilege escalation** if this account has AdminTo or DCSync rights.",
            "🌍 **Lateral movement** across all machines this account can reach.",
        ],
        "remediation": [
            "Enable Kerberos pre-authentication on this account (uncheck 'Do not require Kerberos preauthentication' in AD).",
            "Enforce a strong password policy (20+ chars) as a stop-gap.",
            "Monitor for unusual AS-REP requests in Windows Event Log ID 4768.",
        ],
        "severity": "HIGH",
        "color": "#f5a742",
    },
    "kerberoast": {
        "title": "🟡 Kerberoastable Account (SPN Set)",
        "what": "This account has a **Service Principal Name (SPN)** registered. Any authenticated domain user can request a Kerberos TGS ticket for this account — the ticket is encrypted with the account's NTLM hash.",
        "exploit": [
            "Run `GetUserSPNs.py` (Impacket) or `Rubeus kerberoast` as any domain user.",
            "Extract the RC4/AES encrypted service ticket.",
            "Crack offline: `hashcat -m 13100` (RC4) or `-m 19600` (AES).",
        ],
        "consequence": [
            "🔐 **Service account compromise** — many service accounts run with elevated privileges.",
            "⚙️ **Service impersonation** — attacker can forge tickets for the service.",
            "📈 **Domain Admin escalation** if the service account has DA membership.",
        ],
        "remediation": [
            "Use Managed Service Accounts (gMSA) — passwords rotate automatically, 120-char random.",
            "Audit SPNs: `setspn -T domain -Q */*` and remove unnecessary ones.",
            "Enable AES-only encryption for service accounts (disables RC4 cracking).",
            "Monitor Event ID 4769 with encryption type 0x17 (RC4).",
        ],
        "severity": "HIGH",
        "color": "#f5a742",
    },
    "unconstrained": {
        "title": "🔴 Unconstrained Delegation Enabled",
        "what": "This computer stores **full TGTs of every user who authenticates to it**. An attacker who compromises this machine can impersonate any user in the domain — including Domain Admins.",
        "exploit": [
            "Compromise this machine (local admin sufficient).",
            "Use `Rubeus monitor /interval:5` to capture TGTs as users authenticate.",
            "Combine with PrinterBug/SpoolSample to coerce DC authentication: force DC to authenticate → capture DC TGT.",
            "Use captured DC TGT → `secretsdump` → full domain hash dump (DCSync).",
        ],
        "consequence": [
            "🚨 **Domain takeover** — a compromised unconstrained machine + PrinterBug = full domain compromise in minutes.",
            "🧐 **Credential harvesting** — all TGTs cached persist across reboots until expiry.",
            "💻 **Persistent access** — golden/silver ticket attacks possible after DCSync.",
        ],
        "remediation": [
            "Replace unconstrained delegation with **constrained delegation** or **resource-based constrained delegation (RBCD)**.",
            "Flag this computer account with 'Account is sensitive and cannot be delegated'.",
            "Patch PrintSpooler or disable the Spooler service on DCs.",
            "Monitor: Event ID 4624 Type 3 logins to this computer from DCs.",
        ],
        "severity": "CRITICAL",
        "color": "#f54254",
    },
    # ── By node type ──────────────────────────────────────────────────────────
    "User": {
        "title": "👤 Active Directory User Account",
        "what": "A standard Active Directory user object. Represents a person, service, or application identity within the domain.",
        "exploit": [
            "Password spraying / brute force if lockout policy is weak.",
            "Pass-the-Hash (PtH) if NTLM hash is obtained via other means.",
            "Phishing / credential theft to obtain plaintext password.",
        ],
        "consequence": [
            "Account access to all resources this user can reach.",
            "Lateral movement if user has admin rights on other machines.",
            "Data exfiltration from all shares the user can read.",
        ],
        "remediation": [
            "Enforce MFA for all user accounts.",
            "Apply least-privilege — remove unnecessary group memberships.",
            "Enable Protected Users security group for privileged accounts.",
        ],
        "severity": "MEDIUM",
        "color": "#f5a742",
    },
    "Computer": {
        "title": "💻 Active Directory Computer Account",
        "what": "A machine joined to the domain. Computer accounts authenticate to AD and can hold local admin groups, sessions, and delegation rights.",
        "exploit": [
            "Exploit unpatched services (CVEs) for RCE.",
            "Relay attacks (NTLM relay) if SMB signing is disabled.",
            "Abuse local admin rights held by compromised user accounts.",
        ],
        "consequence": [
            "Local code execution on the machine.",
            "Credential harvesting from LSASS (Mimikatz).",
            "Pivot point for lateral movement across the network.",
        ],
        "remediation": [
            "Enable SMB signing on all hosts.",
            "Deploy LAPS (Local Administrator Password Solution).",
            "Keep systems patched — prioritize CVEs with CVSS ≥ 8.0.",
        ],
        "severity": "MEDIUM",
        "color": "#f54254",
    },
    "Group": {
        "title": "👥 Active Directory Security Group",
        "what": "A collection of users or computers. Group membership determines access to resources across the domain. High-value groups (Domain Admins, Enterprise Admins, etc.) are primary targets.",
        "exploit": [
            "If any member is compromised, the group's permissions are compromised.",
            "Nested group abuse — hidden admin paths through group nesting.",
            "WriteDACL / GenericAll abuse to add self to the group.",
        ],
        "consequence": [
            "Access to all resources the group is permitted.",
            "Domain Admin if this is a privileged group or nested within one.",
        ],
        "remediation": [
            "Audit group memberships regularly — especially nested groups.",
            "Apply Just-In-Time (JIT) provisioning for privileged groups.",
            "Enable Privileged Access Management (PAM) in AD.",
        ],
        "severity": "MEDIUM",
        "color": "#9e54d4",
    },
    "Domain": {
        "title": "🏰 Active Directory Domain",
        "what": "The root AD domain object. Compromising domain-level objects enables domain-wide persistence and control over all objects within the domain.",
        "exploit": [
            "DCSync attack via accounts with GetChanges + GetChangesAll rights.",
            "Skeleton Key injection at Domain Controller level.",
            "Golden Ticket — forge any TGT after obtaining KRBTGT hash.",
        ],
        "consequence": [
            "🚨 **Total domain compromise** — all accounts, machines, and data accessible.",
            "Persistent access via Golden Tickets (valid up to 10 years).",
            "Ability to create backdoor admin accounts that survive domain cleanup.",
        ],
        "remediation": [
            "Rotate KRBTGT password twice (invalidates all existing Golden Tickets).",
            "Audit DCSync rights — only Domain Controllers should have GetChanges rights.",
            "Implement AD Tiering (Tier-0/1/2) to isolate Domain Controllers.",
        ],
        "severity": "CRITICAL",
        "color": "#11c26f",
    },
    "GPO": {
        "title": "📋 Group Policy Object",
        "what": "A policy container that can configure settings on all machines or users within its linked scope. GPO write access = code execution on every linked system.",
        "exploit": [
            "If write access exists: inject malicious startup scripts.",
            "Add a scheduled task that runs a reverse shell on all linked machines.",
            "Deploy software package containing a backdoor to all computers in scope.",
        ],
        "consequence": [
            "Code execution on **all machines** the GPO applies to.",
            "Persistence that survives machine reboots.",
            "Potential domain-wide compromise if GPO is linked to the root domain.",
        ],
        "remediation": [
            "Audit GPO Write permissions — only Domain Admins should modify GPOs.",
            "Enable GPO change monitoring (Event ID 5136).",
            "Use AGPM (Advanced Group Policy Management) for change approval workflow.",
        ],
        "severity": "CRITICAL",
        "color": "#42b9f5",
    },
    "OU": {
        "title": "📂 Organizational Unit (OU)",
        "what": "A container in AD used to organize objects. OU delegation can grant users admin rights over entire subtrees of AD objects.",
        "exploit": [
            "If OU delegation is misconfigured, partial admins can modify/create objects.",
            "OU admin can reset passwords of child user accounts.",
            "GenericAll on OU gives full control over all child objects.",
        ],
        "consequence": [
            "Takeover of all user/computer accounts within the OU.",
            "Password reset and account creation in the OU's scope.",
        ],
        "remediation": [
            "Audit OU delegations with `Get-ADOrganizationalUnit -Filter * | Get-ACL`.",
            "Apply principle of least privilege to OU admin roles.",
        ],
        "severity": "LOW",
        "color": "#42b9f5",
    },
    "default": {
        "title": "🔵 AD Object",
        "what": "An Active Directory object. Its significance depends on its type, group memberships, and the permissions it holds over other objects.",
        "exploit": ["Depends on object type and permissions."],
        "consequence": ["Varies based on assigned privileges and group memberships."],
        "remediation": ["Audit object permissions and apply least-privilege."],
        "severity": "INFO",
        "color": "#42b9f5",
    },
}


def _build_node_modal_content(node_data):
    """Generate rich HTML content for a clicked node based on its type and vulnerability flags."""
    if not node_data:
        return "", False

    name    = node_data.get("label", node_data.get("id", "Unknown"))
    ntype   = node_data.get("type", "Unknown")
    flagged = node_data.get("flagged")  # 'asrep', 'kerberoast', 'unconstrained', or None

    # Look up intel — flag takes priority over node type
    intel = NODE_INTEL.get(flagged) or NODE_INTEL.get(ntype) or NODE_INTEL["default"]

    sev_color = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": "#f5e642", "LOW": CYAN, "INFO": TEXT_COL}
    color = sev_color.get(intel["severity"], TEXT_COL)

    def _section(icon, heading, items, item_color=None):
        return html.Div([
            html.H6([icon, f" {heading}"],
                    style={"color": CYAN, "borderBottom": f"1px solid {CYAN}30", "paddingBottom": "4px", "marginTop": "16px"}),
            html.Ul([
                html.Li(dcc.Markdown(item, style={"color": item_color or TEXT_COL, "fontSize": "0.85rem",
                                                  "marginBottom": "4px"}),
                        style={"listStyle": "disc", "marginLeft": "16px"})
                for item in items
            ], style={"paddingLeft": "0", "marginBottom": "0"})
        ])

    body = html.Div([
        # Node header
        dbc.Row([
            dbc.Col([
                html.H4(name, style={"color": "#fff", "marginBottom": "2px"}),
                html.Div([
                    dbc.Badge(ntype,             color="secondary", className="me-2"),
                    dbc.Badge(intel["severity"], style={"backgroundColor": color}, className="me-2"),
                    *([
                        dbc.Badge(flagged.upper().replace("_", " "), color="danger")
                    ] if flagged else []),
                ]),
            ])
        ], className="mb-3"),

        # What is this node
        html.Div([
            html.H6("📋 What is this?",
                    style={"color": CYAN, "borderBottom": f"1px solid {CYAN}30", "paddingBottom": "4px"}),
            dcc.Markdown(intel["what"], style={"color": TEXT_COL, "fontSize": "0.87rem"}),
        ]),

        _section("⚔️",  "Exploitation Method",    intel["exploit"],      ORANGE),
        _section("💥",  "Attack Consequences",     intel["consequence"],  RED),
        _section("🛡",  "Recommended Remediation", intel["remediation"],  GREEN),
    ], style={"backgroundColor": BG_DARK, "padding": "8px"})

    title = intel["title"]
    return title, body, True


def _score_badge(score):
    """Return a colour-coded badge for the Tier-0 exposure score."""
    if score == 0:
        color, label = "success", "Safe"
    elif score < 30:
        color, label = "warning", "Low Risk"
    elif score < 70:
        color, label = "danger", "Medium Risk"
    else:
        color, label = "danger", "HIGH RISK"

    return dbc.Card([
        dbc.CardBody([
            html.P("Tier-0 Exposure Score", style={"color": TEXT_COL, "fontSize": "0.8rem", "marginBottom": "4px"}),
            html.H1(str(score), style={"color": RED if score >= 70 else ORANGE if score >= 30 else GREEN, "fontWeight": "bold", "margin": "0"}),
            dbc.Badge(label, color=color, className="mt-1"),
        ])
    ], style={**CARD_STYLE, "textAlign": "center"})


def _findings_table(flagged_users, flagged_computers, spooler):
    """Build a DataTable from flagged accounts and computer findings."""
    rows = []
    for u in (flagged_users or []):
        rows.append({"Entity": u.get("name", "?"), "Type": "User", "Finding": u.get("type", "?"), "Severity": "⚠ High"})
    for c in (flagged_computers or []):
        rows.append({"Entity": c.get("name", "?"), "Type": "Computer", "Finding": c.get("type", "?"), "Severity": "🔴 Critical"})
    if spooler:
        rows.append({"Entity": "Domain Controller", "Type": "Service", "Finding": "Print Spooler port 445 open", "Severity": "🔴 Critical"})
    if not rows:
        return html.P("✅ No flagged entities found.", style={"color": GREEN, "padding": "10px"})
    return dash_table.DataTable(
        data=rows,
        columns=[{"name": c, "id": c} for c in ["Entity", "Type", "Finding", "Severity"]],
        style_table={"overflowX": "auto"},
        style_cell={"backgroundColor": BG_DARK, "color": TEXT_COL, "border": "1px solid #333", "fontSize": "0.82rem", "padding": "6px 10px"},
        style_header={"backgroundColor": PANEL_BG, "color": CYAN, "fontWeight": "bold", "border": "1px solid #333"},
        style_data_conditional=[
            {"if": {"filter_query": "{Severity} contains 'Critical'"}, "color": RED},
            {"if": {"filter_query": "{Severity} contains 'High'"},     "color": ORANGE},
        ],
        page_size=20,
    )


# ─────────────────────────────────────────────────────────────────────────────
# LAYOUT
# ─────────────────────────────────────────────────────────────────────────────

def _layout_inner():
    return dbc.Container([
        # ── Header ──────────────────────────────────────────────────────────
        dbc.Row([
            dbc.Col([
                html.H3("🛡 Hybrid AD RedOps Scanner", style={"color": "#fff", "marginBottom": "0"}),
                html.P("Direct LDAP enumeration — AS-REP Roast · Kerberoast · Unconstrained Delegation · Print Spooler",
                       style={"color": TEXT_COL, "fontSize": "0.85rem"}),
            ])
        ], className="mb-2 mt-3"),

        # ── Live KPI Stats Bar ──────────────────────────────────────────────────
        html.Div(id="bh-kpi-bar", className="mb-3"),

        # ── Credential Panel ──────────────────────────────────────────────── ────────────────────────────────────────────────
        dbc.Card([
            dbc.CardHeader(html.Span("🔑 Target Credentials", style={"color": CYAN, "fontWeight": "bold", "fontSize": "0.9rem"}),
                           style={"backgroundColor": "#1a1c24", "border": "none"}),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.Label("DC IP Address", style=LABEL_STYLE),
                        dbc.Input(id="bh-dc-ip",    value="192.168.1.10", placeholder="192.168.1.10", style=INPUT_STYLE),
                    ], width=3),
                    dbc.Col([
                        html.Label("Domain (FQDN)", style=LABEL_STYLE),
                        dbc.Input(id="bh-domain",   value="expedite.local", placeholder="expedite.local", style=INPUT_STYLE),
                    ], width=3),
                    dbc.Col([
                        html.Label("Username", style=LABEL_STYLE),
                        dbc.Input(id="bh-username", value="Administrator", placeholder="Administrator", style=INPUT_STYLE),
                    ], width=3),
                    dbc.Col([
                        html.Label("Password", style=LABEL_STYLE),
                        dbc.Input(id="bh-password", type="password", value="Adomaa12@", placeholder="Adomaa12@", style=INPUT_STYLE),
                    ], width=3),
                ], className="g-2"),
            ], style={"padding": "12px"}),
        ], style={**CARD_STYLE, "marginBottom": "16px"}),

        # ── Action Buttons ───────────────────────────────────────────────────
        dbc.Row([
            dbc.Col([
                dbc.Button([html.I(className="bi bi-search me-2"), "Scan AD Server"],
                           id="bh-scan-btn", color="primary", size="sm", className="me-2",
                           style={"minWidth": "170px"}),
                dbc.Button([html.I(className="bi bi-cloud-download me-2"), "Pull Results"],
                           id="bh-results-btn", color="secondary", size="sm", className="me-2",
                           style={"minWidth": "170px"}),
                dbc.Button([html.I(className="bi bi-diagram-3 me-2"), "Show Graph"],
                           id="bh-graph-btn", color="info", size="sm",
                           style={"minWidth": "170px"}),
            ], width=12),
        ], className="mb-3"),

        # ── Status Bar ──────────────────────────────────────────────────────
        dbc.Row([
            dbc.Col(
                dcc.Loading(
                    html.Div(id="bh-status-msg", style={"color": CYAN, "fontSize": "0.9rem", "minHeight": "24px"}),
                    type="dot", color=CYAN
                ),
                width=12
            )
        ], className="mb-3"),

        # ── Score + Findings Panel ───────────────────────────────────────────
        dbc.Row([
            dbc.Col(html.Div(id="bh-score-panel"), width=3),
            dbc.Col(dbc.Card([
                dbc.CardHeader(html.Span("Flagged Entities", style={"color": CYAN, "fontWeight": "bold"}),
                               style={"backgroundColor": "#1a1c24", "border": "none"}),
                dbc.CardBody(html.Div(id="bh-findings-panel"), style={"padding": "8px"})
            ], style=CARD_STYLE), width=9),
        ], className="mb-4"),

        # ── Exposure Score Trend Chart ──────────────────────────────────────
        dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.H6("📊 Tier-0 Exposure Score History",
                                style={"color": CYAN, "marginBottom": "4px"}),
                        html.Span("Historical scan scores — trend shows if your environment is improving.",
                                  style={"color": TEXT_COL, "fontSize": "0.78rem"}),
                    ], width=9),
                    dbc.Col([
                        dbc.Button([
                            html.I(className="bi bi-arrow-clockwise me-1"),
                            "Refresh Trend"
                        ], id="bh-trend-refresh-btn", color="outline-secondary",
                           size="sm", className="float-end"),
                    ], width=3),
                ], className="mb-2"),
                dcc.Loading(
                    dcc.Graph(
                        id="bh-score-trend-chart",
                        config={"displayModeBar": False},
                        style={"height": "200px"},
                    ),
                    type="dot", color=CYAN
                ),
            ])
        ], style=CARD_STYLE, className="mb-4"),

        # ── Cytoscape Graph ───────────────────────────────────────────────────
        dbc.Card([
            dbc.CardBody([
                # Graph title + legend row
                html.Div([
                    html.H5("AD Relationship Graph", style={"color": "#fff", "display": "inline"}),
                    html.Span(" — Click 'Show Graph' to populate",
                              style={"color": TEXT_COL, "fontSize": "0.8rem", "marginLeft": "8px"}),
                    dbc.ButtonGroup([
                        dbc.Badge("User",     color="warning", className="me-1"),
                        dbc.Badge("Computer", color="danger",  className="me-1"),
                        dbc.Badge("Group",    pill=True, style={"backgroundColor": PURPLE}, className="me-1"),
                        dbc.Badge("Domain",   color="success", className="me-1"),
                    ], className="float-end"),
                ], className="mb-2"),

                # ── Graph View Mode Selector ──────────────────────────────────
                dbc.Row([
                    dbc.Col([
                        html.Label("Graph View:", style={"color": TEXT_COL, "fontSize": "0.8rem", "marginRight": "8px", "verticalAlign": "middle"}),
                        dbc.RadioItems(
                            id="bh-graph-view-mode",
                            options=GRAPH_VIEW_OPTIONS,
                            value="full",
                            inline=True,
                            inputStyle={"marginRight": "4px", "cursor": "pointer"},
                            labelStyle={"marginRight": "16px", "color": TEXT_COL, "fontSize": "0.82rem", "cursor": "pointer"},
                            inputCheckedStyle={"backgroundColor": CYAN, "borderColor": CYAN},
                        ),
                    ], width=12),
                ], className="mb-3 mt-1"),

                dcc.Loading(
                    cyto.Cytoscape(
                        id="bh-cyto-graph",
                        layout={"name": "cose", "idealEdgeLength": 120, "nodeOverlap": 20, "animate": True},
                        style={"width": "100%", "height": "680px", "backgroundColor": BG_DARK, "borderRadius": "8px"},
                        stylesheet=CYTO_STYLESHEET,
                        elements=[],
                        responsive=True,
                    ),
                    type="circle", color=CYAN
                ),
            ])
        ], style=CARD_STYLE),

    ], fluid=True, style={"backgroundColor": BG_DARK, "minHeight": "100vh", "padding": "0 20px 40px"})


# ── Node Detail Modal (rendered outside Container so it overlays everything) ──
_NODE_MODAL = dbc.Modal([
    dbc.ModalHeader(
        dbc.ModalTitle(id="bh-node-modal-title", style={"color": "#fff", "fontSize": "1rem"}),
        style={"backgroundColor": PANEL_BG, "borderBottom": f"1px solid #333"},
        close_button=True,
    ),
    dbc.ModalBody(
        dbc.Tabs([
            dbc.Tab(
                html.Div(id="bh-node-modal-body"),
                label="📋 Intel",
                tab_id="modal-tab-intel",
                label_style={"color": CYAN, "fontSize": "0.85rem"},
                active_label_style={"color": "#fff", "fontWeight": "bold"},
            ),
            dbc.Tab(
                dcc.Loading(
                    html.Div(id="bh-node-modal-llm",
                             style={"color": TEXT_COL, "fontSize": "0.87rem", "padding": "12px",
                                    "minHeight": "200px", "whiteSpace": "pre-wrap",
                                    "lineHeight": "1.6"}),
                    type="circle", color=CYAN
                ),
                label="🤖 AI Narrative",
                tab_id="modal-tab-llm",
                label_style={"color": "#a855f7", "fontSize": "0.85rem"},
                active_label_style={"color": "#fff", "fontWeight": "bold"},
            ),
        ], id="bh-node-modal-tabs", active_tab="modal-tab-intel"),
        style={"backgroundColor": BG_DARK, "padding": "20px"},
    ),
], id="bh-node-modal", is_open=False, size="lg", centered=True,
   backdrop=True, scrollable=True,
   style={"fontFamily": "Inter, sans-serif"})


# ── KPI Drilldown Modal ───────────────────────────────────────────────────────
_KPI_DETAIL_MODAL = dbc.Modal([
    dbc.ModalHeader(
        dbc.ModalTitle(id="kpi-detail-modal-title", style={"color": "#fff", "fontSize": "1.1rem"}),
        style={"backgroundColor": PANEL_BG, "borderBottom": f"1px solid #333"},
        close_button=True,
    ),
    dbc.ModalBody(
        dcc.Loading(
            dbc.Tabs([
                dbc.Tab(html.Div(id="kpi-detail-tab-overview"),
                        label="📋 Overview",    tab_id="kpi-tab-overview",
                        label_style={"color": CYAN,    "fontSize": "0.85rem"},
                        active_label_style={"color": "#fff", "fontWeight": "bold"}),
                dbc.Tab(html.Div(id="kpi-detail-tab-hosts"),
                        label="🎯 Affected Hosts", tab_id="kpi-tab-hosts",
                        label_style={"color": RED,     "fontSize": "0.85rem"},
                        active_label_style={"color": "#fff", "fontWeight": "bold"}),
                dbc.Tab(html.Div(id="kpi-detail-tab-nvd"),
                        label="🔵 NVD CVEs",   tab_id="kpi-tab-nvd",
                        label_style={"color": CYAN,    "fontSize": "0.85rem"},
                        active_label_style={"color": "#fff", "fontWeight": "bold"}),
                dbc.Tab(html.Div(id="kpi-detail-tab-edb"),
                        label="💥 ExploitDB",  tab_id="kpi-tab-edb",
                        label_style={"color": ORANGE,  "fontSize": "0.85rem"},
                        active_label_style={"color": "#fff", "fontWeight": "bold"}),
                dbc.Tab(html.Div(id="kpi-detail-tab-gh"),
                        label="🐙 GitHub Tools", tab_id="kpi-tab-gh",
                        label_style={"color": "#a855f7","fontSize": "0.85rem"},
                        active_label_style={"color": "#fff", "fontWeight": "bold"}),
            ], id="kpi-detail-modal-tabs", active_tab="kpi-tab-overview"),
            type="circle", color=CYAN
        ),
        style={"backgroundColor": BG_DARK, "padding": "20px"},
    ),
], id="kpi-detail-modal", is_open=False, size="xl", centered=True,
   backdrop=True, scrollable=True,
   style={"fontFamily": "Inter, sans-serif"})


def layout_bh_dashboard():
    """Return the full layout: top-level 5-tab AD pipeline."""
    top_tabs = dbc.Tabs([
        dbc.Tab(
            _layout_inner(),
            label="🔍 Enumeration",
            tab_id="ad-tab-enum",
            label_style={"color": CYAN, "fontWeight": "600"},
            active_label_style={"color": "#fff", "fontWeight": "bold"},
        ),
        dbc.Tab(
            ui_ad_redops.layout_redops_tabs(),
            label="⚔️ Exploitation Pipeline",
            tab_id="ad-tab-redops",
            label_style={"color": RED, "fontWeight": "600"},
            active_label_style={"color": "#fff", "fontWeight": "bold"},
        ),
    ], id="ad-top-tabs", active_tab="ad-tab-enum",
       style={"backgroundColor": BG_DARK,
              "borderBottom": f"2px solid {RED}",
              "padding": "0 10px"},
    )
    return html.Div([
        top_tabs,
        _NODE_MODAL,
        _KPI_DETAIL_MODAL,
        ui_ad_redops.CRED_STORE,
    ])


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACKS
# ─────────────────────────────────────────────────────────────────────────────

@callback(
    Output("bh-status-msg",   "children", allow_duplicate=True),
    Output("bh-score-panel",  "children", allow_duplicate=True),
    Output("bh-findings-panel","children", allow_duplicate=True),
    Input("bh-scan-btn", "n_clicks"),
    State("bh-dc-ip",    "value"),
    State("bh-domain",   "value"),
    State("bh-username", "value"),
    State("bh-password", "value"),
    prevent_initial_call=True
)
def handle_scan(n_clicks, dc_ip, domain, username, password):
    """Button 1 — Scan AD Server: runs LDAP enumeration → Neo4j + Postgres."""
    if not n_clicks:
        raise PreventUpdate

    dc_ip    = (dc_ip    or "192.168.1.10").strip()
    domain   = (domain   or "corp.local").strip()
    username = (username or "Administrator").strip()
    password = (password or "").strip()

    result = run_ad_scan(dc_ip=dc_ip, username=username, password=password, domain=domain)

    if result["status"] == "error":
        status = html.Span([
            "❌ Scan Failed: ", html.Code(result.get("message", "Unknown error"),
                                         style={"color": RED, "fontSize": "0.8rem"})
        ])
        return status, _score_badge(0), html.P("No data — scan failed.", style={"color": TEXT_COL})

    findings = result.get("findings", {})
    score    = result.get("score", 0)
    ts       = result.get("timestamp", "")

    status = html.Span([
        f"✅ Scan complete [{ts}] — ",
        html.Strong(f"{len(findings.get('asrep',[]))} AS-REP", style={"color": ORANGE}),
        " · ",
        html.Strong(f"{len(findings.get('kerberoast',[]))} Kerberoast", style={"color": ORANGE}),
        " · ",
        html.Strong(f"{len(findings.get('unconstrained',[]))} Unconstrained", style={"color": RED}),
        " · Spooler: ",
        html.Strong("OPEN" if findings.get("spooler") else "closed",
                    style={"color": RED if findings.get("spooler") else GREEN}),
        f" — Results saved to Neo4j & Postgres."
    ])

    flagged_users = [{"name": u, "type": "AS-REP Roastable"} for u in findings.get("asrep", [])] + \
                   [{"name": k["user"], "type": f"Kerberoastable ({k['spn']})"} for k in findings.get("kerberoast", [])]
    flagged_comps = [{"name": c, "type": "Unconstrained Delegation"} for c in findings.get("unconstrained", [])]

    return status, _score_badge(score), _findings_table(flagged_users, flagged_comps, findings.get("spooler", False))


@callback(
    Output("bh-status-msg",    "children", allow_duplicate=True),
    Output("bh-score-panel",   "children", allow_duplicate=True),
    Output("bh-findings-panel","children", allow_duplicate=True),
    Input("bh-results-btn", "n_clicks"),
    prevent_initial_call=True
)
def handle_pull_results(n_clicks):
    """Button 2 — Pull Results: loads last scan from Postgres + annotates from Neo4j."""
    if not n_clicks:
        raise PreventUpdate

    result = get_last_scan_results()

    if result["status"] == "no_data":
        return (
            html.Span("ℹ️ No scan history found. Run 'Scan AD Server' first.", style={"color": CYAN}),
            _score_badge(0),
            html.P("No data yet.", style={"color": TEXT_COL})
        )
    if result["status"] == "error":
        return (
            html.Span(f"❌ Error: {result.get('message', '')}", style={"color": RED}),
            _score_badge(0),
            html.P("Failed to load results.", style={"color": RED})
        )

    score   = result.get("score", 0)
    ts      = result.get("timestamp", "unknown")
    domain  = result.get("domain", "?")
    dc_ip   = result.get("dc_ip", "?")
    status  = html.Span([
        f"📥 Last scan: ",
        html.Strong(f"{domain} ({dc_ip})", style={"color": CYAN}),
        f" — recorded at {ts}"
    ])

    return (
        status,
        _score_badge(score),
        _findings_table(
            result.get("flagged_users", []),
            result.get("flagged_computers", []),
            result.get("spooler", False)
        )
    )


@callback(
    Output("bh-status-msg",  "children", allow_duplicate=True),
    Output("bh-cyto-graph",  "elements"),
    Input("bh-graph-btn", "n_clicks"),
    State("bh-graph-view-mode", "value"),
    prevent_initial_call=True
)
def handle_show_graph(n_clicks, view_mode):
    """Button 3 — Show Graph: queries Neo4j using the selected view mode."""
    if not n_clicks:
        raise PreventUpdate

    mode = view_mode or "full"
    elements = get_graph_elements(view_mode=mode)

    # Find the label for the selected mode
    mode_labels = {o["value"]: o["label"] for o in GRAPH_VIEW_OPTIONS}
    mode_label  = mode_labels.get(mode, mode)

    if not elements:
        return (
            html.Span(f"⚠️ No data for '{mode_label}' view. Run 'Scan AD Server' first.", style={"color": ORANGE}),
            []
        )

    node_count = sum(1 for e in elements if "source" not in e.get("data", {}))
    edge_count = len(elements) - node_count
    status = html.Span([
        f"🗺 {mode_label} — ",
        html.Strong(f"{node_count} nodes", style={"color": CYAN}),
        " · ",
        html.Strong(f"{edge_count} edges", style={"color": TEXT_COL}),
        " · Red/orange borders = flagged as vulnerable. Click any node for details."
    ])
    return status, elements


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACK: NODE CLICK → DETAIL MODAL (Intel + AI Narrative)
# ─────────────────────────────────────────────────────────────────────────────

@callback(
    Output("bh-node-modal-title",  "children"),
    Output("bh-node-modal-body",   "children"),
    Output("bh-node-modal-llm",    "children"),
    Output("bh-node-modal",        "is_open"),
    Input("bh-cyto-graph", "tapNodeData"),
    prevent_initial_call=True
)
def handle_node_click(node_data):
    """Open the detail modal when a Cytoscape node is clicked.
    Populates the Intel tab immediately and generates an LLM narrative."""
    if not node_data:
        raise PreventUpdate

    title, body, _ = _build_node_modal_content(node_data)

    # Build LLM narrative
    name    = node_data.get("label", node_data.get("id", "Unknown"))
    ntype   = node_data.get("type",  "Unknown")
    flagged = node_data.get("flagged", "")

    flag_desc = {
        "asrep":         "flagged as AS-REP Roastable (Kerberos pre-auth disabled)",
        "kerberoast":    "flagged as Kerberoastable (SPN set, TGS ticket extractable)",
        "unconstrained": "flagged with Unconstrained Delegation (full TGT caching)",
    }.get(flagged, "no specific vulnerability flag")

    prompt = f"""You are an Active Directory red team expert writing a concise attack narrative.

Node: '{name}'
Type: {ntype}
Vulnerability status: {flag_desc}

Write a 3-4 paragraph attack story in plain English (no markdown headers, no bullet points):
1. What this node represents and why it matters in Active Directory
2. Exactly how an attacker would exploit this node — specific tools, commands, techniques
3. What happens after exploitation — privilege escalation path, lateral movement, end goal
4. The single most important remediation action the blue team should take immediately

Be specific, technical, and concise. Address the security team directly."""

    llm_text = "🤖 AI Narrative unavailable — LLM engine not loaded."
    try:
        from llm_engine import call_llm
        llm_text = call_llm(prompt)
    except Exception as e:
        llm_text = f"⚠️ LLM call failed: {str(e)}"

    return title, body, llm_text, True


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACK: TREND CHART — EXPOSURE SCORE HISTORY
# ─────────────────────────────────────────────────────────────────────────────

def _build_trend_figure(history):
    """Build a Plotly area chart from score history rows."""
    if not history:
        fig = go.Figure()
        fig.update_layout(
            plot_bgcolor=BG_DARK, paper_bgcolor=BG_DARK,
            font={"color": TEXT_COL},
            annotations=[{"text": "No scan history yet. Run 'Scan AD Server' to populate.",
                           "showarrow": False, "font": {"color": TEXT_COL, "size": 13},
                           "xref": "paper", "yref": "paper", "x": 0.5, "y": 0.5}],
            xaxis={"visible": False}, yaxis={"visible": False},
            margin={"l": 8, "r": 8, "t": 8, "b": 8},
        )
        return fig

    timestamps = [r["timestamp"] for r in history]
    scores     = [r["score"]     for r in history]
    domains    = [r["domain"]    for r in history]

    # Colour each point by severity
    point_colors = [
        RED if s >= 60 else (ORANGE if s >= 25 else GREEN)
        for s in scores
    ]

    fig = go.Figure()

    # Zone bands
    fig.add_hrect(y0=60,  y1=max(max(scores, default=0) + 20, 80),
                  fillcolor=RED,    opacity=0.07, line_width=0)
    fig.add_hrect(y0=25,  y1=60,
                  fillcolor=ORANGE, opacity=0.07, line_width=0)
    fig.add_hrect(y0=0,   y1=25,
                  fillcolor=GREEN,  opacity=0.07, line_width=0)

    # Area + line
    fig.add_trace(go.Scatter(
        x=timestamps, y=scores,
        mode="lines+markers",
        fill="tozeroy",
        fillcolor="rgba(66, 185, 245, 0.10)",
        line={"color": CYAN, "width": 2},
        marker={"color": point_colors, "size": 8, "line": {"width": 1, "color": "#fff"}},
        text=[f"Domain: {d}<br>Score: {s}" for d, s in zip(domains, scores)],
        hovertemplate="%{text}<br>%{x}<extra></extra>",
        name="Exposure Score",
    ))

    # Threshold lines
    fig.add_hline(y=60, line_dash="dot", line_color=RED,    line_width=1,
                  annotation_text="Critical (60)", annotation_position="right",
                  annotation={"font": {"color": RED, "size": 10}})
    fig.add_hline(y=25, line_dash="dot", line_color=ORANGE, line_width=1,
                  annotation_text="Warning (25)", annotation_position="right",
                  annotation={"font": {"color": ORANGE, "size": 10}})

    fig.update_layout(
        plot_bgcolor=BG_DARK, paper_bgcolor=BG_DARK,
        font={"color": TEXT_COL, "family": "Inter, sans-serif"},
        xaxis={"showgrid": False, "color": TEXT_COL, "tickfont": {"size": 10}},
        yaxis={"showgrid": True, "gridcolor": "#333", "color": TEXT_COL,
               "title": "Score", "tickfont": {"size": 10}, "rangemode": "tozero"},
        margin={"l": 40, "r": 60, "t": 8, "b": 40},
        showlegend=False,
        hovermode="x unified",
    )
    return fig


@callback(
    Output("bh-score-trend-chart", "figure"),
    Input("bh-trend-refresh-btn",  "n_clicks"),
    Input("bh-scan-btn",           "n_clicks"),
    Input("bh-results-btn",        "n_clicks"),
    prevent_initial_call=False
)
def update_trend_chart(refresh_clicks, scan_clicks, pull_clicks):
    """Rebuild the score trend chart whenever the page loads or any data button is clicked."""
    history = get_score_history(limit=50)
    return _build_trend_figure(history)


# ─────────────────────────────────────────────────────────────────────────────
# KPI BAR HELPERS + CALLBACK
# ─────────────────────────────────────────────────────────────────────────────

def _kpi_card(icon, label, value, color, subtitle="", vuln_type=None):
    """Single KPI stat card — number is a clickable button if vuln_type is given."""
    if vuln_type and value > 0:
        number_el = dbc.Button(
            str(value),
            id={"type": "kpi-drilldown-btn", "index": vuln_type},
            n_clicks=0,
            style={
                "fontSize": "2rem", "fontWeight": "bold", "color": color,
                "background": "none", "border": "none", "padding": "0",
                "cursor": "pointer", "lineHeight": "1",
                "textDecoration": "underline dotted",
                "textUnderlineOffset": "3px",
            },
            title=f"Click to see details for {label}",
        )
    else:
        number_el = html.Span(str(value), style={
            "fontSize": "2rem", "fontWeight": "bold", "color": color, "lineHeight": "1"
        })

    return dbc.Col(
        dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.Span(icon, style={"fontSize": "1.5rem", "marginRight": "10px"}),
                    number_el,
                ], style={"display": "flex", "alignItems": "center", "marginBottom": "4px"}),
                html.Div(label,    style={"color": "#fff",   "fontSize": "0.82rem", "fontWeight": "600"}),
                html.Div(subtitle, style={"color": TEXT_COL, "fontSize": "0.72rem", "marginTop": "2px"}),
            ], style={"padding": "14px 16px"}),
        ], style={
            **CARD_STYLE,
            "borderLeft": f"3px solid {color}",
            "transition": "border-color 0.3s ease",
        }),
        width=3,
    )


def _build_kpi_bar(kpi):
    """Build the 4-card KPI row from a get_live_kpi() result dict."""
    asrep  = kpi.get("asrep",         0)
    kerb   = kpi.get("kerberoast",    0)
    unc    = kpi.get("unconstrained", 0)
    err    = kpi.get("error")

    if err:
        return dbc.Alert(f"⚠️ KPI load failed: {err}", color="warning",
                         dismissable=True, className="py-2")

    def _sev(n, warn=1, crit=3):
        if n == 0:   return GREEN
        if n < crit: return ORANGE
        return RED

    return dbc.Row([
        _kpi_card("🟠", "AS-REP Roastable",
                  asrep, _sev(asrep),
                  "No pre-auth required" if asrep else "None detected",
                  vuln_type="asrep"),
        _kpi_card("🟡", "Kerberoastable Accounts",
                  kerb, _sev(kerb),
                  "SPN set — TGS extractable" if kerb else "None detected",
                  vuln_type="kerberoast"),
        _kpi_card("🔴", "Unconstrained Delegation",
                  unc, _sev(unc, warn=1, crit=1),
                  "Full TGT caching enabled" if unc else "None detected",
                  vuln_type="unconstrained"),
        _kpi_card("⚡", "Total Flagged",
                  asrep + kerb + unc,
                  _sev(asrep + kerb + unc, warn=1, crit=5),
                  "Across all vulnerability types"),
    ], className="g-3")


@callback(
    Output("bh-kpi-bar", "children"),
    Input("bh-scan-btn",    "n_clicks"),
    Input("bh-results-btn", "n_clicks"),
    prevent_initial_call=False,      # ← fires on page load too
)
def update_kpi_bar(scan_clicks, pull_clicks):
    """Auto-populate the KPI bar from Neo4j on page load and after scans."""
    kpi = get_live_kpi()
    return _build_kpi_bar(kpi)


# ─────────────────────────────────────────────────────────────────────────────
# KPI DRILLDOWN MODAL CALLBACK + RENDERERS
# ─────────────────────────────────────────────────────────────────────────────

def _sev_badge(severity_str):
    """Return a coloured badge for a CVE severity string."""
    s = str(severity_str).upper()
    color = RED if any(x in s for x in ("CRITICAL", "9.", "10")) else \
            ORANGE if any(x in s for x in ("HIGH", "7.", "8.")) else \
            "#f0c040"
    return html.Span(severity_str, style={
        "backgroundColor": color + "33", "color": color,
        "border": f"1px solid {color}", "borderRadius": "4px",
        "fontSize": "0.72rem", "padding": "1px 6px", "marginLeft": "8px",
        "fontWeight": "bold",
    })


def _render_overview(ref):
    return html.Div([
        html.P(ref.get("description", "No description available."),
               style={"color": TEXT_COL, "lineHeight": "1.7", "marginBottom": "16px"}),
        dbc.Row([
            dbc.Col([
                html.Div("CVSS Score", style={"color": TEXT_COL, "fontSize": "0.75rem", "marginBottom": "2px"}),
                html.Div(ref.get("cvss", "N/A"), style={"color": RED, "fontSize": "1.4rem", "fontWeight": "bold"}),
            ], width=4),
            dbc.Col([
                html.Div("Mitigation Command", style={"color": TEXT_COL, "fontSize": "0.75rem", "marginBottom": "6px"}),
                html.Code(
                    ref.get("mitigation_cmd", "See documentation"),
                    style={"backgroundColor": "#111", "color": GREEN, "padding": "8px 12px",
                           "borderRadius": "6px", "display": "block", "fontSize": "0.82rem",
                           "wordBreak": "break-all"},
                ),
            ], width=8),
        ]),
    ], style={"padding": "8px"})


def _render_hosts(affected):
    if not affected:
        return html.Div([
            html.I(className="bi bi-check-circle-fill me-2", style={"color": GREEN}),
            html.Span("No affected hosts found in the current scan.", style={"color": TEXT_COL}),
        ], style={"padding": "16px"})

    rows = [
        html.Tr([
            html.Td(html.Span("⚠️", style={"fontSize": "1.1rem"})),
            html.Td(r.get("name", "Unknown"), style={"color": RED, "fontWeight": "600", "paddingLeft": "8px"}),
            html.Td(r.get("domain", ""), style={"color": TEXT_COL, "paddingLeft": "16px"}),
            html.Td(r.get("type",   ""), style={"color": CYAN,    "paddingLeft": "8px"}),
            html.Td(r.get("spn",    ""), style={"color": ORANGE,  "paddingLeft": "8px", "fontSize": "0.78rem"}),
        ], style={"borderBottom": "1px solid #222"})
        for r in affected
    ]
    return html.Div([
        html.Div(f"🎯 {len(affected)} affected host(s) found in Neo4j",
                 style={"color": RED, "fontWeight": "bold", "marginBottom": "12px"}),
        html.Table([
            html.Thead(html.Tr([
                html.Th("", style={"width": "30px"}),
                html.Th("Name",   style={"color": TEXT_COL, "fontWeight": "600", "paddingBottom": "8px"}),
                html.Th("Domain", style={"color": TEXT_COL, "fontWeight": "600"}),
                html.Th("Type",   style={"color": TEXT_COL, "fontWeight": "600"}),
                html.Th("SPN",    style={"color": TEXT_COL, "fontWeight": "600"}),
            ], style={"borderBottom": f"1px solid {CYAN}"})),
            html.Tbody(rows),
        ], style={"width": "100%", "borderCollapse": "collapse"}),
    ], style={"padding": "8px"})


def _render_nvd(ref):
    static_cves = ref.get("cves", [])
    live_cves   = ref.get("live_cves", [])

    def _cve_card(cve, is_live=False):
        badge = "🔵 live" if is_live else "📌 curated"
        badge_color = "#a855f7" if is_live else CYAN
        return html.Div([
            html.Div([
                html.A(cve["id"], href=cve["url"], target="_blank",
                       style={"color": CYAN, "fontWeight": "bold", "fontSize": "0.9rem",
                              "textDecoration": "none"}),
                _sev_badge(cve.get("cvss", cve.get("severity", ""))),
                html.Span(f" {badge}", style={"color": badge_color, "fontSize": "0.7rem", "marginLeft": "8px"}),
            ]),
            html.Div(cve.get("title", ""), style={"color": TEXT_COL, "fontSize": "0.8rem", "marginTop": "2px"}),
        ], style={"padding": "10px 12px", "borderLeft": f"3px solid {CYAN}",
                  "backgroundColor": "#0d1117", "borderRadius": "4px", "marginBottom": "8px"})

    items = [_cve_card(c) for c in static_cves] + \
            ([html.Hr(style={"borderColor": "#333"})] if live_cves else []) + \
            ([html.Div("🔵 Live NVD Search Results", style={"color": "#a855f7", "fontWeight": "600",
                                                             "marginBottom": "8px"})] if live_cves else []) + \
            [_cve_card(c, is_live=True) for c in live_cves]
    return html.Div(items or [html.Span("No CVEs found.", style={"color": TEXT_COL})],
                    style={"padding": "8px"})


def _render_exploitdb(ref):
    entries = ref.get("exploitdb", [])
    if not entries:
        return html.Div("No ExploitDB entries found.", style={"color": TEXT_COL, "padding": "16px"})
    cards = []
    for e in entries:
        cards.append(html.Div([
            html.Div([
                html.Span(f"EDB-{e['id']}", style={"color": ORANGE, "fontWeight": "bold", "marginRight": "12px"}),
                html.A("🔗 View on ExploitDB", href=e["url"], target="_blank",
                       style={"color": CYAN, "fontSize": "0.8rem", "textDecoration": "none"}),
                html.Span(f"  {e.get('date', '')}", style={"color": TEXT_COL, "fontSize": "0.75rem",
                                                             "marginLeft": "12px"}),
            ]),
            html.Div(e["title"], style={"color": "#fff", "fontSize": "0.85rem", "marginTop": "4px"}),
        ], style={"padding": "10px 12px", "borderLeft": f"3px solid {ORANGE}",
                  "backgroundColor": "#0d1117", "borderRadius": "4px", "marginBottom": "8px"}))
    return html.Div(cards, style={"padding": "8px"})


def _render_github(ref):
    tools = ref.get("github", [])
    if not tools:
        return html.Div("No GitHub tools listed.", style={"color": TEXT_COL, "padding": "16px"})
    lang_colors = {"Python": "#3572A5", "C#": "#178600", "PowerShell": "#012456"}
    cards = []
    for t in tools:
        lang   = t.get("lang", "")
        lcolor = lang_colors.get(lang, "#888")
        cards.append(html.Div([
            html.Div([
                html.A(t["name"], href=t["url"], target="_blank",
                       style={"color": "#a855f7", "fontWeight": "bold", "fontSize": "0.9rem",
                              "textDecoration": "none"}),
                html.Span(f"  ⭐ {t.get('stars', '')}", style={"color": "#f0c040", "fontSize": "0.75rem",
                                                                 "marginLeft": "8px"}),
                html.Span(lang, style={"backgroundColor": lcolor + "33", "color": lcolor,
                                       "border": f"1px solid {lcolor}", "borderRadius": "4px",
                                       "fontSize": "0.7rem", "padding": "1px 6px", "marginLeft": "8px"}),
            ]),
            html.Div(t.get("desc", ""), style={"color": TEXT_COL, "fontSize": "0.8rem", "marginTop": "4px"}),
        ], style={"padding": "10px 12px", "borderLeft": "3px solid #a855f7",
                  "backgroundColor": "#0d1117", "borderRadius": "4px", "marginBottom": "8px"}))
    return html.Div(cards, style={"padding": "8px"})


@callback(
    Output("kpi-detail-modal-title",  "children"),
    Output("kpi-detail-tab-overview", "children"),
    Output("kpi-detail-tab-hosts",    "children"),
    Output("kpi-detail-tab-nvd",      "children"),
    Output("kpi-detail-tab-edb",      "children"),
    Output("kpi-detail-tab-gh",       "children"),
    Output("kpi-detail-modal",        "is_open"),
    Input({"type": "kpi-drilldown-btn", "index": dash.ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def open_kpi_detail(n_clicks_list):
    """Open the KPI drilldown modal when a stat number is clicked."""
    ctx = dash.callback_context
    if not ctx.triggered or not any(n_clicks_list):
        raise PreventUpdate

    # Identify which button was clicked
    triggered_id = ctx.triggered[0]["prop_id"]
    import json as _json
    vuln_type = _json.loads(triggered_id.split(".")[0]).get("index", "")

    ref = get_vuln_detail(vuln_type)

    title_labels = {
        "asrep":        "🟠 AS-REP Roasting — Vulnerability Detail",
        "kerberoast":   "🟡 Kerberoasting — Vulnerability Detail",
        "unconstrained":"🔴 Unconstrained Delegation — Vulnerability Detail",
    }
    title = title_labels.get(vuln_type, "Vulnerability Detail")

    return (
        title,
        _render_overview(ref),
        _render_hosts(ref.get("affected", [])),
        _render_nvd(ref),
        _render_exploitdb(ref),
        _render_github(ref),
        True,
    )
