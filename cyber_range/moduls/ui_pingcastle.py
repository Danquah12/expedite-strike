"""
ui_pingcastle.py  (v4 — static-DOM fix)
────────────────────────────────────────
Root cause of the Dash error:
  pc-live-feed / pc-line-count were inside pc-tab-content (dynamically rendered),
  so Dash couldn't bind Output callbacks to them on initial load.

Fix:
  • pc-live-feed, pc-line-count, pc-kpi-row, pc-status-badge, pc-elapsed-timer
    are ALL static elements in the layout (always in the DOM).
  • pc-tab-content is ONLY updated with the rotating tab panels
    (gauge, findings, Nmap, BloodHound — or AI, or History).
  • The live feed sits in a permanent left column, tab panels on the right.
"""

from __future__ import annotations

import plotly.graph_objects as go
from dash import html, dcc, callback, ctx, no_update
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
import dash_cytoscape as cyto

from cyber_range.services.scan_orchestrator import ScanOrchestrator, ScanParams

# ── Neo4j connection (reuse creds from neo4j_integration.py) ─────────────────
_NEO4J_URI  = "bolt://localhost:7687"
_NEO4J_USER = "neo4j"
_NEO4J_PASS = "Adomaa12@"

def _fetch_bh_elements() -> list:
    """Query BloodHound-ingested Neo4j data and return cytoscape elements."""
    try:
        from neo4j import GraphDatabase  # type: ignore
        driver = GraphDatabase.driver(_NEO4J_URI,
                                      auth=(_NEO4J_USER, _NEO4J_PASS))
        elements = []
        with driver.session() as s:
            # ── Nodes (BloodHound labels) ────────────────────────────────
            rows = s.run("""
                MATCH (n)
                WHERE any(lbl IN labels(n)
                          WHERE lbl IN ['User','Group','Computer','Domain','GPO','OU'])
                RETURN id(n) AS nid,
                       labels(n)      AS lbls,
                       properties(n)  AS props
                LIMIT 300
            """)
            for r in rows:
                props  = dict(r["props"])
                labels = r["lbls"]
                lbl    = (labels[0] if labels else "Node")
                name   = (props.get("name") or props.get("samaccountname")
                          or props.get("id") or str(r["nid"]))
                elements.append({"data": {
                    "id":    str(r["nid"]),
                    "label": name,
                    "type":  lbl,
                    "enabled": props.get("enabled", True),
                    **{k: str(v)[:120] for k, v in props.items()},
                }})

            # ── Relationships ────────────────────────────────────────────
            rels = s.run("""
                MATCH (a)-[r]->(b)
                WHERE any(lbl IN labels(a)
                          WHERE lbl IN ['User','Group','Computer','Domain','GPO','OU'])
                  AND any(lbl IN labels(b)
                          WHERE lbl IN ['User','Group','Computer','Domain','GPO','OU'])
                RETURN id(a) AS src, id(b) AS dst,
                       type(r) AS rel_type
                LIMIT 600
            """)
            # Risk-colour mapping for edge types
            _RISK = {
                "GenericAll": "#e74c3c", "DCSync": "#e74c3c",
                "WriteDACL":  "#e67e22", "Owns": "#e67e22",
                "AllExtendedRights": "#e67e22", "WriteOwner": "#e67e22",
                "GenericWrite": "#f39c12", "ForceChangePassword": "#f39c12",
                "AdminTo": "#3498db",     "HasSession": "#2ecc71",
                "MemberOf": "#95a5a6",   "Contains": "#555",
            }
            for r in rels:
                rt = r["rel_type"]
                elements.append({"data": {
                    "source": str(r["src"]),
                    "target": str(r["dst"]),
                    "label":  rt,
                    "color":  _RISK.get(rt, "#555"),
                }})
        driver.close()
        return elements
    except Exception as exc:
        return [{"data": {"id": "err", "label": f"Neo4j: {exc}", "type": "Error"}}]


# ── BloodHound-style Cytoscape stylesheet ────────────────────────────────────
_BH_STYLESHEET = [
    # Default node — bigger so it's always clickable
    {"selector": "node",
     "style": {"label": "data(label)", "font-size": "9px",
               "color": "#e0e0e0", "text-valign": "bottom",
               "text-margin-y": "5px", "width": "40px", "height": "40px",
               "border-width": "2px", "border-color": "#333",
               "cursor": "pointer"}},
    # Node types — BloodHound color scheme
    {"selector": "node[type='User']",
     "style": {"background-color": "#17a488", "shape": "ellipse"}},
    {"selector": "node[type='Group']",
     "style": {"background-color": "#e67e22", "shape": "pentagon",
               "width": "44px", "height": "44px"}},
    {"selector": "node[type='Computer']",
     "style": {"background-color": "#2980b9", "shape": "rectangle",
               "width": "44px", "height": "44px"}},
    {"selector": "node[type='Domain']",
     "style": {"background-color": "#e74c3c", "shape": "diamond",
               "width": "54px", "height": "54px"}},
    {"selector": "node[type='GPO']",
     "style": {"background-color": "#8e44ad", "shape": "hexagon",
               "width": "42px", "height": "42px"}},
    {"selector": "node[type='OU']",
     "style": {"background-color": "#16a085", "shape": "tag",
               "width": "42px", "height": "42px"}},
    {"selector": "node[type='Error']",
     "style": {"background-color": "#c0392b", "color": "#fff",
               "font-size": "11px", "width": "200px", "shape": "round-rectangle",
               "text-wrap": "wrap", "text-max-width": "180px"}},
    # Selected / hover
    {"selector": "node:selected",
     "style": {"border-color": "#42b9f5", "border-width": "4px",
               "background-opacity": "1"}},
    {"selector": "node:active",
     "style": {"overlay-color": "#42b9f5", "overlay-padding": "5px",
               "overlay-opacity": "0.3"}},
    # Edges
    {"selector": "edge",
     "style": {"label": "data(label)", "font-size": "8px",
               "color": "#aaa", "text-rotation": "autorotate",
               "line-color": "data(color)",
               "target-arrow-color": "data(color)",
               "target-arrow-shape": "triangle",
               "curve-style": "bezier", "width": "1.5px",
               "text-background-color": "#0d0e14",
               "text-background-opacity": "0.7",
               "text-background-padding": "2px"}},
    # High-risk edge highlight
    {"selector": "edge[label='GenericAll']",
     "style": {"line-color": "#e74c3c", "width": "2.5px",
               "target-arrow-color": "#e74c3c"}},
    {"selector": "edge[label='DCSync']",
     "style": {"line-color": "#e74c3c", "width": "2.5px",
               "target-arrow-color": "#e74c3c", "line-style": "dashed"}},
]



# ── Click callback — registered at module load ───────────────────────────────
@callback(
    Output("pc-bh-node-detail", "children"),
    Input("pc-bh-graph",        "tapNodeData"),
    prevent_initial_call=True,
)
def _bh_node_detail(data):
    """Show node detail panel when a node is clicked."""
    if not data:
        return ""
    ntype = data.get("type", "?")
    name  = data.get("label", data.get("id", "?"))
    _COL  = {"User":"#17a488","Group":"#e67e22","Computer":"#2980b9",
             "Domain":"#e74c3c","GPO":"#8e44ad","OU":"#16a085"}
    col   = _COL.get(ntype, "#42b9f5")

    skip  = {"id","label","type","color"}
    rows  = []
    for k, v in data.items():
        if k in skip or not v or v == "None":
            continue
        rows.append(html.Tr([
            html.Td(k,  style={"color":"#888","fontSize":"10px","paddingRight":"8px"}),
            html.Td(str(v)[:80], style={"color":"#e0e0e0","fontSize":"10px"}),
        ]))

    return html.Div([
        html.Div([
            html.Span(ntype, style={"background": col, "color":"#fff",
                                    "padding":"2px 8px", "borderRadius":"4px",
                                    "fontSize":"10px", "fontWeight":"700"}),
            html.Span(f"  {name}",
                      style={"color":"#e0e0e0","fontWeight":"700","fontSize":"13px",
                             "marginLeft":"8px"}),
        ], style={"marginBottom":"8px"}),
        html.Table(rows, style={"width":"100%", "borderCollapse":"collapse"}),
    ], style={"padding":"10px","background":"#13172a","borderRadius":"8px",
              "border":"1px solid #1e2230"})


# ── Knowledge base for chart click explanations ───────────────────────────────
_CHART_KB = {
    # ── Severity Pie ─────────────────────────────────────────────────────────
    "sev": {
        "Critical": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "Critical findings require immediate attention. These represent actively exploitable vulnerabilities or misconfigurations that give an attacker direct control over AD.",
            "leads_to": "Domain Admin compromise, DCSync, Golden Ticket attacks, persistent backdoors.",
            "hosts": "Domain Controllers, privileged service accounts, Domain Admin workstations.",
            "fix": "Patch immediately. Restrict privileged group membership. Enable Protected Users security group.",
        },
        "High": {
            "risk": "High", "color": "#e67e22",
            "what": "High severity findings are serious misconfigurations attackers commonly exploit during lateral movement or privilege escalation.",
            "leads_to": "Kerberoasting, lateral movement to servers, pass-the-hash attacks.",
            "hosts": "Member servers, service accounts, computers with unconstrained delegation.",
            "fix": "Remediate within 7 days. Audit service account SPNs. Disable NTLM where possible.",
        },
        "Medium": {
            "risk": "Medium", "color": "#f39c12",
            "what": "Medium findings increase the attack surface and are often leveraged during post-exploitation to escalate privileges.",
            "leads_to": "Password spraying, AS-REP Roasting, privilege escalation through misconfigured ACLs.",
            "hosts": "Workstations, low-privilege user accounts, OUs with weak GPO settings.",
            "fix": "Remediate within 30 days. Enforce strong password policies and account lockout.",
        },
        "Info": {
            "risk": "Low", "color": "#42b9f5",
            "what": "Informational findings represent best-practice deviations that don't pose immediate risk but reduce overall security posture.",
            "leads_to": "Reconnaissance data that aids attackers in mapping the environment.",
            "hosts": "General AD infrastructure — all computers and users.",
            "fix": "Address during scheduled hardening cycles. Follow CIS Benchmarks for AD.",
        },
    },
    # ── Category Bar ─────────────────────────────────────────────────────────
    "cat": {
        "Kerberos": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "Kerberos misconfigurations include Kerberoastable accounts, unconstrained delegation, and AS-REP Roasting vulnerabilities.",
            "leads_to": "Offline password cracking of service account tickets → lateral movement → DA.",
            "hosts": "Service accounts with SPNs (e.g., svc_backup, svc_sql), DCs running KDC.",
            "fix": "Use Managed Service Accounts (MSA/gMSA). Set accounts to require pre-auth. Remove unnecessary SPNs.",
        },
        "Delegation": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "Unconstrained / resource-based constrained delegation allows a computer or service to impersonate ANY user.",
            "leads_to": "Full domain compromise — attacker can forge tickets as any user including krbtgt.",
            "hosts": "Computers with 'Trust for delegation' set, IIS/SQL servers in DMZ.",
            "fix": "Audit delegation with: Get-ADComputer -Filter {TrustedForDelegation -eq $true}. Switch to constrained delegation.",
        },
        "Network": {
            "risk": "High", "color": "#e67e22",
            "what": "Network exposure findings cover critical AD ports (88/Kerberos, 389/LDAP, 445/SMB) accessible from unexpected segments.",
            "leads_to": "LDAP enumeration, SMB relay attacks, Kerberos brute-force from untrusted networks.",
            "hosts": "Domain Controllers (EXPEDITE-DC), member servers exposing AD services.",
            "fix": "Segment AD traffic. Block SMB/LDAP from user VLANs to DCs. Enable SMB signing.",
        },
        "Accounts": {
            "risk": "High", "color": "#e67e22",
            "what": "Account hygiene issues: stale accounts, accounts with non-expiring passwords, or accounts in excessive groups.",
            "leads_to": "Compromised dormant accounts give persistent access. Over-privileged accounts escalate quickly.",
            "hosts": "expedite.local — disabled but still-enabled accounts, HR/contractor accounts.",
            "fix": "Run quarterly access reviews. Auto-disable accounts inactive > 90 days. Enforce MFA on all accounts.",
        },
        "GPO": {
            "risk": "High", "color": "#e67e22",
            "what": "Group Policy misconfigurations allow attackers to push malicious policies or bypass security controls.",
            "leads_to": "Disable Windows Defender, add backdoor local admins, modify audit policies.",
            "hosts": "All computers in the expedite.local domain applying affected GPOs.",
            "fix": "Audit GPO permissions. Restrict GPO edit rights. Enable GPO versioning and alerting.",
        },
        "ACEs/DACL": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "ACE/DACL abuse is the most powerful attack vector in AD. GenericAll, WriteDACL, and WriteOwner rights allow full object takeover.",
            "leads_to": "Reset target account passwords, add members to Domain Admins, forge tickets.",
            "hosts": "Objects held by: john.doe, helpdesk group, IT-Admins — targeting EXPEDITE-DC.",
            "fix": "Run BloodHound regularly. Remove non-standard ACEs from AD objects. Use tiered admin model.",
        },
        "Identity": {
            "risk": "Medium", "color": "#f39c12",
            "what": "Identity governance issues include orphaned accounts, SID history abuse, and duplicate SPNs.",
            "leads_to": "SID history injection for privilege escalation. Orphaned accounts as persistent footholds.",
            "hosts": "Migrated accounts from legacy domains, recently departed employees.",
            "fix": "Audit SID history. Remove orphaned accounts. Implement Identity Governance (IGA) solution.",
        },
    },
    # ── Risk Trend ────────────────────────────────────────────────────────────
    "trend": {
        "Baseline": {
            "risk": "High", "color": "#e67e22",
            "what": "Baseline score when monitoring began. Score of 88 indicates a high-risk AD environment with multiple critical misconfigurations.",
            "leads_to": "Multiple attack paths to Domain Admin existed. High probability of breach.",
            "hosts": "Entire expedite.local domain — EXPEDITE-DC and all 27 member computers.",
            "fix": "Compare against ADCS/ADDS hardening benchmarks. Use Ægis AD Analytic Scanner weekly.",
        },
        "Week 1": {
            "risk": "High", "color": "#e67e22",
            "what": "Score reduced to 79 after initial remediation sprint — Kerberoastable accounts reduced and SMB signing enforced.",
            "leads_to": "Fewer attack paths remain but DCSync rights still exist outside DA group.",
            "hosts": "Service accounts cleaned: svc_backup, svc_old, svc_legacy.",
            "fix": "Continue hardening. Focus on delegation and ACL cleanup next.",
        },
        "Week 2": {
            "risk": "Medium", "color": "#f39c12",
            "what": "Score reduced to 75. Delegation issues resolved, several WriteDACL ACEs removed. Still above target of 30.",
            "leads_to": "Residual risk from shadow admin (svc_monitor) and GPO misconfiguration.",
            "hosts": "EXPEDITE-DC — schema admin ACE still present. IT-Admins group still over-privileged.",
            "fix": "Target remaining ACE/DACL findings. Implement PAM solution for privileged accounts.",
        },
        "Current": {
            "risk": "High", "color": "#e67e22",
            "what": "Current unified risk score from live correlation of Ægis AD Analytic Scanner + BloodHound + Nmap findings.",
            "leads_to": "Active attack paths still exist. Recommend immediate remediation of Critical findings.",
            "hosts": "expedite.local — EXPEDITE-DC is the primary target. 27 computers at risk.",
            "fix": "Focus on top 3 critical findings. Achieve score < 30 for acceptable posture.",
        },
    },
    # ── Accounts Doughnut ─────────────────────────────────────────────────────
    "acc": {
        "Secure": {
            "risk": "Low", "color": "#27ae60",
            "what": "Accounts with MFA enabled, compliant password policy, and appropriate group membership. These are your protected accounts.",
            "leads_to": "No immediate risk. Keep monitoring for privilege creep.",
            "hosts": "Standard user workstations in expedite.local.",
            "fix": "Maintain controls. Review quarterly for privilege accumulation.",
        },
        "No MFA": {
            "risk": "High", "color": "#e74c3c",
            "what": "6 accounts have no MFA enrolled. Password alone is the only protection — vulnerable to phishing and credential stuffing.",
            "leads_to": "Phishing → account takeover → lateral movement if account has Any admin rights.",
            "hosts": "Accounts: john.doe, svc_monitor, HR accounts accessing sensitive shares.",
            "fix": "Enforce MFA immediately via Conditional Access or GPO. Prioritise admin accounts.",
        },
        "Shadow Admin": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "Shadow admins have effective Domain Admin rights through ACL paths but are NOT in the Domain Admins group — making them invisible to standard monitoring.",
            "leads_to": "Full domain compromise. Attacker can reset DA passwords, DCSync, create Golden Tickets.",
            "hosts": "svc_monitor has AllExtendedRights on EXPEDITE-DC.",
            "fix": "Immediately remove svc_monitor from any ACE granting rights on DC/Domain objects. Audit with BloodHound.",
        },
        "Schema Admin": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "Schema Admin membership allows permanent, irreversible changes to the AD schema — one of the highest privileges in a domain.",
            "leads_to": "Planting persistent backdoors in schema. Very hard to detect and remediate.",
            "hosts": "expedite.local Schema — any Schema Admin can modify all 142 user objects.",
            "fix": "Remove ALL accounts from Schema Admins. Only add temporarily when schema changes are needed.",
        },
        "Kerberoastable": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "7 accounts have SPNs registered and can have their Kerberos service tickets requested and cracked offline — no special privileges needed to initiate.",
            "leads_to": "Offline cracking → plaintext password → lateral movement → if any account is admin, DA path exists.",
            "hosts": "svc_backup, svc_sql, svc_web — all have admin rights on member servers.",
            "fix": "Use gMSA for service accounts. Set 127-char passwords for all SPN accounts. Monitor TGS requests.",
        },
    },
    # ── Hygiene Stacked Bar ───────────────────────────────────────────────────
    "hyg": {
        "Password Policy": {
            "risk": "High", "color": "#e67e22",
            "what": "AD password policy controls minimum length, complexity, and expiry. Weak policy enables brute-force and credential stuffing.",
            "leads_to": "Password spraying → account lockout bypass → valid credentials for lateral movement.",
            "hosts": "All 142 user accounts in expedite.local.",
            "fix": "Set minimum 14 chars. Enable Fine-Grained Password Policy for admins (20+ chars). Block common passwords.",
        },
        "Inactive Accounts": {
            "risk": "Medium", "color": "#f39c12",
            "what": "Accounts that haven't logged in for 90+ days but remain enabled. These are unused attack surfaces.",
            "leads_to": "Compromised dormant account used as persistent foothold — no legitimate owner to notice.",
            "hosts": "Stale accounts in: HR OU, Contractors OU, Legacy-Computers OU.",
            "fix": "Disable accounts inactive > 90 days. Delete after 180 days. Use automation (PowerShell/script).",
        },
        "Privileged Groups": {
            "risk": "Critical", "color": "#e74c3c",
            "what": "Over-populated privileged groups (Domain Admins, Enterprise Admins, Administrators) expand the blast radius of any compromise.",
            "leads_to": "Every extra DA member is another attack vector. Compromise of ANY DA member = full domain.",
            "hosts": "Domain Admins group — currently has members beyond standard admin accounts.",
            "fix": "Apply principle of least privilege. Use tiered administration model (Tier 0/1/2). PAM for DA access.",
        },
        "Audit Policy": {
            "risk": "Medium", "color": "#f39c12",
            "what": "Missing or incomplete audit policies mean attacker activity goes undetected. No visibility = no detection.",
            "leads_to": "Kerberoasting, DCSync, lateral movement all proceed without any log evidence.",
            "hosts": "EXPEDITE-DC — audit logs not forwarded to SIEM. Event 4769 not monitored.",
            "fix": "Enable Advanced Audit Policy. Forward logs to SIEM. Alert on Event IDs: 4771, 4769, 4624, 4648.",
        },
        "LAPS": {
            "risk": "High", "color": "#e67e22",
            "what": "Without LAPS (Local Administrator Password Solution), all computers share the same local admin password — one credential compromise = all computers compromised.",
            "leads_to": "Pass-the-hash with shared local admin credential → lateral movement across all 27 computers.",
            "hosts": "All 27 computers in expedite.local not enrolled in LAPS.",
            "fix": "Deploy LAPS immediately. Rotate all local admin passwords after deployment.",
        },
        "SMB Signing": {
            "risk": "High", "color": "#e67e22",
            "what": "Without SMB signing enforced, SMB relay attacks allow an attacker to relay captured credentials to any other host.",
            "leads_to": "NTLM relay → remote code execution on any non-signing host without knowing any password.",
            "hosts": "All non-DC computers in expedite.local (DCs enforce signing by default).",
            "fix": "GPO: Network security: Microsoft network server: Digitally sign communications (always) = Enabled.",
        },
    },
}

def _make_click_detail(label: str, kb_section: str) -> html.Div:
    """Build the rich click-detail card from the knowledge base."""
    kb = _CHART_KB.get(kb_section, {})
    entry = kb.get(label) or kb.get(
        next((k for k in kb if k.lower() in label.lower()), None), None)
    if not entry:
        return html.Div(f"No detail available for '{label}'.",
                        style={"color": "#666", "fontStyle": "italic",
                               "padding": "12px"})

    risk_col = entry.get("color", "#888")
    return html.Div([
        # Header
        html.Div([
            html.Span(entry["risk"], style={
                "background": risk_col, "color": "#fff",
                "padding": "3px 10px", "borderRadius": "4px",
                "fontSize": "11px", "fontWeight": "800", "marginRight": "10px"}),
            html.Span(label, style={"color": "#e0e0e0", "fontWeight": "700",
                                    "fontSize": "14px"}),
        ], style={"marginBottom": "10px"}),
        # 4 info rows
        *[html.Div([
            html.Span(title, style={"color": "#888", "fontSize": "10px",
                                    "fontWeight": "700", "textTransform": "uppercase",
                                    "letterSpacing": "0.5px", "display": "block",
                                    "marginBottom": "2px"}),
            html.Span(body, style={"color": "#ccc", "fontSize": "11px",
                                   "lineHeight": "1.6"}),
        ], style={"marginBottom": "10px"})
        for title, body in [
            ("📌 What it means", entry.get("what", "")),
            ("⚔️  Attack outcome", entry.get("leads_to", "")),
            ("🖥️  Affected hosts", entry.get("hosts", "")),
            ("🛠️  Remediation",    entry.get("fix",  "")),
        ]],
    ], style={"padding": "14px 16px", "background": "#0e1120",
              "borderLeft": f"3px solid {risk_col}",
              "borderRadius": "8px", "border": f"1px solid {risk_col}33"})


# ── Unified 5-chart click callback ────────────────────────────────────────────
@callback(
    Output("pc-graph-click-detail", "children"),
    Input("pc-g-sev",   "clickData"),
    Input("pc-g-cat",   "clickData"),
    Input("pc-g-trend", "clickData"),
    Input("pc-g-acc",   "clickData"),
    Input("pc-g-hyg",   "clickData"),
    prevent_initial_call=True,
)
def _chart_click(sev_cd, cat_cd, trend_cd, acc_cd, hyg_cd):
    """Show rich explanation when any chart segment/bar/point is clicked."""
    triggered = ctx.triggered_id
    mapping   = {
        "pc-g-sev":   (sev_cd,   "sev"),
        "pc-g-cat":   (cat_cd,   "cat"),
        "pc-g-trend": (trend_cd, "trend"),
        "pc-g-acc":   (acc_cd,   "acc"),
        "pc-g-hyg":   (hyg_cd,   "hyg"),
    }
    click_data, kb_key = mapping.get(triggered, (None, None))
    if not click_data or not kb_key:
        return no_update

    pts   = click_data.get("points", [{}])
    label = (pts[0].get("label") or pts[0].get("x") or
             pts[0].get("y") or str(pts[0].get("customdata", "?")))

    card = _make_click_detail(str(label), kb_key)
    return html.Div([
        html.Div([
            html.Span("ℹ️ Chart Detail",
                      style={"color": "#42b9f5", "fontWeight": "700", "fontSize": "12px"}),
            html.Span("  — click anywhere else to dismiss",
                      style={"color": "#444", "fontSize": "10px"}),
        ], style={"padding": "6px 14px", "borderBottom": "1px solid #1e2230",
                  "background": "#0d0e14"}),
        html.Div(card, style={"padding": "10px 14px"}),
    ], style={"background": "#0d0e14", "border": "1px solid #1e2230",
              "borderRadius": "10px", "marginTop": "6px"})



# ── Theme ──────────────────────────────────────────────────────────────────────
BG      = "#0d0e14"
CARD    = "#111420"
CARD2   = "#13172a"
BORDER  = "1px solid #1e2230"
CYAN    = "#42b9f5"
GREEN   = "#22c55e"
RED     = "#f54254"
ORANGE  = "#f5a742"
YELLOW  = "#f5e642"
TEXT    = "#a2a5b5"
INPUT_S = {"background": "#1a1d28", "border": BORDER, "color": "#e0e0e0",
           "borderRadius": "6px", "fontSize": "13px"}
LABEL_S = {"color": TEXT, "fontSize": "10px", "fontWeight": "700",
           "textTransform": "uppercase", "letterSpacing": "0.5px", "marginBottom": "3px"}
SEV_COL = {"Critical": RED, "High": ORANGE, "Medium": YELLOW,
           "Info": CYAN, "Low": GREEN}
RISK_COL= {"D": RED, "C": ORANGE, "B": YELLOW, "A": GREEN, "A+": CYAN, "Unknown": "#333"}
CARD_S  = {"background": CARD, "border": BORDER, "borderRadius": "10px"}
TAB_S   = {"backgroundColor": "transparent", "border": "none",
           "color": TEXT, "fontSize": "12px"}
SEL_S   = {"backgroundColor": CARD2, "border": BORDER,
           "color": "#fff", "fontSize": "12px", "borderRadius": "6px 6px 0 0"}


# ─── Static layout — all callback Output IDs must live here ───────────────────
def layout_pingcastle_live() -> html.Div:
    return html.Div([
        dcc.Interval(id="pc-live-timer", interval=1500, n_intervals=0),

        # ── Header ─────────────────────────────────────────────────────────────
        html.Div([
            html.Div([
                html.H3("🛡️ Ægis AD Analytic Scanner — Assessment Dashboard",
                        style={"color": "#fff", "fontWeight": "800",
                               "margin": "0", "fontSize": "17px"}),
                html.Div("Ægis AD Analytic Scanner · Nmap · BloodHound → Scoring → AI → History",
                         style={"color": TEXT, "fontSize": "11px", "marginTop": "2px"}),
            ], style={"flex": "1"}),
            html.Div([
                # ★ STATIC — callback Output targets these directly
                dbc.Badge("IDLE", id="pc-status-badge", color="secondary",
                          style={"fontSize": "11px", "padding": "5px 12px",
                                 "marginRight": "8px", "fontWeight": "700"}),
                html.Code("", id="pc-elapsed-timer",
                          style={"color": TEXT, "fontSize": "11px",
                                 "fontFamily": "monospace", "marginRight": "10px"}),
                dbc.Button("🔄 Reset", id="pc-clear-btn", color="secondary",
                           size="sm", outline=True, style={"fontSize": "10px"}),
            ], style={"display": "flex", "alignItems": "center"}),
        ], style={"display": "flex", "alignItems": "center",
                  "padding": "14px 24px 8px", "borderBottom": BORDER,
                  "background": CARD}),

        dbc.Container([

            # ── Target / Credential Config ──────────────────────────────────────
            dbc.Card([dbc.CardBody([
                html.Div("🎯 Target Configuration",
                         style={"color": CYAN, "fontWeight": "700", "fontSize": "11px",
                                "marginBottom": "10px", "textTransform": "uppercase",
                                "letterSpacing": "0.5px"}),
                dbc.Row([
                    dbc.Col([html.Div("DC IP",           style=LABEL_S),
                             dbc.Input(id="pc-dc-ip",   value="192.168.1.10", style=INPUT_S)], width=2),
                    dbc.Col([html.Div("Domain (FQDN)",  style=LABEL_S),
                             dbc.Input(id="pc-domain",  value="expedite.local",   style=INPUT_S)], width=2),
                    dbc.Col([html.Div("Username",        style=LABEL_S),
                             dbc.Input(id="pc-username", value="Administrator", style=INPUT_S)], width=2),
                    dbc.Col([html.Div("Password",        style=LABEL_S),
                             dbc.Input(id="pc-password", type="password",
                                       value="Adomaa12@", style=INPUT_S)], width=1),
                    dbc.Col([html.Div("Ægis AD Scanner.exe",  style=LABEL_S),
                             dbc.Input(id="pc-exe-path",
                                       value="/home/kali/Downloads/PingCastle_3.5.0.44/PingCastle.exe",
                                       style=INPUT_S)], width=2),
                    dbc.Col([html.Div("SharpHound.exe",  style=LABEL_S),
                             dbc.Input(id="pc-bh-path",
                                       value="/home/kali/Downloads/SharpHound.exe",
                                       style=INPUT_S)], width=2),
                    dbc.Col([html.Div("Extra IPs",       style=LABEL_S),
                             dbc.Input(id="pc-extra-domains",
                                       placeholder="10.0.0.5, 10.0.1.10",
                                       style=INPUT_S)], width=1),
                ], className="g-2 mb-2"),
                dbc.Row([
                    dbc.Col([
                        dbc.Checklist(
                            id="pc-tool-toggles",
                            options=[
                                {"label": "  🛡️ Ægis AD Analytic Scanner", "value": "ping"},
                                {"label": "  🗺️ Nmap",       "value": "nmap"},
                                {"label": "  🩸 BloodHound", "value": "blood"},
                                {"label": "  🧠 AI Report",  "value": "ai"},
                            ],
                            value=["ping", "nmap", "blood", "ai"],
                            inline=True,
                            style={"color": TEXT, "fontSize": "12px"},
                        ),
                    ], width="auto", className="d-flex align-items-center"),
                    dbc.Col([
                        dbc.Button("▶ Run All Scans", id="pc-run-btn",
                                   color="danger", size="sm",
                                   style={"fontWeight": "700", "fontSize": "13px",
                                          "paddingLeft": "22px", "paddingRight": "22px",
                                          "boxShadow": f"0 0 16px {RED}55"}),
                    ], width="auto"),
                ], align="center"),
            ], style={"padding": "12px 16px"})],
                style={**CARD_S, "marginTop": "14px", "marginBottom": "12px",
                       "background": CARD2}),

            # ── Main body: STATIC live feed (left) + tab panels (right) ─────────
            dbc.Row([

                # LEFT: permanent live feed (always in DOM — required for callback Output)
                dbc.Col([
                    html.Div([
                        html.Div([
                            html.Span("📡 Live Activity Feed",
                                      style={"color": CYAN, "fontWeight": "700",
                                             "fontSize": "11px"}),
                            # ★ STATIC
                            html.Span("", id="pc-line-count",
                                      style={"color": "#444", "fontSize": "10px",
                                             "marginLeft": "8px"}),
                        ], style={"padding": "10px 14px", "borderBottom": BORDER,
                                  "display": "flex", "alignItems": "center"}),
                        # ★ STATIC — callback writes here directly
                        html.Div("",
                                 id="pc-live-feed",
                                 style={"height": "460px",
                                        "overflowY": "auto",
                                        "padding": "10px 14px",
                                        "fontFamily": "monospace",
                                        "fontSize": "10.5px",
                                        "lineHeight": "1.7",
                                        "backgroundColor": "#060810",
                                        "color": "#b0e0ff",
                                        "whiteSpace": "pre-wrap",
                                        "wordBreak": "break-all"}),
                    ], style=CARD_S),

                    html.Div(style={"height": "10px"}),
                    # ★ STATIC KPI row
                    html.Div("", id="pc-kpi-row",
                             style={"display": "flex"}),
                    # ★ STATIC KPI drill-down panel
                    html.Div("", id="pc-kpi-detail",
                             style={"marginTop": "8px"}),
                ], width=4),

                # RIGHT: rotating tab panels
                dbc.Col([
                    dbc.Tabs([
                        dbc.Tab(label="📊 Dashboard",    tab_id="pc-tab-dash",
                                tab_style=TAB_S, active_tab_style=SEL_S),
                        dbc.Tab(label="🧠 AI Report",   tab_id="pc-tab-ai",
                                tab_style=TAB_S, active_tab_style=SEL_S),
                        dbc.Tab(label="📂 History",      tab_id="pc-tab-hist",
                                tab_style=TAB_S, active_tab_style=SEL_S),
                        dbc.Tab(label="📊 Graphs",       tab_id="pc-tab-graph",
                                tab_style=TAB_S, active_tab_style=SEL_S),
                        dbc.Tab(label="📄 HTML Report",  tab_id="pc-tab-report",
                                tab_style=TAB_S, active_tab_style=SEL_S),
                    ], id="pc-main-tabs", active_tab="pc-tab-dash",
                       style={"borderBottom": BORDER}),
                    # ★ STATIC container — callback Output updates children
                    html.Div("", id="pc-tab-content",
                             style={"paddingTop": "10px"}),
                    # ★ STATIC chart-click detail panel (populated by click callbacks)
                    html.Div("", id="pc-graph-click-detail",
                             style={"marginTop": "8px"}),
                ], width=8),

            ], className="mb-4"),

        ], fluid=True, style={"padding": "0 20px"}),
    ], style={"background": BG, "minHeight": "100vh"})


# ─── Main Callback ─────────────────────────────────────────────────────────────
# All Output IDs are guaranteed to exist in the static layout above.
@callback(
    Output("pc-status-badge",  "children"),
    Output("pc-status-badge",  "color"),
    Output("pc-elapsed-timer", "children"),
    Output("pc-live-feed",     "children"),   # ★ static
    Output("pc-line-count",    "children"),   # ★ static
    Output("pc-kpi-row",       "children"),   # ★ static
    Output("pc-tab-content",   "children"),   # rotating tab panels
    Input("pc-live-timer",     "n_intervals"),
    Input("pc-run-btn",        "n_clicks"),
    Input("pc-clear-btn",      "n_clicks"),
    Input("pc-main-tabs",      "active_tab"),
    State("pc-dc-ip",          "value"),
    State("pc-domain",         "value"),
    State("pc-username",       "value"),
    State("pc-password",       "value"),
    State("pc-exe-path",       "value"),
    State("pc-bh-path",        "value"),
    State("pc-extra-domains",  "value"),
    State("pc-tool-toggles",   "value"),
    prevent_initial_call=False,
)
def update_dashboard(n_int, run_n, clear_n, active_tab,
                     dc_ip, domain, username, password,
                     pc_exe, bh_exe, extra_str, toggles):

    trigger = ctx.triggered_id if ctx.triggered_id else "pc-live-timer"

    # ── Reset ──────────────────────────────────────────────────────────────────
    if trigger == "pc-clear-btn":
        ScanOrchestrator.reset()
        return ("IDLE", "secondary", "",
                _empty_feed_item(), "0 lines", "",
                _dashboard_panels(ScanOrchestrator.get_session()))

    # ── Launch ─────────────────────────────────────────────────────────────────
    if trigger == "pc-run-btn" and run_n:
        toggles = toggles or ["ping", "nmap", "blood", "ai"]
        extras  = [e.strip() for e in (extra_str or "").split(",") if e.strip()]
        ScanOrchestrator.start(ScanParams(
            dc_ip          = dc_ip     or "192.168.1.10",
            domain         = domain    or "corp.local",
            username       = username  or "Administrator",
            password       = password  or "",
            pc_exe         = pc_exe    or r"C:\Tools\PingCastle\PingCastle.exe",
            bh_exe         = bh_exe    or r"C:\Tools\SharpHound\SharpHound.exe",
            extra_domains  = extras,
            run_ping       = "ping"  in toggles,
            run_nmap       = "nmap"  in toggles,
            run_blood      = "blood" in toggles,
            run_ai         = "ai"    in toggles,
        ))

    # ── Read current session ────────────────────────────────────────────────────
    sess  = ScanOrchestrator.get_session()
    lines = list(sess.log)

    badge_txt, badge_col = (
        ("🔴 RUNNING",  "danger")  if sess.running else
        ("✅ COMPLETE", "success") if sess.done and not sess.error else
        ("❌ ERROR",    "warning") if sess.done and sess.error else
        ("IDLE",        "secondary")
    )

    feed_children = ([_colour_line(l) for l in lines]
                     if lines else [_empty_feed_item()])

    # Tab panels — skip re-rendering graph on plain timer ticks
    # (prevents Cytoscape node dancing + detail panel reset)
    if active_tab == "pc-tab-graph" and trigger == "pc-live-timer":
        tab_content = no_update
    elif active_tab == "pc-tab-ai":
        tab_content = _ai_panel(sess)
    elif active_tab == "pc-tab-hist":
        tab_content = _history_panel()
    elif active_tab == "pc-tab-report":
        tab_content = _report_panel(sess)
    elif active_tab == "pc-tab-graph":
        tab_content = _graph_panel(sess)
    else:
        tab_content = _dashboard_panels(sess)

    return (
        badge_txt, badge_col,
        sess.elapsed,
        feed_children,
        f"{len(lines)} lines",
        _build_kpis(sess),
        tab_content,
    )


import glob as _glob
import os as _os
import math as _math


# ─────────────────────────────────────────────────────────────────────────────
# GRAPH PANEL — D3-style force-directed attack graph via Plotly
# ─────────────────────────────────────────────────────────────────────────────
_NODE_COLORS = {
    "DC":       "#e74c3c",   # red
    "User":     "#3498db",   # blue
    "Group":    "#e67e22",   # orange
    "Computer": "#27ae60",   # green
    "GPO":      "#9b59b6",   # purple
    "Domain":   "#c0392b",   # dark red
}
_EDGE_COLORS = {
    "GenericAll":      "#e74c3c",
    "WriteDACL":       "#e74c3c",
    "GenericWrite":    "#e67e22",
    "Kerberoastable":  "#e67e22",
    "DCSync":          "#c0392b",
    "WriteOwner":      "#f39c12",
    "AllExtendedRights": "#9b59b6",
    "MemberOf":        "#3498db",
}


def _graph_panel(sess) -> html.Div:
    """Multi-chart analytics panel — 6 sub-tabs, all Plotly."""
    import plotly.graph_objects as go

    # ── Pull real data from session where available ───────────────────────
    res = sess.result if (sess and hasattr(sess, "result") and sess.result) else None

    # Severity counts
    findings = res.findings if res else []
    sev_counts = {s: sum(1 for f in findings if f.severity == s)
                  for s in ("Critical", "High", "Medium", "Info")}
    if not any(sev_counts.values()):
        sev_counts = {"Critical": 3, "High": 4, "Medium": 3, "Info": 2}

    # Attack paths
    raw_paths = []
    if res and res.attack_paths:
        for ap in res.attack_paths:
            raw_paths.append({"src": ap.source, "tgt": ap.target,
                               "rel": ap.relationship, "risk": ap.risk})
    demo_paths = [
        {"src": "john.doe",    "rel": "Kerberoastable",   "tgt": "svc_backup",            "risk": "High"},
        {"src": "svc_backup",  "rel": "GenericAll",        "tgt": "Domain Admins",         "risk": "Critical"},
        {"src": "helpdesk",    "rel": "WriteDACL",         "tgt": "EXPEDITE-DC",           "risk": "Critical"},
        {"src": "EXPEDITE-DC", "rel": "DCSync",            "tgt": "Domain Admins",         "risk": "Critical"},
        {"src": "svc_monitor", "rel": "AllExtendedRights", "tgt": "EXPEDITE-DC",           "risk": "Critical"},
        {"src": "IT-Admins",   "rel": "WriteOwner",        "tgt": "Default Domain Policy", "risk": "Medium"},
        {"src": "john.doe",    "rel": "MemberOf",          "tgt": "IT-Admins",             "risk": "Info"},
        {"src": "svc_monitor", "rel": "MemberOf",          "tgt": "IT-Admins",             "risk": "Info"},
    ]
    all_paths  = raw_paths if raw_paths else demo_paths
    source_note = "Live BloodHound data" if raw_paths else "Demo — run a scan for live data"

    # Risk scores
    score_now = res.risk_score if res else 14
    pc_score  = res.pc_global_score if res else 60
    trend_vals = [88, 79, 75, max(score_now, pc_score)]
    trend_lbls = ["Baseline", "Week 1", "Week 2", "Current"]

    # ── Shared layout helper ──────────────────────────────────────────────
    _BG  = "#0b0e1a"
    _PLT = "#0f1221"
    _GC  = "#1e2235"

    def _layout(**kw):
        return go.Layout(
            paper_bgcolor=_BG, plot_bgcolor=_PLT,
            font=dict(color="#e0e0e0"),
            margin=dict(l=10, r=10, t=44, b=10),
            legend=dict(bgcolor="rgba(20,20,40,0.85)",
                        bordercolor="#333", borderwidth=1,
                        font=dict(size=10, color="#ccc")),
            **kw)

    # ═══════════════ TAB 1: Attack Graph ════════════════════════════════════
    _tmap = {"Domain Admins":"Group","IT-Admins":"Group","Enterprise Admins":"Group",
             "EXPEDITE-DC":"DC","expedite.local":"Domain","Default Domain Policy":"GPO"}
    def _nt(n):
        if n in _tmap: return _tmap[n]
        nl = n.lower()
        if "dc" in nl: return "DC"
        if any(x in nl for x in ("admin","group","admins")): return "Group"
        if any(x in nl for x in ("svc_","service")): return "User"
        if ".local" in nl or "domain" in nl: return "Domain"
        return "User"

    node_names = list(dict.fromkeys(
        [p["src"] for p in all_paths] + [p["tgt"] for p in all_paths]))
    n_nd = len(node_names)
    pos = {}
    for i, nm in enumerate(node_names):
        angle = 2 * _math.pi * i / n_nd
        r = 1.0 if _nt(nm) in ("DC","Domain","Group") else 1.6
        pos[nm] = (r * _math.cos(angle) * 300 + 350, r * _math.sin(angle) * 220 + 250)

    ag_traces, annots = [], []
    grouped = {}
    for p in all_paths: grouped.setdefault(p["rel"], []).append(p)
    for rel, grp in grouped.items():
        ex, ey = [], []
        for p in grp:
            sx, sy = pos[p["src"]]; tx, ty = pos[p["tgt"]]
            ex += [sx, tx, None]; ey += [sy, ty, None]
            annots.append(dict(
                x=(sx+tx)/2, y=(sy+ty)/2, text=f"<b>{p['rel']}</b>",
                showarrow=False,
                font=dict(size=8, color=_EDGE_COLORS.get(p["rel"],"#aaa")),
                bgcolor="rgba(10,10,20,0.7)", borderpad=2))
        c = _EDGE_COLORS.get(rel, "#888")
        w = 2.5 if any(p["risk"] == "Critical" for p in grp) else 1.5
        ag_traces.append(go.Scatter(
            x=ex, y=ey, mode="lines", name=rel,
            line=dict(color=c, width=w,
                      dash="solid" if rel in ("GenericAll","WriteDACL","DCSync") else "dot"),
            hoverinfo="skip", showlegend=True))

    by_type: dict = {}
    for nm in node_names: by_type.setdefault(_nt(nm), []).append(nm)
    for ntype, names in by_type.items():
        xs = [pos[nm][0] for nm in names]; ys = [pos[nm][1] for nm in names]
        sz  = [22 if ntype in ("DC","Domain") else 18 if ntype == "Group" else 14 for _ in names]
        sym = ["diamond" if ntype in ("DC","Domain") else
               "square" if ntype == "GPO" else "circle" for _ in names]
        ag_traces.append(go.Scatter(
            x=xs, y=ys, mode="markers+text", name=ntype,
            marker=dict(size=sz, color=_NODE_COLORS.get(ntype,"#95a5a6"),
                        symbol=sym, line=dict(color="#fff", width=1.5)),
            text=[f"<b>{nm}</b>" for nm in names],
            textposition="top center", textfont=dict(size=9, color="#e0e0e0"),
            customdata=names,
            hovertemplate="<b>%{customdata}</b><br>"+ntype+"<extra></extra>"))

    fig_attack = go.Figure(data=ag_traces, layout=_layout(
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-60,760]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-60,560]),
        annotations=annots, dragmode="pan", hovermode="closest",
        title=dict(text="🩸 AD Attack Paths — expedite.local",
                   font=dict(size=12, color=CYAN), x=0.01)))

    # ═══════════════ TAB 2: Severity Pie ════════════════════════════════════
    fig_pie = go.Figure(
        data=[go.Pie(
            labels=list(sev_counts.keys()), values=list(sev_counts.values()),
            marker=dict(colors=["#c0392b","#e67e22","#f39c12","#2980b9"],
                        line=dict(color="#0b0e1a", width=2)),
            hole=0, textfont=dict(color="#fff"))],
        layout=_layout(title=dict(text="🔴 Finding Severity Breakdown",
                                  font=dict(size=12, color=CYAN), x=0.01)))

    # ═══════════════ TAB 3: Category Bar + Line ══════════════════════════════
    cats  = ["Kerberos","Delegation","Network","Accounts","GPO","ACEs/DACL","Identity"]
    cvals = [2, 2, 3, 1, 3, 6, 2]
    csco  = [95, 90, 70, 60, 55, 98, 85]
    fig_cat = go.Figure(data=[
        go.Bar(name="Finding Count", x=cats, y=cvals,
               marker_color="rgba(52,152,219,0.8)",
               marker_line=dict(color="#2980b9", width=1)),
        go.Scatter(name="Heat Score", x=cats, y=csco,
                   mode="lines+markers", yaxis="y2",
                   line=dict(color="#e74c3c", width=2, dash="dot"),
                   marker=dict(size=7, color="#e74c3c"))],
        layout=_layout(
            barmode="group",
            xaxis=dict(tickfont=dict(color="#ccc"), gridcolor=_GC),
            yaxis=dict(title="Finding Count", tickfont=dict(color="#aaa"), gridcolor=_GC),
            yaxis2=dict(title="Heat Score", overlaying="y", side="right",
                        tickfont=dict(color="#e74c3c"), showgrid=False),
            title=dict(text="📊 Risk Categories — Count + Heat Score",
                       font=dict(size=12, color=CYAN), x=0.01)))

    # ═══════════════ TAB 4: Risk Trend ════════════════════════════════════════
    fig_trend = go.Figure(data=[go.Scatter(
        x=trend_lbls, y=trend_vals, mode="lines+markers",
        line=dict(color="#e74c3c", width=2.5),
        fill="tozeroy", fillcolor="rgba(231,76,60,0.1)",
        marker=dict(size=8, color="#e74c3c", line=dict(color="#fff", width=1.5)),
        name="Risk Score")],
        layout=_layout(
            yaxis=dict(range=[0,100], title="Risk Score (lower=better)",
                       tickfont=dict(color="#aaa"), gridcolor=_GC),
            xaxis=dict(tickfont=dict(color="#ccc"), gridcolor=_GC),
            title=dict(text="📈 Risk Score Trend  (target < 30)",
                       font=dict(size=12, color=CYAN), x=0.01),
            shapes=[dict(type="line", x0=0, x1=3, y0=30, y1=30,
                         line=dict(color="#27ae60", width=1, dash="dot"))]))

    # ═══════════════ TAB 5: Accounts Doughnut ════════════════════════════════
    fig_acc = go.Figure(data=[go.Pie(
        labels=["Secure","No MFA","Shadow Admin","Schema Admin","Kerberoastable"],
        values=[128, 6, 1, 2, 7], hole=0.55,
        marker=dict(colors=["#27ae60","#e74c3c","#c0392b","#e67e22","#f39c12"],
                    line=dict(color="#0b0e1a", width=2)),
        textfont=dict(color="#fff"))],
        layout=_layout(
            title=dict(text="👤 Privileged Account Posture (142 accounts)",
                       font=dict(size=12, color=CYAN), x=0.01),
            annotations=[dict(text="142<br>accounts", x=0.5, y=0.5,
                              showarrow=False, font=dict(size=13, color="#ccc"))]))

    # ═══════════════ TAB 6: AD Hygiene Stacked Bar ═══════════════════════════
    fig_hyg = go.Figure(data=[
        go.Bar(name="Active",   x=["Users (142)","Computers (27)"], y=[98,20],
               marker_color="#27ae60"),
        go.Bar(name="Inactive", x=["Users (142)","Computers (27)"], y=[32,5],
               marker_color="#f39c12"),
        go.Bar(name="Disabled", x=["Users (142)","Computers (27)"], y=[12,2],
               marker_color="#6c757d")],
        layout=_layout(
            barmode="stack",
            xaxis=dict(tickfont=dict(color="#ccc")),
            yaxis=dict(title="Count", tickfont=dict(color="#aaa"), gridcolor=_GC),
            title=dict(text="🧹 AD Object Hygiene",
                       font=dict(size=12, color=CYAN), x=0.01)))


    # ═══════════════ TAB 7: AD Attack Surface Risk Heatmap ═══════════════════
    _HM_CATS = ["Kerberos", "Delegation", "Network", "Accounts", "GPO", "ACEs/DACL", "Identity"]
    _HM_SEVS = ["Critical", "High", "Medium", "Info"]

    # Build matrix: rows = severity (Critical→Info), cols = categories
    # Pull from live findings if available, else use demo data
    def _count(sev, cat):
        if findings:
            kw = cat.lower().replace("/", " ").replace("-", " ")
            return sum(1 for f in findings
                       if f.severity == sev and kw in
                       (getattr(f, "category", "") or getattr(f, "rule", "") or "").lower())
        # Demo realistic values  (Critical, High, Medium, Info) × categories
        _demo = {
            ("Critical", "Kerberos"):     3, ("Critical", "Delegation"):   2,
            ("Critical", "Network"):      0, ("Critical", "Accounts"):     1,
            ("Critical", "GPO"):          1, ("Critical", "ACEs/DACL"):    4,
            ("Critical", "Identity"):     1,
            ("High",     "Kerberos"):     2, ("High",     "Delegation"):   1,
            ("High",     "Network"):      3, ("High",     "Accounts"):     2,
            ("High",     "GPO"):          2, ("High",     "ACEs/DACL"):    3,
            ("High",     "Identity"):     1,
            ("Medium",   "Kerberos"):     1, ("Medium",   "Delegation"):   1,
            ("Medium",   "Network"):      2, ("Medium",   "Accounts"):     3,
            ("Medium",   "GPO"):          1, ("Medium",   "ACEs/DACL"):    2,
            ("Medium",   "Identity"):     2,
            ("Info",     "Kerberos"):     0, ("Info",     "Delegation"):   1,
            ("Info",     "Network"):      1, ("Info",     "Accounts"):     2,
            ("Info",     "GPO"):          1, ("Info",     "ACEs/DACL"):    1,
            ("Info",     "Identity"):     1,
        }
        return _demo.get((sev, cat), 0)

    z_vals     = [[_count(s, c) for c in _HM_CATS] for s in _HM_SEVS]
    # Text annotations (count in each cell)
    z_text     = [[str(v) if v > 0 else "" for v in row] for row in z_vals]

    fig_heat = go.Figure(data=go.Heatmap(
        z=z_vals,
        x=_HM_CATS,
        y=_HM_SEVS,
        text=z_text,
        texttemplate="%{text}",
        textfont=dict(size=14, color="#fff", family="JetBrains Mono, monospace"),
        colorscale=[
            [0.0,  "#0b0e1a"],    # 0 = near-black (no findings)
            [0.01, "#0f2a18"],    # tiny positive = dark green
            [0.25, "#1a6b2e"],    # low = green
            [0.45, "#f5c518"],    # medium = amber
            [0.65, "#e67e22"],    # moderate = orange
            [0.85, "#e74c3c"],    # high = red
            [1.0,  "#c0392b"],    # max = dark red
        ],
        zmin=0,
        showscale=True,
        colorbar=dict(
            title=dict(text="Findings", font=dict(color="#aaa", size=10)),
            tickfont=dict(color="#aaa", size=10),
            thickness=12,
            len=0.85,
            bgcolor="rgba(0,0,0,0)",
            bordercolor="#1e2230",
        ),
        xgap=3,   # visible cell borders
        ygap=3,
        hovertemplate=(
            "<b>%{y}</b> findings in <b>%{x}</b><br>"
            "Count: <b>%{z}</b><extra></extra>"
        ),
    ))

    domain = (sess.ping.domain if sess.ping else
              sess.nmap.target  if sess.nmap  else "expedite.local")

    fig_heat.update_layout(
        paper_bgcolor=_BG, plot_bgcolor=_PLT,
        font=dict(color="#e0e0e0", family="Inter, sans-serif"),
        margin=dict(l=10, r=10, t=60, b=60),
        title=dict(
            text=f"🔥 AD Attack Surface Risk Heatmap",
            subtitle=dict(text=f"Severity × Category intensity — {domain}",
                          font=dict(size=10, color="#777")),
            font=dict(size=13, color=CYAN), x=0.01,
        ),
        xaxis=dict(
            title=dict(text="Attack Category", font=dict(color="#aaa", size=11)),
            tickfont=dict(color="#e0e0e0", size=11, family="Inter"),
            tickangle=-25,
            gridcolor=_GC, linecolor=_GC,
            side="bottom",
        ),
        yaxis=dict(
            title=dict(text="Severity", font=dict(color="#aaa", size=11)),
            tickfont=dict(color="#e0e0e0", size=12, family="Inter"),
            categoryorder="array",
            categoryarray=["Info", "Medium", "High", "Critical"],  # Critical at top
            gridcolor=_GC, linecolor=_GC,
        ),
    )

    # ── Shared graph config ───────────────────────────────────────────────
    _CFG = {"displayModeBar": True,
            "modeBarButtonsToRemove": ["lasso2d","select2d"],
            "scrollZoom": True}
    _GH  = {"height": "560px"}

    return html.Div([
        html.Div([
            html.Span("📊 Analytics Graphs",
                      style={"color": CYAN, "fontWeight": "700", "fontSize": "12px"}),
            html.Span(f"  {source_note}",
                      style={"color": "#555", "fontSize": "10px",
                             "float": "right", "marginRight": "4px"}),
        ], style={"padding": "8px 14px", "borderBottom": BORDER,
                  "background": CARD2, "borderRadius": "10px 10px 0 0"}),

        dcc.Tabs([
            dcc.Tab(
                html.Div([
                    # \u2500\u2500 Legend bar \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
                    html.Div([
                        html.Span("Node types: ",
                                  style={"color": TEXT, "fontSize": "10px"}),
                        *[html.Span(f"\u25cf {t}", style={"color": c,
                          "fontSize": "10px", "marginRight": "10px"})
                          for t, c in [("User","#17a488"),("Group","#e67e22"),
                                       ("Computer","#2980b9"),("Domain","#e74c3c"),
                                       ("GPO","#8e44ad"),("OU","#16a085")]],
                        html.Span("Click any node to inspect",
                                  style={"color": "#444", "fontSize": "9px",
                                         "float": "right"}),
                    ], style={"padding": "5px 12px", "background": "#0b0e1a",
                              "borderBottom": BORDER}),
                    # \u2500\u2500 Graph + detail panel side-by-side \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
                    html.Div([
                        # Cytoscape graph (live Neo4j)
                        cyto.Cytoscape(
                            id="pc-bh-graph",
                            elements=_fetch_bh_elements(),
                            layout={"name": "cose",
                                    "animate": False,
                                    "nodeDimensionsIncludeLabels": True,
                                    "idealEdgeLength": 100,
                                    "nodeOverlap": 20,
                                    "refresh": 20,
                                    "fit": True,
                                    "padding": 30,
                                    "randomize": False,
                                    "componentSpacing": 100,
                                    "nodeRepulsion": 400000,
                                    "edgeElasticity": 100,
                                    "nestingFactor": 5,
                                    "gravity": 80,
                                    "numIter": 1000,
                                    "initialTemp": 200,
                                    "coolingFactor": 0.95,
                                    "minTemp": 1.0},
                            stylesheet=_BH_STYLESHEET,
                            style={"width": "70%", "height": "550px",
                                   "background": "#0b0e1a"},
                            userZoomingEnabled=True,
                            userPanningEnabled=True,
                            boxSelectionEnabled=False,
                        ),
                        # Detail panel (populated by click callback)
                        html.Div([
                            html.Div("🔍 Click a node to inspect it",
                                     style={"color": "#444", "fontSize": "11px",
                                            "textAlign": "center",
                                            "paddingTop": "30px"}),
                            html.Div(id="pc-bh-node-detail"),
                        ], style={"width": "30%", "padding": "10px",
                                  "borderLeft": BORDER,
                                  "background": CARD, "overflowY": "auto",
                                  "height": "550px"}),
                    ], style={"display": "flex"}),
                ]),
                label="\U0001fa78 BH Graph", value="g-attack",
                style={"background": CARD2, "color": TEXT, "border": "none", "fontSize": "11px"},
                selected_style={"background": CARD2, "color": CYAN, "border": "none",
                                "borderBottom": f"2px solid {CYAN}", "fontSize": "11px",
                                "fontWeight": "700"}),
            dcc.Tab(dcc.Graph(figure=fig_pie,   id="pc-g-sev",   config=_CFG, style=_GH),
                    label="\U0001f534 Severity",     value="g-sev",
                    style={"background": CARD2, "color": TEXT,   "border": "none", "fontSize": "11px"},
                    selected_style={"background": CARD2, "color": CYAN, "border": "none",
                                    "borderBottom": f"2px solid {CYAN}", "fontSize": "11px", "fontWeight": "700"}),
            dcc.Tab(dcc.Graph(figure=fig_cat,   id="pc-g-cat",   config=_CFG, style=_GH),
                    label="\U0001f4ca Categories",   value="g-cat",
                    style={"background": CARD2, "color": TEXT,   "border": "none", "fontSize": "11px"},
                    selected_style={"background": CARD2, "color": CYAN, "border": "none",
                                    "borderBottom": f"2px solid {CYAN}", "fontSize": "11px", "fontWeight": "700"}),
            dcc.Tab(dcc.Graph(figure=fig_trend, id="pc-g-trend", config=_CFG, style=_GH),
                    label="\U0001f4c8 Risk Trend",   value="g-trend",
                    style={"background": CARD2, "color": TEXT,   "border": "none", "fontSize": "11px"},
                    selected_style={"background": CARD2, "color": CYAN, "border": "none",
                                    "borderBottom": f"2px solid {CYAN}", "fontSize": "11px", "fontWeight": "700"}),
            dcc.Tab(dcc.Graph(figure=fig_acc,   id="pc-g-acc",   config=_CFG, style=_GH),
                    label="\U0001f464 Accounts",     value="g-acc",
                    style={"background": CARD2, "color": TEXT,   "border": "none", "fontSize": "11px"},
                    selected_style={"background": CARD2, "color": CYAN, "border": "none",
                                    "borderBottom": f"2px solid {CYAN}", "fontSize": "11px", "fontWeight": "700"}),
            dcc.Tab(dcc.Graph(figure=fig_hyg,   id="pc-g-hyg",   config=_CFG, style=_GH),
                    label="\U0001f9f9 Hygiene",      value="g-hyg",
                    style={"background": CARD2, "color": TEXT,   "border": "none", "fontSize": "11px"},
                    selected_style={"background": CARD2, "color": CYAN, "border": "none",
                                    "borderBottom": f"2px solid {CYAN}", "fontSize": "11px", "fontWeight": "700"}),
            dcc.Tab(dcc.Graph(figure=fig_heat,  id="pc-g-heat",  config=_CFG, style=_GH),
                    label="\U0001f525 Heatmap",      value="g-heat",
                    style={"background": CARD2, "color": TEXT,   "border": "none", "fontSize": "11px"},
                    selected_style={"background": CARD2, "color": CYAN, "border": "none",
                                    "borderBottom": f"2px solid {CYAN}", "fontSize": "11px", "fontWeight": "700"}),
        ], value="g-attack",
           style={"background": CARD2, "borderBottom": BORDER}),



    ], style=CARD_S)



def _report_panel(sess) -> html.Div:
    """Embed the latest Ægis AD Scanner HTML report in an iframe."""
    PC_DIR = "/home/kali/Downloads/PingCastle_3.5.0.44"
    reports = sorted(
        _glob.glob(_os.path.join(PC_DIR, "ad_hc_*.html")),
        key=_os.path.getmtime,
        reverse=True
    )
    report_exists = bool(reports)
    report_name   = _os.path.basename(reports[0]) if reports else None

    return html.Div([
        # Header bar
        html.Div([
            html.Span("📄 Ægis AD Analytic Scanner — HTML Report",
                      style={"color": CYAN, "fontWeight": "700", "fontSize": "12px"}),
            html.Span(f"  {report_name}" if report_name else "  No report yet",
                      style={"color": TEXT, "fontSize": "10px", "marginLeft": "10px"}),
            html.A("⎋ Open in new tab",
                   href="/pingcastle-report",
                   target="_blank",
                   style={"color": ORANGE, "fontSize": "10px", "float": "right",
                          "textDecoration": "none", "marginRight": "4px"})
        ], style={"padding": "10px 14px", "borderBottom": BORDER,
                  "background": CARD2, "borderRadius": "10px 10px 0 0",
                  "overflow": "hidden"}),

        # iframe or placeholder
        html.Iframe(
            src="/pingcastle-report",
            style={"width": "100%", "height": "680px",
                   "border": "none", "borderRadius": "0 0 10px 10px",
                   "background": "#fff"},
        ) if report_exists else html.Div(
            [
                html.Div("🏰", style={"fontSize": "48px", "marginBottom": "10px"}),
                html.Div("No Ægis AD Analytic Scanner report found yet.",
                         style={"color": CYAN, "fontWeight": "700", "fontSize": "14px"}),
                html.Div(f"Run a scan — the report will be saved to {PC_DIR}",
                         style={"color": TEXT, "fontSize": "11px", "marginTop": "6px"}),
                html.Div("Make sure Wine is installed: sudo apt install wine",
                         style={"color": TEXT, "fontSize": "11px"}),
            ],
            style={"textAlign": "center", "padding": "60px 20px"}
        ),
    ], style=CARD_S)


def _dashboard_panels(sess) -> html.Div:
    """SOC dashboard — unified risk score + correlation engine + attack paths."""
    import math

    # ── Run correlation engine (safe, never crashes the UI) ────────────────
    corr = None
    try:
        from cyber_range.services.risk_correlation import RiskCorrelationEngine
        corr = RiskCorrelationEngine().correlate()
    except Exception as _e:
        pass  # fall back to scan-session score below

    # ── Score from either correlation or legacy scan result ─────────────────
    if corr and corr.unified_score > 0:
        score_val   = corr.unified_score
        score_level = corr.level
        by_src      = corr.by_source      # {Ægis AD Scanner:3, Nmap:4, BloodHound:2}
        by_sev      = corr.by_severity    # {Critical:2, High:5 …}
        top_path    = corr.top_path_str
        findings    = corr.findings
        attack_paths = corr.attack_paths
    else:
        score_val   = sess.score.total if sess.score else 0
        score_level = sess.score.level if sess.score else "LOW"
        by_src      = {}; by_sev = {}; top_path = ""; findings = []; attack_paths = []

    # ── Gauge colour ────────────────────────────────────────────────────────
    gauge_col = ("#e74c3c" if score_val >= 75 else
                 "#e67e22" if score_val >= 50 else
                 "#f39c12" if score_val >= 25 else "#27ae60")

    # ═══════════════ Row 1: Unified Risk Score + Source Breakdown ═══════════
    gauge_fig = _score_gauge(score_val, score_level) if sess.score else None
    _cor_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score_val,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Unified Risk Score", "font": {"color": "#aaa", "size": 12}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#555"},
            "bar": {"color": gauge_col},
            "bgcolor": "#0f1221",
            "bordercolor": "#1e2230",
            "steps": [
                {"range": [0, 25],  "color": "rgba(39,174,96,0.15)"},
                {"range": [25, 50], "color": "rgba(243,156,18,0.12)"},
                {"range": [50, 75], "color": "rgba(230,126,34,0.12)"},
                {"range": [75, 100],"color": "rgba(231,76,60,0.15)"},
            ],
            "threshold": {
                "line": {"color": gauge_col, "width": 3},
                "thickness": 0.8, "value": score_val,
            },
        },
        number={"font": {"color": gauge_col, "size": 32}},
    ))
    _cor_gauge.update_layout(
        paper_bgcolor="#0b0e1a", plot_bgcolor="#0b0e1a",
        font=dict(color="#e0e0e0"),
        margin=dict(l=10, r=10, t=30, b=5),
        height=200,
    )

    # Source breakdown badges
    _SRC_COL = {"Ægis AD Scanner": "#9b59b6", "Nmap": "#3498db",
                "BloodHound": "#e74c3c", "Correlation": "#e67e22"}
    src_badges = [
        html.Span(f"{src}: {cnt}", style={
            "background": _SRC_COL.get(src, "#555"), "color": "#fff",
            "padding": "2px 8px", "borderRadius": "4px",
            "fontSize": "10px", "fontWeight": "700", "marginRight": "6px"})
        for src, cnt in by_src.items()
    ] or [html.Span("Run a scan to see source breakdown",
                    style={"color": "#444", "fontSize": "10px"})]

    sev_cols = {"Critical": RED, "High": ORANGE, "Medium": YELLOW, "Info": CYAN}
    sev_badges = [
        html.Span(f"{sev}: {cnt}", style={
            "background": sev_cols.get(sev, "#555"), "color": "#fff",
            "padding": "2px 8px", "borderRadius": "4px",
            "fontSize": "10px", "fontWeight": "700", "marginRight": "6px"})
        for sev, cnt in by_sev.items()
    ]

    # ═══════════════ Row 2: Top Attack Path ════════════════════════════════════
    from cyber_range.services.attack_simulator import simulate_from_paths
    scenarios = simulate_from_paths(attack_paths) if attack_paths else []

    if scenarios:
        sc = scenarios[0]
        path_card = html.Div([
            html.Div("🔥 Top Attack Path to Domain Admin", style={
                "color": RED, "fontWeight": "700", "fontSize": "12px",
                "padding": "8px 14px", "borderBottom": BORDER}),
            html.Div([
                html.Div(sc.title, style={"color": ORANGE, "fontSize": "11px",
                                          "fontWeight": "700", "marginBottom": "8px"}),
                *[html.Div(step, style={
                    "color": TEXT if "↳" not in step else "#888",
                    "fontSize": "11px",
                    "paddingLeft": "16px" if "↳" in step else "0",
                    "paddingBottom": "3px",
                    "fontFamily": "monospace" if "↳" in step else "inherit",
                }) for step in sc.steps],
                html.Div([
                    html.Span("MITRE: ", style={"color": "#888", "fontSize": "9px"}),
                    *[html.Span(m, style={
                        "background": "#1e1030", "color": "#b39ddb",
                        "padding": "1px 5px", "borderRadius": "3px",
                        "fontSize": "9px", "marginRight": "4px"})
                      for m in sc.mitre[:4]],
                ], style={"marginTop": "10px"}) if sc.mitre else "",
            ], style={"padding": "12px 16px"}),
        ], style={**CARD_S, "marginBottom": "10px"})
    else:
        path_card = html.Div("No attack paths to Domain Admin found in Neo4j yet.",
                             style={"color": TEXT, "fontStyle": "italic",
                                    "padding": "20px", **CARD_S, "marginBottom": "10px"})

    # ═══════════════ Row 3: Correlated Findings Table ══════════════════════════
    finding_rows = []
    for f in sorted(findings, key=lambda x: x.score, reverse=True)[:12]:
        col = sev_cols.get(f.severity, "#888")
        src_col = _SRC_COL.get(f.source, "#555")
        finding_rows.append(html.Tr([
            html.Td(html.Span(f.severity, style={
                "background": col, "color": "#fff",
                "padding": "1px 6px", "borderRadius": "3px", "fontSize": "9px"})),
            html.Td(html.Span(f.source, style={
                "background": src_col, "color": "#fff",
                "padding": "1px 6px", "borderRadius": "3px", "fontSize": "9px"})),
            html.Td(f.title, style={"color": "#e0e0e0", "fontSize": "11px",
                                    "paddingLeft": "8px"}),
            html.Td(f.detail[:50] if f.detail else "",
                    style={"color": "#666", "fontSize": "10px", "paddingLeft": "8px"}),
        ], style={"borderBottom": "1px solid #1a1d28"}))

    findings_card = html.Div([
        html.Div("⚠️ Correlated Findings", style={
            "color": ORANGE, "fontWeight": "700", "fontSize": "12px",
            "padding": "8px 14px", "borderBottom": BORDER}),
        html.Table([
            html.Thead(html.Tr([
                html.Th("Severity", style={"color": TEXT, "fontSize": "10px", "padding": "4px 8px"}),
                html.Th("Source",   style={"color": TEXT, "fontSize": "10px", "padding": "4px 8px"}),
                html.Th("Finding",  style={"color": TEXT, "fontSize": "10px", "padding": "4px 8px"}),
                html.Th("Detail",   style={"color": TEXT, "fontSize": "10px", "padding": "4px 8px"}),
            ])),
            html.Tbody(finding_rows or [
                html.Tr(html.Td("No findings yet. Run a scan to populate.",
                                colSpan=4,
                                style={"color": "#444", "fontStyle": "italic",
                                       "padding": "20px", "textAlign": "center"}))
            ]),
        ], style={"width": "100%", "borderCollapse": "collapse",
                  "fontSize": "11px", "padding": "0 10px"}),
    ], style={**CARD_S, "marginBottom": "10px"})

    # ═══════════════ Assemble ═══════════════════════════════════════════════
    return html.Div([
        # Row 1: Gauge + level + source breakdown
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.Div("🎯 Unified Risk Score", style={
                        "color": CYAN, "fontWeight": "700", "fontSize": "11px",
                        "padding": "8px 14px", "borderBottom": BORDER}),
                    dcc.Graph(figure=_cor_gauge,
                              config={"displayModeBar": False},
                              style={"height": "200px"}),
                    html.Div([
                        html.Span(score_level, style={
                            "background": gauge_col, "color": "#fff",
                            "padding": "3px 12px", "borderRadius": "6px",
                            "fontWeight": "800", "fontSize": "12px", "marginRight": "10px"}),
                        *src_badges,
                    ], style={"padding": "8px 14px 10px"}),
                    html.Div(sev_badges, style={"padding": "0 14px 12px"}),
                ], style=CARD_S),
            ], width=4),
            dbc.Col([
                _tool_card("🛡️ Ægis AD Analytic Scanner", _build_ping_panel(sess.ping)),
            ], width=4),
            dbc.Col([
                _tool_card("🩸 BloodHound", _build_blood_panel(sess.blood)),
            ], width=4),
        ], className="g-2 mb-2"),

        # Row 2: Top attack path
        path_card,

        # Row 3: Correlated findings
        findings_card,

        # Row 4: Nmap full panel
        _tool_card("🗺️ Nmap Ports", _build_nmap_panel(sess.nmap)),
    ])




def _ai_panel(sess) -> html.Div:
    result = sess.result
    if not result or not result.ai_recommendation:
        msg = ("AI report will appear after scan completes. Make sure 🧠 AI Report is checked."
               if not sess.done else
               "No AI narrative was generated for this scan.")
        return html.Div(msg, style={"color": TEXT, "fontStyle": "italic",
                                    "padding": "40px", "textAlign": "center"})

    lines = result.ai_recommendation.split("\n")
    content = []
    for line in lines:
        clean = line.replace("**", "").strip()
        if not clean:
            continue
        if line.startswith("## ") or line.startswith("# "):
            content.append(html.H5(clean.lstrip("# "),
                                   style={"color": CYAN, "fontWeight": "700",
                                          "marginTop": "14px", "marginBottom": "5px",
                                          "fontSize": "13px"}))
        elif clean.startswith("-") or clean.startswith("•"):
            content.append(html.Li(clean[1:].strip(),
                                   style={"color": TEXT, "fontSize": "12px",
                                          "marginBottom": "4px", "marginLeft": "14px"}))
        else:
            content.append(html.P(clean, style={"color": TEXT, "fontSize": "12px",
                                                "lineHeight": "1.7", "marginBottom": "5px"}))

    return html.Div([
        html.Div([
            html.Span("🧠 AI Security Assessment",
                      style={"color": CYAN, "fontWeight": "700", "fontSize": "13px"}),
            html.Span(f"  Scan #{result.scan_id}  •  {result.domain}  •  "
                      f"Score {result.risk_score}/100",
                      style={"color": TEXT, "fontSize": "11px", "marginLeft": "10px"}),
        ], style={"padding": "10px 14px", "borderBottom": BORDER}),
        html.Div(content,
                 style={"padding": "14px 18px", "maxHeight": "520px",
                        "overflowY": "auto"}),
    ], style=CARD_S)


def _history_panel() -> html.Div:
    rows = ScanOrchestrator.get_history(limit=15)
    if not rows:
        return html.Div(
            "No scan history yet — run your first assessment.",
            style={"color": TEXT, "fontStyle": "italic",
                   "padding": "40px", "textAlign": "center"})

    cols = ["Scan ID", "Time", "Domain", "Score", "Level",
            "Critical", "High", "Ports", "DA Paths"]
    header = html.Tr([
        html.Th(c, style={"color": CYAN, "fontSize": "9px", "fontWeight": "700",
                          "textTransform": "uppercase", "padding": "6px 8px",
                          "borderBottom": BORDER, "whiteSpace": "nowrap"})
        for c in cols])

    body_rows = []
    for r in rows:
        level = r.get("risk_level", "?")
        col   = RISK_COL.get(level, TEXT)
        body_rows.append(html.Tr([
            html.Td(r.get("scan_id",""),
                    style={"color": CYAN, "fontFamily": "monospace",
                           "fontSize": "10px", "padding": "5px 8px"}),
            html.Td((r.get("timestamp","")[:16]),
                    style={"color": TEXT, "fontSize": "9px", "padding": "5px 8px",
                           "whiteSpace": "nowrap"}),
            html.Td(r.get("domain",""),
                    style={"color": TEXT, "fontSize": "10px", "padding": "5px 8px"}),
            html.Td(str(r.get("risk_score", 0)),
                    style={"color": col, "fontWeight": "800",
                           "fontSize": "13px", "padding": "5px 8px"}),
            html.Td(level, style={"color": col, "fontWeight": "700",
                                  "padding": "5px 8px"}),
            html.Td(str(r.get("critical_count", 0)),
                    style={"color": RED, "fontWeight": "700", "padding": "5px 8px"}),
            html.Td(str(r.get("high_count", 0)),
                    style={"color": ORANGE, "padding": "5px 8px"}),
            html.Td(str(r.get("nmap_open_ports", 0)),
                    style={"color": YELLOW, "padding": "5px 8px"}),
            html.Td(str(r.get("da_paths", 0)),
                    style={"color": RED, "fontWeight": "700", "padding": "5px 8px"}),
        ], style={"borderBottom": "1px solid #111"}))

    return html.Div([
        html.Div("📂 Scan History",
                 style={"color": CYAN, "fontWeight": "700", "fontSize": "11px",
                        "padding": "10px 14px", "borderBottom": BORDER}),
        html.Div([
            html.Table([html.Thead(header), html.Tbody(body_rows)],
                       style={"width": "100%", "borderCollapse": "collapse"}),
        ], style={"overflowX": "auto", "maxHeight": "500px", "overflowY": "auto",
                  "padding": "8px"}),
    ], style=CARD_S)


# ── Widget helpers ─────────────────────────────────────────────────────────────
def _tool_card(title: str, body) -> html.Div:
    return html.Div([
        html.Div(title, style={"color": CYAN, "fontWeight": "700",
                               "fontSize": "11px", "padding": "8px 12px",
                               "borderBottom": BORDER}),
        html.Div(body, style={"padding": "8px", "maxHeight": "260px",
                              "overflowY": "auto", "fontSize": "11px"}),
    ], style=CARD_S)


def _empty_feed_item() -> html.Div:
    return html.Div(
        "Configure targets above and click ▶ Run All Scans",
        style={"color": "#2a2d3e", "fontStyle": "italic",
               "padding": "20px", "textAlign": "center"})


def _colour_line(line: str) -> html.Div:
    if "🚨" in line or "CRITICAL" in line:     c = RED
    elif "⚠️" in line or "❌" in line:         c = ORANGE
    elif "✅" in line or "📊" in line:         c = GREEN
    elif "═" in line or "━" in line:            c = "#282c3e"
    elif line.startswith("[") and "]" in line:  c = "#7ec8f5"
    else:                                        c = "#b0e0ff"
    return html.Div(line, style={"color": c, "lineHeight": "1.7"})


def _empty_gauge() -> go.Figure:
    return _score_gauge(0, "Unknown", empty=True)


def _score_gauge(score: int, level: str, empty: bool = False) -> go.Figure:
    col = "#2a2d3e" if empty else RISK_COL.get(level, RED)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        title={"text": ("Risk Score" if empty else f"Risk Level  <b>{level}</b>"),
               "font": {"color": col, "size": 12}},
        number={"font": {"color": col, "size": 40},
                "suffix": "/100", "valueformat": "d"},
        gauge={"axis": {"range": [0, 100], "tickcolor": TEXT,
                        "tickfont": {"size": 9}},
               "bar": {"color": col if not empty else "#1a1d2e",
                       "thickness": 0.28},
               "bgcolor": "#0a0c18",
               "steps": [{"range": [0,  25],  "color": "#0b1e13"},
                         {"range": [25, 50],  "color": "#181d0a"},
                         {"range": [50, 75],  "color": "#1f1500"},
                         {"range": [75, 100], "color": "#1a0808"}],
               "threshold": {"line": {"color": col, "width": 2}, "value": score}},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin={"t": 28, "b": 8, "l": 18, "r": 18}, height=180,
        font={"color": TEXT},
    )
    return fig


def _score_breakdown(score) -> html.Div:
    rows = [html.Div([
        html.Span(f"• {k}", style={"color": TEXT, "fontSize": "10px"}),
        html.Span(v, style={"color": CYAN, "fontSize": "10px",
                            "fontFamily": "monospace"}),
    ], style={"display": "flex", "justifyContent": "space-between", "marginBottom": "2px"})
        for k, v in score.breakdown.items()]
    return html.Div(rows)


def _build_kpis(sess) -> list:
    pr, nr, br = sess.ping, sess.nmap, sess.blood
    crits = sum(1 for f in pr.findings if f.severity == "Critical") if pr else 0
    highs = sum(1 for f in pr.findings if f.severity == "High")     if pr else 0
    ports = nr.open_count if nr else 0
    paths = br.da_paths   if br else 0

    _HOVER = ("background: #1a1e30; border-color: {col}; "
              "box-shadow: 0 0 8px {col}44; transform: translateY(-1px);")

    def _k(card_id, label, val, col, src=""):
        return html.Div([
            html.Div(str(val), style={
                "color": col, "fontSize": "24px",
                "fontWeight": "900", "lineHeight": "1", "marginBottom": "4px",
            }),
            html.Div(label, style={
                "color": "#c8d0d8", "fontSize": "9px",
                "fontWeight": "800", "letterSpacing": "1.5px",
            }),
            html.Div(src, style={
                "color": col, "fontSize": "8px", "opacity": "0.55",
                "marginTop": "4px", "letterSpacing": "0.5px",
                "fontStyle": "italic",
            }),
            html.Div("▼ click to drill", style={
                "color": col, "fontSize": "7px",
                "marginTop": "5px", "opacity": "0.35",
                "letterSpacing": "0.5px",
            }),
        ], id=card_id, n_clicks=0,
           style={
               "background": CARD2, "border": BORDER, "borderRadius": "6px",
               "padding": "12px 8px", "textAlign": "center",
               "flex": "1", "marginRight": "6px",
               "cursor": "pointer", "transition": "all 0.15s ease",
               "minWidth": "0",
           })

    return [
        _k("pc-kpi-critical", "CRITICAL",   crits, RED,    "Ægis AD Scanner"),
        _k("pc-kpi-high",     "HIGH",       highs, ORANGE, "Ægis AD Scanner"),
        _k("pc-kpi-ports",    "OPEN PORTS", ports, YELLOW, "Nmap"),
        _k("pc-kpi-paths",    "DA PATHS",   paths, RED,    "BloodHound"),
    ]




# ── KPI card click callback ────────────────────────────────────────────────────
@callback(
    Output("pc-kpi-detail", "children"),
    Input("pc-kpi-critical", "n_clicks"),
    Input("pc-kpi-high",     "n_clicks"),
    Input("pc-kpi-ports",    "n_clicks"),
    Input("pc-kpi-paths",    "n_clicks"),
    prevent_initial_call=True,
)
def _kpi_detail(n_crit, n_high, n_ports, n_paths):
    """Drill-down panel when a KPI card is clicked."""
    triggered = ctx.triggered_id
    if not triggered:
        return no_update

    sess = ScanOrchestrator.get_session()
    pr, nr, br = sess.ping, sess.nmap, sess.blood

    _SEV_COL = {"Critical": "#e74c3c", "High": "#e67e22",
                "Medium":  "#f39c12", "Info": "#42b9f5"}
    _PORT_RISK = {3389: ("Critical", "RDP — brute-force / BlueKeep"),
                  5985: ("Critical", "WinRM — remote code execution"),
                  5986: ("Critical", "WinRM (HTTPS) — remote code execution"),
                  445:  ("High",     "SMB — lateral movement / ransomware"),
                  389:  ("High",     "LDAP — AD enumeration"),
                  636:  ("High",     "LDAPS — AD enumeration (TLS)"),
                  88:   ("High",     "Kerberos — ticket attacks"),
                  139:  ("High",     "NetBIOS — SMB session setup"),
                  21:   ("High",     "FTP — cleartext credentials"),
                  23:   ("High",     "Telnet — cleartext credentials"),
                  2049: ("High",     "NFS — unauthenticated mount"),
                  1433: ("Medium",   "MSSQL — database access"),
                  3306: ("Medium",   "MySQL — database access"),
                  5900: ("Medium",   "VNC — remote desktop")}

    def _header(icon, title, col):
        return html.Div([
            html.Span(icon + " " + title,
                      style={"color": col, "fontWeight": "700", "fontSize": "12px"}),
            html.Span(" — click card again to refresh",
                      style={"color": "#444", "fontSize": "9px"}),
        ], style={"padding": "6px 14px", "borderBottom": "1px solid #1e2230",
                  "background": "#0b0e1a"})

    # ── CRITICAL / HIGH findings ───────────────────────────────────────────
    if triggered in ("pc-kpi-critical", "pc-kpi-high"):
        sev_filter = "Critical" if triggered == "pc-kpi-critical" else "High"
        col = "#e74c3c" if sev_filter == "Critical" else "#e67e22"
        findings = [f for f in (pr.findings if pr else [])
                    if f.severity == sev_filter]

        if not findings:
            body = html.Div(f"No {sev_filter} findings yet — run an Ægis AD Analytic Scanner scan.",
                            style={"color": "#555", "fontStyle": "italic",
                                   "padding": "16px"})
        else:
            rows = []
            for f in findings:
                rows.append(html.Div([
                    # Row 1: severity badge + rule name
                    html.Div([
                        html.Span(f.severity, style={
                            "background": col, "color": "#fff",
                            "padding": "1px 7px", "borderRadius": "3px",
                            "fontSize": "9px", "fontWeight": "800",
                            "marginRight": "8px"}),
                        html.Span((getattr(f, "rule", None) or getattr(f, "title", None) or "AD Finding")[:50],
                                  style={"color": "#e0e0e0", "fontWeight": "700",
                                         "fontSize": "11px"}),
                    ]),
                    # Row 2: description
                    html.Div(getattr(f, "description", ""),
                             style={"color": TEXT, "fontSize": "10px",
                                    "marginTop": "3px", "paddingLeft": "3px",
                                    "lineHeight": "1.5"}),
                    # Row 3: what it leads to
                    html.Div([
                        html.Span("⚔️ Risk: ", style={"color": "#888", "fontSize": "9px"}),
                        html.Span(
                            "Domain Admin compromise via Kerberoasting" if sev_filter == "Critical"
                            else "Lateral movement to privileged systems",
                            style={"color": "#f39c12", "fontSize": "9px"}),
                    ], style={"marginTop": "4px", "paddingLeft": "3px"}),
                ], style={"borderBottom": "1px solid #15182a",
                          "paddingBottom": "10px", "marginBottom": "10px"}))
            body = html.Div(rows, style={"padding": "12px 14px",
                                         "maxHeight": "320px", "overflowY": "auto"})

        return html.Div([
            _header("🔴" if sev_filter == "Critical" else "🟠",
                    f"{sev_filter} Findings ({len(findings)})", col),
            body,
        ], style={"background": "#0d0e14", "border": f"1px solid {col}66",
                  "borderRadius": "10px"})

    # ── OPEN PORTS ────────────────────────────────────────────────────────
    if triggered == "pc-kpi-ports":
        ports_list = list(nr.ports) if (nr and hasattr(nr, "ports")) else []

        if not ports_list:
            # Try to pull directly from Neo4j
            try:
                from neo4j import GraphDatabase
                drv = GraphDatabase.driver("bolt://localhost:7687",
                                           auth=("neo4j", "Adomaa12@"))
                with drv.session() as s:
                    res = s.run("""
                        MATCH (c:Computer)-[:HAS_PORT]->(pt:Port)
                        RETURN c.ip AS host, pt.port AS port, pt.risk AS risk
                        ORDER BY host, port LIMIT 100
                    """)
                    ports_list = [{"host": r["host"], "port": str(r["port"]),
                                   "risk": r["risk"]} for r in res]
                drv.close()
            except Exception:
                pass

        if not ports_list:
            body = html.Div("No port data yet — run an Nmap scan.",
                            style={"color": "#555", "fontStyle": "italic", "padding": "16px"})
        else:
            rows = []
            for p in sorted(ports_list,
                            key=lambda x: (x.get("risk", "Low") != "High",
                                           x.get("port", "0"))):
                port_num = int(p.get("port", 0))
                risk_info = _PORT_RISK.get(port_num, ("Low", "Standard port"))
                risk_lv, risk_desc = risk_info
                risk_col = _SEV_COL.get(risk_lv, "#888")
                host = p.get("host", p.get("ip", "?"))
                rows.append(html.Div([
                    html.Div([
                        html.Span(str(port_num),
                                  style={"color": risk_col, "fontWeight": "800",
                                         "fontSize": "13px", "marginRight": "8px",
                                         "fontFamily": "monospace"}),
                        html.Span(risk_lv, style={
                            "background": risk_col, "color": "#fff",
                            "padding": "1px 5px", "borderRadius": "3px",
                            "fontSize": "9px", "fontWeight": "700",
                            "marginRight": "8px"}),
                        html.Span(host, style={"color": "#888", "fontSize": "10px"}),
                    ]),
                    html.Div(risk_desc,
                             style={"color": TEXT, "fontSize": "10px",
                                    "marginTop": "2px", "paddingLeft": "3px"}),
                ], style={"borderBottom": "1px solid #15182a",
                          "paddingBottom": "7px", "marginBottom": "7px"}))

            body = html.Div(rows, style={"padding": "12px 14px",
                                          "maxHeight": "320px", "overflowY": "auto"})

        return html.Div([
            _header("🟡", f"Open Ports ({len(ports_list)})", YELLOW),
            body,
        ], style={"background": "#0d0e14", "border": "1px solid #f5e64266",
                  "borderRadius": "10px"})

    # ── DA PATHS ──────────────────────────────────────────────────────────
    if triggered == "pc-kpi-paths":
        # Query live DA paths from Neo4j
        paths = []
        try:
            from neo4j import GraphDatabase
            drv = GraphDatabase.driver("bolt://localhost:7687",
                                       auth=("neo4j", "Adomaa12@"))
            with drv.session() as s:
                res = s.run("""
                    MATCH p=shortestPath((u:User)-[*1..8]->(g:Group))
                    WHERE toLower(g.name) CONTAINS 'domain admin'
                    RETURN
                        [n IN nodes(p) | coalesce(n.name, n.id, 'node')] AS path,
                        [r IN relationships(p) | type(r)]                AS rels,
                        length(p) AS hops
                    ORDER BY hops ASC LIMIT 8
                """)
                paths = [dict(r) for r in res]
            drv.close()
        except Exception:
            pass

        if not paths and br and br.attack_paths:
            paths = [{"path": [ap.source, ap.target],
                      "rels":  [ap.relationship],
                      "hops":  1}
                     for ap in br.attack_paths[:8]]

        if not paths:
            body = html.Div("No DA paths found in Neo4j yet — run a BloodHound scan.",
                            style={"color": "#555", "fontStyle": "italic", "padding": "16px"})
        else:
            rows = []
            for i, p in enumerate(paths):
                node_names = p.get("path", [])
                rel_types  = p.get("rels",  [])
                hops       = p.get("hops",  len(node_names) - 1)
                score      = max(100 - hops * 12, 20)
                s_col      = "#e74c3c" if score >= 70 else "#e67e22"

                # Build path chain
                chain = []
                for j, nm in enumerate(node_names):
                    chain.append(html.Span(nm, style={
                        "background": "#1e1030", "color": "#b39ddb",
                        "padding": "1px 6px", "borderRadius": "3px",
                        "fontSize": "9px", "marginRight": "3px"}))
                    if j < len(rel_types):
                        chain.append(html.Span(
                            f"—[{rel_types[j]}]→",
                            style={"color": "#e74c3c", "fontSize": "9px",
                                   "marginRight": "3px",
                                   "fontFamily": "monospace"}))

                rows.append(html.Div([
                    html.Div([
                        html.Span(f"Path {i+1}", style={
                            "color": "#888", "fontSize": "9px",
                            "marginRight": "8px"}),
                        html.Span(f"{hops} hops", style={
                            "background": s_col, "color": "#fff",
                            "padding": "1px 6px", "borderRadius": "3px",
                            "fontSize": "9px", "fontWeight": "700",
                            "marginRight": "8px"}),
                        html.Span(f"Risk Score: {score}/100",
                                  style={"color": s_col, "fontSize": "9px",
                                         "fontWeight": "700"}),
                    ], style={"marginBottom": "5px"}),
                    html.Div(chain, style={"flexWrap": "wrap", "display": "flex",
                                           "alignItems": "center",
                                           "gap": "2px"}),
                    html.Div([
                        html.Span("⚔️ Impact: ", style={"color": "#888", "fontSize": "9px"}),
                        html.Span("Full domain compromise — DCSync, Golden Ticket, persistence",
                                  style={"color": "#f39c12", "fontSize": "9px"}),
                    ], style={"marginTop": "5px"}),
                ], style={"borderBottom": "1px solid #15182a",
                          "paddingBottom": "10px", "marginBottom": "10px"}))

            body = html.Div(rows, style={"padding": "12px 14px",
                                          "maxHeight": "360px", "overflowY": "auto"})

        return html.Div([
            _header("🩸", f"Attack Paths to Domain Admin ({len(paths)})", RED),
            body,
        ], style={"background": "#0d0e14", "border": "1px solid #f5425466",
                  "borderRadius": "10px"})

    return no_update


def _build_ping_panel(pr) -> html.Div:
    if not pr or not pr.success:
        return _ph("Run scan to see findings")
    rows = []
    for f in pr.findings:
        c = SEV_COL.get(f.severity, TEXT)
        rows.append(html.Div([
            dbc.Badge(f.severity,
                      style={"backgroundColor": c, "color": "#000",
                             "fontSize": "8px", "fontWeight": "800",
                             "marginRight": "6px", "padding": "2px 5px"}),
            html.Span(f.rule, style={"color": "#fff", "fontSize": "10px",
                                      "fontWeight": "600"}),
            html.Div(f.description,
                     style={"color": TEXT, "fontSize": "9px",
                            "marginTop": "2px", "paddingLeft": "3px"}),
        ], style={"borderBottom": "1px solid #1a1d28", "paddingBottom": "6px",
                  "marginBottom": "6px"}))
    return html.Div([
        html.Div(f"Score: {pr.global_score}/100  Level: {pr.risk_level}",
                 style={"color": RISK_COL.get(pr.risk_level, TEXT),
                        "fontWeight": "700", "fontSize": "10px",
                        "background": CARD2, "padding": "4px 8px",
                        "borderRadius": "5px", "marginBottom": "8px"}),
    ] + rows)


def _build_nmap_panel(nr) -> html.Div:
    if not nr or not nr.success:
        return _ph("Run scan to see ports")
    HI = {3389, 5985, 5986, 23, 21, 2049}
    MED = {445, 139, 135}
    return html.Div([
        html.Div(f"Open: {nr.open_count}  Target: {nr.target}",
                 style={"color": GREEN, "fontSize": "10px", "fontWeight": "700",
                        "background": CARD2, "padding": "4px 8px",
                        "borderRadius": "5px", "marginBottom": "8px"}),
    ] + [html.Div([
        html.Span(f"{p.port:<6}",
                  style={"color": RED if p.port in HI else
                         (ORANGE if p.port in MED else GREEN),
                         "fontFamily": "monospace", "fontWeight": "700",
                         "fontSize": "10px"}),
        html.Span(f"{p.protocol:<5}",
                  style={"color": "#444", "fontFamily": "monospace",
                         "fontSize": "10px"}),
        html.Span(f"{p.service:<18}",
                  style={"color": CYAN, "fontFamily": "monospace",
                         "fontSize": "10px"}),
        html.Span(p.version, style={"color": TEXT, "fontSize": "9px"}),
    ], style={"borderBottom": "1px solid #111", "padding": "3px 2px"})
        for p in nr.open_ports])


def _build_blood_panel(br) -> html.Div:
    if not br or not br.success:
        return _ph("Run scan to see attack paths")
    def kv(label, val, col):
        return html.Div([
            html.Span(label, style={"color": TEXT, "fontSize": "10px"}),
            html.Span(str(val),
                      style={"color": col, "fontWeight": "700",
                             "fontSize": "10px", "fontFamily": "monospace"}),
        ], style={"display": "flex", "justifyContent": "space-between",
                  "marginBottom": "3px"})

    path_rows = [html.Div([
        dbc.Badge(ap.risk,
                  style={"backgroundColor": SEV_COL.get(ap.risk, TEXT),
                         "color": "#000", "fontSize": "8px",
                         "fontWeight": "800", "marginRight": "5px"}),
        html.Span(ap.source, style={"color": ORANGE, "fontWeight": "700",
                                    "fontSize": "10px"}),
        html.Span("→", style={"color": "#333", "margin": "0 4px"}),
        html.Span(ap.target, style={"color": RED, "fontWeight": "700",
                                    "fontSize": "10px"}),
        html.Div(f"via {ap.relationship}",
                 style={"color": "#444", "fontSize": "9px", "marginLeft": "2px"}),
    ], style={"borderBottom": "1px solid #111", "padding": "4px 2px"})
        for ap in br.attack_paths]

    return html.Div([
        kv("Users",     br.users_found, CYAN),
        kv("Computers", br.computers,   CYAN),
        kv("DA Paths",  br.da_paths,    RED),
        html.Div("Attack Paths",
                 style={"color": RED, "fontWeight": "700", "fontSize": "10px",
                        "margin": "8px 0 5px", "borderTop": BORDER,
                        "paddingTop": "6px"}),
    ] + path_rows)


def _ph(text: str) -> html.Div:
    return html.Div(text, style={"color": "#2a2d3e", "fontStyle": "italic",
                                 "padding": "16px", "textAlign": "center",
                                 "fontSize": "11px"})


# ── Legacy stubs ───────────────────────────────────────────────────────────────
def layout_adt_dashboard():       return layout_pingcastle_live()
def layout_adt_assessments():     return layout_pingcastle_live()
def layout_adt_domain_analysis(): return layout_pingcastle_live()
def layout_adt_privilege():       return layout_pingcastle_live()
def layout_adt_trust():           return layout_pingcastle_live()
def layout_adt_config():          return layout_pingcastle_live()
def layout_adt_risk():            return layout_pingcastle_live()
def layout_adt_reports():         return layout_pingcastle_live()
def layout_adt_history():         return layout_pingcastle_live()
def layout_adt_settings():        return layout_pingcastle_live()
