import dash
from dash import html, dcc, callback
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import dash_cytoscape as cyto
from neo4j import GraphDatabase
from dash.exceptions import PreventUpdate
from dash.dependencies import Input, Output, State, ALL

# Theme variables
bg_dark = "#1c1e26"
panel_bg = "#232530"
text_col = "#a2a5b5"
accent_cyan = "#42b9f5"
accent_green = "#42f593"
accent_red = "#f54254"
accent_orange = "#f5a742"
accent_yellow = "#f5d142"

def _header(title, subtitle):
    return dbc.Row([
        dbc.Col([
            html.H3(title, style={"color": "#fff", "marginBottom": "0"}),
            html.P(subtitle, style={"color": text_col, "fontSize": "0.9rem"})
        ])
    ], className="mb-4 mt-3")

def _placeholder_card(title, text="Data will populate here after an Active Directory Assessment."):
    return dbc.Card([
        dbc.CardBody([
            html.H5(title, style={"color": "#fff", "marginBottom": "15px"}),
            html.Div(text, style={"color": text_col, "fontStyle": "italic", "padding": "20px", "textAlign": "center"})
        ])
    ], style={"backgroundColor": panel_bg, "border": "none", "borderRadius": "10px", "height": "100%", "marginBottom": "20px"})

# 1. Dashboard (Executive Overview)
def layout_adt_dashboard():
    return dbc.Container([
        _header("Active Directory Dashboard", "Executive Overview & High-level AD Health Visibility"),
        dbc.Row([
            dbc.Col(_placeholder_card("Overall AD Health Score", "A+ (Simulated)"), md=3),
            dbc.Col(_placeholder_card("Risk Breakdown", "Critical: 2 | High: 5 | Medium: 12"), md=6),
            dbc.Col(_placeholder_card("Privileged Accounts", "47 Domain Admins"), md=3),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("Top 10 Critical Findings", "1. Domain Admin passwords stale\n2. Print Spooler on DC"), md=6),
            dbc.Col(_placeholder_card("Trend Graph", "Score improving over 30 days."), md=6),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 2. Assessments
def layout_adt_assessments():
    return dbc.Container([
        _header("AD Assessments", "Run and manage Active Directory scans"),
        dbc.Row([
            dbc.Col([
                dbc.Button("Run Full Health Assessment", color="primary", className="me-2"),
                dbc.Button("Run Quick Scan", color="info", className="me-2"),
                dbc.Button("Schedule Scan", color="secondary"),
            ], className="mb-4")
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("Scan Status", "Last scan run: Today at 08:00 AM"), md=6),
            dbc.Col(_placeholder_card("Scan Logs", "Validating LDAP connectivity... OK\nChecking SYSVOL... OK"), md=6),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 3. Domain Analysis
def layout_adt_domain_analysis():
    return dbc.Container([
        _header("Domain Analysis", "Structural and hygiene analysis of the AD Environment"),
        dbc.Row([
            dbc.Col(_placeholder_card("Domain Controllers Overview"), md=4),
            dbc.Col(_placeholder_card("Stale Computer Accounts"), md=4),
            dbc.Col(_placeholder_card("Stale User Accounts"), md=4),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("OU Structure Review"), md=6),
            dbc.Col(_placeholder_card("GPO Inventory"), md=6),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 4. Privilege & Access Review
def layout_adt_privilege():
    return dbc.Container([
        _header("Privilege & Access Review", "Attack surface & escalation risks (BloodHound style)"),
        dbc.Row([
            dbc.Col(_placeholder_card("Domain Admins Review"), md=6),
            dbc.Col(_placeholder_card("Enterprise Admins Review"), md=6),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("Nested Groups Analysis"), md=4),
            dbc.Col(_placeholder_card("Excessive Privileges (GenericAll)"), md=4),
            dbc.Col(_placeholder_card("Shadow Admin Detection"), md=4),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 5. Trust & Delegation
def layout_adt_trust():
    return dbc.Container([
        _header("Trust & Delegation", "Lateral movement risk detection"),
        dbc.Row([
            dbc.Col(_placeholder_card("Domain Trust Relationships"), md=6),
            dbc.Col(_placeholder_card("Unconstrained Delegation"), md=6),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("Constrained Delegation"), md=6),
            dbc.Col(_placeholder_card("Kerberos Configuration Risks"), md=6),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 6. Configuration & Policy
def layout_adt_config():
    return dbc.Container([
        _header("Configuration & Policy", "Security hygiene standards"),
        dbc.Row([
            dbc.Col(_placeholder_card("Password Policy Review"), md=4),
            dbc.Col(_placeholder_card("SMB Signing Status"), md=4),
            dbc.Col(_placeholder_card("LDAP Signing Status"), md=4),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("NTLM Configuration"), md=6),
            dbc.Col(_placeholder_card("Weak Encryption Usage"), md=6),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 7. Risk & Scoring
def layout_adt_risk():
    return dbc.Container([
        _header("Risk & Scoring", "Categorized vulnerability review"),
        dbc.Row([
            dbc.Col(_placeholder_card("Overall Risk Score"), md=4),
            dbc.Col(_placeholder_card("Critical Findings"), md=4),
            dbc.Col(_placeholder_card("Maturity Score"), md=4),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("Attack Path Risk Score"), md=6),
            dbc.Col(_placeholder_card("Compliance Mapping (CIS / MITRE)"), md=6),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 8. Reports
def layout_adt_reports():
    return dbc.Container([
        _header("Reporting", "Exporting & Documentation"),
        dbc.Row([
            dbc.Col([
                dbc.Button("View Latest HTML Report", color="info", className="w-100 mb-3"),
                dbc.Button("Download Executive Summary (PDF)", color="primary", className="w-100 mb-3"),
                dbc.Button("Export XML / CSV", color="secondary", className="w-100 mb-3"),
            ], md=4),
            dbc.Col(_placeholder_card("Recent Reports Archive"), md=8),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 9. History & Trends
def layout_adt_history():
    return dbc.Container([
        _header("History & Trends", "Long-term security tracking"),
        dbc.Row([
            dbc.Col(_placeholder_card("Historical Risk Scores"), md=6),
            dbc.Col(_placeholder_card("Remediation Progress"), md=6),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("Findings Closed vs Open"), md=12),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})

# 10. Settings
def layout_adt_settings():
    return dbc.Container([
        _header("Settings", "PingCastle Configuration & Integrations"),
        dbc.Row([
            dbc.Col(_placeholder_card("Domain Settings & Credentials"), md=6),
            dbc.Col(_placeholder_card("Integration (SIEM / Ticketing)"), md=6),
        ]),
        dbc.Row([
            dbc.Col(_placeholder_card("Alert Thresholds & Email Notifications"), md=12),
        ]),
    ], fluid=True, style={"backgroundColor": bg_dark, "minHeight": "100vh", "padding": "20px"})
