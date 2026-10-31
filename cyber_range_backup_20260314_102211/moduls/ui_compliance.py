"""
ui_compliance.py
Compliance & GRC Dashboard
PCI-DSS · HIPAA · ISO 27001 · NIST CSF · CIS Controls · SOC 2 ·
Gap Analysis · Evidence Collection · AI Remediation · DORA / NIS2
"""
from __future__ import annotations

import json
from datetime import datetime

from dash import callback, dcc, html, Input, Output, State, ctx, ALL, MATCH
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
from cyber_range.moduls.compliance_data import (
    QUESTIONNAIRES_BY_FRAMEWORK,
    MASTER_CONTROL_MATRIX,
    NIST_800_53_CATALOG
)

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "6px", "fontSize": "13px"}
BTN_SM    = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL     = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
             "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}

STATUS_CLR = {
    "compliant":     "#27ae60",
    "partial":       "#f1c40f",
    "non-compliant": "#c0392b",
    "not-applicable":"#636e72",
}
STATUS_ICON = {
    "compliant": "✅", "partial": "⚠️",
    "non-compliant": "❌", "not-applicable": "—",
}

# ── Framework definitions ─────────────────────────────────────────────────────
FRAMEWORKS: dict[str, list[dict]] = {
    "pci-dss": [
        {"id": "1", "control": "Install and Maintain Network Security Controls",
         "desc": "Firewalls and routers restrict inbound/outbound traffic"},
        {"id": "2", "control": "Apply Secure Configurations to All System Components",
         "desc": "No vendor default passwords; hardening standards applied"},
        {"id": "3", "control": "Protect Stored Account Data",
         "desc": "PAN data encrypted or truncated; CHD protected at rest"},
        {"id": "4", "control": "Protect Cardholder Data with Strong Cryptography",
         "desc": "TLS 1.2+ for all transmissions; no legacy protocols"},
        {"id": "5", "control": "Protect All Systems Against Malware",
         "desc": "Anti-malware deployed and updated on all systems"},
        {"id": "6", "control": "Develop and Maintain Secure Systems and Software",
         "desc": "Patching, SDLC security, vulnerability management"},
        {"id": "7", "control": "Restrict Access to System Components and CHD",
         "desc": "Need-to-know access control; deny by default"},
        {"id": "8", "control": "Identify Users and Authenticate Access",
         "desc": "MFA for all non-console admin access and CDE access"},
        {"id": "9", "control": "Restrict Physical Access to Cardholder Data",
         "desc": "Physical security controls for CDE areas"},
        {"id": "10", "control": "Log and Monitor All Access",
         "desc": "Audit trails; logs retained for 12 months; SIEM alerts"},
        {"id": "11", "control": "Test Security of Systems and Networks Regularly",
         "desc": "Quarterly ASV scans; annual pen tests; WAF"},
        {"id": "12", "control": "Support Information Security with Org Policies",
         "desc": "Security policies, risk assessments, training programme"},
    ],
    "iso27001": [
        {"id": "A.5",  "control": "Organisational Controls",
         "desc": "Policies, roles, responsibilities, threat intelligence"},
        {"id": "A.6",  "control": "People Controls",
         "desc": "Screening, T&Cs, disciplinary, remote working"},
        {"id": "A.7",  "control": "Physical Controls",
         "desc": "Physical security, clean desk, clear screen, equipment"},
        {"id": "A.8",  "control": "Technological Controls",
         "desc": "User endpoints, access control, cryptography, logging"},
        {"id": "A.8.1","control": "User Endpoint Devices",
         "desc": "Managed endpoints, MDM, BYOD policy"},
        {"id": "A.8.8","control": "Management of Technical Vulnerabilities",
         "desc": "Patch management, vulnerability scanning, disclosure"},
        {"id": "A.8.16","control":"Monitoring Activities",
         "desc": "Network monitoring, anomaly detection, SIEM"},
        {"id": "A.8.23","control":"Web Filtering",
         "desc": "URL filtering, malicious content blocking"},
        {"id": "A.8.28","control":"Secure Coding",
         "desc": "SAST, DAST, code review, secure SDLC"},
    ],
    "nist-csf": [
        {"id": "GV",   "control": "Govern",
         "desc": "Cybersecurity risk management strategy, expectations, policy"},
        {"id": "ID",   "control": "Identify",
         "desc": "Asset management, risk assessment, improvement planning"},
        {"id": "PR",   "control": "Protect",
         "desc": "Identity management, awareness, data security, resilience"},
        {"id": "DE",   "control": "Detect",
         "desc": "Continuous monitoring, adverse event detection"},
        {"id": "RS",   "control": "Respond",
         "desc": "Incident management, analysis, communication, containment"},
        {"id": "RC",   "control": "Recover",
         "desc": "Incident recovery, communication, improvements"},
    ],
    "hipaa": [
        {"id": "164.308(a)(1)", "control": "Security Management Process",
         "desc": "Risk analysis, risk management, sanction policy, reviews"},
        {"id": "164.308(a)(3)", "control": "Workforce Security",
         "desc": "Authorisation, supervision, termination procedures"},
        {"id": "164.308(a)(4)", "control": "Information Access Management",
         "desc": "Isolating healthcare clearinghouse, access authorisation"},
        {"id": "164.308(a)(5)", "control": "Security Awareness and Training",
         "desc": "Malicious software protection, log-in monitoring, passwords"},
        {"id": "164.308(a)(6)", "control": "Security Incident Procedures",
         "desc": "Response and reporting for security incidents"},
        {"id": "164.312(a)(1)", "control": "Access Control",
         "desc": "Unique user IDs, emergency access, automatic logoff, encryption"},
        {"id": "164.312(b)",   "control": "Audit Controls",
         "desc": "Hardware, software, procedural mechanisms to record/examine activity"},
        {"id": "164.312(e)(1)","control": "Transmission Security",
         "desc": "Encryption for ePHI transmitted over networks"},
    ],
    "cis": [
        {"id": "IG1.1", "control": "Enterprise Asset Inventory",
         "desc": "Actively manage and track all enterprise assets"},
        {"id": "IG1.4", "control": "Software Inventory",
         "desc": "Actively manage licensed software on all enterprise assets"},
        {"id": "IG2.1", "control": "Establish an Access Control Policy",
         "desc": "Access control policies based on business need"},
        {"id": "IG2.2", "control": "Use Unique Passwords",
         "desc": "Use unique passwords and MFA for all accounts"},
        {"id": "IG2.7", "control": "Establish a Data Management Process",
         "desc": "Data classification, retention, disposal processes"},
        {"id": "IG3.1", "control": "Establish & Maintain Vulnerability Mgmt",
         "desc": "Track and remediate vulnerabilities on priority basis"},
        {"id": "IG3.4", "control": "Perform Penetration Testing",
         "desc": "External and internal pen testing at least annually"},
        {"id": "IG3.14","control": "Conduct Audit Log Management",
         "desc": "Collect, alert, review, and retain audit logs"},
    ],
    "soc2": [
        {"id": "CC1", "control": "Control Environment",
         "desc": "Integrity and ethical values; oversight by board/management"},
        {"id": "CC2", "control": "Communication & Information",
         "desc": "Internal/external communication; financial reporting info"},
        {"id": "CC3", "control": "Risk Assessment",
         "desc": "Fraud risk, change management risk assessment processes"},
        {"id": "CC4", "control": "Monitoring Activities",
         "desc": "Ongoing and separate evaluations; deficiency communication"},
        {"id": "CC5", "control": "Control Activities — Policies",
         "desc": "Policies that address risks; deploy control activities"},
        {"id": "CC6", "control": "Logical & Physical Access",
         "desc": "Restrict logical/physical access; MFA; least privilege"},
        {"id": "CC7", "control": "System Operations",
         "desc": "Detect and respond to threats, anomalies, and incidents"},
        {"id": "CC8", "control": "Change Management",
         "desc": "Authorise, design, test, approve, deploy changes"},
        {"id": "CC9", "control": "Risk Mitigation",
         "desc": "Business disruption risk; vendor / business partner risk"},
        {"id": "A1",  "control": "Availability",
         "desc": "Meet availability commitments and system requirements"},
        {"id": "C1",  "control": "Confidentiality",
         "desc": "Protect confidential information per commitments"},
    ],
    "gdpr": [
        {"id": "Art.5",  "control": "Data Processing Principles",
         "desc": "Lawfulness, fairness, transparency, purpose limitation, data minimisation"},
        {"id": "Art.6",  "control": "Lawful Basis for Processing",
         "desc": "Consent, contract, legal obligation, legitimate interests"},
        {"id": "Art.13", "control": "Transparency & Privacy Notice",
         "desc": "Provide comprehensive privacy information at point of collection"},
        {"id": "Art.17", "control": "Right to Erasure (RTBF)",
         "desc": "Process individual deletion requests within 30 days"},
        {"id": "Art.25", "control": "Data Protection by Design",
         "desc": "Privacy by design; data minimisation at system level"},
        {"id": "Art.28", "control": "Data Processor Agreements",
         "desc": "DPAs in place with all processors; liability defined"},
        {"id": "Art.32", "control": "Security of Processing",
         "desc": "Encryption at rest/transit; pseudonymisation; resilience"},
        {"id": "Art.33", "control": "Breach Notification — Authority",
         "desc": "Report breaches to DPA within 72 hours"},
        {"id": "Art.35", "control": "Data Protection Impact Assessment",
         "desc": "DPIA required for high-risk processing activities"},
        {"id": "Art.37", "control": "Data Protection Officer",
         "desc": "Appoint DPO where mandatory; publish contact details"},
    ],
    "cmmc": [
        {"id": "AC.1.001", "control": "Authorised Access Control",
         "desc": "Limit information system access to authorised users"},
        {"id": "AC.1.002", "control": "Access to Approved Transactions",
         "desc": "Limit access to types of transactions authorised users can execute"},
        {"id": "AU.2.042", "control": "Audit Event Review",
         "desc": "Review and update logged events for anomalous activity"},
        {"id": "IA.1.076", "control": "User Identification",
         "desc": "Identify information system users, processes, and devices"},
        {"id": "IA.1.077", "control": "User Authentication",
         "desc": "Authenticate identities before allowing system access"},
        {"id": "CM.2.061", "control": "Baseline Configurations",
         "desc": "Establish and maintain baseline configurations of systems"},
        {"id": "IR.2.092", "control": "Incident Response",
         "desc": "Track, document, and report incidents to designated officials"},
        {"id": "RA.3.144", "control": "CVE / Vulnerability Scan",
         "desc": "Periodically scan for vulnerabilities using updated tools"},
        {"id": "SC.3.177", "control": "CUI Encryption",
         "desc": "Employ FIPS-validated cryptography when used to protect CUI"},
        {"id": "SI.1.210", "control": "Malicious Code Protection",
         "desc": "Provide protection from malicious code at appropriate locations"},
    ],
    "nis2": [
        {"id": "Art.21.a", "control": "Risk Analysis & Security Policies",
         "desc": "Policies on information security risk analysis and IS security"},
        {"id": "Art.21.b", "control": "Incident Handling",
         "desc": "Incident handling including detection, analysis, containment"},
        {"id": "Art.21.c", "control": "Business Continuity & Crisis Mgmt",
         "desc": "BCM, DR, crisis management; backup management procedures"},
        {"id": "Art.21.d", "control": "Supply Chain Security",
         "desc": "Security in supply chain including supplier/service relationships"},
        {"id": "Art.21.e", "control": "Acquisition & Development Security",
         "desc": "Security in network/IS acquisition, development, maintenance"},
        {"id": "Art.21.f", "control": "Access Control & Asset Management",
         "desc": "Policies for access control, asset management, privileged access"},
        {"id": "Art.21.g", "control": "Cryptography & Encryption",
         "desc": "Use of cryptography and, where appropriate, encryption"},
        {"id": "Art.21.h", "control": "HR Security & Multi-Factor Auth",
         "desc": "HR security policies, access control policies, MFA/continuous auth"},
        {"id": "Art.23",   "control": "Incident Notification — CSIRT",
         "desc": "Early warning within 24h; notification within 72h; final report 30 days"},
    ],
    "dora": [
        {"id": "Art.5",  "control": "ICT Risk Management Framework",
         "desc": "Robust ICT risk management framework; CISO accountability"},
        {"id": "Art.9",  "control": "Protection & Prevention Measures",
         "desc": "ICT systems identification, classification, and protection"},
        {"id": "Art.10", "control": "Detection Controls",
         "desc": "Detect anomalous activities; ICT-related incident detection"},
        {"id": "Art.11", "control": "BCM & DR Policies",
         "desc": "Business continuity and disaster recovery plans; RTO/RPO defined"},
        {"id": "Art.13", "control": "ICT Incident Classification",
         "desc": "Classify, record, and report all major ICT-related incidents"},
        {"id": "Art.17", "control": "Major Incident Reporting",
         "desc": "Report major incidents to competent authorities within defined timelines"},
        {"id": "Art.19", "control": "Digital Operational Resilience Testing",
         "desc": "Basic testing programme; TLPT for significant entities"},
        {"id": "Art.28", "control": "ICT Third-Party Risk Management",
         "desc": "Policy for ICT third-party risk; register of arrangements"},
        {"id": "Art.30", "control": "Key Contractual Provisions",
         "desc": "Contract clauses: audit rights, SLAs, exit strategies, DORA alignment"},
    ],
    "iso42001": [
        {"id": "4",    "control": "Context of the Organisation",
         "desc": "Understand AI context, stakeholders, intended use, and AI policy scope"},
        {"id": "5",    "control": "Leadership & Commitment",
         "desc": "Top management responsibilities; AI policy; organisational roles"},
        {"id": "6",    "control": "Planning — AI Risk & Opportunity",
         "desc": "AI risk assessment; objectives; plans to address risks"},
        {"id": "7",    "control": "Support Resources",
         "desc": "Competence, awareness, communication, documented information"},
        {"id": "8",    "control": "Operation — AI System Development",
         "desc": "Operational planning; AI system impact assessment; data governance"},
        {"id": "8.4",  "control": "AI System Impact Assessment",
         "desc": "Identify and evaluate AI impacts on individuals and society"},
        {"id": "9",    "control": "Performance Evaluation",
         "desc": "Monitoring, measurement, AI system audits, management review"},
        {"id": "10",   "control": "Improvement",
         "desc": "Nonconformity, corrective action, continual AI ISMS improvement"},
        {"id": "A.6",  "control": "AI System Design Controls",
         "desc": "Functional requirements, bias testing, robustness, explainability"},
        {"id": "A.9",  "control": "Third-Party AI Governance",
         "desc": "Supplier AI controls, data sharing agreements, third-party AI audits"},
    ],
    "nist-800-53": NIST_800_53_CATALOG,
    "master-matrix": MASTER_CONTROL_MATRIX,
}

# ── Framework gallery metadata (icon, colour, shortname) ───────────────────
FRAMEWORK_GALLERY = [
    ("master-matrix", "⌘", "#ffb142", "Master Matrix"),
    ("pci-dss",      "💳", "#0066cc", "PCI-DSS v4"),
    ("iso27001",     "🔒", "#c0392b", "ISO 27001"),
    ("nist-csf",     "🏛", "#2ecc71", "NIST CSF 2.0"),
    ("nist-800-53",  "📘", "#1a3a6c", "NIST 800-53 R5"),
    ("hipaa",        "🏥", "#16a085", "HIPAA"),
    ("cis",          "🛡", "#8e44ad", "CIS Controls"),
    ("soc2",         "🔐", "#e67e22", "SOC 2 Type II"),
    ("gdpr",         "🇪🇺", "#2980b9", "GDPR"),
    ("cmmc",         "🦅", "#1a3a5c", "CMMC 2.0"),
    ("nis2",         "🌐", "#27ae60", "NIS2"),
    ("dora",         "🏦", "#c0392b", "DORA"),
    ("iso42001",     "🤖", "#7f8c8d", "ISO 42001"),
]




def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)

def _label(t): return html.Div(t, style=LABEL)


def _status_selector(ctrl_id: str, fw: str) -> dbc.Select:
    return dbc.Select(
        id={"type": "ctrl-status", "fw": fw, "id": ctrl_id},
        options=[
            {"label": "✅ Compliant",       "value": "compliant"},
            {"label": "⚠️ Partial",         "value": "partial"},
            {"label": "❌ Non-Compliant",   "value": "non-compliant"},
            {"label": "— Not Applicable",   "value": "not-applicable"},
        ],
        value="non-compliant",
        style={**INPUT_STY, "fontSize": "11px", "padding": "2px 4px",
               "height": "28px"},
    )


def _control_row(ctrl: dict, fw: str) -> html.Div:
    mappings_ui = []
    if "mappings" in ctrl:
        mappings_ui = [
            html.Span(
                mapping, 
                style={
                    "background": "#2c3e50", "color": "#ecf0f1", 
                    "fontSize": "9px", "marginRight": "4px", "padding": "2px 6px", 
                    "borderRadius": "4px", "fontWeight": "600", "display": "inline-block", "marginTop": "4px"
                }
            ) for mapping in ctrl["mappings"]
        ]

    return html.Div([
        dbc.Row([
            dbc.Col([
                html.Span(f"{ctrl.get('id', '')}",
                          style={"color": "#3498db", "fontWeight": "700",
                                 "fontSize": "11px", "marginRight": "6px"}),
                html.Span(ctrl.get("control") or ctrl.get("name", ""),
                          style={"color": "#e0e0e0", "fontSize": "12px",
                                 "fontWeight": "600"}),
                html.Div(ctrl.get("desc", ""),
                         style={"color": "#8e9eb0", "fontSize": "10px",
                                "marginTop": "2px", "paddingLeft": "4px"}),
                html.Div(mappings_ui) if mappings_ui else None
            ], width=9),
            dbc.Col(_status_selector(ctrl.get("id", ""), fw), width=3),
        ], align="center"),
    ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}"})


def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="gc-assessments", data={}),
        dcc.Store(id="gc-gap-store",   data=None),
        dcc.Store(id="gc-evidence-store", data=[]),
        dcc.Store(id="gc-questionnaire-federal-store", data={}),
        dcc.Store(id="gc-questionnaire-private-store", data={}),
        dcc.Store(id="gc-sent-log-store", data=[]),
        # Always-present outputs so callbacks fire regardless of active tab
        html.Div(id="gc-score-out",  style={"display": "none"}),
        html.Div(id="gc-gap-detail", style={"display": "none"}),

        # ── Header ───────────────────────────────────────────────────────────
        html.Div([
            html.H4("📋 Compliance & GRC Dashboard",
                    style={"color": "#FFD700", "fontWeight": "700", "margin": "0",
                           "textShadow": "0 0 10px #FFD70044"}),
            html.Div("PCI-DSS · ISO 27001 · NIST CSF · HIPAA · CIS · SOC2 · "
                     "GDPR · CMMC · NIS2 · DORA · ISO 42001  ·  Gap Analysis · AI Remediation",
                     style={"color": "#636e72", "fontSize": "12px"}),
        ], style={"marginBottom": "10px"}),

        # ── Framework Gallery Banner — clickable tiles ───────────────────────
        html.Div([
            html.Div(
                [
                    dbc.Button(
                        [
                            html.Div(icon, style={"fontSize": "1.4rem", "lineHeight": "1"}),
                            html.Div(name, style={"fontSize": "0.65rem", "color": "#ccc",
                                                  "fontWeight": "600", "marginTop": "3px",
                                                  "textAlign": "center", "lineHeight": "1.2"}),
                        ],
                        id={"type": "fw-tile", "fw": fw_key},
                        n_clicks=0,
                        style={
                            "display": "flex", "flexDirection": "column",
                            "alignItems": "center", "justifyContent": "center",
                            "background": f"linear-gradient(135deg, {clr}22, {clr}11)",
                            "border": f"1px solid {clr}55",
                            "borderRadius": "8px", "padding": "8px 12px",
                            "minWidth": "80px", "cursor": "pointer",
                            "transition": "all 0.2s",
                        },
                        color="link", className="p-0",
                    )
                    for fw_key, icon, clr, name in FRAMEWORK_GALLERY
                ],
                style={
                    "display": "flex", "flexWrap": "nowrap", "gap": "8px",
                    "overflowX": "auto", "paddingBottom": "6px",
                    "scrollbarWidth": "thin", "scrollbarColor": "#333 transparent",
                }
            ),
        ], style={
            "background": "#111317", "border": "1px solid #1e2230",
            "borderRadius": "10px", "padding": "12px 16px",
            "marginBottom": "16px",
        }),

        # ── Framework count badge ────────────────────────────────────────────
        html.Div([
            dbc.Badge(f"✅  {len(FRAMEWORK_GALLERY)} Supported GRC Frameworks",
                      color="secondary", className="me-2",
                      style={"fontSize": "0.72rem", "background": "#2c3347",
                             "color": "#FFD700", "padding": "5px 12px"}),
        ], style={"marginBottom": "16px"}),


        dbc.Row([
            # ── Left ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🏢 Assessment Config",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("Organisation"),
                    dbc.Input(id="gc-org", placeholder="ACME Corp",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Framework"),
                    dbc.Select(id="gc-framework",
                               options=[
                                   {"label": "💳  PCI-DSS v4.0",         "value": "pci-dss"},
                                   {"label": "🔒  ISO 27001:2022",        "value": "iso27001"},
                                   {"label": "🏛  NIST CSF 2.0",          "value": "nist-csf"},
                                   {"label": "📘  NIST 800-53 Rev 5",     "value": "nist-800-53"},
                                   {"label": "🏥  HIPAA",                 "value": "hipaa"},
                                   {"label": "🛡  CIS Controls v8",       "value": "cis"},
                                   {"label": "🔐  SOC 2 Type II",         "value": "soc2"},
                                   {"label": "🇪🇺  GDPR",                 "value": "gdpr"},
                                   {"label": "🦅  CMMC 2.0",              "value": "cmmc"},
                                   {"label": "🌐  NIS2 Directive",        "value": "nis2"},
                                   {"label": "🏦  DORA",                  "value": "dora"},
                                   {"label": "🤖  ISO 42001 (AI ISMS)",   "value": "iso42001"},
                               ], value="nist-800-53",
                               style={**INPUT_STY, "marginBottom": "8px"}),

                    _label("Assessor"),
                    dbc.Input(id="gc-assessor", placeholder="John Smith",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Assessment Date"),
                    dbc.Input(id="gc-date",
                              value=datetime.now().strftime("%Y-%m-%d"),
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("📊 Calculate Score", id="gc-score-btn",
                               color="primary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("✨ AI Gap Analysis", id="gc-ai-gap",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("📥 Export Report", id="gc-export-btn",
                               color="outline-secondary", size="sm",
                               style={**BTN_SM, "width": "100%"}),
                    dcc.Download(id="gc-download"),
                    html.Div(id="gc-score-display",
                             style={"marginTop": "10px"}),
                ),
                _card(
                    html.Div("🌍 Regulatory Calendar",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span(f"{reg}: ", style={"color": "#3498db",
                                                       "fontWeight": "700",
                                                       "fontSize": "11px"}),
                        html.Span(note, style={"color": "#b0b0b0",
                                               "fontSize": "10px"}),
                      ], style={"marginBottom": "5px"})
                      for reg, note in [
                          ("DORA",   "EU – In force since Jan 2025"),
                          ("NIS2",   "EU – Oct 2024 deadline passed"),
                          ("SEC Cyber", "US – Effective Dec 2023"),
                          ("GDPR",   "Ongoing; €20M max fine"),
                          ("PCI-DSS v4", "Full enforcement Mar 2025"),
                          ("AI Act",    "EU – Phased from 2024-2027"),
                      ]],
                ),
            ], width=3),

            # ── Centre ───────────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="gc-tabs", active_tab="gc-tab-controls",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="🔥 Risk",         tab_id="gc-tab-risk"),
                     dbc.Tab(label="⚠️ Incident",     tab_id="gc-tab-incident"),
                     dbc.Tab(label="🔏 Privacy",      tab_id="gc-tab-privacy"),
                     dbc.Tab(label="✅ Controls",     tab_id="gc-tab-controls"),
                     dbc.Tab(label="📊 Gap Analysis", tab_id="gc-tab-gap"),
                     dbc.Tab(label="🗂️ Evidence",     tab_id="gc-tab-evidence"),
                     dbc.Tab(label="🔍 Audit",        tab_id="gc-tab-audit"),
                     dbc.Tab(label="📜 Policy",       tab_id="gc-tab-policy"),
                     dbc.Tab(label="🆘 BCP",          tab_id="gc-tab-bcp"),
                     dbc.Tab(label="📋 Questionnaire", tab_id="gc-tab-questionnaire"),
                     dbc.Tab(label="💬 Client Comms",  tab_id="gc-tab-comms"),
                 ]),
                html.Div(id="gc-phase-content"),
            ], width=6),

            # ── Right ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🤖 AI Analysis",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    html.Div(
                        "Click ✨ AI Gap Analysis to generate AI-powered remediation\n"
                        "guidance, control recommendations, and priority actions\n"
                        "for the selected framework.",
                        id="gc-ai-out",
                        style={"color": "#636e72", "fontSize": "11px",
                               "whiteSpace": "pre-wrap", "fontStyle": "italic",
                               "minHeight": "80px", "maxHeight": "320px",
                               "overflowY": "auto", "lineHeight": "1.6"},
                    ),
                ),
                _card(
                    html.Div("📋 Evidence Requirements",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    html.Div(id="gc-evidence-req-panel",
                             style={"fontSize": "11px"}),
                ),
            ], width=3),
        ]),

        # ── Standards & Regulations Scrolling Ticker ─────────────────────────
        # (CSS: assets/compliance_ticker.css — grcTicker keyframe)
        html.Div([
            # Left label pill
            html.Span("📋 GRC", style={
                "background": "#FFD700", "color": "#0d1117",
                "fontWeight": "800", "fontSize": "0.7rem",
                "padding": "3px 10px", "borderRadius": "4px",
                "marginRight": "12px", "flexShrink": "0",
                "letterSpacing": "1px",
            }),
            # Red pulse dot
            html.Span("●", style={
                "color": "#c0392b", "fontSize": "0.7rem",
                "marginRight": "10px", "flexShrink": "0",
            }),
            # Scrolling track wrapper
            html.Div(
                # Double the content for seamless loop (0% → -50%)
                html.Span(
                    ("  ·  ".join([
                        f"{icon} {name}"
                        for _, icon, _, name in FRAMEWORK_GALLERY
                    ]) + "      ") * 2,
                    className="grc-ticker-track",
                    style={
                        "color": "#FFD700",
                        "fontSize": "0.76rem",
                        "fontFamily": "monospace",
                        "fontWeight": "600",
                        "letterSpacing": "0.8px",
                    }
                ),
                style={"overflow": "hidden", "width": "100%", "minWidth": "0"},
            ),
        ], style={
            "display": "flex", "alignItems": "center",
            "background": "#0a0c10",
            "border": "1px solid #FFD70044",
            "borderLeft": "4px solid #FFD700",
            "borderRadius": "6px",
            "padding": "8px 14px",
            "marginTop": "20px",
            "boxShadow": "0 0 18px #FFD70022",
            "overflow": "hidden",
        }),

    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


@callback(
    Output("gc-framework", "value"),
    Output("gc-tabs",      "active_tab"),
    Input({"type": "fw-tile", "fw": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _fw_tile_click(n_clicks_list):
    tid = ctx.triggered_id
    if not tid or not any(n_clicks_list):
        raise PreventUpdate
    return tid["fw"], "gc-tab-controls"


@callback(
    Output("gc-phase-content", "children"),
    Input("gc-tabs",           "active_tab"),
    Input("gc-framework",      "value"),
)
def render_phase(tab, fw):
    fw = fw or "nist-csf"
    controls = FRAMEWORKS.get(fw, [])

    if tab == "gc-tab-controls":
        # ── Enhanced view for NIST 800-53 Rev 5 ────────────────────────────
        if fw == "nist-800-53":
            from datetime import date as _date
            today = _date(2026, 3, 10)

            # Example pre-seeded mitigation dates (past = overdue)
            _example_dates = {
                "AC-1": "2026-01-15", "AC-2": "2026-02-01", "AC-3": "2026-03-01",
                "AC-17": "2026-04-30", "AU-2": "2026-02-28", "AU-6": "2026-01-31",
                "AU-11": "2026-06-01", "CA-2": "2026-03-31", "CA-7": "2026-05-01",
                "CM-2": "2026-02-15", "CM-6": "2026-02-20", "CM-8": "2026-03-15",
                "CP-2": "2026-01-30", "CP-9": "2026-03-20", "IA-2": "2026-03-05",
                "IA-5": "2026-03-08", "IR-1": "2026-02-10", "IR-2": "2026-03-01",
                "IR-4": "2026-02-05", "IR-5": "2026-04-30", "IR-6": "2026-05-15",
                "IR-7": "2026-06-01", "IR-8": "2026-01-20", "RA-3": "2026-02-28",
                "RA-5": "2026-03-10", "SI-2": "2026-02-01", "SI-3": "2026-03-09",
            }

            # Family colour palette
            _fam_clr = {
                "AC": "#3498db", "AU": "#9b59b6", "CA": "#1abc9c",
                "CM": "#e67e22", "CP": "#16a085", "IA": "#2980b9",
                "IR": "#e74c3c", "RA": "#f39c12", "SI": "#27ae60",
            }

            hdr = html.Tr([
                html.Th(h, style={"color": "#3498db", "fontSize": "10px", "fontWeight": "700",
                                  "background": "#1a1d24", "padding": "6px 8px",
                                  "borderBottom": "1px solid #2c3347", "whiteSpace": "nowrap"})
                for h in ["ID", "Fam", "Control Name", "NIST Control Text",
                          "Implementation Notes", "Artifact Ref", "Mitigate By", "Status"]
            ])

            ctrl_rows = []
            for c in controls:
                cid      = c["id"]
                family   = c.get("family", "")
                fam_clr  = _fam_clr.get(family, "#636e72")
                ex_date  = _example_dates.get(cid, "2026-06-30")
                try:
                    mdate = _date.fromisoformat(ex_date)
                    overdue = mdate < today
                    status_badge = html.Span(
                        "⛔ OVERDUE" if overdue else "✅ ON TRACK",
                        style={"color": "#c0392b" if overdue else "#27ae60",
                               "fontWeight": "700", "fontSize": "9px",
                               "background": "#2d0a0a" if overdue else "#0a2d15",
                               "padding": "2px 6px", "borderRadius": "4px",
                               "border": f"1px solid {'#c0392b' if overdue else '#27ae60'}"}
                    )
                    days_label = f"{(today - mdate).days}d overdue" if overdue else f"{(mdate - today).days}d left"
                    days_style = {"color": "#c0392b" if overdue else "#636e72",
                                  "fontSize": "9px", "display": "block", "marginTop": "2px"}
                except Exception:
                    status_badge = html.Span("—")
                    days_label = ""
                    days_style = {}

                ctrl_rows.append(html.Tr([
                    # Control ID
                    html.Td(html.Span(cid, style={
                        "fontFamily": "monospace", "fontWeight": "700",
                        "fontSize": "10px", "color": fam_clr})),
                    # Family badge
                    html.Td(html.Span(family, style={
                        "background": fam_clr + "33", "color": fam_clr,
                        "fontWeight": "700", "fontSize": "9px",
                        "padding": "2px 6px", "borderRadius": "4px"})),
                    # Control name
                    html.Td(c["control"], style={
                        "color": "#e0e0e0", "fontSize": "10px",
                        "fontWeight": "600", "whiteSpace": "nowrap",
                        "padding": "6px 8px", "maxWidth": "160px",
                        "overflow": "hidden", "textOverflow": "ellipsis"}),
                    # NIST control text (read-only desc)
                    html.Td(html.Div(c["desc"], style={
                        "color": "#8e9eb0", "fontSize": "9px",
                        "maxWidth": "200px", "lineHeight": "1.4",
                        "maxHeight": "50px", "overflowY": "auto"})),
                    # Implementation notes
                    html.Td(dbc.Textarea(
                        placeholder="Describe how this control is implemented…",
                        style={"background": "#0d1117", "color": "#ccc",
                               "border": "1px solid #2c3347", "fontSize": "9px",
                               "width": "160px", "height": "50px",
                               "borderRadius": "4px", "padding": "4px"},
                    )),
                    # Artifact reference
                    html.Td(dbc.Input(
                        placeholder="e.g. policy_v3.pdf | JIRA-122",
                        style={"background": "#0d1117", "color": "#ccc",
                               "border": "1px solid #2c3347", "fontSize": "9px",
                               "width": "140px", "height": "28px",
                               "borderRadius": "4px", "padding": "4px"},
                    )),
                    # Mitigation date
                    html.Td(html.Div([
                        dbc.Input(
                            value=ex_date, type="date",
                            style={"background": "#0d1117", "color": "#ccc",
                                   "border": f"1px solid {'#c0392b' if overdue else '#2c3347'}",
                                   "fontSize": "9px", "width": "120px",
                                   "height": "28px", "borderRadius": "4px",
                                   "padding": "2px 4px"},
                        ),
                        html.Span(days_label, style=days_style),
                    ])),
                    # Status badge
                    html.Td(status_badge),
                ], style={"borderBottom": "1px solid #1a1d24",
                          "background": "#1a0808" if overdue else "transparent"}))

            # Summary KPIs
            n_overdue = sum(
                1 for c in controls
                if _date.fromisoformat(_example_dates.get(c["id"], "2026-12-31")) < today
            )
            n_ok = len(controls) - n_overdue

            return _card(
                html.Div("📘 NIST 800-53 Rev 5 — Control Implementation Tracker",
                         style={"color": "#e0e0e0", "fontWeight": "700", "marginBottom": "4px"}),
                html.Div("Track implementation notes, artifact evidence, and remediation deadlines per control. "
                         "Red rows = overdue.",
                         style={"color": "#636e72", "fontSize": "11px", "marginBottom": "10px"}),
                # KPI row
                dbc.Row([
                    dbc.Col(html.Div([
                        html.Div(str(len(controls)), style={"color": "#3498db", "fontSize": "22px",
                                                             "fontWeight": "700", "textAlign": "center"}),
                        html.Div("Total Controls", style={"color": "#636e72", "fontSize": "9px", "textAlign": "center"}),
                    ], style={"background": "#1a1d24", "borderRadius": "6px", "padding": "8px"}), md=3),
                    dbc.Col(html.Div([
                        html.Div(str(n_overdue), style={"color": "#c0392b", "fontSize": "22px",
                                                         "fontWeight": "700", "textAlign": "center"}),
                        html.Div("Overdue", style={"color": "#636e72", "fontSize": "9px", "textAlign": "center"}),
                    ], style={"background": "#1a1d24", "borderRadius": "6px", "padding": "8px"}), md=3),
                    dbc.Col(html.Div([
                        html.Div(str(n_ok), style={"color": "#27ae60", "fontSize": "22px",
                                                    "fontWeight": "700", "textAlign": "center"}),
                        html.Div("On Track", style={"color": "#636e72", "fontSize": "9px", "textAlign": "center"}),
                    ], style={"background": "#1a1d24", "borderRadius": "6px", "padding": "8px"}), md=3),
                    dbc.Col(html.Div([
                        html.Div("IR", style={"color": "#e74c3c", "fontSize": "22px",
                                              "fontWeight": "700", "textAlign": "center"}),
                        html.Div("7 IR Controls", style={"color": "#636e72", "fontSize": "9px", "textAlign": "center"}),
                    ], style={"background": "#1a1d24", "borderRadius": "6px", "padding": "8px"}), md=3),
                ], className="g-2", style={"marginBottom": "12px"}),
                # Control table
                html.Div(
                    html.Table([html.Thead(hdr), html.Tbody(ctrl_rows)],
                               style={"width": "100%", "borderCollapse": "collapse"}),
                    style={"overflowX": "auto", "maxHeight": "520px", "overflowY": "auto"},
                ),
            )

        # ── Enhanced tracker: all other frameworks ──────────────────────────
        from datetime import date as _date
        today = _date(2026, 3, 10)

        # Derive a short family tag from the control ID (e.g. "AC" from "AC-2",
        # "Art" from "Art.5", "REQ" from "REQ-1.2", etc.)
        def _family_tag(cid):
            for sep in ["-", "."]:
                if sep in cid:
                    return cid.split(sep)[0]
            return cid[:3]

        # Generic colour cycle for non-NIST families
        _palette = ["#3498db","#e74c3c","#2ecc71","#f39c12","#9b59b6",
                    "#1abc9c","#e67e22","#2980b9","#16a085","#8e44ad"]
        _seen_families: dict = {}
        def _fam_colour(tag):
            if tag not in _seen_families:
                _seen_families[tag] = _palette[len(_seen_families) % len(_palette)]
            return _seen_families[tag]

        hdr = html.Tr([
            html.Th(h, style={"color": "#3498db", "fontSize": "10px", "fontWeight": "700",
                              "background": "#1a1d24", "padding": "6px 8px",
                              "borderBottom": "1px solid #2c3347", "whiteSpace": "nowrap"})
            for h in ["ID", "Grp", "Control Name", "Control Text",
                      "Implementation Notes", "Artifact Ref", "Mitigate By", "Status"]
        ])

        ctrl_rows = []
        for idx, c in enumerate(controls):
            cid     = c["id"]
            tag     = _family_tag(cid)
            fclr    = _fam_colour(tag)
            # Spread example dates across 3 months so some are naturally overdue
            day_offset = idx * 9
            from datetime import timedelta
            ex_date = (_date(2026, 1, 10) + timedelta(days=day_offset)).isoformat()

            mdate   = _date.fromisoformat(ex_date)
            overdue = mdate < today
            status_badge = html.Span(
                "⛔ OVERDUE" if overdue else "✅ ON TRACK",
                style={"color": "#c0392b" if overdue else "#27ae60",
                       "fontWeight": "700", "fontSize": "9px",
                       "background": "#2d0a0a" if overdue else "#0a2d15",
                       "padding": "2px 6px", "borderRadius": "4px",
                       "border": f"1px solid {'#c0392b' if overdue else '#27ae60'}"}
            )
            days_label = (f"{(today - mdate).days}d overdue"
                          if overdue else f"{(mdate - today).days}d left")
            days_style = {"color": "#c0392b" if overdue else "#636e72",
                          "fontSize": "9px", "display": "block", "marginTop": "2px"}

            ctrl_rows.append(html.Tr([
                html.Td(html.Span(cid, style={
                    "fontFamily": "monospace", "fontWeight": "700",
                    "fontSize": "10px", "color": fclr})),
                html.Td(html.Span(tag, style={
                    "background": fclr + "33", "color": fclr,
                    "fontWeight": "700", "fontSize": "9px",
                    "padding": "2px 5px", "borderRadius": "4px"})),
                html.Td(c.get("control",""), style={
                    "color": "#e0e0e0", "fontSize": "10px", "fontWeight": "600",
                    "padding": "6px 8px", "whiteSpace": "nowrap",
                    "maxWidth": "160px", "overflow": "hidden",
                    "textOverflow": "ellipsis"}),
                html.Td(html.Div(c.get("desc",""), style={
                    "color": "#8e9eb0", "fontSize": "9px",
                    "maxWidth": "200px", "lineHeight": "1.4",
                    "maxHeight": "50px", "overflowY": "auto"})),
                html.Td(dbc.Textarea(
                    placeholder="Describe how this control is implemented…",
                    style={"background": "#0d1117", "color": "#ccc",
                           "border": "1px solid #2c3347", "fontSize": "9px",
                           "width": "160px", "height": "50px",
                           "borderRadius": "4px", "padding": "4px"},
                )),
                html.Td(dbc.Input(
                    placeholder="e.g. policy_v3.pdf | JIRA-122",
                    style={"background": "#0d1117", "color": "#ccc",
                           "border": "1px solid #2c3347", "fontSize": "9px",
                           "width": "140px", "height": "28px",
                           "borderRadius": "4px", "padding": "4px"},
                )),
                html.Td(html.Div([
                    dbc.Input(
                        value=ex_date, type="date",
                        style={"background": "#0d1117", "color": "#ccc",
                               "border": f"1px solid {'#c0392b' if overdue else '#2c3347'}",
                               "fontSize": "9px", "width": "120px",
                               "height": "28px", "borderRadius": "4px",
                               "padding": "2px 4px"},
                    ),
                    html.Span(days_label, style=days_style),
                ])),
                html.Td(status_badge),
            ], style={"borderBottom": "1px solid #1a1d24",
                      "background": "#1a0808" if overdue else "transparent"}))

        n_overdue = sum(1 for r in ctrl_rows
                        if "1a0808" in str(r.style or {}))
        n_ok = len(controls) - n_overdue

        # Derive a nice title from the framework key
        _fw_labels = {
            "pci-dss":  "💳 PCI-DSS v4.0", "iso27001": "🔒 ISO 27001:2022",
            "nist-csf": "🏛 NIST CSF 2.0",  "hipaa":    "🏥 HIPAA",
            "cis":      "🛡 CIS Controls v8","soc2":     "🔐 SOC 2 Type II",
            "gdpr":     "🇪🇺 GDPR",          "cmmc":     "🦅 CMMC 2.0",
            "nis2":     "🌐 NIS2",           "dora":     "🏦 DORA",
            "iso42001": "🤖 ISO 42001",
        }
        fw_title = _fw_labels.get(fw, fw.upper())

        return _card(
            html.Div(f"{fw_title} — Control Implementation Tracker",
                     style={"color": "#e0e0e0", "fontWeight": "700", "marginBottom": "4px"}),
            html.Div("Track implementation notes, artifact evidence, and remediation deadlines. "
                     "Red rows = overdue.",
                     style={"color": "#636e72", "fontSize": "11px", "marginBottom": "10px"}),
            dbc.Row([
                dbc.Col(html.Div([
                    html.Div(str(len(controls)), style={"color": "#3498db", "fontSize": "22px",
                                                         "fontWeight": "700", "textAlign": "center"}),
                    html.Div("Total Controls", style={"color": "#636e72", "fontSize": "9px", "textAlign": "center"}),
                ], style={"background": "#1a1d24", "borderRadius": "6px", "padding": "8px"}), md=4),
                dbc.Col(html.Div([
                    html.Div(str(n_overdue), style={"color": "#c0392b", "fontSize": "22px",
                                                     "fontWeight": "700", "textAlign": "center"}),
                    html.Div("Overdue", style={"color": "#636e72", "fontSize": "9px", "textAlign": "center"}),
                ], style={"background": "#1a1d24", "borderRadius": "6px", "padding": "8px"}), md=4),
                dbc.Col(html.Div([
                    html.Div(str(n_ok), style={"color": "#27ae60", "fontSize": "22px",
                                               "fontWeight": "700", "textAlign": "center"}),
                    html.Div("On Track", style={"color": "#636e72", "fontSize": "9px", "textAlign": "center"}),
                ], style={"background": "#1a1d24", "borderRadius": "6px", "padding": "8px"}), md=4),
            ], className="g-2", style={"marginBottom": "12px"}),
            html.Div(
                html.Table([html.Thead(hdr), html.Tbody(ctrl_rows)],
                           style={"width": "100%", "borderCollapse": "collapse"}),
                style={"overflowX": "auto", "maxHeight": "520px", "overflowY": "auto"},
            ),
        )



    elif tab == "gc-tab-gap":
        return _card(
            html.Div("📊 Gap Analysis",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div("Click 'Calculate Score' to see gap analysis after "
                     "setting control statuses.",
                     style={"color": "#636e72", "fontSize": "11px",
                            "marginBottom": "10px"}),
            # Reads from the store (populated by calc_score callback)
            html.Div(id="gc-gap-view",
                     style={"maxHeight": "500px", "overflowY": "auto"}),
        )

    elif tab == "gc-tab-evidence":
        return _card(
            html.Div("🗂️ Evidence Collection",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("Evidence Item"),
            dbc.Input(id="gc-ev-item", placeholder="Network diagram v3.2",
                      style={**INPUT_STY, "marginBottom": "8px"}),
            _label("Control Reference"),
            dbc.Input(id="gc-ev-ctrl", placeholder="PCI-DSS Req 1.2.3",
                      style={**INPUT_STY, "marginBottom": "8px"}),
            _label("Status"),
            dbc.Select(id="gc-ev-status",
                       options=[
                           {"label": "Collected",   "value": "collected"},
                           {"label": "Pending",     "value": "pending"},
                           {"label": "Missing",     "value": "missing"},
                       ], value="pending",
                       style={**INPUT_STY, "marginBottom": "8px"}),
            _label("Notes"),
            dbc.Textarea(id="gc-ev-notes",
                         placeholder="Evidence description, location, date...",
                         style={**INPUT_STY, "height": "80px",
                                "marginBottom": "8px"}),
            dbc.Button("➕ Add Evidence", id="gc-ev-add",
                       color="outline-success", size="sm",
                       style={**BTN_SM, "marginBottom": "8px"}),
            html.Div(id="gc-ev-list",
                     style={"maxHeight": "300px", "overflowY": "auto"}),
        )

    # ── Risk Register ────────────────────────────────────────────────────────
    elif tab == "gc-tab-risk":
        def _risk_badge(level):
            colours = {"Critical":"#c0392b","High":"#e67e22",
                       "Medium":"#f1c40f","Low":"#27ae60","Info":"#3498db"}
            return html.Span(level, style={
                "background": colours.get(level,"#636e72"),
                "color":"#fff","padding":"2px 8px","borderRadius":"4px",
                "fontSize":"10px","fontWeight":"700"})

        risks = [
            ("R-01","Unpatched critical vulnerabilities on internet-facing hosts","Critical","High","High","SOC","Open"),
            ("R-02","Weak password policy enables brute-force attacks","High","Medium","High","IT Admin","In Review"),
            ("R-03","No MFA on VPN / remote access","High","High","Critical","CISO","Open"),
            ("R-04","Third-party vendor with excessive data access","Medium","Medium","High","Privacy","In Progress"),
            ("R-05","Outdated disaster recovery plan (>12 months)","Medium","Low","Medium","Risk Team","Open"),
            ("R-06","Shadow IT — unsanctioned cloud storage","Low","Medium","Medium","IT Admin","Accepted"),
        ]
        header = html.Tr([
            html.Th(h, style={"color":"#3498db","fontSize":"10px",
                              "fontWeight":"700","background":"#1a1d24",
                              "padding":"6px 8px","borderBottom":"1px solid #2c3347"})
            for h in ["ID","Risk Description","Likelihood","Impact","Severity","Owner","Status"]
        ])
        rows = [html.Tr([
            html.Td(r[0], style={"color":"#3498db","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(r[1], style={"color":"#ccc","fontSize":"10px","padding":"6px 8px"}),
            html.Td(_risk_badge(r[2])),
            html.Td(_risk_badge(r[3])),
            html.Td(_risk_badge(r[4])),
            html.Td(r[5], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
            html.Td(html.Span(r[6], style={
                "color": "#27ae60" if r[6]=="Accepted" else
                         "#e67e22" if r[6]=="In Progress" else
                         "#f1c40f" if r[6]=="In Review" else "#c0392b",
                "fontSize":"10px","fontWeight":"600"})),
        ], style={"borderBottom":"1px solid #1e2230"}) for r in risks]
        # Risk register store (holds user-added rows as list of tuples)
        _rr_store = dcc.Store(id="gc-rr-store", data=[], storage_type="memory")
        return _card(
                html.Div("🔥 Risk Register",
                         style={"color":"#e0e0e0","fontWeight":"600","marginBottom":"10px"}),
                html.Div("Integrated risk tracking linked to controls, incidents and frameworks.",
                         style={"color":"#636e72","fontSize":"11px","marginBottom":"10px"}),
                html.Table(
                    [html.Thead(header),
                     html.Tbody(rows, id="gc-rr-tbody")],
                    style={"width":"100%","borderCollapse":"collapse"},
                ),
                html.Div([
                    dbc.Row([
                        dbc.Col([_label("Risk ID"),
                                 dbc.Input(id="gc-rr-id", placeholder="R-07", style=INPUT_STY)], md=2),
                        dbc.Col([_label("Description"),
                                 dbc.Input(id="gc-rr-desc", placeholder="New risk description", style=INPUT_STY)], md=5),
                        dbc.Col([_label("Severity"), dbc.Select(id="gc-rr-severity", options=[
                            {"label":s,"value":s} for s in ["Critical","High","Medium","Low"]
                        ], value="High", style=INPUT_STY)], md=2),
                        dbc.Col([_label("Owner"),
                                 dbc.Input(id="gc-rr-owner", placeholder="Owner", style=INPUT_STY)], md=2),
                        dbc.Col([dbc.Button("➕ Add", id="gc-rr-add",
                                            color="outline-warning", size="sm",
                                            style={**BTN_SM,"marginTop":"18px"})], md=1),
                    ], className="g-2", style={"marginTop":"12px"}),
                    html.Div(id="gc-rr-feedback",
                             style={"color":"#27ae60","fontSize":"11px","marginTop":"6px"}),
                ]),
                _rr_store,
            )

    # ── Incident Register ────────────────────────────────────────────────────
    elif tab == "gc-tab-incident":
        incidents = [
            ("I-12","Unauthorized Access","High","In Progress","Network misconfiguration","SOC Analyst"),
            ("I-11","Ransomware Attempt Blocked","Critical","Resolved","Phishing email link","IR Team"),
            ("I-10","Data Exfiltration — Insider Threat","Critical","Under Review","Excess privileges","CISO"),
            ("I-09","VPN Brute-Force Attack","Medium","Resolved","No account lockout policy","IT Admin"),
            ("I-08","Data Breach — Customer PII","Critical","Resolved","SQL injection","Dev Team"),
        ]
        inc_header = html.Tr([
            html.Th(h, style={"color":"#3498db","fontSize":"10px","fontWeight":"700",
                              "background":"#1a1d24","padding":"6px 8px",
                              "borderBottom":"1px solid #2c3347"})
            for h in ["ID","Title","Severity","Status","Root Cause","Assigned To"]
        ])
        sev_col = {"Critical":"#c0392b","High":"#e67e22","Medium":"#f1c40f","Low":"#27ae60"}
        sta_col = {"Resolved":"#27ae60","In Progress":"#e67e22","Under Review":"#f1c40f"}
        inc_rows = [html.Tr([
            html.Td(i[0], style={"color":"#e67e22","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(i[1], style={"color":"#ccc","fontSize":"10px","padding":"6px 8px","fontWeight":"600"}),
            html.Td(html.Span(i[2], style={"color":sev_col.get(i[2],"#fff"),"fontSize":"10px","fontWeight":"700"})),
            html.Td(html.Span(i[3], style={"color":sta_col.get(i[3],"#aaa"),"fontSize":"10px","fontWeight":"600"})),
            html.Td(i[4], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
            html.Td(i[5], style={"color":"#b0b0b0","fontSize":"10px","padding":"6px 8px"}),
        ], style={"borderBottom":"1px solid #1e2230"}) for i in incidents]
        return _card(
            html.Div("⚠️ Incident Register",
                     style={"color":"#e0e0e0","fontWeight":"600","marginBottom":"10px"}),
            html.Div("Centralized incident intelligence with root-cause analysis and remediation tracking.",
                     style={"color":"#636e72","fontSize":"11px","marginBottom":"10px"}),
            dbc.Row([
                dbc.Col(html.Div([
                    html.Div("5", style={"color":"#e0e0e0","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("Total", style={"color":"#636e72","fontSize":"10px","textAlign":"center"})
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"8px"}), md=3),
                dbc.Col(html.Div([
                    html.Div("2", style={"color":"#c0392b","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("Critical", style={"color":"#636e72","fontSize":"10px","textAlign":"center"})
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"8px"}), md=3),
                dbc.Col(html.Div([
                    html.Div("1", style={"color":"#e67e22","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("Open", style={"color":"#636e72","fontSize":"10px","textAlign":"center"})
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"8px"}), md=3),
                dbc.Col(html.Div([
                    html.Div("3", style={"color":"#27ae60","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("Resolved", style={"color":"#636e72","fontSize":"10px","textAlign":"center"})
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"8px"}), md=3),
            ], className="g-2", style={"marginBottom":"10px"}),
            html.Table(
                [html.Thead(inc_header), html.Tbody(inc_rows, id="gc-inc-tbody")],
                style={"width":"100%","borderCollapse":"collapse"}
            ),
            html.Div([
                dbc.Row([
                    dbc.Col([_label("Incident ID"),
                             dbc.Input(id="gc-inc-id", placeholder="I-15", style=INPUT_STY)], md=2),
                    dbc.Col([_label("Title"),
                             dbc.Input(id="gc-inc-title", placeholder="Incident title", style=INPUT_STY)], md=4),
                    dbc.Col([_label("Severity"), dbc.Select(id="gc-inc-severity", options=[
                        {"label":s,"value":s} for s in ["Critical","High","Medium","Low"]
                    ], value="High", style=INPUT_STY)], md=2),
                    dbc.Col([_label("Assigned To"),
                             dbc.Input(id="gc-inc-assigned", placeholder="SOC Analyst", style=INPUT_STY)], md=3),
                    dbc.Col([dbc.Button("➕ Add", id="gc-inc-add",
                                        color="outline-warning", size="sm",
                                        style={**BTN_SM,"marginTop":"18px"})], md=1),
                ], className="g-2", style={"marginTop":"12px"}),
                html.Div(id="gc-inc-feedback",
                         style={"color":"#27ae60","fontSize":"11px","marginTop":"6px"}),
            ]),
        )

    # ── Privacy (GDPR / RoPA / DSAR) ────────────────────────────────────────
    elif tab == "gc-tab-privacy":
        processing = [
            ("PA-15","Employee Onboarding","HR","GDPR Art.6(b)","EU","NEW"),
            ("PA-14","Payroll Processing","Finance","GDPR Art.6(b)","EU + UK","Active"),
            ("PA-13","Customer Analytics","Marketing","GDPR Art.6(a)","EU + US","Active"),
            ("PA-12","Security Monitoring","IT / SOC","GDPR Art.6(f)","EU","Active"),
            ("PA-11","Vendor Due Diligence","Procurement","GDPR Art.6(f)","EU","Active"),
        ]
        pa_header = html.Tr([
            html.Th(h, style={"color":"#3498db","fontSize":"10px","fontWeight":"700",
                              "background":"#1a1d24","padding":"6px 8px",
                              "borderBottom":"1px solid #2c3347"})
            for h in ["Key","Processing Activity","Controller","Lawful Basis","Transfer Region","Status"]
        ])
        pa_rows = [html.Tr([
            html.Td(p[0], style={"color":"#3498db","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(p[1], style={"color":"#ccc","fontSize":"10px","padding":"6px 8px"}),
            html.Td(p[2], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
            html.Td(p[3], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(p[4], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
            html.Td(html.Span(p[5], style={"color":"#2ecc71" if p[5]=="Active" else "#3498db",
                                            "fontSize":"10px","fontWeight":"600"})),
        ], style={"borderBottom":"1px solid #1e2230"}) for p in processing]
        return _card(
            html.Div("🔏 Privacy & Data Protection",
                     style={"color":"#e0e0e0","fontWeight":"600","marginBottom":"10px"}),
            html.Div("Record of Processing Activities (RoPA) · DSAR Management · Multi-framework privacy ops",
                     style={"color":"#636e72","fontSize":"11px","marginBottom":"10px"}),
            html.Div("📋 Record of Processing Activities", style={"color":"#e0e0e0","fontWeight":"600",
                                                                    "fontSize":"12px","marginBottom":"6px"}),
            html.Table([html.Thead(pa_header), html.Tbody(pa_rows)],
                       style={"width":"100%","borderCollapse":"collapse","marginBottom":"14px"}),
            html.Div("📩 DSAR Tracker", style={"color":"#e0e0e0","fontWeight":"600",
                                                 "fontSize":"12px","marginBottom":"6px"}),
            html.Div([
                dbc.Row([
                    dbc.Col([_label("Request ID"), dbc.Input(placeholder="DSAR-001", style=INPUT_STY)], md=2),
                    dbc.Col([_label("Data Subject"), dbc.Input(placeholder="J. Smith", style=INPUT_STY)], md=3),
                    dbc.Col([_label("Request Type"), dbc.Select(options=[
                        {"label":t,"value":t} for t in ["Access","Erasure","Rectification","Portability","Restriction"]
                    ], value="Access", style=INPUT_STY)], md=3),
                    dbc.Col([_label("Received"), dbc.Input(value="2026-03-10", style=INPUT_STY)], md=2),
                    dbc.Col([dbc.Button("➕ Log", color="outline-info", size="sm",
                                        style={**BTN_SM,"marginTop":"18px"})], md=2),
                ], className="g-2"),
            ]),
        )

    # ── Audit ────────────────────────────────────────────────────────────────
    elif tab == "gc-tab-audit":
        audits = [
            ("AUD-14","Internal ISO 27001:2022 Gap Analysis","ISO 27001","In Audit","2026-03-01","2026-03-30","85%"),
            ("AUD-13","SOC 2 Type II Readiness Review","SOC 2","Planned","2026-04-01","2026-04-30","—"),
            ("AUD-12","PCI-DSS v4 QSA Assessment","PCI-DSS","Completed","2026-01-15","2026-02-15","92%"),
            ("AUD-11","HIPAA Security Rule Audit","HIPAA","Completed","2025-11-01","2025-11-30","78%"),
        ]
        aud_header = html.Tr([
            html.Th(h, style={"color":"#3498db","fontSize":"10px","fontWeight":"700",
                              "background":"#1a1d24","padding":"6px 8px",
                              "borderBottom":"1px solid #2c3347"})
            for h in ["Key","Audit Name","Framework","Status","Start","End","Progress"]
        ])
        sta_col2 = {"In Audit":"#e67e22","Planned":"#3498db","Completed":"#27ae60"}
        aud_rows = [html.Tr([
            html.Td(a[0], style={"color":"#3498db","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(a[1], style={"color":"#ccc","fontSize":"10px","padding":"6px 8px","fontWeight":"600"}),
            html.Td(a[2], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
            html.Td(html.Span(a[3], style={"color":sta_col2.get(a[3],"#aaa"),"fontSize":"10px","fontWeight":"600"})),
            html.Td(a[4], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(a[5], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(html.Span(a[6], style={"color":"#2ecc71","fontSize":"10px","fontWeight":"700"})),
        ], style={"borderBottom":"1px solid #1e2230"}) for a in audits]
        return _card(
            html.Div("🔍 Audit Management",
                     style={"color":"#e0e0e0","fontWeight":"600","marginBottom":"10px"}),
            html.Div("Continuous audit readiness · Automated evidence collection · Unified control monitoring",
                     style={"color":"#636e72","fontSize":"11px","marginBottom":"10px"}),
            dbc.Row([
                dbc.Col(html.Div([
                    html.Div("85%", style={"color":"#27ae60","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("ISO 27001 Readiness", style={"color":"#636e72","fontSize":"10px","textAlign":"center"}),
                    dbc.Progress(value=85, color="success", style={"height":"6px","marginTop":"4px"}),
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"10px"}), md=4),
                dbc.Col(html.Div([
                    html.Div("92%", style={"color":"#27ae60","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("PCI-DSS Score", style={"color":"#636e72","fontSize":"10px","textAlign":"center"}),
                    dbc.Progress(value=92, color="success", style={"height":"6px","marginTop":"4px"}),
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"10px"}), md=4),
                dbc.Col(html.Div([
                    html.Div("78%", style={"color":"#e67e22","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("HIPAA Score", style={"color":"#636e72","fontSize":"10px","textAlign":"center"}),
                    dbc.Progress(value=78, color="warning", style={"height":"6px","marginTop":"4px"}),
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"10px"}), md=4),
            ], className="g-2", style={"marginBottom":"12px"}),
            html.Table([html.Thead(aud_header), html.Tbody(aud_rows)],
                       style={"width":"100%","borderCollapse":"collapse"}),
        )

    # ── Policy Library ───────────────────────────────────────────────────────
    elif tab == "gc-tab-policy":
        policies = [
            ("P-01","Information Security Policy","Active","1.4","2025-01-10","2026-01-10","CISO"),
            ("P-02","Acceptable Use Policy","Active","2.1","2025-03-01","2026-03-01","IT Admin"),
            ("P-03","Data Classification Policy","Active","1.2","2025-02-15","2026-02-15","DPO"),
            ("P-04","Incident Response Policy","Active","3.0","2025-06-01","2026-06-01","SOC"),
            ("P-05","Business Continuity Policy","Active","1.1","2024-11-01","2025-11-01","Risk"),
            ("P-06","Vendor Management Policy","Under Review","1.0","2024-09-01","2025-09-01","Procurement"),
            ("P-07","Cryptography & Key Mgmt Policy","Active","1.3","2025-04-01","2026-04-01","IT Sec"),
            ("P-08","Remote Working Policy","Active","2.0","2025-01-20","2026-01-20","HR"),
        ]
        pol_header = html.Tr([
            html.Th(h, style={"color":"#3498db","fontSize":"10px","fontWeight":"700",
                              "background":"#1a1d24","padding":"6px 8px",
                              "borderBottom":"1px solid #2c3347"})
            for h in ["Key","Policy Name","Status","Version","Approved","Review","Owner"]
        ])
        pol_rows = [html.Tr([
            html.Td(p[0], style={"color":"#3498db","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(p[1], style={"color":"#ccc","fontSize":"10px","padding":"6px 8px","fontWeight":"600"}),
            html.Td(html.Span(p[2], style={
                "color":"#27ae60" if p[2]=="Active" else "#f1c40f",
                "fontSize":"10px","fontWeight":"600"})),
            html.Td(html.Span(f"v{p[3]}", style={"color":"#8e9eb0","fontSize":"10px","fontFamily":"monospace"})),
            html.Td(p[4], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(p[5], style={
                "color": "#c0392b" if p[5] < "2026-03-10" else "#8e9eb0",
                "fontSize":"10px","padding":"6px 8px","fontFamily":"monospace","fontWeight":"700"}),
            html.Td(p[6], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
        ], style={"borderBottom":"1px solid #1e2230"}) for p in policies]
        return _card(
            html.Div("📜 Policy Library",
                     style={"color":"#e0e0e0","fontWeight":"600","marginBottom":"10px"}),
            html.Div("Centralised policy management with version control, review scheduling, and owner tracking.",
                     style={"color":"#636e72","fontSize":"11px","marginBottom":"10px"}),
            html.Table(
                [html.Thead(pol_header), html.Tbody(pol_rows, id="gc-pol-tbody")],
                style={"width":"100%","borderCollapse":"collapse"}
            ),
            html.Div([
                dbc.Row([
                    dbc.Col([_label("Policy Name"),
                             dbc.Input(id="gc-pol-name", placeholder="New Policy Name", style=INPUT_STY)], md=5),
                    dbc.Col([_label("Owner"),
                             dbc.Input(id="gc-pol-owner", placeholder="Owner", style=INPUT_STY)], md=3),
                    dbc.Col([_label("Review Date"),
                             dbc.Input(id="gc-pol-review", value="2027-01-01", style=INPUT_STY)], md=3),
                    dbc.Col([dbc.Button("➕ Add", id="gc-pol-add",
                                        color="outline-warning", size="sm",
                                        style={**BTN_SM,"marginTop":"18px"})], md=1),
                ], className="g-2", style={"marginTop":"12px"}),
                html.Div(id="gc-pol-feedback",
                         style={"color":"#27ae60","fontSize":"11px","marginTop":"6px"}),
            ]),
        )

    # ── BCP / Business Continuity ────────────────────────────────────────────
    elif tab == "gc-tab-bcp":
        bia_items = [
            ("BIA-01","Core Business Systems (ERP/CRM)","Critical","4h","1h","IT Department","Active"),
            ("BIA-02","Customer Payment Processing","Critical","1h","0h","Finance + IT","Active"),
            ("BIA-03","Email & Communication","High","8h","4h","IT Admin","Active"),
            ("BIA-04","Employee HR Systems","Medium","24h","8h","HR","Active"),
            ("BIA-05","Physical Office Access","Medium","48h","24h","Facilities","Active"),
            ("BIA-06","Website / Marketing Portal","Low","72h","24h","Marketing","Active"),
        ]
        bia_header = html.Tr([
            html.Th(h, style={"color":"#3498db","fontSize":"10px","fontWeight":"700",
                              "background":"#1a1d24","padding":"6px 8px",
                              "borderBottom":"1px solid #2c3347"})
            for h in ["Key","Critical Process","Impact","RTO","RPO","Owner","Plan Status"]
        ])
        crit_c = {"Critical":"#c0392b","High":"#e67e22","Medium":"#f1c40f","Low":"#27ae60"}
        bia_rows = [html.Tr([
            html.Td(b[0], style={"color":"#3498db","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
            html.Td(b[1], style={"color":"#ccc","fontSize":"10px","padding":"6px 8px","fontWeight":"600"}),
            html.Td(html.Span(b[2], style={"color":crit_c.get(b[2],"#aaa"),"fontSize":"10px","fontWeight":"700"})),
            html.Td(html.Span(b[3], style={"color":"#3498db","fontSize":"10px","fontFamily":"monospace","fontWeight":"700"})),
            html.Td(html.Span(b[4], style={"color":"#e67e22","fontSize":"10px","fontFamily":"monospace","fontWeight":"700"})),
            html.Td(b[5], style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
            html.Td(html.Span(b[6], style={"color":"#27ae60","fontSize":"10px","fontWeight":"600"})),
        ], style={"borderBottom":"1px solid #1e2230"}) for b in bia_items]
        return _card(
            html.Div("🆘 Business Continuity Plan",
                     style={"color":"#e0e0e0","fontWeight":"600","marginBottom":"10px"}),
            html.Div("Business Impact Analysis · RTO/RPO targets · Centralized continuity plan management",
                     style={"color":"#636e72","fontSize":"11px","marginBottom":"10px"}),
            dbc.Row([
                dbc.Col(html.Div([
                    html.Div("4", style={"color":"#27ae60","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("Active Plans", style={"color":"#636e72","fontSize":"10px","textAlign":"center"}),
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"10px"}), md=3),
                dbc.Col(html.Div([
                    html.Div("1h", style={"color":"#3498db","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("Min RTO (Critical)", style={"color":"#636e72","fontSize":"10px","textAlign":"center"}),
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"10px"}), md=3),
                dbc.Col(html.Div([
                    html.Div("0h", style={"color":"#e67e22","fontSize":"26px","fontWeight":"700","textAlign":"center"}),
                    html.Div("Min RPO (Payments)", style={"color":"#636e72","fontSize":"10px","textAlign":"center"}),
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"10px"}), md=3),
                dbc.Col(html.Div([
                    html.Div("✅", style={"fontSize":"26px","textAlign":"center"}),
                    html.Div("Last Tested: Feb 2026", style={"color":"#636e72","fontSize":"10px","textAlign":"center"}),
                ], style={"background":"#1a1d24","borderRadius":"6px","padding":"10px"}), md=3),
            ], className="g-2", style={"marginBottom":"12px"}),
            html.Div("📊 Business Impact Analysis", style={"color":"#e0e0e0","fontWeight":"600",
                                                            "fontSize":"12px","marginBottom":"6px"}),
            html.Table([html.Thead(bia_header), html.Tbody(bia_rows)],
                       style={"width":"100%","borderCollapse":"collapse"}),
        )

    # ── Assessment Questionnaire ─────────────────────────────────────────────
    elif tab == "gc-tab-questionnaire":

        def _qs_panel(panel_id, fw_key, title, flag, colour, qs_dict):
            """Reusable builder panel for a dynamic questionnaire."""
            if not qs_dict:
                return html.Div("No questionnaire defined for this framework.", style={"color": "#636e72", "padding": "20px"})
                
            ctrl_options = [
                {"label": f"{cid} — {v['title']}", "value": cid}
                for cid, v in qs_dict.items()
            ]
            return html.Div([
                # ── Panel header ────────────────────────────────────────────
                html.Div([
                    html.Span(flag, style={"fontSize": "1.6rem", "marginRight": "8px"}),
                    html.Span(title, style={"color": colour, "fontWeight": "700",
                                            "fontSize": "15px"}),
                ], style={"display": "flex", "alignItems": "center",
                           "borderBottom": f"2px solid {colour}44",
                           "paddingBottom": "8px", "marginBottom": "12px"}),

                # ── Control selector ────────────────────────────────────────
                html.Div("Select Controls to Include:", style={
                    "color": "#8e9eb0", "fontSize": "10px",
                    "fontWeight": "700", "marginBottom": "4px"}),
                dcc.Checklist(
                    id={"type": "gc-qd-ctrl-check", "fw": fw_key},
                    options=ctrl_options,
                    value=[list(qs_dict.keys())[0]] if qs_dict else [],
                    labelStyle={"display": "flex", "alignItems": "center",
                                "gap": "6px", "marginBottom": "4px",
                                "color": "#ccc", "fontSize": "11px",
                                "cursor": "pointer"},
                    inputStyle={"accentColor": colour},
                    style={"maxHeight": "160px", "overflowY": "auto",
                           "background": "#1a1d24", "borderRadius": "6px",
                           "padding": "8px", "marginBottom": "10px",
                           "border": "1px solid #2c3347"},
                ),

                # ── Custom question input ───────────────────────────────────
                html.Div("Add Custom Question:", style={
                    "color": "#8e9eb0", "fontSize": "10px",
                    "fontWeight": "700", "marginBottom": "4px"}),
                dbc.InputGroup([
                    dbc.Input(id=f"{panel_id}-custom-q",
                              placeholder="Type a custom question...",
                              style={"background": "#0d1117", "color": "#ccc",
                                     "border": "1px solid #2c3347",
                                     "fontSize": "11px"}),
                    dbc.Button("➕", id=f"{panel_id}-add-custom",
                               color="link",
                               style={"color": colour, "fontSize": "16px",
                                      "border": f"1px solid {colour}44",
                                      "borderLeft": "none"}),
                ], style={"marginBottom": "10px"}),
                html.Div(id=f"{panel_id}-custom-list",
                         style={"marginBottom": "10px"}),

                # ── Question preview ────────────────────────────────────────
                html.Div(id={"type": "gc-qd-preview", "fw": fw_key},
                         style={"maxHeight": "200px", "overflowY": "auto",
                                "background": "#0d1117", "borderRadius": "6px",
                                "padding": "10px", "marginBottom": "12px",
                                "border": f"1px solid {colour}33",
                                "fontSize": "11px", "color": "#ccc"}),

                html.Hr(style={"borderColor": "#2c3347", "margin": "10px 0"}),

                # ── Client info + send ──────────────────────────────────────
                html.Div("📧 Send to Client", style={
                    "color": "#e0e0e0", "fontWeight": "700",
                    "fontSize": "13px", "marginBottom": "8px"}),
                dbc.Input(id={"type": "gc-qd-client-name", "fw": fw_key},
                          placeholder="Client / Organization Name",
                          style={"background": "#0d1117", "color": "#ccc",
                                 "border": "1px solid #2c3347",
                                 "fontSize": "11px", "marginBottom": "6px"}),
                dbc.Input(id={"type": "gc-qd-client-email", "fw": fw_key},
                          placeholder="client@example.com",
                          type="email",
                          style={"background": "#0d1117", "color": "#ccc",
                                 "border": "1px solid #2c3347",
                                 "fontSize": "11px", "marginBottom": "6px"}),
                dbc.Input(id={"type": "gc-qd-subject", "fw": fw_key},
                          value=f"Compliance Assessment Questionnaire — {title}",
                          style={"background": "#0d1117", "color": "#ccc",
                                 "border": "1px solid #2c3347",
                                 "fontSize": "11px", "marginBottom": "8px"}),
                dcc.Upload(
                    id={"type": "gc-qd-upload", "fw": fw_key},
                    children=html.Div(["📁 Drag & Drop or ", html.A("Select a .zip file", style={"color": "#82aaff"})]),
                    style={
                        "width": "100%", "height": "40px", "lineHeight": "40px",
                        "borderWidth": "1px", "borderStyle": "dashed", "borderColor": "#3b4261",
                        "borderRadius": "4px", "textAlign": "center", "marginBottom": "4px",
                        "fontSize": "11px", "color": "#636e72"
                    },
                    multiple=False,
                    accept=".zip"
                ),
                html.Div(id={"type": "gc-qd-upload-status", "fw": fw_key}, style={"fontSize": "10px", "color": "#82aaff", "marginBottom": "8px", "textAlign": "center", "minHeight": "14px"}),
                dbc.Button([
                    html.Span("📨", style={"marginRight": "6px"}),
                    "Send Assessment Email",
                ], id={"type": "gc-qd-send-btn", "fw": fw_key}, color="link", style={
                    "width": "100%", "background": f"{colour}22",
                    "border": f"1px solid {colour}66", "color": colour,
                    "fontWeight": "700", "fontSize": "12px",
                    "borderRadius": "6px", "padding": "8px",
                }),
                html.Div(id={"type": "gc-qd-send-status", "fw": fw_key},
                         style={"marginTop": "8px", "fontSize": "11px"}),
            ], style={
                "background": "#111317", "border": f"1px solid {colour}33",
                "borderRadius": "10px", "padding": "16px",
                "height": "100%",
            })

        # Dynamically determine the framework details
        target_fw = fw or "pci-dss"
        fw_icon = "📋"
        fw_color = "#3498db"
        fw_name = "Compliance"
        
        for k, i, c, n in FRAMEWORK_GALLERY:
            if k == target_fw:
                fw_icon, fw_color, fw_name = i, c, n
                break
                
        active_qs_dict = QUESTIONNAIRES_BY_FRAMEWORK.get(target_fw, {})

        return html.Div([
            html.Div(f"📋 Assessment Questionnaire Builder ({fw_name})",
                     style={"color": "#e0e0e0", "fontWeight": "700",
                            "fontSize": "15px", "marginBottom": "4px"}),
            html.Div(f"Build and send compliance assessment questionnaires specifically tailored for {fw_name}.",
                     style={"color": "#636e72", "fontSize": "11px",
                            "marginBottom": "14px"}),
            dbc.Row([
                dbc.Col(
                    _qs_panel(f"gc-qd-{target_fw}", target_fw, fw_name,
                              fw_icon, fw_color, active_qs_dict),
                    md=12),
            ], className="g-3"),
            
            # --- NEW INBOX PANEL ---
            html.Div(style={"marginTop": "24px", "background": "#111317", "border": "1px solid #2c3347", "borderRadius": "10px", "padding": "16px"}, children=[
                html.Div([
                    html.Span("📥 Received Responses Inbox", style={"color": "#e0e0e0", "fontWeight": "700", "fontSize": "15px"}),
                    dbc.Button("🔄 Refresh", id="gc-inbox-refresh-btn", size="sm", color="link", style={"float": "right", "color": "#3498db", "padding": "0"}),
                ], style={"marginBottom": "12px"}),
                html.Div("Submitted ZIP files from the Secure Client Portal will appear here.", style={"color": "#636e72", "fontSize": "11px", "marginBottom": "14px"}),
                html.Div(id="gc-inbox-content", style={"minHeight": "60px"})
            ]),
        ])

    elif tab == "gc-tab-comms":
        # ── Client Comms Hub ──────────────────────────────────────────────────
        return html.Div([
            html.Div("💬 Client Communications Hub",
                     style={"color": "#e0e0e0", "fontWeight": "700",
                            "fontSize": "15px", "marginBottom": "4px"}),
            html.Div("Secure, real-time chat with active clients.",
                     style={"color": "#636e72", "fontSize": "11px",
                            "marginBottom": "14px"}),
            
            dcc.Interval(id="gc-comms-poll", interval=3000, n_intervals=0),
            dcc.Store(id="gc-comms-active-client", data=""),
            
            dbc.Row([
                # Left Pane: Client List
                dbc.Col([
                    html.Div("Active Clients", style={"color":"#82aaff", "fontSize":"12px", "fontWeight":"bold", "marginBottom":"8px"}),
                    html.Div(id="gc-comms-client-list", style={
                        "background": "#111317", "border": "1px solid #2c3347",
                        "borderRadius": "6px", "height": "500px", "overflowY": "auto",
                        "padding": "8px"
                    })
                ], md=4),
                
                # Right Pane: Chat Window
                dbc.Col([
                    html.Div(id="gc-comms-active-header", children="Select a client to start chatting", style={"color":"#e0e0e0", "fontSize":"13px", "fontWeight":"bold", "marginBottom":"8px", "paddingBottom":"8px", "borderBottom":"1px solid #2c3347"}),
                    
                    # Chat History
                    html.Div(id="gc-comms-history", style={
                        "background": "#0d1117", "border": "1px solid #2c3347",
                        "borderRadius": "6px", "height": "400px", "overflowY": "auto",
                        "padding": "16px", "display": "flex", "flexDirection": "column", "gap": "12px",
                        "marginBottom": "12px"
                    }),
                    
                    # Input Area
                    html.Div([
                        dbc.Input(id="gc-comms-input", placeholder="Type a message to the client...", style={"background": "#1a1d24", "color": "#ccc", "border": "1px solid #3b4261", "borderRadius": "20px"}),
                        dbc.Button("Send", id="gc-comms-send-btn", color="primary", style={"borderRadius": "20px", "marginLeft": "8px"})
                    ], style={"display": "flex", "alignItems": "center"}),
                    
                    html.Div(id="gc-comms-send-status", style={"display": "none"})
                ], md=8)
            ])
        ])

    return html.Div()


# ── Received Responses Inbox Callback ───────────────────────────────────────────
@callback(
    Output("gc-inbox-content", "children"),
    Input("gc-inbox-refresh-btn", "n_clicks"),
)
def _refresh_inbox(n):
    import os, time
    UPLOAD_FOLDER = "/opt/vuln_intel/app/uploads/assessments"
    if not os.path.exists(UPLOAD_FOLDER):
        return html.Div("No submissions yet.", style={"color": "#636e72", "fontStyle": "italic", "fontSize": "12px"})
    
    files = os.listdir(UPLOAD_FOLDER)
    if not files:
        return html.Div("No submissions yet.", style={"color": "#636e72", "fontStyle": "italic", "fontSize": "12px"})
    
    # Sort files by newest first (since filename starts with timestamp)
    files.sort(reverse=True)
    
    rows = []
    for f in files:
        if not f.endswith(".zip"): continue
        
        parts = f.split("_", 2)
        if len(parts) == 3:
            ts, email, orig_name = parts
            try:
                dt_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))
            except:
                dt_str = "Unknown"
        else:
            dt_str, email, orig_name = "Unknown", "Unknown", f
            
        filepath = os.path.join(UPLOAD_FOLDER, f)
        size_kb = os.path.getsize(filepath) / 1024
        
        rows.append(html.Tr([
            html.Td(dt_str, style={"padding": "8px", "color": "#ccc", "fontSize": "12px", "borderBottom": "1px solid #2c3347"}),
            html.Td(email, style={"padding": "8px", "color": "#82aaff", "fontSize": "12px", "borderBottom": "1px solid #2c3347"}),
            html.Td(orig_name, style={"padding": "8px", "color": "#ccc", "fontSize": "12px", "borderBottom": "1px solid #2c3347"}),
            html.Td(f"{size_kb:.1f} KB", style={"padding": "8px", "color": "#636e72", "fontSize": "12px", "borderBottom": "1px solid #2c3347"}),
            html.Td(html.A("⬇ Download", href=f"/download-assessment/{f}", download=f, style={"color": "#27ae60", "fontWeight": "bold", "textDecoration": "none", "fontSize": "12px"}), style={"padding": "8px", "textAlign": "right", "borderBottom": "1px solid #2c3347"})
        ]))
        
    return html.Table([
        html.Thead(html.Tr([
            html.Th("Received (Local Time)", style={"padding": "8px", "textAlign": "left", "color": "#636e72", "fontSize": "11px", "borderBottom": "1px solid #2c3347"}),
            html.Th("Client Email", style={"padding": "8px", "textAlign": "left", "color": "#636e72", "fontSize": "11px", "borderBottom": "1px solid #2c3347"}),
            html.Th("Original Filename", style={"padding": "8px", "textAlign": "left", "color": "#636e72", "fontSize": "11px", "borderBottom": "1px solid #2c3347"}),
            html.Th("Size", style={"padding": "8px", "textAlign": "left", "color": "#636e72", "fontSize": "11px", "borderBottom": "1px solid #2c3347"}),
            html.Th("", style={"padding": "8px", "textAlign": "right", "borderBottom": "1px solid #2c3347"})
        ])),
        html.Tbody(rows)
    ], style={"width": "100%", "borderCollapse": "collapse"})



# ── Dynamic Questionnaire Preview Callback ────────────────────────────────────
@callback(
    Output({"type": "gc-qd-preview", "fw": MATCH}, "children"),
    Input({"type": "gc-qd-ctrl-check", "fw": MATCH}, "value"),
    State("gc-framework", "value"),
    prevent_initial_call=True,
)
def _qd_preview(selected, fw):
    if not selected:
        return html.Span("Select controls above to preview questions.",
                         style={"color": "#636e72"})
                         
    items = []
    target_fw = fw or "pci-dss"
    active_qs_dict = QUESTIONNAIRES_BY_FRAMEWORK.get(target_fw, {})
    
    for cid in selected:
        ctrl = active_qs_dict.get(cid, {})
        if not ctrl: continue
        
        # Use the control's framework/family if available, else the global framework
        item_fw = ctrl.get("framework", ctrl.get("family", target_fw.upper()))
        
        items.append(html.Div([
            html.Div(f"── {item_fw} / {cid}: {ctrl.get('title','')} ──",
                     style={"color": "#3498db", "fontWeight": "700",
                            "marginBottom": "4px", "fontSize": "10px"}),
            *[html.Div(f"  Q{i+1}. {q}",
                       style={"color": "#ccc", "marginLeft": "8px",
                              "marginBottom": "2px"})
              for i, q in enumerate(ctrl.get("questions", []))],
            html.Div("Evidence: " + " · ".join(ctrl.get("evidence", [])),
                     style={"color": "#636e72", "fontSize": "9px",
                            "marginTop": "4px", "marginLeft": "8px",
                            "marginBottom": "8px"}),
        ]))
    return items


@callback(
    Output({"type": "gc-qd-upload-status", "fw": MATCH}, "children"),
    Input({"type": "gc-qd-upload", "fw": MATCH}, "filename"),
    prevent_initial_call=True
)
def _qd_upload_status(filename):
    if filename:
        return f"📎 Attached: {filename}"
    return ""


def _build_html_email(client_name, controls_selected, qs_dict, label):
    """Build a rich HTML assessment email body."""
    from datetime import date as _d
    today = _d.today().strftime("%B %d, %Y")
    sections = ""
    for cid in controls_selected:
        ctrl = qs_dict.get(cid, {})
        fw   = ctrl.get("framework", ctrl.get("family", ""))
        qs_html = "".join(
            f"<tr><td style='padding:8px 12px;vertical-align:top;color:#999;width:24px'>{i+1}.</td>"
            f"<td style='padding:8px 0;color:#222'>{q}</td>"
            f"<td style='padding:8px 12px;min-width:200px'>"
            f"<div style='border-bottom:1px solid #ccc;min-height:32px'></div></td></tr>"
            for i, q in enumerate(ctrl.get("questions", []))
        )
        ev_items = "".join(f"<li style='color:#555;margin:2px 0'>{e}</li>"
                           for e in ctrl.get("evidence", []))
        enh_items = "".join(f"<span style='background:#e8f4ff;color:#1a5276;padding:2px 8px;"
                            f"border-radius:12px;font-size:11px;margin:2px;display:inline-block'>{e}</span>"
                            for e in ctrl.get("enhancements", []))
        sections += f"""
<div style='margin-bottom:28px;border-left:4px solid #2980b9;padding-left:14px'>
  <h3 style='margin:0 0 4px;color:#1a3a6c'>{cid} — {ctrl.get("title","")}</h3>
  <div style='margin-bottom:8px'>{enh_items}</div>
  <table style='width:100%;border-collapse:collapse;font-size:13px'>
    <thead><tr>
      <th style='background:#f0f4f8;padding:6px 12px;text-align:left;color:#444'>#</th>
      <th style='background:#f0f4f8;padding:6px;text-align:left;color:#444'>Assessment Question</th>
      <th style='background:#f0f4f8;padding:6px 12px;text-align:left;color:#444'>Client Response</th>
    </tr></thead>
    <tbody>{qs_html}</tbody>
  </table>
  <div style='margin-top:10px;background:#f9f9f9;border-radius:4px;padding:8px 12px'>
    <strong style='font-size:12px;color:#666'>Evidence Required:</strong>
    <ul style='margin:4px 0 0 0;padding-left:18px'>{ev_items}</ul>
  </div>
  <div style='margin-top:8px'>
    <strong style='font-size:12px;color:#666'>Artifact References (please attach or link):</strong>
    <div style='border:1px solid #ddd;border-radius:4px;min-height:36px;
                margin-top:4px;padding:4px 8px;color:#aaa;font-size:12px'>
      Enter file names, URLs, or ticket IDs…
    </div>
  </div>
</div>"""

    return f"""<!DOCTYPE html><html><head>
<meta charset='utf-8'>
<style>body{{font-family:Arial,sans-serif;color:#222;max-width:860px;margin:0 auto;padding:24px}}
h2{{color:#1a3a6c}} blockquote{{border-left:4px solid #aaa;margin:0;padding-left:12px;color:#555}}</style>
</head><body>
<div style='border-bottom:3px solid #1a3a6c;padding-bottom:12px;margin-bottom:20px'>
  <h2 style='margin:0'>📋 Compliance Assessment Questionnaire</h2>
  <div style='color:#555;font-size:13px'>Framework: <strong>{label}</strong> &nbsp;·&nbsp; Date: {today}</div>
</div>
<p>Dear <strong>{client_name or "Client"}</strong>,</p>
<p>Please complete the assessment questionnaire below for each control listed. Provide a response
to each question in the <em>Client Response</em> column, and gather the requested evidence artifacts.</p>
<div style='background:#e8f4ff; border:1px solid #b3d7ff; padding:12px; border-radius:6px; margin:20px 0;'>
  <strong style='color:#0056b3; font-size:14px;'>Secure Submission Instructions:</strong><br>
  <span style='color:#333; font-size:13px;'>When you have completed your responses and gathered your evidence, please put them in a single <strong>.zip folder</strong> and upload them securely using our Client Portal:</span><br>
  <a href='http://127.0.0.1:9000/client-upload' style='display:inline-block; margin-top:8px; background:#0056b3; color:#fff; padding:8px 16px; text-decoration:none; border-radius:4px; font-weight:bold;'>Open Secure Client Portal</a>
</div>
<blockquote style='margin-bottom:20px'>
  <strong>Checklist:</strong><br>
  1. Answer each question as thoroughly as possible.<br>
  2. For each <em>Evidence Required</em> item, include the document in your ZIP file.<br>
  3. Upload the ZIP via the portal within <strong>10 business days</strong>.
</blockquote>
{sections}
<hr style='border:1px solid #eee;margin:24px 0'>
<p style='font-size:12px;color:#999'>This assessment was generated by the <strong>Aegis Security Operations Center</strong>
GRC platform. Responses are treated as confidential.</p>
</body></html>"""


def _send_smtp(to_addr, subject, html_body, attachment_data=None):
    """Send email — reads credentials directly from .env file on every call."""
    import smtplib, os as _os, base64
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    # We are using Mailjet SMTP Relay because Google Workspace blocks scripts.
    host = "in-v3.mailjet.com"
    port = 587
    user = "ed080ab53685d60a92f1e7db6ec6d834"       # Mailjet Public API Key
    pwd  = "b078ec1cd223ec2c7c5ef09dd8fd7462"       # Mailjet Secret Key
    # The 'From' address must be the verified Mailjet account email
    frm  = "asiedudanquah@gmail.com"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = frm
    msg["To"]      = to_addr
    msg.attach(MIMEText(html_body, "html"))

    if attachment_data:
        filename, b64_contents = attachment_data
        if "," in b64_contents:
            b64_contents = b64_contents.split(",")[1]
        part = MIMEBase("application", "zip")
        part.set_payload(base64.b64decode(b64_contents))
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(part)

    with smtplib.SMTP(host, port) as sv:
        sv.ehlo()
        sv.starttls()
        sv.login(user, pwd)
        sv.sendmail(frm, [to_addr], msg.as_string())


# ── Dynamic Send Callback ─────────────────────────────────────────────────────
@callback(
    Output({"type": "gc-qd-send-status", "fw": MATCH}, "children"),
    Input({"type": "gc-qd-send-btn", "fw": MATCH},     "n_clicks"),
    State({"type": "gc-qd-ctrl-check", "fw": MATCH},   "value"),
    State({"type": "gc-qd-client-name", "fw": MATCH},  "value"),
    State({"type": "gc-qd-client-email", "fw": MATCH}, "value"),
    State({"type": "gc-qd-subject", "fw": MATCH},      "value"),
    State({"type": "gc-qd-upload", "fw": MATCH},       "contents"),
    State({"type": "gc-qd-upload", "fw": MATCH},       "filename"),
    State("gc-framework", "value"),
    prevent_initial_call=True,
)
def _qd_send(n, selected, client, email_to, subject, file_content, file_name, fw):
    if not n:
        raise PreventUpdate
    if not email_to:
        return html.Span("⚠️ Please enter a client email address.",
                         style={"color": "#e67e22"})
    if not selected:
        return html.Span("⚠️ Select at least one control first.",
                         style={"color": "#e67e22"})
                         
    try:
        target_fw = fw or "pci-dss"
        active_qs_dict = QUESTIONNAIRES_BY_FRAMEWORK.get(target_fw, {})
        fw_name = "Compliance"
        for k, _, _, n_ in FRAMEWORK_GALLERY:
            if k == target_fw:
                fw_name = n_
                break
                
        html_body = _build_html_email(client, selected, active_qs_dict, fw_name)
        attachment = (file_name, file_content) if file_content else None
        
        _send_smtp(email_to, subject or f"{fw_name} Assessment", html_body, attachment)
        from datetime import datetime as _dt
        return html.Span(f"✅ Email sent to {email_to} at {_dt.now().strftime('%H:%M')}",
                         style={"color": "#27ae60", "fontWeight": "600"})
    except Exception as e:
        return html.Span(f"❌ Send failed: {e}",
                         style={"color": "#c0392b"})



@callback(
    Output("gc-evidence-store", "data"),
    Output("gc-ev-list",        "children"),
    Output("gc-ev-item",        "value"),
    Output("gc-ev-ctrl",        "value"),
    Output("gc-ev-status",      "value"),
    Output("gc-ev-notes",       "value"),
    Input("gc-ev-add",          "n_clicks"),
    State("gc-evidence-store",  "data"),
    State("gc-ev-item",         "value"),
    State("gc-ev-ctrl",         "value"),
    State("gc-ev-status",       "value"),
    State("gc-ev-notes",        "value"),
    prevent_initial_call=True,
)
def add_evidence(n_clicks, store, item, ctrl, status, notes):
    if not n_clicks or not item:
        raise PreventUpdate

    from datetime import datetime as _dt
    store = store or []
    store.append({
        "item":   item   or "",
        "ctrl":   ctrl   or "",
        "status": status or "pending",
        "notes":  notes  or "",
        "ts":     _dt.now().strftime("%Y-%m-%d %H:%M"),
    })

    _clr = {"collected": "#27ae60", "pending": "#f39c12", "missing": "#c0392b"}
    _ico = {"collected": "✅", "pending": "⏳", "missing": "❌"}

    cards = []
    for e in reversed(store):                      # newest first
        c = _clr.get(e["status"], "#636e72")
        cards.append(html.Div([
            html.Div([
                html.Span(_ico.get(e["status"], "📎"), style={"marginRight": "6px"}),
                html.Span(e["item"], style={"fontWeight": "700", "color": "#e0e0e0",
                                            "fontSize": "12px"}),
                html.Span(f"  ·  {e['ctrl']}" if e["ctrl"] else "",
                          style={"color": "#636e72", "fontSize": "11px"}),
                html.Span(e["status"].upper(),
                          style={"float": "right", "background": c + "33", "color": c,
                                 "fontSize": "9px", "fontWeight": "700",
                                 "padding": "2px 6px", "borderRadius": "4px",
                                 "border": f"1px solid {c}"}),
            ], style={"marginBottom": "4px"}),
            html.Div(e["notes"], style={"color": "#8e9eb0", "fontSize": "10px",
                                        "marginLeft": "22px"}) if e["notes"] else None,
            html.Div(e["ts"], style={"color": "#2c3347", "fontSize": "9px",
                                     "textAlign": "right", "marginTop": "2px"}),
        ], style={
            "background": "#1a1d24", "border": f"1px solid {c}44",
            "borderLeft": f"3px solid {c}", "borderRadius": "6px",
            "padding": "8px 12px", "marginBottom": "6px",
        }))

    return store, cards, "", "", "pending", ""


@callback(
    Output("gc-score-display", "children"),
    Output("gc-gap-detail",    "children"),
    Output("gc-gap-store",     "data"),
    Input("gc-score-btn",      "n_clicks"),
    State({"type": "ctrl-status", "fw": ALL, "id": ALL}, "value"),
    State("gc-framework",      "value"),
    prevent_initial_call=True,
)
def calc_score(n, statuses, fw):
    """Compute score + gap list and push results to the sidebar."""
    if not n:
        raise PreventUpdate
    total = len(statuses)
    if total == 0:
        return "No controls loaded.", None, None
    compliant   = statuses.count("compliant")
    partial     = statuses.count("partial")
    non_comp    = statuses.count("non-compliant")
    na          = statuses.count("not-applicable")
    effective   = total - na
    score       = int((compliant + partial * 0.5) / effective * 100) if effective else 0
    s_color     = "#27ae60" if score >= 80 else ("#e67e22" if score >= 50 else "#c0392b")

    score_widget = html.Div([
        html.Div(f"{score}%",
                 style={"color": s_color, "fontSize": "32px",
                        "fontWeight": "700", "textAlign": "center"}),
        html.Div("Compliance Score", style={"color": "#8e9eb0",
                                             "textAlign": "center",
                                             "fontSize": "11px"}),
        html.Hr(style={"borderColor": "#1e2230", "margin": "8px 0"}),
        *[html.Div(f"{icon} {count} {lbl}",
                   style={"color": color, "fontSize": "11px", "fontWeight": "600"})
          for icon, count, lbl, color in [
              ("✅", compliant, "Compliant",     "#27ae60"),
              ("⚠️", partial,   "Partial",        "#f1c40f"),
              ("❌", non_comp,  "Non-Compliant",  "#c0392b"),
              ("—",  na,        "Not Applicable", "#636e72"),
          ]],
    ])

    controls = FRAMEWORKS.get(fw or "nist-csf", [])
    gap_rows = []
    for i, ctrl in enumerate(controls):
        st = statuses[i] if i < len(statuses) else "non-compliant"
        if st in ("non-compliant", "partial"):
            gap_rows.append({"id": ctrl["id"], "control": ctrl["control"],
                             "desc": ctrl["desc"], "status": st})

    # Build gap UI for the gap-view div (on Gap Analysis tab)
    gap_ui_rows = []
    for g in gap_rows:
        color = STATUS_CLR[g["status"]]
        icon  = STATUS_ICON[g["status"]]
        gap_ui_rows.append(html.Div([
            html.Div([
                html.Span(f"{icon} ", style={"color": color}),
                html.Span(f"{g['id']}: {g['control']}",
                          style={"color": "#e0e0e0", "fontWeight": "600",
                                 "fontSize": "12px"}),
            ]),
            html.Div(g["desc"],
                     style={"color": "#8e9eb0", "fontSize": "10px",
                            "paddingLeft": "20px", "marginBottom": "2px"}),
        ], style={"padding": "6px 4px", "borderBottom": f"1px solid {DARK_BG}"}))

    gap_content = _card(
        html.Div(f"❌ {len(gap_rows)} Gaps Identified",
                 style={"color": "#e0e0e0", "fontWeight": "600",
                        "marginBottom": "10px"}),
        html.Div(gap_ui_rows or [html.Div("✅ No gaps — all controls compliant!",
                                           style={"color": "#27ae60",
                                                  "textAlign": "center",
                                                  "padding": "20px"})]),
    ) if gap_rows else html.Div("All controls compliant! ✅",
                                 style={"color": "#27ae60", "textAlign": "center",
                                        "padding": "20px", "fontWeight": "700"})

    # Store serialisable gap summary for the Gap tab view
    store_data = {"score": score, "compliant": compliant, "partial": partial,
                  "non_comp": non_comp, "na": na, "gaps": gap_rows}

    return score_widget, gap_content, store_data


@callback(
    Output("gc-gap-view",  "children"),
    Input("gc-gap-store",  "data"),
    Input("gc-tabs",       "active_tab"),
)
def populate_gap_view(store, tab):
    """Populate the Gap Analysis tab whenever the store updates or the tab is opened."""
    if tab != "gc-tab-gap" or not store:
        return html.Div("Click 'Calculate Score' on the Controls tab first.",
                        style={"color": "#636e72", "fontSize": "12px",
                               "textAlign": "center", "padding": "30px"})
    gap_rows = store.get("gaps", [])
    gap_ui_rows = []
    for g in gap_rows:
        color = STATUS_CLR.get(g["status"], "#fff")
        icon  = STATUS_ICON.get(g["status"], "?")
        gap_ui_rows.append(html.Div([
            html.Div([
                html.Span(f"{icon} ", style={"color": color}),
                html.Span(f"{g['id']}: {g['control']}",
                          style={"color": "#e0e0e0", "fontWeight": "600",
                                 "fontSize": "12px"}),
            ]),
            html.Div(g["desc"],
                     style={"color": "#8e9eb0", "fontSize": "10px",
                            "paddingLeft": "20px", "marginBottom": "2px"}),
        ], style={"padding": "6px 4px", "borderBottom": f"1px solid {DARK_BG}"}))
    if not gap_ui_rows:
        return html.Div("✅ All controls compliant!",
                        style={"color": "#27ae60", "textAlign": "center",
                               "padding": "20px", "fontWeight": "700"})
    return _card(
        html.Div(f"❌ {len(gap_rows)} Gaps Identified",
                 style={"color": "#e0e0e0", "fontWeight": "600",
                        "marginBottom": "10px"}),
        html.Div(gap_ui_rows),
    )


@callback(
    Output("gc-ai-out",  "children"),
    Input("gc-ai-gap",   "n_clicks"),
    State("gc-framework","value"),
    State("gc-org",      "value"),
    State({"type": "ctrl-status", "fw": ALL, "id": ALL}, "value"),
    prevent_initial_call=True,
)
def ai_gap(n, fw, org, statuses):
    if not n:
        raise PreventUpdate
    controls = FRAMEWORKS.get(fw or "nist-csf", [])
    gaps = []
    for i, ctrl in enumerate(controls):
        st = statuses[i] if i < len(statuses) else "non-compliant"
        if st in ("non-compliant", "partial"):
            gaps.append(f"- {ctrl['id']}: {ctrl['control']} [{st.upper()}] — {ctrl['desc']}")
    prompt = (
        f"You are a compliance consultant. "
        f"Provide a remediation plan for {org or 'the organisation'} "
        f"to achieve {(fw or 'nist-csf').upper()} compliance.\n\n"
        f"GAPS IDENTIFIED:\n" + ("\n".join(gaps) or "None") + "\n\n"
        f"For each gap provide:\n"
        f"1) **Root cause** — why this is typically non-compliant\n"
        f"2) **Remediation steps** — specific technical actions\n"
        f"3) **Effort estimate** — Low/Medium/High\n"
        f"4) **Quick wins** — controls fixable in < 1 week\n"
        f"5) **Business risk** if left unaddressed\n\n"
        f"End with a **30/60/90 day remediation roadmap**."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


@callback(
    Output("gc-download",   "data"),
    Input("gc-export-btn",  "n_clicks"),
    State("gc-framework",   "value"),
    State("gc-org",         "value"),
    State("gc-assessor",    "value"),
    State("gc-date",        "value"),
    State({"type": "ctrl-status", "fw": ALL, "id": ALL}, "value"),
    State("gc-ai-out",      "children"),
    prevent_initial_call=True,
)
def export_report(n, fw, org, assessor, date, statuses, ai_out):
    if not n:
        raise PreventUpdate
    controls = FRAMEWORKS.get(fw or "nist-csf", [])
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    total = len(controls)
    compliant  = statuses.count("compliant")
    partial    = statuses.count("partial")
    non_comp   = statuses.count("non-compliant")
    na         = statuses.count("not-applicable")
    effective  = total - na
    score      = int((compliant + partial * 0.5) / effective * 100) if effective else 0
    s_color    = "#27ae60" if score >= 80 else ("#e67e22" if score >= 50 else "#c0392b")

    rows = ""
    for i, ctrl in enumerate(controls):
        st    = statuses[i] if i < len(statuses) else "non-compliant"
        sc    = STATUS_CLR.get(st, "#fff")
        ic    = STATUS_ICON.get(st, "?")
        rows += (f"<tr><td>{ctrl['id']}</td><td>{ctrl['control']}</td>"
                 f"<td style='color:{sc};font-weight:700'>{ic} {st.replace('-',' ').title()}</td>"
                 f"<td>{ctrl['desc']}</td></tr>")

    html_content = f"""<!DOCTYPE html>
<html><head>
<meta charset='utf-8'>
<title>{(fw or 'compliance').upper()} Compliance Report — {org or 'Organisation'}</title>
<style>
  body{{font-family:Arial,sans-serif;background:#0d1117;color:#e0e0e0;
       max-width:1100px;margin:40px auto;padding:0 20px;}}
  h1,h2{{color:#3498db;}} h3{{color:#e0e0e0;}}
  table{{border-collapse:collapse;width:100%;margin:16px 0;}}
  th{{background:#2c3347;color:#e0e0e0;padding:8px;text-align:left;font-size:12px;}}
  td{{padding:6px 8px;border-bottom:1px solid #2c3347;color:#b0b0b0;font-size:11px;}}
  pre{{background:#161b22;padding:12px;border-radius:6px;
       color:#50fa7b;font-size:11px;white-space:pre-wrap;}}
  .score{{font-size:48px;font-weight:700;color:{s_color};text-align:center;}}
</style>
</head><body>
<h1>📋 {(fw or 'Compliance').upper()} Compliance Assessment</h1>
<p><strong>Organisation:</strong> {org or 'N/A'} |
   <strong>Assessor:</strong> {assessor or 'N/A'} |
   <strong>Date:</strong> {date or ts[:10]}</p>
<div class='score'>{score}%</div>
<p style='text-align:center;color:#8e9eb0;'>Compliance Score</p>
<table>
  <tr>
    <th>✅ Compliant</th><th>⚠️ Partial</th>
    <th>❌ Non-Compliant</th><th>— N/A</th>
  </tr>
  <tr>
    <td style='color:#27ae60;font-size:20px;font-weight:700'>{compliant}</td>
    <td style='color:#f1c40f;font-size:20px;font-weight:700'>{partial}</td>
    <td style='color:#c0392b;font-size:20px;font-weight:700'>{non_comp}</td>
    <td style='color:#636e72;font-size:20px;font-weight:700'>{na}</td>
  </tr>
</table>
<h2>Control Assessment</h2>
<table><tr><th>ID</th><th>Control</th><th>Status</th><th>Description</th></tr>
{rows}
</table>
<h2>AI Gap Analysis</h2>
<pre>{ai_out or 'Run AI Gap Analysis first.'}</pre>
<hr><p style='color:#636e72;font-size:11px;'>
Compliance & GRC Dashboard — Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}
</p></body></html>"""

    return dcc.send_string(html_content, f"{fw or 'compliance'}_report_{ts}.html")


# ── Client Comms Callbacks ────────────────────────────────────────────────────
@callback(
    Output("gc-comms-active-client", "data"),
    Input({"type": "gc-comms-client-btn", "email": ALL}, "n_clicks"),
    State("gc-comms-active-client", "data"),
    prevent_initial_call=True
)
def _select_client(n_clicks_list, current_active):
    import dash
    ctx = dash.callback_context
    if not ctx.triggered:
        return current_active
    btn_id = ctx.triggered[0]["prop_id"].split(".")[0]
    import json
    try:
        email = json.loads(btn_id).get("email")
        # Don't update if it's identical
        return email if email else current_active
    except:
        return current_active

@callback(
    Output("gc-comms-client-list", "children"),
    Output("gc-comms-history", "children"),
    Output("gc-comms-active-header", "children"),
    Input("gc-comms-poll", "n_intervals"),
    Input("gc-comms-active-client", "data")
)
def _refresh_comms(n_int, active_client):
    import json, os, time
    COMMS_FILE = "/opt/vuln_intel/app/uploads/assessments/client_messages.json"
    
    msgs = []
    if os.path.exists(COMMS_FILE):
        try:
            with open(COMMS_FILE, "r") as f:
                msgs = json.load(f)
        except Exception:
            msgs = []

    # Get unique clients and their last message time
    clients = {}
    for m in msgs:
        em = m.get("client_email")
        if em:
            if em not in clients or m["timestamp"] > clients[em]["last_ts"]:
                clients[em] = {"last_ts": m["timestamp"], "last_msg": m["message"][:30]}

    # Build Left Pane List
    sorted_clients = sorted(clients.items(), key=lambda x: x[1]["last_ts"], reverse=True)
    list_items = []
    for em, data in sorted_clients:
        is_active = (em == active_client)
        bg = "#1a3a6c" if is_active else "#1a1d24"
        ts_str = time.strftime('%H:%M', time.localtime(data["last_ts"]))
        list_items.append(
            dbc.Button([
                html.Div(em, style={"fontWeight": "bold", "color": "#e0e0e0", "marginBottom": "2px", "fontSize": "13px"}),
                html.Div([
                    html.Span(data["last_msg"] + "...", style={"color": "#b0b0b0"}),
                    html.Span(ts_str, style={"float": "right", "color": "#636e72"})
                ], style={"fontSize": "11px", "clear": "both"})
            ], id={"type": "gc-comms-client-btn", "email": em}, color="link", style={
                "width": "100%", "textAlign": "left", "padding": "10px",
                "background": bg, "border": "1px solid #2c3347", "borderRadius": "4px",
                "marginBottom": "4px", "textDecoration": "none"
            })
        )
    
    if not list_items:
        list_items = [html.Div("No active client conversations yet.", style={"color": "#636e72", "fontSize": "11px", "fontStyle": "italic", "padding": "8px"})]

    # Build Right Pane History
    history_items = []
    header_text = "Select a client to start chatting"
    
    if active_client:
        header_text = f"Chatting with: {active_client}"
        client_msgs = [m for m in msgs if m.get("client_email") == active_client]
        
        for m in client_msgs:
            is_soc = m.get("sender") != "Client"
            bg_color = "#204a8e" if is_soc else "#292d3e"
            align = "flex-end" if is_soc else "flex-start"
            radius = "8px 8px 2px 8px" if is_soc else "8px 8px 8px 2px"
            border = "1px solid #3b4261" if is_soc else "none"
            time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(m.get("timestamp", 0)))
            sender_label = m.get("sender", "Aegis SOC") if is_soc else "Client"
            
            history_items.append(
                html.Div([
                    html.Div(m.get("message", ""), style={"background": bg_color, "color": "#fff", "padding": "10px 14px", "borderRadius": radius, "fontSize": "13px", "border": border, "maxWidth": "75%", "lineHeight": "1.4"}),
                    html.Div(f"{sender_label} · {time_str}", style={"fontSize": "10px", "color": "#636e72", "marginTop": "4px"})
                ], style={"display": "flex", "flexDirection": "column", "alignItems": align, "marginBottom": "2px"})
            )
            
        if not history_items:
             history_items = [html.Div(f"No messages found for {active_client}.", style={"color": "#636e72", "fontSize": "12px", "textAlign": "center", "marginTop": "20px"})]
    
    return list_items, history_items, header_text


@callback(
    Output("gc-comms-input", "value"),
    Input("gc-comms-send-btn", "n_clicks"),
    State("gc-comms-input", "value"),
    State("gc-comms-active-client", "data"),
    prevent_initial_call=True
)
def _send_soc_msg(n, msg_text, active_client):
    if not n or not msg_text or not active_client:
        raise PreventUpdate
        
    import json, os, time
    COMMS_FILE = "/opt/vuln_intel/app/uploads/assessments/client_messages.json"
    
    msgs = []
    if os.path.exists(COMMS_FILE):
        try:
            with open(COMMS_FILE, "r") as f:
                msgs = json.load(f)
        except Exception:
            msgs = []
            
    msgs.append({
        "timestamp": int(time.time()),
        "client_email": active_client,
        "sender": "Aegis SOC Analyst",
        "message": msg_text.strip()
    })
    
    with open(COMMS_FILE, "w") as f:
        json.dump(msgs, f)
        
    # Clear input on send
    return ""


# ── Risk Register — Add Row Callback ──────────────────────────────────────────
@callback(
    Output("gc-rr-tbody",    "children"),
    Output("gc-rr-feedback", "children"),
    Output("gc-rr-id",       "value"),
    Output("gc-rr-desc",     "value"),
    Output("gc-rr-owner",    "value"),
    Input("gc-rr-add",       "n_clicks"),
    State("gc-rr-id",        "value"),
    State("gc-rr-desc",      "value"),
    State("gc-rr-severity",  "value"),
    State("gc-rr-owner",     "value"),
    State("gc-rr-tbody",     "children"),
    prevent_initial_call=True,
)
def _add_risk_row(n_clicks, rid, desc, sev, owner, existing_rows):
    if not n_clicks:
        raise PreventUpdate
    if not desc or not desc.strip():
        return existing_rows, "⚠️ Description is required.", rid, desc, owner

    sev = sev or "Medium"
    rid = (rid or "").strip() or f"R-{(len(existing_rows or []) + 7):02d}"
    desc  = desc.strip()
    owner = (owner or "").strip() or "—"

    colours = {"Critical":"#c0392b","High":"#e67e22","Medium":"#f1c40f","Low":"#27ae60"}

    def _badge(level):
        return html.Span(level, style={
            "background": colours.get(level, "#636e72"),
            "color":"#fff","padding":"2px 8px","borderRadius":"4px",
            "fontSize":"10px","fontWeight":"700"})

    new_row = html.Tr([
        html.Td(rid, style={"color":"#3498db","fontSize":"10px","padding":"6px 8px","fontFamily":"monospace"}),
        html.Td(desc, style={"color":"#ccc","fontSize":"10px","padding":"6px 8px"}),
        html.Td(_badge(sev)),
        html.Td("—"),        # Impact (not collected in form)
        html.Td(_badge(sev)),# Severity badge same as selected
        html.Td(owner, style={"color":"#8e9eb0","fontSize":"10px","padding":"6px 8px"}),
        html.Td(html.Span("Open", style={"color":"#c0392b","fontSize":"10px","fontWeight":"600"})),
    ], style={"borderBottom":"1px solid #1e2230"})

    updated = list(existing_rows or []) + [new_row]
    return updated, f"✅ Risk {rid} added.", "", "", ""


# ── Evidence Requirements — framework-aware panel ─────────────────────────────
_EVIDENCE_BY_FRAMEWORK = {
    "pci-dss":    ["Network segmentation diagram", "Firewall rule exports", "Cardholder data flow diagram",
                   "Vulnerability scan reports (ASV)", "Penetration test report", "Access control list review",
                   "Change management records", "Security awareness training records", "Log review evidence",
                   "Encryption key management policy"],
    "iso27001":   ["ISMS scope document", "Risk assessment & treatment plan", "Statement of Applicability",
                   "Asset inventory", "Access control records", "Business continuity plan",
                   "Internal audit reports", "Management review minutes", "Incident log",
                   "Supplier security agreements"],
    "nist-csf":   ["Asset inventory", "Risk register", "Incident response plan", "Recovery plan",
                   "Threat intelligence feeds", "Security monitoring evidence", "Vulnerability management records",
                   "Supply chain risk assessments", "Awareness training records"],
    "nist-800-53":["System Security Plan (SSP)", "Privacy Impact Assessment", "Contingency plan",
                   "Security assessment report", "Plan of Action & Milestones (POA&M)",
                   "Configuration management baseline", "Audit logs", "Penetration test results",
                   "Identity & access management records"],
    "hipaa":      ["Risk analysis report", "Workforce training records", "Sanction policy",
                   "Audit log evidence", "ePHI access controls", "Business Associate Agreements",
                   "Encryption evidence", "Incident response records", "Physical access controls"],
    "cis":        ["Asset inventory (HW & SW)", "Vulnerability scan reports", "Secure configuration baselines",
                   "Privileged access review", "Audit log review", "Malware defence evidence",
                   "Email security controls", "Network monitoring logs", "Penetration test report"],
    "soc2":       ["Trust Services Criteria mapping", "Control environment documentation",
                   "CC6 logical access evidence", "Availability monitoring logs", "Incident response plan",
                   "Vendor management records", "Change management log", "Encryption evidence",
                   "CC9 risk mitigation records"],
    "gdpr":       ["Data Processing Register (RoPA)", "Privacy notices", "Data subject request log (DSAR)",
                   "Data Protection Impact Assessment (DPIA)", "Data breach register",
                   "Consent records", "Data retention schedule", "DPO appointment record",
                   "Third-party data sharing agreements"],
    "cmmc":       ["Access control policy", "Audit and accountability plan", "Incident response plan",
                   "Risk assessment documentation", "System and communications protection records",
                   "Vulnerability scan reports", "Supply chain risk evidence", "CUI handling procedures"],
    "nis2":       ["Governance & risk management policy", "Incident reporting records (24h/72h logs)",
                   "Business continuity & disaster recovery plans", "Supply chain security assessments",
                   "Encryption & access control evidence", "Cyber hygiene training records",
                   "Vulnerability disclosure policy"],
    "dora":       ["ICT risk management framework", "Business continuity & recovery plans",
                   "Incident classification & reporting log", "Third-party ICT provider register",
                   "Threat-led penetration test (TLPT) report", "ICT change management log",
                   "Resilience testing results"],
    "iso42001":   ["AI risk register", "AI impact assessment", "AI governance policy",
                   "Data quality & bias assessment", "AI system transparency documentation",
                   "Third-party AI supplier agreements", "AI incident log", "Explainability evidence"],
}
_DEFAULT_EVIDENCE = ["Network diagram", "Firewall rule export", "Vulnerability scan reports",
                     "Penetration test report", "Access control review", "Patch management logs",
                     "Incident response plan", "Business continuity plan",
                     "Security awareness training records", "Risk assessment documentation"]

@callback(
    Output("gc-evidence-req-panel", "children"),
    Input("gc-framework", "value"),
)
def _update_evidence_req(fw):
    items = _EVIDENCE_BY_FRAMEWORK.get(fw or "", _DEFAULT_EVIDENCE)
    return [
        html.Div([
            html.Span("📄 ", style={"color": "#3498db"}),
            html.Span(ev, style={"color": "#b0b0b0", "fontSize": "11px"}),
        ], style={"marginBottom": "4px"})
        for ev in items
    ]


# ── Incident Register — Add Row Callback ───────────────────────────────────────
@callback(
    Output("gc-inc-tbody",    "children"),
    Output("gc-inc-feedback", "children"),
    Output("gc-inc-id",       "value"),
    Output("gc-inc-title",    "value"),
    Output("gc-inc-assigned", "value"),
    Input("gc-inc-add",       "n_clicks"),
    State("gc-inc-id",        "value"),
    State("gc-inc-title",     "value"),
    State("gc-inc-severity",  "value"),
    State("gc-inc-assigned",  "value"),
    State("gc-inc-tbody",     "children"),
    prevent_initial_call=True,
)
def _add_incident_row(n_clicks, iid, title, sev, assigned, existing_rows):
    if not n_clicks:
        raise PreventUpdate
    if not title or not title.strip():
        return existing_rows, "⚠️ Title is required.", iid, title, assigned

    sev      = sev or "High"
    iid      = (iid or "").strip() or f"I-{(len(existing_rows or []) + 13):02d}"
    title    = title.strip()
    assigned = (assigned or "").strip() or "—"

    sev_col = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f1c40f", "Low": "#27ae60"}
    new_row = html.Tr([
        html.Td(iid,   style={"color": "#e67e22", "fontSize": "10px", "padding": "6px 8px", "fontFamily": "monospace"}),
        html.Td(title, style={"color": "#ccc",    "fontSize": "10px", "padding": "6px 8px", "fontWeight": "600"}),
        html.Td(html.Span(sev, style={"color": sev_col.get(sev, "#fff"), "fontSize": "10px", "fontWeight": "700"})),
        html.Td(html.Span("In Progress", style={"color": "#e67e22", "fontSize": "10px", "fontWeight": "600"})),
        html.Td("—",       style={"color": "#8e9eb0", "fontSize": "10px", "padding": "6px 8px"}),
        html.Td(assigned,  style={"color": "#b0b0b0", "fontSize": "10px", "padding": "6px 8px"}),
    ], style={"borderBottom": "1px solid #1e2230"})

    updated = list(existing_rows or []) + [new_row]
    return updated, f"✅ Incident {iid} logged.", "", "", ""


# ── Policy Library — Add Row Callback ─────────────────────────────────────────
@callback(
    Output("gc-pol-tbody",    "children"),
    Output("gc-pol-feedback", "children"),
    Output("gc-pol-name",     "value"),
    Output("gc-pol-owner",    "value"),
    Input("gc-pol-add",       "n_clicks"),
    State("gc-pol-name",      "value"),
    State("gc-pol-owner",     "value"),
    State("gc-pol-review",    "value"),
    State("gc-pol-tbody",     "children"),
    prevent_initial_call=True,
)
def _add_policy_row(n_clicks, name, owner, review, existing_rows):
    if not n_clicks:
        raise PreventUpdate
    if not name or not name.strip():
        return existing_rows, "⚠️ Policy name is required.", name, owner

    name   = name.strip()
    owner  = (owner  or "").strip() or "—"
    review = (review or "").strip() or "2027-01-01"
    from datetime import date as _date
    today  = _date.today().isoformat()
    pol_id = f"P-{(len(existing_rows or []) + 9):02d}"

    new_row = html.Tr([
        html.Td(pol_id, style={"color": "#3498db", "fontSize": "10px", "padding": "6px 8px", "fontFamily": "monospace"}),
        html.Td(name,   style={"color": "#ccc",    "fontSize": "10px", "padding": "6px 8px", "fontWeight": "600"}),
        html.Td(html.Span("Active",  style={"color": "#27ae60", "fontSize": "10px", "fontWeight": "600"})),
        html.Td(html.Span("v1.0",    style={"color": "#8e9eb0", "fontSize": "10px", "fontFamily": "monospace"})),
        html.Td(today,  style={"color": "#8e9eb0", "fontSize": "10px", "padding": "6px 8px", "fontFamily": "monospace"}),
        html.Td(review, style={"color": "#8e9eb0", "fontSize": "10px", "padding": "6px 8px", "fontFamily": "monospace"}),
        html.Td(owner,  style={"color": "#8e9eb0", "fontSize": "10px", "padding": "6px 8px"}),
    ], style={"borderBottom": "1px solid #1e2230"})

    updated = list(existing_rows or []) + [new_row]
    return updated, f"✅ Policy {pol_id} added.", "", ""
