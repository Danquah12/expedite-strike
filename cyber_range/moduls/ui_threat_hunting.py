"""
ui_threat_hunting.py
Proactive Threat Hunting Tab
Sigma Rule Editor · YARA Rule Builder/Scanner · Hunt Hypotheses ·
Log Query Builder (Splunk/ELK) · AI Hunt Suggestions · IOC Enrichment
"""
from __future__ import annotations

import subprocess
import threading
import time
from datetime import datetime

from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

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
MONO      = {"fontFamily": "monospace", "fontSize": "11px"}

_OUTPUTS: dict[str, str] = {}
_LOCK     = threading.Lock()

HUNT_HYPOTHESES = [
    {"id": "h1", "title": "Living-off-the-Land (LOLBins)",
     "desc": "Attackers using built-in Windows tools (certutil, mshta, regsvr32) to evade AV",
     "tactic": "Defense Evasion", "technique": "T1218"},
    {"id": "h2", "title": "Credential Dumping",
     "desc": "LSASS access patterns indicating Mimikatz or similar tools",
     "tactic": "Credential Access", "technique": "T1003"},
    {"id": "h3", "title": "Lateral Movement via SMB",
     "desc": "Unusual SMB connections between workstations indicating lateral movement",
     "tactic": "Lateral Movement", "technique": "T1021.002"},
    {"id": "h4", "title": "Scheduled Task Persistence",
     "desc": "New scheduled tasks created in unusual locations",
     "tactic": "Persistence", "technique": "T1053"},
    {"id": "h5", "title": "DNS Tunneling",
     "desc": "Unusually long DNS queries indicating data exfiltration via DNS",
     "tactic": "Exfiltration", "technique": "T1048.003"},
    {"id": "h6", "title": "Beacon Behaviour",
     "desc": "Regular outbound connections at exact intervals (C2 beaconing)",
     "tactic": "Command & Control", "technique": "T1071"},
    {"id": "h7", "title": "PowerShell Abuse",
     "desc": "Encoded PowerShell commands bypassing execution policy",
     "tactic": "Execution", "technique": "T1059.001"},
    {"id": "h8", "title": "Kerberoasting",
     "desc": "Excessive Kerberos TGS requests for service accounts",
     "tactic": "Credential Access", "technique": "T1558.003"},
]

DEFAULT_SIGMA = """title: Suspicious PowerShell Encoded Command
status: experimental
description: Detects PowerShell executing encoded commands often used by attackers
author: Hunt Team
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc '
            - '-encodedcommand'
            - 'JAB'
            - 'SUVYA'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high
"""

DEFAULT_YARA = """rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands"
        author = "Hunt Team"
        date = "2024-01-01"
        severity = "HIGH"

    strings:
        $enc1 = "-encodedcommand" nocase
        $enc2 = "-enc " nocase
        $b64  = /JAB[A-Za-z0-9+\/=]{20,}/
        $iex  = "Invoke-Expression" nocase
        $iwr  = "Invoke-WebRequest" nocase

    condition:
        any of ($enc*) or ($b64 and any of ($iex, $iwr))
}"""


def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)

def _label(t): return html.Div(t, style=LABEL)
def _cmd(c):   return html.Div(c, style={**MONO, "color": "#50fa7b",
                                          "background": "#0d0d0d",
                                          "padding": "3px 8px",
                                          "borderRadius": "4px",
                                          "marginBottom": "3px"})

def _run_bg(cmd: str, key: str):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=60)
        out = r.stdout + ("\n[STDERR]\n" + r.stderr if r.stderr else "")
    except subprocess.TimeoutExpired:
        out = "[TIMEOUT]"
    except Exception as e:
        out = f"[ERROR] {e}"
    with _LOCK:
        _OUTPUTS[key] = out


def _hypo_card(h: dict) -> html.Div:
    tactic_colors = {
        "Defense Evasion": "#9b59b6", "Credential Access": "#c0392b",
        "Lateral Movement": "#e67e22", "Persistence": "#f39c12",
        "Exfiltration": "#e74c3c",    "Command & Control": "#3498db",
        "Execution": "#27ae60",
    }
    color = tactic_colors.get(h["tactic"], "#636e72")
    return html.Div([
        html.Div([
            html.Span(h["title"], style={"color": "#e0e0e0", "fontWeight": "700",
                                          "fontSize": "12px", "marginRight": "8px"}),
            html.Span(h["tactic"], style={"color": color, "fontSize": "10px",
                                           "fontWeight": "600", "marginRight": "6px",
                                           "background": "#1a1d24",
                                           "padding": "1px 6px",
                                           "borderRadius": "3px"}),
            html.Span(h["technique"], style={"color": "#3498db", "fontSize": "10px"}),
        ]),
        html.Div(h["desc"], style={"color": "#8e9eb0", "fontSize": "11px",
                                    "marginTop": "2px", "paddingLeft": "4px"}),
    ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}",
              "cursor": "pointer"})


def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="th-state", data={}),

        html.Div([
            html.H4("🔭 Proactive Threat Hunting",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("Sigma Rules · YARA Scanner · Hunt Hypotheses · "
                     "Log Queries · AI Hunt Suggestions · IOC Enrichment",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🎯 Hunt Configuration",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("Environment"),
                    dbc.Select(id="th-env",
                               options=[
                                   {"label": "Windows Enterprise", "value": "windows"},
                                   {"label": "Linux Server",        "value": "linux"},
                                   {"label": "Cloud (AWS/Azure)",   "value": "cloud"},
                                   {"label": "Mixed",               "value": "mixed"},
                               ], value="windows",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("SIEM Platform"),
                    dbc.Select(id="th-siem",
                               options=[
                                   {"label": "Splunk",       "value": "splunk"},
                                   {"label": "Elastic/ELK",  "value": "elastic"},
                                   {"label": "Microsoft Sentinel", "value": "sentinel"},
                                   {"label": "QRadar",       "value": "qradar"},
                                   {"label": "Chronicle",    "value": "chronicle"},
                               ], value="splunk",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("IOC to Enrich"),
                    dbc.Input(id="th-ioc", placeholder="IP, domain, hash, or CVE",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("🔍 Enrich IOC", id="th-enrich-btn",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "4px"}),
                    html.Div(id="th-enrich-out",
                             style={"color": "#b0b0b0", "fontSize": "11px",
                                    "maxHeight": "100px", "overflowY": "auto",
                                    "marginTop": "4px"}),
                ),
                _card(
                    html.Div("🤖 AI Hunt",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    dbc.Button("💡 Suggest Hunts", id="th-ai-suggest",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("📝 Generate Sigma", id="th-ai-sigma",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("📊 Hunt Report", id="th-ai-report",
                               color="outline-warning", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="th-ai-out",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "280px", "overflowY": "auto"}),
                ),
            ], width=3),

            # ── Centre ───────────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="th-tabs", active_tab="th-tab-hypo",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="💡 Hypotheses",  tab_id="th-tab-hypo"),
                     dbc.Tab(label="Σ Sigma Rules",  tab_id="th-tab-sigma"),
                     dbc.Tab(label="🔍 YARA Scanner", tab_id="th-tab-yara"),
                     dbc.Tab(label="📊 Log Queries",  tab_id="th-tab-logs"),
                 ]),
                html.Div(id="th-phase-content"),
            ], width=6),

            # ── Right ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("✅ Hunt Methodology",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span(f"{i+1}. ", style={"color": "#3498db",
                                                      "fontWeight": "700",
                                                      "fontSize": "11px"}),
                        html.Span(step, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for i, step in enumerate([
                          "Form hypothesis (MITRE-backed)",
                          "Identify data sources required",
                          "Collect & normalize logs",
                          "Profile baseline behaviour",
                          "Hunt for anomalies/IOCs",
                          "Investigate findings",
                          "Escalate or close",
                          "Create detection rule (Sigma)",
                          "Measure & report",
                      ])],
                ),
                _card(
                    html.Div("📋 Quick Commands",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[_cmd(c) for c in [
                        "sigma convert -t splunk rule.yml",
                        "sigma convert -t elastic rule.yml",
                        "yara rule.yar /suspect/path/",
                        "yara -r rules/ /mnt/evidence/",
                        "chainsaw hunt . --rules rules/",
                        "hayabusa-win64.exe logon-summary -d .",
                    ]],
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


@callback(
    Output("th-phase-content", "children"),
    Input("th-tabs",           "active_tab"),
    State("th-siem",           "value"),
    State("th-env",            "value"),
)
def render_phase(tab, siem, env):
    siem = siem or "splunk"
    env  = env  or "windows"

    if tab == "th-tab-hypo":
        rows = [_hypo_card(h) for h in HUNT_HYPOTHESES]
        return _card(
            html.Div("💡 Hunt Hypotheses (MITRE ATT&CK Mapped)",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div("Select a hypothesis and use AI to generate "
                     "detection rules and log queries.",
                     style={"color": "#636e72", "fontSize": "11px",
                            "marginBottom": "10px"}),
            html.Div(rows),
        )

    elif tab == "th-tab-sigma":
        return _card(
            html.Div("Σ Sigma Rule Editor",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("Rule YAML"),
            dbc.Textarea(id="th-sigma-rule", value=DEFAULT_SIGMA,
                         style={**INPUT_STY, "height": "280px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button(f"→ Convert to {siem.title()}", id="th-sigma-convert",
                                   color="primary", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=4),
            ], style={"marginBottom": "8px"}),
            _label("Converted Query"),
            dbc.Textarea(id="th-sigma-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "150px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b", "marginBottom": "6px"}),
            html.Div(id="th-sigma-ai-out",
                     style={"color": "#b0b0b0", "fontSize": "12px",
                            "whiteSpace": "pre-wrap",
                            "maxHeight": "180px", "overflowY": "auto"}),
        )

    elif tab == "th-tab-yara":
        return _card(
            html.Div("🔍 YARA Rule Builder & Scanner",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("YARA Rule"),
            dbc.Textarea(id="th-yara-rule", value=DEFAULT_YARA,
                         style={**INPUT_STY, "height": "220px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            _label("Target Path to Scan"),
            dbc.Input(id="th-yara-path", placeholder="/suspect/path or /mnt/evidence",
                      value="/tmp",
                      style={**INPUT_STY, "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("▶ Run YARA", id="th-yara-run",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=4),
                dbc.Col(dbc.Button("✨ AI Improve", id="th-yara-ai",
                                   color="outline-info", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=4),
            ], style={"marginBottom": "8px"}),
            dbc.Textarea(id="th-yara-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "160px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b", "marginBottom": "6px"}),
            html.Div(id="th-yara-ai-out",
                     style={"color": "#b0b0b0", "fontSize": "12px",
                            "whiteSpace": "pre-wrap",
                            "maxHeight": "150px", "overflowY": "auto"}),
        )

    elif tab == "th-tab-logs":
        spl_queries = {
            "splunk": {
                "LOLBins": 'index=wineventlog EventCode=4688 (Process_Command_Line="*certutil*" OR Process_Command_Line="*mshta*" OR Process_Command_Line="*regsvr32*" OR Process_Command_Line="*wmic*") | table _time, ComputerName, Account_Name, Process_Command_Line',
                "Credential Dump": 'index=wineventlog EventCode=10 TargetImage="*lsass.exe*" | table _time, ComputerName, SourceImage, TargetImage',
                "DNS Exfil": 'index=network sourcetype=dns query_length>60 | stats count by src_ip, query | sort -count',
                "Beacon": 'index=network | timechart span=1m count by dest_ip | where count>0 AND count<3 | stats count by dest_ip | where count>20',
                "Kerberoast": 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Account_Name, Service_Name | sort -count',
            },
            "elastic": {
                "LOLBins": '{"query": {"bool": {"should": [{"match": {"process.command_line": "certutil"}}, {"match": {"process.command_line": "mshta"}}, {"match": {"process.command_line": "regsvr32"}}]}}}',
                "Credential Dump": 'event.code: 10 AND target.process.name: lsass.exe',
                "PowerShell Encoded": 'process.command_line: (*-enc* OR *-encodedcommand* OR *JAB*) AND process.name: powershell.exe',
            },
            "sentinel": {
                "LOLBins": 'SecurityEvent | where EventID == 4688 | where CommandLine has_any ("certutil","mshta","regsvr32","wmic") | project TimeGenerated, Computer, Account, CommandLine',
                "Credential Dump": 'SecurityEvent | where EventID == 10 | where TargetImage contains "lsass.exe" | project TimeGenerated, Computer, SourceImage',
                "DNS Exfil": 'DnsEvents | where QueryType == "A" | where strlen(Name) > 60 | summarize count() by Name, ClientIP | sort by count_ desc',
            },
        }
        queries = spl_queries.get(siem, spl_queries["splunk"])
        tabs = [html.Div([
            html.Div(k, style={"color": "#3498db", "fontWeight": "700",
                               "fontSize": "11px", "marginBottom": "4px",
                               "marginTop": "8px"}),
            html.Div(v, style={**MONO, "color": "#50fa7b",
                               "background": "#0d0d0d",
                               "padding": "8px", "borderRadius": "4px",
                               "fontSize": "10px", "whiteSpace": "pre-wrap"}),
        ]) for k, v in queries.items()]
        return _card(
            html.Div(f"📊 {siem.title()} Hunt Queries",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div(tabs, style={"maxHeight": "500px", "overflowY": "auto"}),
        )

    return html.Div()


@callback(
    Output("th-sigma-out",    "value"),
    Input("th-sigma-convert", "n_clicks"),
    State("th-sigma-rule",    "value"),
    State("th-siem",          "value"),
    prevent_initial_call=True,
)
def convert_sigma(n, rule, siem):
    if not n or not rule:
        raise PreventUpdate
    siem = siem or "splunk"
    with _LOCK:
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(rule)
            fname = f.name
    threading.Thread(
        target=_run_bg,
        args=(f"sigma convert -t {siem} {fname} 2>&1", "sigma"),
        daemon=True
    ).start()
    time.sleep(3)
    with _LOCK:
        return _OUTPUTS.get("sigma", "[Running…]")


@callback(
    Output("th-yara-out",  "value"),
    Input("th-yara-run",   "n_clicks"),
    State("th-yara-rule",  "value"),
    State("th-yara-path",  "value"),
    prevent_initial_call=True,
)
def run_yara(n, rule, path):
    if not n or not rule:
        raise PreventUpdate
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as f:
        f.write(rule)
        fname = f.name
    threading.Thread(
        target=_run_bg,
        args=(f"yara {fname} {path or '/tmp'} 2>&1", "yara"),
        daemon=True
    ).start()
    time.sleep(5)
    with _LOCK:
        return _OUTPUTS.get("yara", "[Running…]")


@callback(
    Output("th-ai-out",    "children"),
    Input("th-ai-suggest", "n_clicks"),
    Input("th-ai-sigma",   "n_clicks"),
    Input("th-ai-report",  "n_clicks"),
    Input("th-yara-ai",    "n_clicks"),
    State("th-env",        "value"),
    State("th-siem",       "value"),
    State("th-sigma-rule", "value"),
    State("th-yara-rule",  "value"),
    prevent_initial_call=True,
)
def ai_hunt(sug_n, sig_n, rep_n, yara_ai_n, env, siem, sigma, yara):
    if not ctx.triggered_id:
        raise PreventUpdate
    tid = ctx.triggered_id
    env  = env  or "windows"
    siem = siem or "splunk"
    if tid == "th-ai-suggest":
        prompt = (
            f"You are a threat hunting expert. Suggest 5 high-value hunt hypotheses "
            f"for a {env} environment using {siem}.\n\n"
            f"For each hypothesis:\n"
            f"1) **Hypothesis** — what are you looking for?\n"
            f"2) **MITRE Technique** — ATT&CK ID and name\n"
            f"3) **Data Sources** — what logs/telemetry needed?\n"
            f"4) **Hunt Query** — {siem} query to detect it\n"
            f"5) **Why Now** — why is this relevant to current threat landscape (2025)?"
        )
    elif tid == "th-ai-sigma":
        prompt = (
            f"Improve this Sigma rule for better detection coverage:\n\n"
            f"```yaml\n{sigma or DEFAULT_SIGMA}\n```\n\n"
            f"Provide:\n"
            f"1) **Improved rule** with additional detection strings\n"
            f"2) **False positive reduction** techniques\n"
            f"3) **{siem.title()} query** equivalent\n"
            f"4) **Testing approach** — how to validate this rule fires correctly\n"
            f"5) **Related rules** to complement detection"
        )
    elif tid == "th-yara-ai":
        prompt = (
            f"Improve this YARA rule for better malware detection:\n\n"
            f"```\n{yara or DEFAULT_YARA}\n```\n\n"
            f"Provide:\n"
            f"1) **Improved rule** with additional strings/conditions\n"
            f"2) **Entropy checks** for packed/encrypted malware\n"
            f"3) **PE header** checks if Windows executable\n"
            f"4) **False positive** risk assessment\n"
            f"5) **Related YARA rules** from public repositories"
        )
    else:  # hunt report
        with _LOCK:
            all_out = "\n\n".join(f"[{k.upper()}]\n{v[:300]}"
                                   for k, v in _OUTPUTS.items())
        prompt = (
            f"Generate a threat hunting report for {env} environment.\n\n"
            f"Hunt results:\n{all_out or 'No hunts run yet'}\n\n"
            f"Write:\n"
            f"1) **Executive Summary** — what was hunted and what was found\n"
            f"2) **Findings** categorised by MITRE tactic\n"
            f"3) **IOCs** discovered\n"
            f"4) **Detection Gaps** identified\n"
            f"5) **Recommendations** — new rules to productionize"
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"
