"""
EDR Gap Analysis — Evaluate endpoint detection coverage and LOTL blind spots.
Covers: EDR telemetry gaps, LOTL technique detection, detection rule testing,
        Atomic Red Team validation, coverage heat map.
"""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc
from cyber_range.services import findings_service as fs

def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background":"#1e2230","border":"1px solid #2e3450","borderRadius":"8px","marginBottom":"12px"})

def _cmd(t):
    return html.Pre(t, style={"background":"#0d0f1a","color":"#00e6e6","padding":"8px","borderRadius":"6px","fontSize":"11px","overflowX":"auto","marginBottom":"6px"})

def _badge(t, c): return dbc.Badge(t, color=c, className="me-1 mb-1")

LOTL_TECHNIQUES = [
    ("T1059.001", "PowerShell execution",          "Nearly all EDRs detect", "LOW"),
    ("T1059.003", "cmd.exe spawning process",       "Good coverage",          "LOW"),
    ("T1218.011", "Rundll32 proxy execution",       "Partial — LOLBins vary", "HIGH"),
    ("T1218.010", "Regsvr32 (COM scriptlet)",       "Partial",                "HIGH"),
    ("T1047",     "WMI remote execution",           "Often missed",           "CRITICAL"),
    ("T1053.005", "Scheduled task creation",        "Good coverage",          "MEDIUM"),
    ("T1134",     "Access token manipulation",      "Patchy",                 "HIGH"),
    ("T1055",     "Process injection",              "Good for common methods","MEDIUM"),
    ("T1003.001", "LSASS memory dump",              "Good coverage",          "MEDIUM"),
    ("T1218.007", "Msiexec proxy execution",        "Often missed",           "HIGH"),
    ("T1574.002", "DLL side-loading",               "Often missed",           "CRITICAL"),
    ("T1140",     "Deobfuscate/Decode via certutil","Partial",                "HIGH"),
]

def layout():
    return html.Div([
        html.Div([
            html.H4("🛡️ EDR Gap Analysis",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("Evaluate EDR telemetry gaps, test LOTL technique detection, validate atomic tests, and build detection coverage heat map.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                _card(
                    dbc.Label("EDR Platform", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="edr-platform", options=[
                        {"label": "CrowdStrike Falcon",   "value": "crowdstrike"},
                        {"label": "Microsoft Defender XDR","value": "mde"},
                        {"label": "SentinelOne",          "value": "s1"},
                        {"label": "Carbon Black",         "value": "cb"},
                        {"label": "Cortex XDR",           "value": "cortex"},
                        {"label": "Elastic Security",     "value": "elastic"},
                        {"label": "Trend Vision One",     "value": "trend"},
                    ], value="mde",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("Test Mode", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="edr-mode", options=[
                        {"label": "Atomic Red Team (local)",    "value": "atomic"},
                        {"label": "Caldera (automated C2)",     "value": "caldera"},
                        {"label": "Manual technique walkthrough","value": "manual"},
                    ], value="atomic",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Button("▶ Start Coverage Test", id="edr-run-btn", color="danger",
                               size="sm", className="w-100 mb-2"),
                    html.Div(id="edr-run-out"),
                    title="EDR Config"
                ),
                _card(
                    dbc.Button("🤖 AI Gap Analysis", id="edr-ai-btn", color="secondary",
                               size="sm", className="w-100"),
                    html.Div(id="edr-ai-out"),
                    title="AI Analysis"
                ),
            ], width=3),

            dbc.Col([
                dbc.Tabs(id="edr-tabs", active_tab="edr-lotl", children=[
                    dbc.Tab(label="LOTL Coverage",   tab_id="edr-lotl"),
                    dbc.Tab(label="Atomic Tests",    tab_id="edr-atomic"),
                    dbc.Tab(label="Telemetry Gaps",  tab_id="edr-telemetry"),
                    dbc.Tab(label="Detections",      tab_id="edr-detections"),
                    dbc.Tab(label="Scoring",         tab_id="edr-scoring"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="edr-tab-content"),
            ], width=6),

            dbc.Col([
                _card(
                    _badge("Atomic Red Team", "info"),
                    _badge("MITRE ATT&CK", "secondary"),
                    _badge("Caldera", "primary"),
                    html.Hr(style={"borderColor":"#333"}),
                    html.P("Living-off-the-Land Binaries (LOLBins) — attackers abuse trusted Windows binaries to evade EDR.", style={"color":"#ccc","fontSize":"12px"}),
                    title="Key Concepts"
                ),
                _card(
                    html.P("Atomic Red Team:", style={"color":"#ffd700","fontSize":"12px"}),
                    _cmd("# Install\nInstall-Module -Name invoke-atomicredteam\nImport-Module invoke-atomicredteam\n\n# Run specific technique\nInvoke-AtomicTest T1218.011 -TestNumbers 1\n\n# Run and check (auto-validate)\nInvoke-AtomicTest T1059.001 -CheckPrereqs"),
                    title="Quick Start"
                ),
            ], width=3),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


@callback(Output("edr-tab-content","children"), Input("edr-tabs","active_tab"))
def render_edr_tab(tab):
    if tab == "edr-lotl":
        rows = []
        for tid, name, coverage, risk in LOTL_TECHNIQUES:
            color = {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"info","LOW":"secondary"}.get(risk)
            rows.append(html.Tr([
                html.Td(tid,     style={"color":"#00e6e6","fontSize":"11px"}),
                html.Td(name,    style={"color":"#ccc","fontSize":"11px"}),
                html.Td(coverage,style={"color":"#aaa","fontSize":"11px"}),
                html.Td(_badge(risk, color)),
                html.Td(dbc.Select(options=[{"label":"Not Tested","value":"nt"},
                                            {"label":"Detected","value":"det"},
                                            {"label":"Missed","value":"miss"},
                                            {"label":"Partial","value":"part"}],
                                   value="nt",
                                   style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","fontSize":"11px","padding":"2px"})),
            ]))
        return _card(
            html.H6("LOTL Technique Coverage Matrix", style={"color": "#ffd700"}),
            dbc.Table([html.Thead(html.Tr([html.Th("Technique"),html.Th("Description"),html.Th("Typical EDR Coverage"),html.Th("Risk"),html.Th("Result")])),
                       html.Tbody(rows)], bordered=True, hover=True, size="sm"),
            html.Hr(style={"borderColor":"#333","marginTop":"12px"}),
            html.H6("Save Gap Finding to Dashboard", style={"color":"#aaa","fontSize":"12px"}),
            dbc.Row([
                dbc.Col(dbc.Select(id="edr-save-sev", options=[
                    {"label":"Critical","value":"Critical"},{"label":"High","value":"High"},
                    {"label":"Medium","value":"Medium"},{"label":"Low","value":"Low"},
                ], value="Critical",
                style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055"}), width=3),
                dbc.Col(dbc.Input(id="edr-save-title", placeholder="e.g. WMI remote execution not detected (T1047)...",
                                  style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055"}), width=6),
                dbc.Col(dbc.Button("💾 Save Finding", id="edr-save-btn", color="success", size="sm", className="w-100"), width=3),
            ], className="mt-2 mb-1 g-2"),
            html.Div(id="edr-save-out"),
        )

    elif tab == "edr-atomic":
        return _card(
            html.H6("Atomic Red Team Test Execution", style={"color": "#ffd700"}),
            _cmd("""# List all atomics for a technique
Invoke-AtomicTest T1218.011 -ShowDetailsBrief

# Run atomic test
Invoke-AtomicTest T1218.011 -TestNumbers 1

# Run and check for EDR alert
Invoke-AtomicTest T1047 -TestNumbers 1,2,3

# Full tactic sweep
$tactics = @("T1059.001","T1218.011","T1047","T1574.002","T1140")
foreach ($t in $tactics) {
    Invoke-AtomicTest $t -TestNumbers 1
    Start-Sleep -Seconds 60  # Wait for EDR to fire
}"""),
            dbc.Alert("Run atomics in a dedicated test VM — never on production systems. Ensure SOC is aware of testing window.", color="warning", style={"fontSize":"12px"}),
        )

    elif tab == "edr-telemetry":
        return _card(
            html.H6("Common EDR Telemetry Gaps", style={"color": "#ffd700"}),
            dbc.ListGroup([
                dbc.ListGroupItem([_badge("CRITICAL","danger"), " Container/K8s workloads — many EDRs have no agent deployment"], color=""),
                dbc.ListGroupItem([_badge("HIGH","warning"),    " Linux servers — reduced telemetry vs Windows agents"]),
                dbc.ListGroupItem([_badge("HIGH","warning"),    " Network shares — file write operations often missed"]),
                dbc.ListGroupItem([_badge("HIGH","warning"),    " Memory-only malware — fileless attacks bypass file scanning"]),
                dbc.ListGroupItem([_badge("MEDIUM","info"),     " GCP/AWS Lambda functions — serverless has no EDR agent"]),
                dbc.ListGroupItem([_badge("MEDIUM","info"),     " Legacy OT/SCADA — incompatible OS versions"]),
                dbc.ListGroupItem([_badge("MEDIUM","info"),     " Mobile devices (BYOD) — MDM ≠ EDR"]),
            ], style={"fontSize": "12px"})
        )

    elif tab == "edr-detections":
        return _card(
            html.H6("Detection Rule Improvement", style={"color": "#ffd700"}),
            html.P("Write targeted KQL/Sigma rules for the gaps identified above:", style={"color":"#ccc","fontSize":"12px"}),
            _cmd("""# KQL — Detect rundll32 with suspicious arguments (T1218.011)
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript","vbscript","http","\\\\")
| project Timestamp, DeviceName, ProcessCommandLine

# KQL — WMI process creation (T1047)
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName !in~ ("msiexec.exe","SearchIndexer.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine"""),
        )

    elif tab == "edr-scoring":
        return _card(
            html.H6("EDR Coverage Score", style={"color": "#ffd700"}),
            dbc.Row([
                dbc.Col([
                    html.Div("72%", style={"fontSize":"48px","color":"#ffd700","fontWeight":"700","textAlign":"center"}),
                    html.P("Overall Detection Coverage", style={"textAlign":"center","color":"#999","fontSize":"12px"}),
                ], width=4),
                dbc.Col([
                    dbc.Progress(value=90, label="Process Events",    style={"marginBottom":"8px"}),
                    dbc.Progress(value=75, label="Network Events",    color="warning", style={"marginBottom":"8px"}),
                    dbc.Progress(value=60, label="File Events",       color="warning", style={"marginBottom":"8px"}),
                    dbc.Progress(value=40, label="Registry Events",   color="danger",  style={"marginBottom":"8px"}),
                    dbc.Progress(value=30, label="Memory Events",     color="danger",  style={"marginBottom":"8px"}),
                    dbc.Progress(value=55, label="WMI/COM Events",    color="warning", style={"marginBottom":"8px"}),
                ], width=8),
            ])
        )
    return html.Div()


@callback(Output("edr-run-out","children"), Input("edr-run-btn","n_clicks"),
          State("edr-platform","value"), State("edr-mode","value"), prevent_initial_call=True)
def run_edr_test(n, platform, mode):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(f"Coverage test initiated on {platform} using {mode} mode. Review LOTL Coverage tab.", color="info", style={"fontSize":"12px","marginTop":"8px"})


@callback(Output("edr-ai-out","children"), Input("edr-ai-btn","n_clicks"),
          State("edr-platform","value"), prevent_initial_call=True)
def edr_ai(n, platform):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(html.Pre(
        f"EDR Gap Analysis — {platform}\n\n"
        "Coverage Score: 72% (Industry average: 68%)\n\n"
        "Critical Gaps:\n"
        "- T1047 (WMI): Detected in only 2/5 test cases — WMI subscriptions missed\n"
        "- T1574.002 (DLL sideload): 0/3 tests detected — major blind spot\n"
        "- T1218.011 (Rundll32): Partial — JS/VBScript args detected, HTTP not\n\n"
        "Priority Detections to Deploy:\n"
        "1. WMI subscription creation monitoring (Event ID 5861)\n"
        "2. DLL load from non-system paths by signed binaries\n"
        "3. Rundll32 with HTTP/UNC path arguments\n\n"
        "Recommendation: Deploy Sysmon with SwiftOnSecurity config to fill telemetry gaps.",
        style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}),
        color="dark", style={"marginTop":"8px"})


@callback(Output("edr-save-out","children"),
          Input("edr-save-btn","n_clicks"),
          State("edr-save-title","value"),
          State("edr-save-sev","value"),
          prevent_initial_call=True)
def save_edr_finding(n, title, severity):
    if not n: raise dash.exceptions.PreventUpdate
    if not title:
        return dbc.Alert("Enter a finding title.", color="warning", style={"fontSize":"12px"})
    fs.save_finding("EDR Gaps", title, severity or "Medium", "", "", "")
    return dbc.Alert(f"✅ Saved: [{severity}] {title}", color="success", style={"fontSize":"12px","marginTop":"6px"})
