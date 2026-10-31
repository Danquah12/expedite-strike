"""
DFIR Case Management — Digital Forensics & Incident Response case tracker.
Covers: case creation, evidence management, timeline reconstruction,
        artefact analysis, reporting, and DFIR toolbox.
"""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc

def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background":"#1e2230","border":"1px solid #2e3450","borderRadius":"8px","marginBottom":"12px"})

def _cmd(t):
    return html.Pre(t, style={"background":"#0d0f1a","color":"#00e6e6","padding":"8px","borderRadius":"6px","fontSize":"11px","overflowX":"auto","marginBottom":"6px"})

def _badge(t, c): return dbc.Badge(t, color=c, className="me-1 mb-1")

CASES = [
    ("DFIR-001", "Ransomware — Finance Dept",     "Active",   "P1", "2026-03-01"),
    ("DFIR-002", "Insider Exfiltration — DevOps", "Active",   "P2", "2026-03-03"),
    ("DFIR-003", "BEC Phishing Campaign",         "Closed",   "P2", "2026-02-20"),
    ("DFIR-004", "Credential Spray — VPN",        "Closed",   "P3", "2026-02-15"),
    ("DFIR-005", "Cloud Storage Exposure (S3)",   "Pending",  "P2", "2026-03-05"),
]

def layout():
    return html.Div([
        html.Div([
            html.H4("📋 DFIR Case Management",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("Digital Forensics & Incident Response case tracker — evidence management, timeline builder, artefact analysis, and reporting.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                _card(
                    dbc.Label("New Case", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="dfir-case-name", placeholder="Case description",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Select(id="dfir-case-priority", options=[
                        {"label": "P1 — Critical", "value": "P1"},
                        {"label": "P2 — High",     "value": "P2"},
                        {"label": "P3 — Medium",   "value": "P3"},
                        {"label": "P4 — Low",      "value": "P4"},
                    ], value="P2",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Select(id="dfir-case-type", options=[
                        {"label": "Ransomware",         "value": "ransomware"},
                        {"label": "Data Exfiltration",  "value": "exfil"},
                        {"label": "Insider Threat",     "value": "insider"},
                        {"label": "Phishing/BEC",       "value": "bec"},
                        {"label": "Malware Analysis",   "value": "malware"},
                        {"label": "Other",              "value": "other"},
                    ], value="ransomware",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Button("➕ Open Case", id="dfir-open-btn", color="success",
                               size="sm", className="w-100 mb-2"),
                    html.Div(id="dfir-open-out"),
                    title="Case Management"
                ),
                _card(
                    dbc.Button("🤖 AI Case Summary", id="dfir-ai-btn", color="secondary",
                               size="sm", className="w-100"),
                    html.Div(id="dfir-ai-out"),
                    title="AI Summary"
                ),
            ], width=3),

            dbc.Col([
                dbc.Tabs(id="dfir-tabs", active_tab="dfir-cases", children=[
                    dbc.Tab(label="Case Register",   tab_id="dfir-cases"),
                    dbc.Tab(label="Evidence",        tab_id="dfir-evidence"),
                    dbc.Tab(label="Timeline",        tab_id="dfir-timeline"),
                    dbc.Tab(label="Artefact Tools",  tab_id="dfir-tools"),
                    dbc.Tab(label="Final Report",    tab_id="dfir-report"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="dfir-tab-content"),
            ], width=9),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


@callback(Output("dfir-tab-content","children"), Input("dfir-tabs","active_tab"))
def render_dfir_tab(tab):
    if tab == "dfir-cases":
        rows = []
        for cid, desc, status, priority, date in CASES:
            status_color = {"Active":"danger","Closed":"success","Pending":"warning"}.get(status,"secondary")
            pri_color = {"P1":"danger","P2":"warning","P3":"info","P4":"secondary"}.get(priority,"secondary")
            rows.append(html.Tr([
                html.Td(cid, style={"color":"#ffd700","fontSize":"11px"}),
                html.Td(desc, style={"color":"#ccc","fontSize":"11px"}),
                html.Td(_badge(status, status_color)),
                html.Td(_badge(priority, pri_color)),
                html.Td(date, style={"color":"#aaa","fontSize":"11px"}),
                html.Td(dbc.Button("Open", size="sm", color="outline-info", style={"fontSize":"10px","padding":"2px 6px"})),
            ]))
        return _card(
            html.H6("DFIR Case Register", style={"color":"#ffd700"}),
            dbc.Row([
                dbc.Col(_badge("Active: 2","danger"),  width="auto"),
                dbc.Col(_badge("Pending: 1","warning"),width="auto"),
                dbc.Col(_badge("Closed: 2","success"), width="auto"),
            ], className="mb-2"),
            dbc.Table([html.Thead(html.Tr([html.Th("Case ID"),html.Th("Description"),html.Th("Status"),html.Th("Priority"),html.Th("Opened"),html.Th("")])),
                       html.Tbody(rows)], bordered=True, hover=True, size="sm")
        )

    elif tab == "dfir-evidence":
        return _card(
            html.H6("Evidence Chain of Custody", style={"color":"#ffd700"}),
            dbc.Row([
                dbc.Col([
                    dbc.Table([
                        html.Thead(html.Tr([html.Th("Item"),html.Th("Type"),html.Th("Source"),html.Th("Hash (SHA256)"),html.Th("Collected"),html.Th("By")])),
                        html.Tbody([
                            html.Tr([html.Td("MEM-001"),html.Td("Memory dump"),html.Td("WRK01"),html.Td("a1b2c3..."),html.Td("2026-03-01 14:22"),html.Td("IR Lead")]),
                            html.Tr([html.Td("DISK-001"),html.Td("Disk image"),html.Td("WRK01"),html.Td("d4e5f6..."),html.Td("2026-03-01 15:10"),html.Td("Forensics")]),
                            html.Tr([html.Td("LOG-001"),html.Td("Firewall logs"),html.Td("FW01"),html.Td("g7h8i9..."),html.Td("2026-03-01 13:45"),html.Td("SOC")]),
                            html.Tr([html.Td("PCAP-001"),html.Td("Network capture"),html.Td("SW-Core"),html.Td("j0k1l2..."),html.Td("2026-03-01 14:00"),html.Td("Network")]),
                        ])
                    ], bordered=True, hover=True, size="sm"),
                ], width=12),
            ])
        )

    elif tab == "dfir-timeline":
        return _card(
            html.H6("Incident Timeline Reconstruction", style={"color":"#ffd700"}),
            dbc.ListGroup([
                dbc.ListGroupItem([_badge("T-07d","secondary"), " 2026-02-22 — Phishing email received by finance user (Sandra M.)"], color=""),
                dbc.ListGroupItem([_badge("T-07d","secondary"), " 2026-02-22 14:31 — User opened attachment; macro executed PowerShell dropper"]),
                dbc.ListGroupItem([_badge("T-06d","warning"),   " 2026-02-23 09:15 — Cobalt Strike beacon established to C2: 185.220.101.47"]),
                dbc.ListGroupItem([_badge("T-05d","warning"),   " 2026-02-24 — Lateral movement: WMI used to reach DC01"]),
                dbc.ListGroupItem([_badge("T-03d","danger"),    " 2026-02-26 — NTDS.dit extracted; Kerberoasting performed"]),
                dbc.ListGroupItem([_badge("T-01d","danger"),    " 2026-02-28 — Ransomware (LockBit 3.0) deployed across 47 endpoints"]),
                dbc.ListGroupItem([_badge("T+00h","info"),      " 2026-03-01 06:42 — First alert: EDR CRITICAL — mass file encryption"]),
                dbc.ListGroupItem([_badge("T+01h","info"),      " 2026-03-01 07:45 — IR team activated; network isolation applied"]),
            ], style={"fontSize":"12px"})
        )

    elif tab == "dfir-tools":
        return _card(
            html.H6("DFIR Toolbox", style={"color":"#ffd700"}),
            dbc.Row([
                dbc.Col([
                    html.P("Memory Forensics:", style={"color":"#00e6e6","fontSize":"12px"}),
                    _cmd("# Volatility 3\nvol -f memory.lime windows.pslist\nvol -f memory.lime windows.netscan\nvol -f memory.lime windows.malfind\n\n# Dump suspicious process\nvol -f memory.lime windows.dumpfiles --pid 1234"),

                    html.P("Disk Forensics:", style={"color":"#00e6e6","fontSize":"12px"}),
                    _cmd("# Autopsy / TSK\nmmls disk.img\nfls -r disk.img\n\n# Mount forensically\nlosetup /dev/loop0 disk.img\nmount -o ro,noexec /dev/loop0p2 /mnt/evidence"),
                ], width=6),
                dbc.Col([
                    html.P("Log Analysis:", style={"color":"#00e6e6","fontSize":"12px"}),
                    _cmd("# EVTX parsing\npython3 evtx_dump.py Security.evtx | grep 4624\n\n# Chainsaw (fast Windows event hunting)\nchainsaw hunt . --sigma sigma_rules/ --mapping mappings/sigma.yml\n\n# Hayabusa\nhayabusa csv-timeline -d C:\\Windows\\System32\\winevt\\Logs -o timeline.csv"),

                    html.P("Network Forensics:", style={"color":"#00e6e6","fontSize":"12px"}),
                    _cmd("# Zeek / NetworkMiner / Wireshark\ntshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri\n\n# Extract files from PCAP\ntshark -r capture.pcap --export-objects 'http,./extracted/'"),
                ], width=6),
            ])
        )

    elif tab == "dfir-report":
        return _card(
            html.H6("Final DFIR Report Structure", style={"color":"#ffd700"}),
            dbc.Accordion([
                dbc.AccordionItem([
                    html.P("Incident type, severity, affected systems, business impact summary, dates/times, IR team members.", style={"color":"#ccc","fontSize":"12px"})
                ], title="1. Executive Summary"),
                dbc.AccordionItem([
                    html.P("Chronological reconstruction of attacker actions from initial access to detection.", style={"color":"#ccc","fontSize":"12px"})
                ], title="2. Attack Timeline"),
                dbc.AccordionItem([
                    html.P("How initial access was obtained (phishing, vuln exploitation, credential theft, etc.)", style={"color":"#ccc","fontSize":"12px"})
                ], title="3. Root Cause Analysis"),
                dbc.AccordionItem([
                    html.P("MITRE ATT&CK technique mapping for each observed attacker action.", style={"color":"#ccc","fontSize":"12px"})
                ], title="4. MITRE ATT&CK Mapping"),
                dbc.AccordionItem([
                    html.P("Containment, eradication, and recovery actions taken with timestamps.", style={"color":"#ccc","fontSize":"12px"})
                ], title="5. Response Actions"),
                dbc.AccordionItem([
                    html.P("MTTD, MTTR, estimated financial impact, data volume affected.", style={"color":"#ccc","fontSize":"12px"})
                ], title="6. Impact Assessment"),
                dbc.AccordionItem([
                    html.P("Short, medium, long-term security improvements with owners and deadlines.", style={"color":"#ccc","fontSize":"12px"})
                ], title="7. Recommendations"),
            ])
        )
    return html.Div()


@callback(Output("dfir-open-out","children"),
          Input("dfir-open-btn","n_clicks"),
          State("dfir-case-name","value"),
          State("dfir-case-priority","value"),
          State("dfir-case-type","value"),
          prevent_initial_call=True)
def open_dfir_case(n, name, priority, case_type):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(f"Case opened: {name or 'New Case'} ({priority}, {case_type}). Check Case Register tab.", color="success", style={"fontSize":"12px","marginTop":"8px"})


@callback(Output("dfir-ai-out","children"), Input("dfir-ai-btn","n_clicks"), prevent_initial_call=True)
def dfir_ai(n):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(html.Pre(
        "DFIR Portfolio Summary\n\n"
        "Active Cases: 2 (both P1/P2 — require daily updates)\n"
        "Avg MTTD: 6 days (target: <24hrs) — critical gap in detection\n"
        "Avg MTTR: 5 days (target: <48hrs) — containment taking too long\n\n"
        "Trends:\n"
        "- 3 of 5 cases originated from phishing email — awareness training needed\n"
        "- All ransomware cases had >4 day dwell time before detection\n"
        "- No cases were detected by SIEM — all via EDR or user report\n\n"
        "Recommendations:\n"
        "1. Implement BEC detection rules in email gateway\n"
        "2. Deploy NDR solution to reduce dwell time\n"
        "3. Automate network isolation via EDR playbook",
        style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}),
        color="dark", style={"marginTop":"8px"})
