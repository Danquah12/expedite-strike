"""
Incident Response Playbooks — Live IR workflow (NIST SP 800-61 aligned).
"""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc

def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background":"#1e2230","border":"1px solid #2e3450","borderRadius":"8px","marginBottom":"12px"})

def _badge(t, c): return dbc.Badge(t, color=c, className="me-1 mb-1")

PLAYBOOKS = {
    "ransomware": {
        "name": "🔒 Ransomware",
        "phases": {
            "Detection":    ["Identify affected systems via EDR","Determine ransomware family","Identify initial access vector"],
            "Containment":  ["Isolate infected endpoints (network isolation)","Block C2 IPs/domains at firewall","Preserve memory and disk images","Disable affected AD accounts"],
            "Eradication":  ["Remove ransomware binaries","Rebuild systems from clean baseline","Reset all domain credentials","Close initial access vector"],
            "Recovery":     ["Restore from verified clean backup","Test restored data integrity","Monitor 72hrs post-restore"],
            "Post-Incident":["Root cause analysis","Lessons learned report","Notify regulators if data exfiltrated"],
        }
    },
    "phishing": {
        "name": "🎣 BEC / Phishing",
        "phases": {
            "Detection":    ["Identify affected mailboxes","Check forwarding rules","Review sign-in logs"],
            "Containment":  ["Reset account passwords + revoke sessions","Remove malicious inbox rules","Block attacker IPs in Conditional Access"],
            "Eradication":  ["Delete phishing emails from all mailboxes","Review OAuth app permissions"],
            "Recovery":     ["Re-enable MFA (phishing-resistant)","Retrain targeted users"],
            "Post-Incident":["GDPR 72hr breach assessment","Submit to Microsoft Defender"],
        }
    },
    "data_breach": {
        "name": "💾 Data Breach",
        "phases": {
            "Detection":    ["Identify exfiltration vector","Quantify data involved","Identify affected individuals"],
            "Containment":  ["Block exfiltration channel","Revoke attacker access","Capture PCAP forensics"],
            "Eradication":  ["Remove persistence","Patch exploited vulnerability","Reset credentials"],
            "Recovery":     ["Monitor for re-exfiltration","Restore from clean backup"],
            "Post-Incident":["GDPR/HIPAA/PCI notification","Engage legal counsel"],
        }
    },
}

def layout():
    return html.Div([
        html.Div([
            html.H4("🚨 Incident Response Playbooks",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("NIST SP 800-61 aligned live IR workflow — Detection · Containment · Eradication · Recovery · Lessons Learned.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                _card(
                    dbc.Label("Incident Type", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="ir-type", options=[
                        {"label": "🔒 Ransomware",     "value": "ransomware"},
                        {"label": "🎣 BEC / Phishing", "value": "phishing"},
                        {"label": "💾 Data Breach",    "value": "data_breach"},
                    ], value="ransomware",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("Severity", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="ir-severity", options=[
                        {"label": "P1 — Critical", "value": "p1"},
                        {"label": "P2 — High",     "value": "p2"},
                        {"label": "P3 — Medium",   "value": "p3"},
                    ], value="p1",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("IR Lead", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="ir-lead", placeholder="CISO / Lead name",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Button("🚨 Activate Playbook", id="ir-activate-btn", color="danger",
                               size="sm", className="w-100 mb-2"),
                    html.Div(id="ir-activate-out"),
                    title="Incident Setup"
                ),
                _card(
                    _badge("GDPR","warning"), html.Span(" 72hr", style={"color":"#ccc","fontSize":"11px"}), html.Br(),
                    _badge("NIS2","info"),    html.Span(" 24hr early warning", style={"color":"#ccc","fontSize":"11px"}), html.Br(),
                    _badge("SEC","secondary"),html.Span(" 4 days", style={"color":"#ccc","fontSize":"11px"}), html.Br(),
                    _badge("HIPAA","primary"),html.Span(" 60 days", style={"color":"#ccc","fontSize":"11px"}),
                    title="Notification Deadlines"
                ),
                _card(
                    dbc.Button("🤖 AI Timeline", id="ir-ai-btn", color="secondary",
                               size="sm", className="w-100"),
                    html.Div(id="ir-ai-out"),
                    title="AI Summary"
                ),
            ], width=3),

            dbc.Col([
                dbc.Tabs(id="ir-tabs", active_tab="ir-playbook", children=[
                    dbc.Tab(label="Active Playbook", tab_id="ir-playbook"),
                    dbc.Tab(label="Evidence Log",    tab_id="ir-evidence"),
                    dbc.Tab(label="Communications",  tab_id="ir-comms"),
                    dbc.Tab(label="Lessons Learned", tab_id="ir-lessons"),
                    dbc.Tab(label="NIST Alignment",  tab_id="ir-nist"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="ir-tab-content"),
            ], width=9),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


@callback(Output("ir-tab-content","children"),
          Input("ir-tabs","active_tab"),
          State("ir-type","value"))
def render_ir_tab(tab, ir_type):
    playbook = PLAYBOOKS.get(ir_type, PLAYBOOKS["ransomware"])
    phase_colors = {"Detection":"info","Containment":"warning","Eradication":"danger",
                    "Recovery":"success","Post-Incident":"primary"}

    if tab == "ir-playbook":
        accordion_items = []
        for phase, steps in playbook["phases"].items():
            color = phase_colors.get(phase, "secondary")
            accordion_items.append(dbc.AccordionItem([
                dbc.Checklist(
                    options=[{"label": s, "value": i} for i, s in enumerate(steps)],
                    value=[], style={"color":"#ccc","fontSize":"12px"}
                )
            ], title=html.Span([_badge(phase, color)])))
        return _card(html.H6(playbook["name"], style={"color":"#ffd700"}),
                     dbc.Accordion(accordion_items, always_open=True))

    elif tab == "ir-evidence":
        return _card(
            html.H6("Evidence Chain of Custody", style={"color":"#ffd700"}),
            dbc.Table([
                html.Thead(html.Tr([html.Th("Item"),html.Th("Type"),html.Th("Collected By"),html.Th("SHA256 Hash"),html.Th("Timestamp")])),
                html.Tbody([
                    html.Tr([html.Td("Memory image — DC01"),html.Td("LIME dump"),html.Td("IR Lead"),html.Td("a3f2c1..."),html.Td("T+01:00")]),
                    html.Tr([html.Td("Disk image — WRK01"),html.Td("dc3dd"),html.Td("Forensics"),html.Td("b1c4d2..."),html.Td("T+02:30")]),
                    html.Tr([html.Td("Firewall logs"),html.Td("Syslog"),html.Td("SOC"),html.Td("c2d5e3..."),html.Td("T+00:30")]),
                    html.Tr([html.Td("PCAP — core switch"),html.Td("tcpdump"),html.Td("Network"),html.Td("d3e6f4..."),html.Td("T+01:45")]),
                ])
            ], bordered=True, hover=True, size="sm")
        )

    elif tab == "ir-comms":
        return _card(
            html.H6("Internal Notification Template", style={"color":"#ffd700"}),
            html.Pre(
                "SUBJECT: [INCIDENT NOTIFICATION] Security Incident Declared\n\n"
                "Team,\n\nAn incident has been declared. Severity: [P1/P2].\n\n"
                "What we know:\n- [Brief description]\n- Systems affected: [list]\n"
                "- Business impact: [describe]\n\nActions taken:\n"
                "- IR team activated\n- Containment in progress\n\nNext update: [TIME]\nIR Lead: [NAME]",
                style={"fontSize":"11px","color":"#e6e6e6","whiteSpace":"pre-wrap","background":"#0d0f1a","padding":"10px","borderRadius":"6px"}
            )
        )

    elif tab == "ir-lessons":
        return _card(
            html.H6("Lessons Learned (complete within 2 weeks)", style={"color":"#ffd700"}),
            dbc.Checklist(options=[
                {"label": "Timeline reconstruction complete",               "value": 1},
                {"label": "Root cause confirmed",                           "value": 2},
                {"label": "What went well documented",                      "value": 3},
                {"label": "Improvement areas identified",                   "value": 4},
                {"label": "New detection rules deployed",                   "value": 5},
                {"label": "Playbook updated",                               "value": 6},
                {"label": "Security awareness updated",                     "value": 7},
                {"label": "MTTD / MTTR / cost metrics captured",           "value": 8},
            ], value=[], id="ir-lessons-items", style={"color":"#ccc","fontSize":"12px"})
        )

    elif tab == "ir-nist":
        return _card(
            html.H6("NIST SP 800-61 Phase Tracker", style={"color":"#ffd700"}),
            dbc.Table([
                html.Thead(html.Tr([html.Th("Phase"),html.Th("Key Activities"),html.Th("Status")])),
                html.Tbody([
                    html.Tr([html.Td("1. Preparation"),html.Td("IR plan, team, tools"),html.Td(_badge("Complete","success"))]),
                    html.Tr([html.Td("2. Detection & Analysis"),html.Td("Identify, scope, classify"),html.Td(_badge("In Progress","warning"))]),
                    html.Tr([html.Td("3. Containment"),html.Td("Short/long-term containment"),html.Td(_badge("In Progress","warning"))]),
                    html.Tr([html.Td("4. Eradication"),html.Td("Remove threat, patch vuln"),html.Td(_badge("Pending","secondary"))]),
                    html.Tr([html.Td("5. Recovery"),html.Td("Restore, monitor, validate"),html.Td(_badge("Pending","secondary"))]),
                    html.Tr([html.Td("6. Post-Incident"),html.Td("Lessons learned, reporting"),html.Td(_badge("Pending","secondary"))]),
                ])
            ], bordered=True, hover=True, size="sm")
        )
    return html.Div()


@callback(Output("ir-activate-out","children"),
          Input("ir-activate-btn","n_clicks"),
          State("ir-type","value"), State("ir-severity","value"), State("ir-lead","value"),
          prevent_initial_call=True)
def activate_ir(n, ir_type, severity, lead):
    if not n: raise dash.exceptions.PreventUpdate
    name = PLAYBOOKS.get(ir_type, {}).get("name", "Incident")
    return dbc.Alert([html.B("🚨 INCIDENT ACTIVATED"), html.Br(),
                      f"{name} | {severity.upper()} | Lead: {lead or 'TBA'}"],
                     color="danger", style={"fontSize":"12px","marginTop":"8px"})


@callback(Output("ir-ai-out","children"), Input("ir-ai-btn","n_clicks"),
          State("ir-type","value"), prevent_initial_call=True)
def ir_ai(n, ir_type):
    if not n: raise dash.exceptions.PreventUpdate
    name = PLAYBOOKS.get(ir_type, {}).get("name", "Incident")
    return dbc.Alert(html.Pre(
        f"IR Timeline — {name}\n\n"
        "T+00:00 Alert triggered by EDR\nT+00:15 IR team activated\n"
        "T+00:30 Scope: 12 endpoints affected\nT+01:00 Network isolation applied\n"
        "T+02:00 Memory/disk images captured\nT+04:00 Initial vector confirmed\n"
        "T+06:00 Credentials rotated\nT+12:00 Eradication complete\nT+24:00 Recovery initiated\n\n"
        "MTTD: 45min | MTTR: 24hrs\nGDPR 72hr clock: started T+00:30",
        style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}),
        color="dark", style={"marginTop":"8px"})
