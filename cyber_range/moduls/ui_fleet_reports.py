#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ui_fleet_reports.py
===================
Dedicated report layouts for each Ægis standalone suite.
Safe to import into reports_app.py — uses unique IDs prefixed per suite.
"""

import os, json, datetime
from dash import html, dcc, callback, Input, Output, State, no_update
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px

# ── Shared Neo4j helper ───────────────────────────────────────────────────────
def _neo(cypher, params=None):
    try:
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver("bolt://localhost:7687",
                                   auth=("neo4j", os.environ.get("NEO4J_PASSWORD","Adomaa12@")))
        with drv.session() as s:
            r = s.run(cypher, params or {})
            return [dict(record) for record in r]
    except Exception:
        return []

def _blank(label="No data"):
    fig = go.Figure()
    fig.add_annotation(text=label, x=0.5, y=0.5, xref="paper", yref="paper",
                       font={"color":"#333","size":13}, showarrow=False)
    fig.update_layout(paper_bgcolor="#0a0a0a", plot_bgcolor="#0a0a0a",
                      margin=dict(l=0,r=0,t=0,b=0), height=160)
    return fig

def _section_header(icon, title, subtitle, color="#00b4ff"):
    return html.Div([
        html.Div([
            html.Span(icon, style={"fontSize":"24px","marginRight":"12px"}),
            html.Div([
                html.Div(title, style={"color":color,"fontWeight":"900","fontSize":"16px",
                                       "letterSpacing":"1px"}),
                html.Div(subtitle, style={"color":"#1a3a5a","fontSize":"11px","marginTop":"2px"}),
            ]),
        ], style={"display":"flex","alignItems":"center"}),
        html.Div(style={"height":"1px","background":f"linear-gradient(90deg,{color}44,transparent)",
                        "marginTop":"12px"}),
    ], style={"padding":"20px 28px 10px"})

def _kpi(icon, label, value, color="#00b4ff"):
    return html.Div([
        html.Div(icon, style={"fontSize":"20px","marginBottom":"4px"}),
        html.Div(str(value), style={"color":color,"fontSize":"22px","fontWeight":"900","fontFamily":"monospace"}),
        html.Div(label, style={"color":"#2a3a4a","fontSize":"9px","fontWeight":"700","letterSpacing":"2px"}),
    ], style={"background":"#0a0c10","border":"1px solid #0f1520","borderRadius":"10px",
              "padding":"14px 18px","textAlign":"center","minWidth":"110px"})

# ─────────────────────────────────────────────────────────────────────────────
# 1. EXTERNAL ASSESSMENT REPORT
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_external():
    rows = _neo("MATCH (v:Vulnerability) WHERE v.source IN ['nmap','shodan','osint'] "
                "RETURN v.host as host, v.cve_id as cve, v.cvss as cvss, v.severity as sev "
                "ORDER BY cvss DESC LIMIT 20")
    total = len(rows)
    critical = sum(1 for r in rows if (r.get("sev") or "").lower()=="critical")

    rows_osint = _neo("MATCH (v:Vulnerability) WHERE v.source='osint' RETURN count(v) as n")
    osint_n = rows_osint[0]["n"] if rows_osint else 0

    rows_ti = _neo("MATCH (t:ThreatActor) RETURN count(t) as n")
    ti_n = rows_ti[0]["n"] if rows_ti else 0

    table_rows = [html.Tr([
        html.Td(r.get("host","—"), style={"color":"#aaa","fontSize":"11px","padding":"6px 10px"}),
        html.Td(r.get("cve","—"),  style={"color":"#00b4ff","fontSize":"11px","padding":"6px 10px","fontFamily":"monospace"}),
        html.Td(str(r.get("cvss","—")), style={"color":"#ff8800","fontSize":"11px","padding":"6px 10px"}),
        html.Td(r.get("sev","—"),  style={"color":"#ff4444" if (r.get("sev") or "").lower()=="critical" else "#aaa",
                                          "fontSize":"10px","fontWeight":"700","padding":"6px 10px"}),
    ]) for r in rows[:15]]

    return html.Div([
        _section_header("🔭", "External Assessment Report", "OSINT · Threat Intel · Dark Web · External Pentest", "#a855f7"),
        html.Div([
            dbc.Row([
                dbc.Col(_kpi("🔭", "OSINT FINDINGS", osint_n, "#a855f7"), width="auto"),
                dbc.Col(_kpi("🕵️", "THREAT ACTORS", ti_n, "#a855f7"), width="auto"),
                dbc.Col(_kpi("⚠️", "EXT SURFACE", total, "#ff8800"), width="auto"),
                dbc.Col(_kpi("💀", "CRITICAL", critical, "#ff4444"), width="auto"),
            ], className="g-3 mb-4"),
            html.Div([
                html.Div("EXTERNAL SURFACE FINDINGS", style={"color":"#2a1a5a","fontSize":"9px",
                         "fontWeight":"900","letterSpacing":"2px","padding":"8px 0 4px"}),
                html.Table([
                    html.Thead(html.Tr([
                        html.Th("HOST",     style={"color":"#1a2a4a","fontSize":"9px","fontWeight":"700","letterSpacing":"1.5px","padding":"8px 10px"}),
                        html.Th("CVE ID",   style={"color":"#1a2a4a","fontSize":"9px","fontWeight":"700","letterSpacing":"1.5px","padding":"8px 10px"}),
                        html.Th("CVSS",     style={"color":"#1a2a4a","fontSize":"9px","fontWeight":"700","letterSpacing":"1.5px","padding":"8px 10px"}),
                        html.Th("SEVERITY", style={"color":"#1a2a4a","fontSize":"9px","fontWeight":"700","letterSpacing":"1.5px","padding":"8px 10px"}),
                    ], style={"borderBottom":"1px solid #0f1520"})),
                    html.Tbody(table_rows or [html.Tr(html.Td("No external findings in graph",
                        colSpan=4, style={"color":"#222","padding":"20px","textAlign":"center"}))]),
                ], style={"width":"100%","borderCollapse":"collapse"}),
            ], style={"background":"#060810","border":"1px solid #0f1520","borderRadius":"10px",
                      "padding":"8px","overflow":"auto"}),
        ], style={"padding":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh"})


# ─────────────────────────────────────────────────────────────────────────────
# 2. RED TEAM REPORT
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_redteam():
    rows = _neo("MATCH (v:Vulnerability) WHERE v.severity IN ['Critical','High'] "
                "RETURN v.host as host, v.cve_id as cve, v.cvss as cvss, v.exploit_available as exp, v.severity as sev "
                "ORDER BY cvss DESC LIMIT 20")
    critical    = sum(1 for r in rows if (r.get("sev") or "").lower() == "critical")
    exploitable = sum(1 for r in rows if r.get("exp"))

    hosts     = _neo("MATCH (v:Vulnerability) WHERE v.severity='Critical' RETURN DISTINCT v.host as h LIMIT 10")
    host_list = [r["h"] for r in hosts if r.get("h")]

    mitre = _neo("MATCH (m:MitreTechnique) RETURN m.technique_id as tid, m.name as name LIMIT 8")

    # Pre-build lists to avoid syntax issues with starred comprehensions in Col
    host_items = [html.Div([
        html.Span("●", style={"color":"#ef4444","marginRight":"8px","fontSize":"10px"}),
        html.Span(h,   style={"color":"#aaa","fontSize":"11px","fontFamily":"monospace"}),
    ], style={"padding":"5px 8px","borderBottom":"1px solid #0f1520"})
    for h in (host_list or ["No critical hosts detected"])]

    mitre_items = ([html.Div([
        html.Span(r.get("tid","?"), style={"color":"#ef4444","fontSize":"9px","fontFamily":"monospace","marginRight":"10px","fontWeight":"700"}),
        html.Span(r.get("name","Unknown"), style={"color":"#888","fontSize":"11px"}),
    ], style={"padding":"5px 8px","borderBottom":"1px solid #0f1520"})
    for r in mitre] or [html.Div("No MITRE data in graph", style={"color":"#222","fontSize":"11px","padding":"12px"})])

    return html.Div([
        _section_header("🔴", "Red Team Operations Report", "AD RedOps · Automated PT · Exploitation · C2 Activity", "#ef4444"),
        html.Div([
            dbc.Row([
                dbc.Col(_kpi("💀","CRITICAL HOSTS", len(host_list), "#ef4444"), width="auto"),
                dbc.Col(_kpi("💥","EXPLOITABLE",    exploitable,    "#ff8800"), width="auto"),
                dbc.Col(_kpi("🔑","CRIT + HIGH",    len(rows),      "#ef4444"), width="auto"),
                dbc.Col(_kpi("⚔️","MITRE TTPS",     len(mitre),     "#a855f7"), width="auto"),
            ], className="g-3 mb-4"),
            dbc.Row([
                dbc.Col(
                    [html.Div("🎯 COMPROMISED HOSTS", style={"color":"#3a1a1a","fontSize":"9px","fontWeight":"900","letterSpacing":"2px","marginBottom":"8px"})] + host_items,
                    md=5, style={"background":"#060810","border":"1px solid #1a0808","borderRadius":"10px","padding":"14px"}),
                dbc.Col(
                    [html.Div("⚔️ MITRE ATT&CK TECHNIQUES", style={"color":"#3a1a1a","fontSize":"9px","fontWeight":"900","letterSpacing":"2px","marginBottom":"8px"})] + mitre_items,
                    md=7, style={"background":"#060810","border":"1px solid #1a0808","borderRadius":"10px","padding":"14px"}),
            ], className="g-3"),
        ], style={"padding":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh"})


# ─────────────────────────────────────────────────────────────────────────────
# 3. CYBER DEFENCE REPORT
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_defence():
    rows = _neo("MATCH (v:Vulnerability) WHERE v.category IN ['sast','api','container','supply_chain','phishing'] "
                "RETURN v.category as cat, count(v) as n ORDER BY n DESC")
    total = sum(r.get("n",0) for r in rows)

    sast_n      = next((r["n"] for r in rows if r.get("cat")=="sast"), 0)
    api_n       = next((r["n"] for r in rows if r.get("cat")=="api"), 0)
    container_n = next((r["n"] for r in rows if r.get("cat")=="container"), 0)

    cats = [r.get("cat","?") for r in rows]
    vals = [r.get("n",0) for r in rows]
    fig = go.Figure(go.Bar(
        x=cats or ["SAST","API","Container","Supply Chain"],
        y=vals or [0,0,0,0],
        marker_color=["#00c2ff","#00e676","#ff9800","#a855f7","#ef4444"][:len(cats or [1])],
    ))
    fig.update_layout(paper_bgcolor="#0a0c10", plot_bgcolor="#0a0c10",
                      font={"color":"#555"}, margin=dict(l=10,r=10,t=20,b=20), height=180,
                      xaxis={"showgrid":False}, yaxis={"showgrid":False,"gridcolor":"#111"})

    return html.Div([
        _section_header("🛡️", "Cyber Defence Report", "SAST · API · Container · Supply Chain · Threat Hunting · EDR", "#00c2ff"),
        html.Div([
            dbc.Row([
                dbc.Col(_kpi("🔍", "SAST ISSUES",      sast_n,      "#00c2ff"), width="auto"),
                dbc.Col(_kpi("🔌", "API FINDINGS",     api_n,       "#00e676"), width="auto"),
                dbc.Col(_kpi("📦", "CONTAINER VULNS",  container_n, "#ff9800"), width="auto"),
                dbc.Col(_kpi("🛡️", "TOTAL DEFENCE",   total,       "#00c2ff"), width="auto"),
            ], className="g-3 mb-3"),
            html.Div([
                html.Div("FINDINGS BY DEFENCE MODULE", style={"color":"#0a2a3a","fontSize":"9px","fontWeight":"900","letterSpacing":"2px","padding":"8px"}),
                dcc.Graph(figure=fig, config={"displayModeBar":False}),
            ], style={"background":"#060810","border":"1px solid #0a2030","borderRadius":"10px"}),
        ], style={"padding":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh"})


# ─────────────────────────────────────────────────────────────────────────────
# 4. SPECIALISED OPS REPORT
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_specialised():
    cloud = _neo("MATCH (v:Vulnerability) WHERE v.category='cloud' RETURN count(v) as n")
    iot   = _neo("MATCH (v:Vulnerability) WHERE v.category='iot' RETURN count(v) as n")
    ir    = _neo("MATCH (i:Incident) RETURN count(i) as n")

    cloud_n = cloud[0]["n"] if cloud else 0
    iot_n   = iot[0]["n"]   if iot   else 0
    ir_n    = ir[0]["n"]    if ir    else 0

    modules = [
        ("☁️",  "Cloud / ICS",    cloud_n, "#ffaa00", "AWS · Azure · GCP misconfigurations"),
        ("📡",  "IoT / OT",       iot_n,   "#ff8800", "Industrial & embedded device security"),
        ("🚨",  "IR Playbooks",   ir_n,    "#ef4444", "Active incident response cases"),
        ("📱",  "Mobile Security",0,        "#a855f7", "iOS / Android DAST & SAST"),
        ("🔬",  "DFIR",           0,        "#9d4edd", "Evidence chain & case management"),
    ]

    return html.Div([
        _section_header("🏭", "Specialised Operations Report", "Cloud · IoT/OT · IR · Mobile · DFIR", "#ffaa00"),
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Div([
                            html.Span(icon, style={"fontSize":"22px","marginRight":"12px"}),
                            html.Div([
                                html.Div(label, style={"color":color,"fontWeight":"700","fontSize":"12px"}),
                                html.Div(desc,  style={"color":"#1a3a2a","fontSize":"10px"}),
                            ], style={"flex":"1"}),
                            html.Div(str(count), style={"color":color,"fontSize":"20px","fontWeight":"900",
                                                        "fontFamily":"monospace","minWidth":"50px","textAlign":"right"}),
                        ], style={"display":"flex","alignItems":"center","padding":"12px 14px",
                                  "borderBottom":"1px solid #0f1010"}),
                    ]) for icon, label, count, color, desc in modules],
                style={"background":"#060810","border":"1px solid #1a1000","borderRadius":"10px","overflow":"hidden"}),
            ]),
        ], style={"padding":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh"})


# ─────────────────────────────────────────────────────────────────────────────
# 5. GRC REPORT
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_grc():
    vulns = _neo("MATCH (v:Vulnerability) RETURN count(v) as n, avg(v.cvss) as avg_cvss")
    total   = vulns[0]["n"]       if vulns else 0
    avg_cvs = round(vulns[0]["avg_cvss"] or 0, 1) if vulns else 0
    critical = _neo("MATCH (v:Vulnerability) WHERE v.severity='Critical' RETURN count(v) as n")
    crit_n  = critical[0]["n"] if critical else 0

    risk_score = min(100, int((crit_n / max(total, 1)) * 100 * 3))

    frameworks = [
        ("NIST CSF",    "PR.AC", "Access Control",    "⚠️ Review", "#ff8800"),
        ("ISO 27001",   "A.12",  "Operations Security","✅ Compliant","#00e676"),
        ("SOC 2",       "CC6",   "Logical Access",     "⚠️ Review", "#ff8800"),
        ("PCI-DSS",     "Req 6", "Patch Management",   "❌ Gap",    "#ff4444"),
        ("HIPAA",       "§164",  "PHI Protection",     "✅ Compliant","#00e676"),
    ]

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        title={"text":"GRC Risk Score","font":{"color":"#888","size":12}},
        number={"suffix":"%","font":{"color":"#fff","size":24}},
        gauge={"axis":{"range":[0,100]},"bar":{"color":"#00e676" if risk_score<40 else "#ff8800" if risk_score<70 else "#ff4444"},
               "bgcolor":"#111","steps":[{"range":[0,40],"color":"#0a1a0a"},{"range":[40,70],"color":"#1a1000"},{"range":[70,100],"color":"#1a0000"}]}
    ))
    fig.update_layout(paper_bgcolor="#0a0c10", plot_bgcolor="#0a0c10",
                      margin=dict(l=10,r=10,t=40,b=10), height=180)

    return html.Div([
        _section_header("📋", "GRC Compliance Report", "NIST · ISO 27001 · SOC 2 · PCI-DSS · HIPAA", "#00e676"),
        html.Div([
            dbc.Row([
                dbc.Col(_kpi("📊", "TOTAL FINDINGS", total,    "#00e676"), width="auto"),
                dbc.Col(_kpi("💀", "CRITICAL",       crit_n,   "#ef4444"), width="auto"),
                dbc.Col(_kpi("📈", "AVG CVSS",       avg_cvs,  "#ff8800"), width="auto"),
                dbc.Col(_kpi("⚖️", "RISK SCORE",     f"{risk_score}%","#00e676"), width="auto"),
            ], className="g-3 mb-4"),
            dbc.Row([
                dbc.Col([
                    dcc.Graph(figure=fig, config={"displayModeBar":False}),
                ], md=4),
                dbc.Col([
                    html.Div("FRAMEWORK COMPLIANCE STATUS", style={"color":"#0a2a1a","fontSize":"9px","fontWeight":"900","letterSpacing":"2px","marginBottom":"8px"}),
                    *[html.Div([
                        html.Span(fw,   style={"color":"#00e676","fontSize":"9px","fontWeight":"900","fontFamily":"monospace","minWidth":"80px"}),
                        html.Span(ctrl, style={"color":"#1a3a2a","fontSize":"9px","marginRight":"10px"}),
                        html.Span(desc, style={"color":"#888","fontSize":"10px","flex":"1"}),
                        html.Span(status, style={"fontSize":"10px","fontWeight":"700",
                                                  "color":color,"marginLeft":"8px"}),
                    ], style={"display":"flex","alignItems":"center","gap":"8px",
                              "padding":"8px 10px","borderBottom":"1px solid #0a1a0a"})
                    for fw, ctrl, desc, status, color in frameworks],
                ], md=8, style={"background":"#060810","border":"1px solid #0a1a0a","borderRadius":"10px","padding":"12px"}),
            ], className="g-3"),
        ], style={"padding":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh"})


# ─────────────────────────────────────────────────────────────────────────────
# 6. DFIR REPORT
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_dfir():
    incidents = _neo("MATCH (i:Incident) RETURN i.title as title, i.severity as sev, i.status as status LIMIT 10")
    open_inc  = sum(1 for i in incidents if (i.get("status") or "").lower() in ["open","active"])
    evidence  = _neo("MATCH (e:Evidence) RETURN count(e) as n")
    ev_n      = evidence[0]["n"] if evidence else 0

    timeline = [
        ("09:14", "🔴", "CRITICAL", "Malware execution detected on HOST-007"),
        ("09:18", "🟠", "HIGH",     "Lateral movement observed — VLAN pivot"),
        ("09:31", "🟠", "HIGH",     "C2 beacon initiated — 185.220.x.x"),
        ("09:47", "🟡", "MED",      "Data staging observed in /tmp/exfil/"),
        ("10:02", "🟢", "INFO",     "Containment action executed — host isolated"),
        ("10:15", "🟢", "INFO",     "Evidence chain locked — hash validated"),
    ]

    return html.Div([
        _section_header("🔬", "Digital Forensics & IR Report", "Memory · Disk · Network · Evidence Chain · Case Management", "#9d4edd"),
        html.Div([
            dbc.Row([
                dbc.Col(_kpi("🚨", "OPEN INCIDENTS",  open_inc, "#ef4444"), width="auto"),
                dbc.Col(_kpi("⛓",  "EVIDENCE ITEMS",  ev_n,     "#9d4edd"), width="auto"),
                dbc.Col(_kpi("📂", "TOTAL CASES",     len(incidents), "#9d4edd"), width="auto"),
                dbc.Col(_kpi("🕐", "TIMELINE EVENTS", len(timeline), "#c77dff"), width="auto"),
            ], className="g-3 mb-4"),
            html.Div([
                html.Div("🕐 INCIDENT TIMELINE", style={"color":"#1a0a3a","fontSize":"9px","fontWeight":"900","letterSpacing":"2px","padding":"10px 14px 6px"}),
                *[html.Div([
                    html.Span(t,   style={"color":"#4a3a6a","fontSize":"10px","fontFamily":"monospace","minWidth":"50px"}),
                    html.Span(dot, style={"fontSize":"10px"}),
                    html.Span(sev, style={"color":"#6a4a9a","fontSize":"9px","fontWeight":"700","minWidth":"55px"}),
                    html.Span(msg, style={"color":"#888","fontSize":"11px"}),
                ], style={"display":"flex","alignItems":"center","gap":"10px",
                          "padding":"7px 14px","borderBottom":"1px solid #100818"})
                for t, dot, sev, msg in timeline],
            ], style={"background":"#080612","border":"1px solid #1a0a3a","borderRadius":"10px","overflow":"hidden"}),
        ], style={"padding":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh"})


# ─────────────────────────────────────────────────────────────────────────────
# 7. PLATFORM REPORT
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_platform():
    import psutil
    cpu  = psutil.cpu_percent(interval=0.1)
    mem  = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    net  = psutil.net_io_counters()
    sent = round(net.bytes_sent/1024/1024, 1)
    recv = round(net.bytes_recv/1024/1024, 1)

    _PORTS = [
        (9000, "Mission Control",    "#00b4ff"),
        (9001, "Home Screen",        "#38bdf8"),
        (8050, "Ægis SOC Platform", "#00b4ff"),
        (9012, "External Assessment","#a855f7"),
        (9013, "Red Team Ops",       "#ef4444"),
        (9014, "Red Team Suite",     "#f97316"),
        (9015, "Cyber Defence",      "#00c2ff"),
        (9016, "Specialised Ops",    "#ffaa00"),
        (9017, "GRC Suite",          "#00e676"),
        (9018, "DFIR Suite",         "#9d4edd"),
        (9019, "Platform Suite",     "#00ccff"),
        (9020, "Reports Suite",      "#e8a020"),
    ]

    def _check(port):
        try:
            import socket
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close(); return True
        except: return False

    service_rows = []
    for port, name, color in _PORTS:
        up = _check(port)
        service_rows.append(html.Tr([
            html.Td(html.Span("●", style={"color":"#00e676" if up else "#ff5252","fontSize":"12px"}),
                    style={"padding":"7px 14px"}),
            html.Td(name,     style={"color":color,"fontSize":"11px","fontWeight":"600","padding":"7px 10px"}),
            html.Td(f":{port}",style={"color":"#1a3a4a","fontSize":"10px","fontFamily":"monospace","padding":"7px 10px"}),
            html.Td("ONLINE" if up else "OFFLINE",
                    style={"color":"#00e676" if up else "#ff5252","fontSize":"9px","fontWeight":"700",
                           "letterSpacing":"1px","padding":"7px 10px"}),
        ]))

    online = sum(1 for p,_,__ in _PORTS if _check(p))

    return html.Div([
        _section_header("⚙️", "Platform Health Report", "System Status · Service Fleet · Network · CPU · Memory", "#00ccff"),
        html.Div([
            dbc.Row([
                dbc.Col(_kpi("🖥️", "CPU",      f"{cpu}%",  "#00ccff"), width="auto"),
                dbc.Col(_kpi("💾", "MEMORY",   f"{mem}%",  "#ff9800"), width="auto"),
                dbc.Col(_kpi("💿", "DISK",     f"{disk}%", "#a855f7"), width="auto"),
                dbc.Col(_kpi("📤", "NET SENT", f"{sent}MB","#00e676"), width="auto"),
                dbc.Col(_kpi("🟢", "ONLINE",   f"{online}/12","#00e676"), width="auto"),
            ], className="g-3 mb-4"),
            html.Div([
                html.Div("ÆGIS SERVICE FLEET STATUS", style={"color":"#0a2a3a","fontSize":"9px","fontWeight":"900","letterSpacing":"2px","padding":"10px 14px 4px"}),
                html.Table(
                    [html.Thead(html.Tr([
                        html.Th("",       style={"padding":"6px 14px"}),
                        html.Th("SERVICE",style={"color":"#0a2a3a","fontSize":"9px","fontWeight":"900","letterSpacing":"1.5px","padding":"6px 10px"}),
                        html.Th("PORT",   style={"color":"#0a2a3a","fontSize":"9px","fontWeight":"900","letterSpacing":"1.5px","padding":"6px 10px"}),
                        html.Th("STATUS", style={"color":"#0a2a3a","fontSize":"9px","fontWeight":"900","letterSpacing":"1.5px","padding":"6px 10px"}),
                    ], style={"borderBottom":"1px solid #0f1520"}))] + service_rows,
                    style={"width":"100%","borderCollapse":"collapse"}
                ),
            ], style={"background":"#060810","border":"1px solid #0a2030","borderRadius":"10px","overflow":"hidden"}),
        ], style={"padding":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh"})


# ─────────────────────────────────────────────────────────────────────────────
# 8. FLEET OVERVIEW (cross-suite executive summary)
# ─────────────────────────────────────────────────────────────────────────────
def fleet_report_overview():
    vulns  = _neo("MATCH (v:Vulnerability) RETURN count(v) as n, avg(v.cvss) as avg") 
    total  = vulns[0]["n"]   if vulns else 0
    avg_cv = round(vulns[0]["avg"] or 0, 1) if vulns else 0
    crit   = _neo("MATCH (v:Vulnerability) WHERE v.severity='Critical' RETURN count(v) as n")
    crit_n = crit[0]["n"] if crit else 0
    hosts  = _neo("MATCH (v:Vulnerability) RETURN DISTINCT v.host as h LIMIT 200")
    host_n = len(hosts)
    actors = _neo("MATCH (t:ThreatActor) RETURN count(t) as n")
    act_n  = actors[0]["n"] if actors else 0
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    suites = [
        ("🔭","External Assessment", "9012","Recon · Threat Intel · Dark Web · Ext Pentest","#a855f7"),
        ("🔴","Red Team Ops",        "9013","Web App · C2 · Exploitation · Post-Exploit",    "#ef4444"),
        ("🔴","Red Team Suite",      "9014","AD RedOps · Automated PT · 12 Modules",          "#f97316"),
        ("🛡️","Cyber Defence",      "9015","SAST · API · Container · Threat Hunt · EDR",     "#00c2ff"),
        ("🏭","Specialised Ops",     "9016","Cloud · IoT/OT · IR · Mobile · DFIR",            "#ffaa00"),
        ("📋","GRC Suite",           "9017","NIST · ISO 27001 · SOC 2 · PCI-DSS",            "#00e676"),
        ("🔬","Digital Forensics",   "9018","Memory · Disk · Network · Evidence Chain",       "#9d4edd"),
        ("⚙️","Platform Suite",     "9019","System · LLM · Chatbot · PhD Research",          "#00ccff"),
        ("📊","Reports Suite",       "9020","14 Report Types · Full Incident Coverage",       "#e8a020"),
    ]

    return html.Div([
        html.Div([
            html.Div("ÆGIS SOC — FLEET EXECUTIVE OVERVIEW", style={
                "fontFamily":"'JetBrains Mono',monospace","fontSize":"11px","fontWeight":"900",
                "letterSpacing":"3px","color":"#1a3a5a","textAlign":"center","padding":"24px 0 4px",
            }),
            html.Div(f"Generated: {now}", style={"color":"#0f1f2f","fontSize":"9px","textAlign":"center","marginBottom":"24px"}),
            dbc.Row([
                dbc.Col(_kpi("📊","TOTAL FINDINGS",total,   "#00b4ff"), width="auto"),
                dbc.Col(_kpi("💀","CRITICAL",       crit_n, "#ef4444"), width="auto"),
                dbc.Col(_kpi("🖥️","HOSTS AT RISK",  host_n, "#ff8800"), width="auto"),
                dbc.Col(_kpi("📈","AVG CVSS",        avg_cv, "#ff8800"), width="auto"),
                dbc.Col(_kpi("🕵️","THREAT ACTORS",  act_n,  "#a855f7"), width="auto"),
                dbc.Col(_kpi("🚀","SUITES ACTIVE",   9,      "#00e676"), width="auto"),
            ], className="g-3 mb-4", justify="center"),
            html.Div(style={"height":"1px","background":"linear-gradient(90deg,transparent,rgba(0,180,255,.2),transparent)","margin":"8px 0 20px"}),
            html.Div("STANDALONE SUITE DIRECTORY", style={"color":"#0a2a4a","fontSize":"9px","fontWeight":"900","letterSpacing":"3px","marginBottom":"12px"}),
            *[html.Div([
                html.Span(icon, style={"fontSize":"18px","marginRight":"12px","minWidth":"28px"}),
                html.Div([
                    html.Div(name, style={"color":color,"fontWeight":"700","fontSize":"12px"}),
                    html.Div(desc, style={"color":"#1a3a4a","fontSize":"10px"}),
                ], style={"flex":"1"}),
                html.A(f":{port} ↗", href=f"http://localhost:{port}/", target="_blank",
                       style={"color":color,"fontSize":"10px","fontFamily":"monospace","fontWeight":"700",
                              "textDecoration":"none","padding":"4px 10px",
                              "border":f"1px solid {color}40","borderRadius":"5px"}),
            ], style={"display":"flex","alignItems":"center","gap":"8px",
                      "padding":"10px 14px","borderBottom":"1px solid #0a1020"})
            for icon, name, port, desc, color in suites],
        ], style={"background":"#060810","border":"1px solid #0f1520","borderRadius":"12px",
                  "padding":"0 0 8px","overflow":"hidden","margin":"0 28px 28px"}),
    ], style={"background":"#060608","minHeight":"100vh","padding":"20px 0 0"})
