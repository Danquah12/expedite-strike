"""
ui_iot_security.py
IoT / OT / SCADA Security Tab
Shodan ICS Scan · Modbus/DNP3 Scanner · OT Network Map ·
NIST SP 800-82 / ISA-IEC 62443 Compliance · Volt Typhoon TTPs · AI Analysis
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


NIST_80082_CONTROLS = [
    {"id": "2.1", "control": "OT System Security Plan",
     "desc": "Documented security plan for each OT system"},
    {"id": "2.2", "control": "Network Segmentation",
     "desc": "IT/OT separation; demilitarised zone (DMZ) implemented"},
    {"id": "2.3", "control": "Remote Access Controls",
     "desc": "VPN with MFA; no direct internet-facing OT devices"},
    {"id": "2.4", "control": "Patch Management",
     "desc": "OT-specific patch process; vendor-approved updates only"},
    {"id": "2.5", "control": "Physical Security",
     "desc": "Access control to control rooms, substations, panels"},
    {"id": "2.6", "control": "Monitoring and Detection",
     "desc": "OT-specific IDS; passive monitoring; baselining comms"},
    {"id": "2.7", "control": "Incident Response",
     "desc": "OT-specific IR plan; safe shutdown procedures"},
    {"id": "2.8", "control": "Supply Chain Risk",
     "desc": "Vendor vetting; secure hardware procurement"},
    {"id": "2.9", "control": "Configuration Management",
     "desc": "Hardened baseline configs for PLCs, RTUs, HMIs"},
    {"id": "2.10","control": "Backup & Recovery",
     "desc": "PLC ladder logic backups; tested restoration procedures"},
]


def _shodan_cmd(target: str) -> str:
    t = target or "10.0.0.0/8"
    return f"""# ── Shodan ICS / IoT Search ──────────────────────────────
# Requires SHODAN_API_KEY environment variable
export SHODAN_API_KEY="your_key_here"

# Search for exposed ICS on Shodan
shodan search "product:modbus" --fields ip_str,port,org,city
shodan search "port:102 siemens s7" --fields ip_str,port,org
shodan search "port:20000 dnp3" --fields ip_str,port,org
shodan search "product:OPC" --fields ip_str,port,org

# Search your IP range
shodan search "net:{t}" --fields ip_str,port,product,os

# Get host details
shodan host IP_ADDRESS

# Alert on new exposures
shodan alert create "OT Exposure Monitor" 10.0.0.0/8

# Free InternetDB (no key required)
python3 -c "
import requests
ips = ['{t.split('/')[0]}']
for ip in ips:
    r = requests.get(f'https://internetdb.shodan.io/{{ip}}')
    if r.status_code == 200:
        d = r.json()
        print(f'IP: {{ip}}')
        print(f'Ports: {{d.get(\\\"ports\\\",[])}}'[:80])
        print(f'CVEs: {{d.get(\\\"cves\\\",[])}}'[:80])
"

# Censys ICS search (free tier)
censys search "{t}" --index hosts"""


def _proto_scan_cmd(target: str, proto: str) -> str:
    t = target or "192.168.1.0/24"
    if proto == "modbus":
        return f"""# ── Modbus Protocol Scanner ─────────────────────────────
# Modbus TCP runs on port 502
nmap -p 502 --script modbus-discover {t}

# Read device ID
nmap -p 502 --script modbus-discover --script-args modbus-discover.aggressive=true {t}

# mbtget (Modbus client)
# mbtget -t 3 -r 1 -n 10 TARGET_IP  # Read holding registers

# python-modbus
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('{t.split('/')[0]}', port=502)
c.connect()
r = c.read_holding_registers(0, 10)
if not r.isError():
    print('Registers:', r.registers)
c.close()
"

# Metasploit Modbus modules
# use auxiliary/scanner/scada/modbusdetect
# set RHOSTS {t}
# run"""
    elif proto == "dnp3":
        return f"""# ── DNP3 Protocol Scanner ───────────────────────────────
# DNP3 typically runs on port 20000
nmap -p 20000 --script dnp3-info {t}

# Aegis DNP3 scanner
# dnp3_fuzzer TARGET_IP 20000

# Wireshark filter for DNP3
# wireshark -i eth0 -f "port 20000"

# Metasploit
# use auxiliary/scanner/scada/dnp3_info
# set RHOSTS {t}
# run

# OpenDNP3 client test
python3 -c "
import socket
TARGET = '{t.split('/')[0]}'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((TARGET, 20000))
    print(f'DNP3 port open on {{TARGET}}')
    s.close()
except Exception as e:
    print(f'Error: {{e}}')
"
"""
    elif proto == "ethernetip":
        return f"""# ── EtherNet/IP (Allen-Bradley) Scanner ──────────────────
# EtherNet/IP runs on port 44818
nmap -p 44818 --script enip-info {t}

# cpppo EtherNet/IP scanner
python3 -m cpppo.server.enip.client --print {t.split('/')[0]}

# plcscan
# python3 plcscan.py {t}"""
    else:  # general OT
        return f"""# ── General OT / ICS Network Discovery ───────────────────
# Scan common OT/ICS ports
nmap -sV -p 102,502,20000,44818,4840,1911,9600,1962,789 {t}

# Ports: 102=S7, 502=Modbus, 20000=DNP3, 44818=EtherNet/IP
#        4840=OPC-UA, 1911=Fox, 9600=OMRON, 1962=PCWorx

# ICS-specific Nmap scripts
nmap --script s7-info -p 102 {t}
nmap --script modbus-discover -p 502 {t}
nmap --script enip-info -p 44818 {t}
nmap --script opc-ua-info -p 4840 {t}

# Passive OT discovery (Zeek + custom scripts)
# zeek -r capture.pcap ot-detect.zeek

# Claroty OT visibility (commercial)
# dragos platform (commercial)
# nozomi networks (commercial)

# Free: Gravwell OT visibility
# Free: Security Onion with OT rules"""


def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="iot-state", data={}),

        html.Div([
            html.H4("🏭 IoT / OT / SCADA Security",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("Shodan ICS Search · Modbus/DNP3/EtherNet-IP · OT Assessment · "
                     "NIST SP 800-82 · ISA/IEC 62443 · Volt Typhoon TTPs",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🎯 OT Target Config",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("IP Range / Host"),
                    dbc.Input(id="iot-target", placeholder="192.168.1.0/24",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Protocol Focus"),
                    dbc.Select(id="iot-proto",
                               options=[
                                   {"label": "All OT Protocols",    "value": "all"},
                                   {"label": "Modbus (TCP/502)",     "value": "modbus"},
                                   {"label": "DNP3 (20000)",         "value": "dnp3"},
                                   {"label": "EtherNet/IP (44818)",  "value": "ethernetip"},
                               ], value="all",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("🔄 Update Commands", id="iot-update-btn",
                               color="primary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "4px"}),
                    html.Div(id="iot-update-status",
                             style={"color": "#636e72", "fontSize": "11px",
                                    "minHeight": "14px"}),
                ),
                _card(
                    html.Div("🤖 AI OT Analysis",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    dbc.Button("⚡ Threat Model", id="iot-ai-threat",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("🛡️ Segmentation Guide", id="iot-ai-segment",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="iot-ai-out",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "280px", "overflowY": "auto"}),
                ),
                _card(
                    html.Div("📋 Quick Commands",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[_cmd(c) for c in [
                        "nmap -p 102,502,20000,44818 TARGET",
                        "nmap --script s7-info -p 102 TARGET",
                        "nmap --script modbus-discover -p 502 TARGET",
                        "nmap --script enip-info -p 44818 TARGET",
                        "shodan search port:502 modbus",
                        "shodan search siemens s7-1200",
                        "wireshark -i eth0 -f port 502",
                    ]],
                ),
            ], width=3),

            # ── Centre ───────────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="iot-tabs", active_tab="iot-tab-shodan",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="🔍 Shodan ICS",   tab_id="iot-tab-shodan"),
                     dbc.Tab(label="📡 Protocol Scan", tab_id="iot-tab-proto"),
                     dbc.Tab(label="📋 NIST 800-82",   tab_id="iot-tab-nist"),
                     dbc.Tab(label="⚡ Volt Typhoon",  tab_id="iot-tab-volt"),
                 ]),
                html.Div(id="iot-phase-content"),
            ], width=6),

            # ── Right: Checklists ────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("✅ OT Hardening Checklist",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("□ ", style={"color": "#636e72"}),
                        html.Span(item, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for item in [
                          "IT/OT network segmentation",
                          "No direct internet on OT network",
                          "VPN + MFA for remote access",
                          "Default passwords changed on all PLCs",
                          "Firmware versions documented",
                          "Patch process for OT systems",
                          "Passive OT monitoring (Claroty/Dragos)",
                          "OT-specific incident response plan",
                          "Physical access controls to OT areas",
                          "USB policy enforced in OT zones",
                          "OT backups tested and offline",
                          "Supply chain vetted for OT equipment",
                      ]],
                ),
                _card(
                    html.Div("🚨 High-Risk OT Exposures",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("⚠ ", style={"color": "#c0392b",
                                                "fontWeight": "700"}),
                        html.Span(r, style={"color": "#b0b0b0",
                                            "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for r in [
                          "PLC directly on internet",
                          "HMI running Windows XP",
                          "Modbus no authentication",
                          "Default vendor credentials",
                          "Remote desktop to SCADA",
                          "OT/IT flat network",
                          "Unpatched Siemens S7-1500",
                          "SNMP community=public on RTUs",
                      ]],
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


@callback(
    Output("iot-phase-content", "children"),
    Output("iot-update-status", "children"),
    Input("iot-tabs",           "active_tab"),
    Input("iot-update-btn",     "n_clicks"),
    State("iot-target",         "value"),
    State("iot-proto",          "value"),
)
def render_phase(tab, upd_n, target, proto):
    status = f"✅ Updated {datetime.now().strftime('%H:%M:%S')}" if upd_n else ""
    t = target or "192.168.1.0/24"
    p = proto  or "all"

    if tab == "iot-tab-shodan":
        return _card(
            html.Div(f"🔍 Shodan ICS Scanner — {t}",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("Command"),
            dbc.Textarea(id="iot-shodan-cmd", value=_shodan_cmd(t),
                         style={**INPUT_STY, "height": "220px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("▶ Run", id="iot-shodan-run",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=4),
            ], style={"marginBottom": "8px"}),
            dbc.Textarea(id="iot-shodan-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "180px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b"}),
        ), status

    elif tab == "iot-tab-proto":
        return _card(
            html.Div(f"📡 {p.upper()} Protocol Scan — {t}",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _label("Command"),
            dbc.Textarea(id="iot-proto-cmd", value=_proto_scan_cmd(t, p),
                         style={**INPUT_STY, "height": "240px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("▶ Run", id="iot-proto-run",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=4),
            ], style={"marginBottom": "8px"}),
            dbc.Textarea(id="iot-proto-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "160px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b"}),
        ), status

    elif tab == "iot-tab-nist":
        rows = [html.Div([
            dbc.Row([
                dbc.Col([
                    html.Span(f"{c['id']}: ", style={"color": "#3498db",
                                                       "fontWeight": "700",
                                                       "fontSize": "11px",
                                                       "marginRight": "4px"}),
                    html.Span(c["control"], style={"color": "#e0e0e0",
                                                    "fontSize": "12px",
                                                    "fontWeight": "600"}),
                    html.Div(c["desc"], style={"color": "#8e9eb0",
                                               "fontSize": "10px",
                                               "paddingLeft": "4px"}),
                ], width=9),
                dbc.Col(dbc.Select(
                    id={"type": "iot-ctrl", "id": c["id"]},
                    options=[
                        {"label": "✅ Met",     "value": "met"},
                        {"label": "⚠️ Partial", "value": "partial"},
                        {"label": "❌ Gap",     "value": "gap"},
                    ], value="gap",
                    style={**INPUT_STY, "fontSize": "11px",
                           "height": "28px"},
                ), width=3),
            ], align="center"),
        ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}"}
        ) for c in NIST_80082_CONTROLS]

        return _card(
            html.Div("📋 NIST SP 800-82 ICS Assessment",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "500px", "overflowY": "auto"}),
        ), status

    elif tab == "iot-tab-volt":
        ttps = [
            ("T1190", "Exploit Public-Facing Application",
             "Targeting internet-exposed VPNs, firewalls, and OT HMIs",
             "Patch immediately; WAF; IDS signatures"),
            ("T1078", "Valid Accounts",
             "Using stolen contractor/vendor credentials for OT access",
             "MFA on all remote access; audit service accounts"),
            ("T1571", "Non-Standard Port",
             "C2 traffic over unusual ports to evade firewall inspection",
             "Egress filtering; DPI on OT network"),
            ("T1090", "Proxy",
             "Using SOHO router botnets (KV-Botnet) to proxy traffic",
             "Monitor outbound connections; geofencing"),
            ("T1562", "Impair Defenses",
             "Disabling logging and security tools before activity",
             "Log integrity monitoring; alerting on log gaps"),
            ("T1021", "Remote Services",
             "Lateral movement via RDP/SMB after initial OT access",
             "Micro-segmentation; privileged access workstations"),
            ("T0886", "Remote Services (OT)",
             "Exploiting OT remote management protocols (VNC, RDP to HMI)",
             "Isolate HMIs; jump server for all OT access"),
            ("T0882", "Theft of Operational Information",
             "Exfiltrating PLC ladder logic, schematics, configurations",
             "DLP on OT data; classify OT documents"),
        ]
        rows = [html.Div([
            html.Div([
                html.Span(t[0], style={"color": "#3498db", "fontWeight": "700",
                                        "fontSize": "11px", "marginRight": "8px"}),
                html.Span(t[1], style={"color": "#e0e0e0", "fontWeight": "600",
                                        "fontSize": "12px"}),
            ]),
            html.Div(t[2], style={"color": "#8e9eb0", "fontSize": "10px",
                                   "paddingLeft": "4px", "marginTop": "2px"}),
            html.Div(f"🛡️ {t[3]}", style={"color": "#27ae60", "fontSize": "10px",
                                           "paddingLeft": "4px"}),
        ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}"})
        for t in ttps]
        return _card(
            html.Div("⚡ Volt Typhoon OT Attack TTPs (CISA Advisory 2024)",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div("PRC-linked Volt Typhoon targets US critical infrastructure OT systems "
                     "for pre-positioning rather than immediate disruption.",
                     style={"color": "#636e72", "fontSize": "11px",
                            "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "480px", "overflowY": "auto"}),
        ), status

    return html.Div(), status


# Run callbacks
@callback(
    Output("iot-shodan-out", "value"),
    Input("iot-shodan-run",  "n_clicks"),
    State("iot-shodan-cmd",  "value"),
    prevent_initial_call=True,
)
def run_shodan(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    threading.Thread(target=_run_bg, args=(cmd, "shodan"), daemon=True).start()
    time.sleep(5)
    with _LOCK:
        return _OUTPUTS.get("shodan", "[Running…]")


@callback(
    Output("iot-proto-out", "value"),
    Input("iot-proto-run",  "n_clicks"),
    State("iot-proto-cmd",  "value"),
    prevent_initial_call=True,
)
def run_proto(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    threading.Thread(target=_run_bg, args=(cmd, "proto"), daemon=True).start()
    time.sleep(5)
    with _LOCK:
        return _OUTPUTS.get("proto", "[Running…]")


@callback(
    Output("iot-ai-out",    "children"),
    Input("iot-ai-threat",  "n_clicks"),
    Input("iot-ai-segment", "n_clicks"),
    State("iot-target",     "value"),
    prevent_initial_call=True,
)
def ai_ot(threat_n, seg_n, target):
    if not ctx.triggered_id:
        raise PreventUpdate
    t = target or "OT network"
    with _LOCK:
        results = "\n".join(f"[{k}]\n{v[:300]}" for k, v in _OUTPUTS.items())
    tid = ctx.triggered_id
    if tid == "iot-ai-threat":
        prompt = (
            f"OT/ICS threat model for {t}:\n\n"
            f"Scan results:\n{results or 'None run yet'}\n\n"
            f"Provide:\n"
            f"1) **Top Threats** specific to OT/ICS (ransomware, Volt Typhoon, etc.)\n"
            f"2) **Attack Paths** from IT network to OT devices\n"
            f"3) **Impact Scenarios** (safety, production, physical damage)\n"
            f"4) **Detection Opportunities** — what logs/sensors to monitor\n"
            f"5) **Priority Hardening** — top 5 actions this week"
        )
    else:
        prompt = (
            f"IT/OT network segmentation guide for {t}:\n\n"
            f"Design a zero-trust OT network architecture:\n"
            f"1) **Network Zones** — define IT, OT Level 0-5, DMZ\n"
            f"2) **Firewall Rules** — what to allow/deny between zones\n"
            f"3) **Jump Server** architecture for OT remote access\n"
            f"4) **Monitoring** — where to place sensors/collectors\n"
            f"5) **YAML/diagram** of recommended architecture\n\n"
            f"Follow Purdue Model / ISA-95 hierarchy."
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"
