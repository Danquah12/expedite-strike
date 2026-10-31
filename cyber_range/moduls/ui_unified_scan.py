"""
ui_unified_scan.py — Unified Scan Engine with Traffic-Light Progress
=====================================================================
Consolidates all scan tools into a single orchestrated workflow:
  nmap → httpx → gobuster → nikto → sqlmap
With real-time traffic-light status indicators per tool.
"""
import time, threading, subprocess, os, json, shutil
from collections import defaultdict
from datetime import datetime

from dash import html, dcc, Input, Output, State, callback, ctx, no_update
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

# ── Design tokens ──────────────────────────────────────────────────────────────
_DARK   = "#0a0d14"
_CARD   = "#0f1420"
_BORDER = "#1e2a3a"
_GOLD   = "#ffd700"
_CYAN   = "#00c8ff"
_GREEN  = "#00ff88"
_RED    = "#ff3355"
_ORANGE = "#ff8c00"
_PURPLE = "#cc44ff"
_DIM    = "#4a5568"

# Traffic light colors
_TL_QUEUED  = "#4a5568"
_TL_RUNNING = "#ff8c00"
_TL_DONE    = "#00ff88"
_TL_ERROR   = "#ff3355"
_TL_SKIP    = "#2a3a50"

# ── Global scan state ──────────────────────────────────────────────────────────
_SCAN_STATE: dict = {
    "running": False,
    "target": "",
    "start_time": None,
    "tools": {},
    "results": {},
    "log": [],
}

# Tool configurations
_TOOLS = [
    {
        "id":      "nmap",
        "label":   "Nmap",
        "icon":    "🗺",
        "desc":    "Port scan + service fingerprinting",
        "color":   _CYAN,
        "cmd_fn":  lambda target: ["nmap", "-sV", "-sC", "-T4", "--open", "-p-",
                                   "--min-rate=1000", target, "-oN", f"/tmp/nmap_{target}.txt"],
        "binary":  "nmap",
    },
    {
        "id":      "httpx",
        "label":   "HTTPX",
        "icon":    "🌐",
        "desc":    "HTTP probing + tech detection",
        "color":   _PURPLE,
        "cmd_fn":  lambda target: ["httpx", "-u", f"http://{target}", "-title", "-tech-detect",
                                   "-status-code", "-follow-redirects", "-o", f"/tmp/httpx_{target}.txt"],
        "binary":  "httpx",
    },
    {
        "id":      "gobuster",
        "label":   "Gobuster",
        "icon":    "🔍",
        "desc":    "Directory & file brute-force",
        "color":   _ORANGE,
        "cmd_fn":  lambda target: ["gobuster", "dir", "-u", f"http://{target}",
                                   "-w", "/usr/share/wordlists/dirb/common.txt",
                                   "-t", "20", "--no-error", "-q",
                                   "-o", f"/tmp/gobuster_{target}.txt"],
        "binary":  "gobuster",
    },
    {
        "id":      "nikto",
        "label":   "Nikto",
        "icon":    "🕷",
        "desc":    "Web vulnerability scanner",
        "color":   "#ff9800",
        "cmd_fn":  lambda target: ["nikto", "-h", f"http://{target}", "-maxtime", "120",
                                   "-o", f"/tmp/nikto_{target}.txt", "-Format", "txt"],
        "binary":  "nikto",
    },
    {
        "id":      "sqlmap",
        "label":   "SQLMap",
        "icon":    "💉",
        "desc":    "SQL injection detection",
        "color":   _RED,
        "cmd_fn":  lambda target: ["sqlmap", "-u", f"http://{target}/",
                                   "--batch", "--level=1", "--risk=1",
                                   "--output-dir=/tmp/sqlmap"],
        "binary":  "sqlmap",
    },
    {
        "id":      "ffuf",
        "label":   "FFUF",
        "icon":    "⚡",
        "desc":    "Fast web fuzzer",
        "color":   _GOLD,
        "cmd_fn":  lambda target: ["ffuf", "-u", f"http://{target}/FUZZ",
                                   "-w", "/usr/share/wordlists/dirb/common.txt",
                                   "-t", "40", "-mc", "200,301,302,403",
                                   "-o", f"/tmp/ffuf_{target}.json", "-of", "json"],
        "binary":  "ffuf",
    },
]

# ── Helpers ────────────────────────────────────────────────────────────────────
def _tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def _log(msg: str, level="INFO"):
    ts = time.strftime("%H:%M:%S")
    _SCAN_STATE["log"].append(f"[{ts}] [{level}] {msg}")
    _SCAN_STATE["log"] = _SCAN_STATE["log"][-500:]


def _set_tool_status(tool_id: str, status: str, progress: int = 0, output: str = ""):
    _SCAN_STATE["tools"][tool_id] = {
        "status": status,
        "progress": progress,
        "output": output,
        "updated": time.strftime("%H:%M:%S"),
    }


def _run_tool_bg(tool: dict, target: str):
    tid = tool["id"]
    if not _tool_available(tool["binary"]):
        _set_tool_status(tid, "SKIP", 100, f"⚠ {tool['binary']} not installed")
        _log(f"⚠ {tool['label']} skipped — binary not found", "WARN")
        return
    try:
        _set_tool_status(tid, "RUNNING", 10)
        _log(f"▶ Starting {tool['label']} against {target}", "SCAN")
        cmd = tool["cmd_fn"](target)
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd="/tmp",
        )
        output_lines = []
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                output_lines.append(line)
                _set_tool_status(tid, "RUNNING", min(90, 10 + len(output_lines) * 2))

        proc.wait()
        status  = "DONE"  if proc.returncode == 0 else "ERROR"
        pct     = 100     if status == "DONE" else 100
        summary = "\n".join(output_lines[-30:]) if output_lines else "(no output)"
        _set_tool_status(tid, status, pct, summary)
        _log(f"{'✅' if status=='DONE' else '❌'} {tool['label']} complete (rc={proc.returncode})",
             "SUCCESS" if status == "DONE" else "ERROR")

        # Store results
        _SCAN_STATE["results"][tid] = {
            "output": "\n".join(output_lines),
            "rc":     proc.returncode,
            "ts":     datetime.now().isoformat(),
        }

    except Exception as e:
        _set_tool_status(tid, "ERROR", 100, str(e))
        _log(f"❌ {tool['label']} error: {e}", "ERROR")


def start_scan(target: str, selected_tools: list):
    if _SCAN_STATE["running"]:
        return
    _SCAN_STATE["running"]    = True
    _SCAN_STATE["target"]     = target
    _SCAN_STATE["start_time"] = datetime.now().isoformat()
    _SCAN_STATE["results"]    = {}
    _SCAN_STATE["tools"]      = {}
    _SCAN_STATE["log"]        = []

    _log(f"🚀 Unified scan started → target: {target}", "SYSTEM")
    _log(f"Selected tools: {', '.join(selected_tools)}", "SYSTEM")

    def _orchestrate():
        # Queue all selected tools
        for tool in _TOOLS:
            if tool["id"] in selected_tools:
                _set_tool_status(tool["id"], "QUEUED", 0)
            else:
                _set_tool_status(tool["id"], "SKIP", 100, "Not selected")

        # Run: nmap first (sequential), then the rest in parallel
        nmap_tool = next((t for t in _TOOLS if t["id"] == "nmap"), None)
        if nmap_tool and "nmap" in selected_tools:
            _run_tool_bg(nmap_tool, target)

        threads = []
        for tool in _TOOLS:
            if tool["id"] == "nmap" or tool["id"] not in selected_tools:
                continue
            t = threading.Thread(target=_run_tool_bg, args=(tool, target), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=180)

        _SCAN_STATE["running"] = False
        _log("🏁 Scan orchestration complete.", "SYSTEM")

    t = threading.Thread(target=_orchestrate, daemon=True)
    t.start()


# ── Traffic light card ─────────────────────────────────────────────────────────
def _tl_card(tool: dict) -> html.Div:
    state     = _SCAN_STATE["tools"].get(tool["id"], {})
    status    = state.get("status", "IDLE")
    progress  = state.get("progress", 0)
    updated   = state.get("updated", "—")
    available = _tool_available(tool["binary"])

    color_map = {
        "IDLE":    _DIM,
        "QUEUED":  _TL_QUEUED,
        "RUNNING": _TL_RUNNING,
        "DONE":    _TL_DONE,
        "ERROR":   _TL_ERROR,
        "SKIP":    _TL_SKIP,
    }
    icon_map = {
        "IDLE":    "◯",
        "QUEUED":  "⏳",
        "RUNNING": "⚡",
        "DONE":    "✅",
        "ERROR":   "❌",
        "SKIP":    "⊘",
    }

    color  = color_map.get(status, _DIM)
    status_icon = icon_map.get(status, "◯")

    # Animated pulse for RUNNING
    pulse_style = {}
    if status == "RUNNING":
        pulse_style = {"animation": "pulse 1s infinite"}

    return html.Div([
        # Tool header
        html.Div([
            html.Span(tool["icon"], style={"fontSize": "18px", "marginRight": "8px"}),
            html.Div([
                html.Div(tool["label"], style={
                    "color": "#ddd", "fontSize": "13px", "fontWeight": "700",
                }),
                html.Div(tool["desc"], style={
                    "color": _DIM, "fontSize": "10px",
                }),
            ]),
            html.Div([
                html.Span(status_icon, style={
                    "color": color, "fontSize": "14px", **pulse_style
                }),
                html.Span(f" {status}", style={
                    "color": color, "fontSize": "10px", "fontWeight": "700",
                    "fontFamily": "monospace", "marginLeft": "4px",
                }),
            ], style={"marginLeft": "auto"}),
        ], style={"display": "flex", "alignItems": "center", "marginBottom": "10px"}),

        # Progress bar
        html.Div([
            html.Div(style={
                "width": f"{progress}%",
                "height": "4px",
                "background": color,
                "borderRadius": "2px",
                "transition": "width 0.5s ease",
            }),
        ], style={
            "background": f"{_BORDER}",
            "borderRadius": "2px",
            "marginBottom": "8px",
            "height": "4px",
        }),

        # Footer
        html.Div([
            html.Span(f"{progress}%", style={
                "color": color, "fontSize": "10px", "fontWeight": "700", "fontFamily": "monospace",
            }),
            html.Span(f"Updated: {updated}", style={
                "color": _DIM, "fontSize": "9px", "marginLeft": "auto",
            }),
            html.Span("✓" if available else "✗", style={
                "color": _GREEN if available else _RED,
                "fontSize": "11px", "marginLeft": "8px",
            }),
        ], style={"display": "flex", "alignItems": "center"}),

    ], style={
        "background": _CARD,
        "border": f"1px solid {_BORDER}",
        "borderLeft": f"3px solid {color}",
        "borderRadius": "8px",
        "padding": "14px",
        "marginBottom": "10px",
        "transition": "border-color 0.3s ease",
    })


# ── Main layout ────────────────────────────────────────────────────────────────
def unified_scan_layout():
    tool_opts = [{"label": f"{t['icon']} {t['label']}", "value": t["id"]} for t in _TOOLS]
    default_selected = [t["id"] for t in _TOOLS if _tool_available(t["binary"])]

    return html.Div([
        dcc.Interval(id="scan-refresh-timer", interval=1500, n_intervals=0),
        dcc.Store(id="scan-state-store", data={}),

        # ── CSS injected via clientside or just inline ──────────────────
        # ── Header ───────────────────────────────────────────────────────
        html.Div([
            html.Div([
                html.Div("🎯  UNIFIED SCAN ENGINE", style={
                    "color": _GOLD, "fontSize": "11px", "fontWeight": "900",
                    "letterSpacing": "3px", "fontFamily": "monospace",
                }),
                html.Div("Orchestrated multi-tool scanner with real-time traffic-light progress", style={
                    "color": _DIM, "fontSize": "12px", "marginTop": "2px",
                }),
            ]),
            html.Div(id="scan-master-status", children=[
                html.Span("◯", style={"color": _DIM, "marginRight": "6px"}),
                html.Span("IDLE", style={"color": _DIM, "fontSize": "11px",
                                          "fontWeight": "700", "fontFamily": "monospace"}),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": _DARK, "border": f"1px solid {_BORDER}",
                "borderRadius": "20px", "padding": "6px 14px",
            }),
        ], style={
            "display": "flex", "justifyContent": "space-between", "alignItems": "center",
            "marginBottom": "24px", "borderBottom": f"2px solid {_GOLD}33",
            "paddingBottom": "16px",
        }),

        # ── Config row ────────────────────────────────────────────────────
        dbc.Row([
            dbc.Col([
                html.Div("🎯 TARGET (IP or hostname)", style={
                    "color": _CYAN, "fontSize": "9px", "fontWeight": "700",
                    "letterSpacing": "1px", "marginBottom": "6px",
                }),
                dcc.Input(
                    id="scan-target-input",
                    value="192.168.195.138",
                    placeholder="192.168.195.138 (Windows Server)",
                    type="text",
                    style={
                        "background": _DARK, "border": f"1px solid {_BORDER}",
                        "color": "#fff", "borderRadius": "8px", "padding": "10px 14px",
                        "width": "100%", "fontSize": "14px", "fontFamily": "monospace",
                    },
                ),
            ], width=5),
            dbc.Col([
                html.Div("⚙ SELECT TOOLS", style={
                    "color": _ORANGE, "fontSize": "9px", "fontWeight": "700",
                    "letterSpacing": "1px", "marginBottom": "6px",
                }),
                dcc.Checklist(
                    id="scan-tool-select",
                    options=tool_opts,
                    value=default_selected,
                    inline=True,
                    inputStyle={"marginRight": "4px"},
                    labelStyle={
                        "color": "#ccc", "fontSize": "11px",
                        "marginRight": "12px", "cursor": "pointer",
                    },
                ),
            ], width=5),
            dbc.Col([
                html.Div(" ", style={"fontSize": "9px", "marginBottom": "6px"}),
                html.Div([
                    dbc.Button("🚀 Launch Scan", id="scan-launch-btn",
                               color="success",
                               style={"fontWeight": "800", "fontSize": "13px",
                                      "letterSpacing": "1px", "marginRight": "8px"}),
                    dbc.Button("🛑 Stop", id="scan-stop-btn",
                               color="danger",
                               style={"fontWeight": "700", "fontSize": "11px"}),
                ]),
            ], width=2),
        ], className="mb-4", style={
            "background": _DARK, "border": f"1px solid {_BORDER}",
            "borderRadius": "10px", "padding": "18px", "marginBottom": "20px",
        }),

        # ── Traffic light panels + log ─────────────────────────────────
        dbc.Row([
            # Tool status cards
            dbc.Col([
                html.Div("⬡  TOOL STATUS — TRAFFIC LIGHT", style={
                    "color": _GOLD, "fontSize": "9px", "fontWeight": "900",
                    "letterSpacing": "2px", "fontFamily": "monospace", "marginBottom": "14px",
                }),
                html.Div(id="scan-tl-panel", children=[
                    _tl_card(t) for t in _TOOLS
                ]),
            ], width=5),

            # Live log
            dbc.Col([
                html.Div([
                    html.Div("📋  LIVE SCAN LOG", style={
                        "color": _CYAN, "fontSize": "9px", "fontWeight": "900",
                        "letterSpacing": "2px", "fontFamily": "monospace", "marginBottom": "10px",
                    }),
                    html.Div(id="scan-live-log", style={
                        "background": _DARK, "border": f"1px solid {_BORDER}",
                        "borderRadius": "8px", "padding": "12px",
                        "height": "380px", "overflowY": "auto",
                        "fontFamily": "monospace", "fontSize": "10px",
                    }, children=[
                        html.Div("— Enter a target and click Launch Scan —",
                                 style={"color": _DIM, "fontStyle": "italic"}),
                    ]),
                ], style={
                    "background": _CARD, "border": f"1px solid {_BORDER}",
                    "borderRadius": "10px", "padding": "16px", "marginBottom": "16px",
                }),

                # Results summary
                html.Div([
                    html.Div("📊  FINDINGS SUMMARY", style={
                        "color": _PURPLE, "fontSize": "9px", "fontWeight": "900",
                        "letterSpacing": "2px", "fontFamily": "monospace", "marginBottom": "10px",
                    }),
                    html.Div(id="scan-findings-summary", children=[
                        html.Div("Run a scan to see findings.",
                                 style={"color": _DIM, "fontStyle": "italic"}),
                    ], style={
                        "background": _DARK, "border": f"1px solid {_BORDER}",
                        "borderRadius": "8px", "padding": "12px",
                        "minHeight": "80px",
                    }),
                ], style={
                    "background": _CARD, "border": f"1px solid {_BORDER}",
                    "borderRadius": "10px", "padding": "16px",
                }),
            ], width=7),
        ]),

    ], style={
        "background": _CARD, "minHeight": "100vh",
        "padding": "24px", "fontFamily": "'Inter', monospace",
    })


# ── Callbacks ──────────────────────────────────────────────────────────────────
def register_callbacks(app):

    @app.callback(
        Output("scan-master-status",     "children"),
        Output("scan-tl-panel",          "children"),
        Output("scan-live-log",          "children"),
        Output("scan-findings-summary",  "children"),
        Input("scan-refresh-timer",      "n_intervals"),
        Input("scan-launch-btn",         "n_clicks"),
        Input("scan-stop-btn",           "n_clicks"),
        State("scan-target-input",       "value"),
        State("scan-tool-select",        "value"),
        prevent_initial_call=False,
    )
    def update_scan_ui(_, launch, stop, target, selected_tools):
        trigger = ctx.triggered_id

        # Launch
        if trigger == "scan-launch-btn":
            if not target or not target.strip():
                return (
                    [html.Span("⚠", style={"color": _ORANGE, "marginRight": "6px"}),
                     html.Span("NO TARGET", style={"color": _ORANGE, "fontWeight": "700"})],
                    [_tl_card(t) for t in _TOOLS],
                    [html.Div("⚠ Enter a target IP or hostname first.", style={"color": _ORANGE})],
                    no_update,
                )
            if not _SCAN_STATE["running"]:
                start_scan(target.strip(), selected_tools or [t["id"] for t in _TOOLS])

        # Stop
        if trigger == "scan-stop-btn":
            _SCAN_STATE["running"] = False
            _log("🛑 Scan stopped by user.", "SYSTEM")

        # Master pill
        is_running = _SCAN_STATE["running"]
        if is_running:
            master = [
                html.Span("⚡", style={"color": _ORANGE, "marginRight": "6px",
                                       "animation": "pulse 0.8s infinite"}),
                html.Span("SCANNING", style={"color": _ORANGE, "fontWeight": "700",
                                              "fontFamily": "monospace", "fontSize": "11px"}),
            ]
        else:
            done_count = sum(1 for t in _SCAN_STATE["tools"].values() if t["status"] == "DONE")
            if done_count > 0:
                master = [
                    html.Span("✅", style={"color": _GREEN, "marginRight": "6px"}),
                    html.Span(f"DONE ({done_count} tools)", style={"color": _GREEN, "fontWeight": "700",
                                                                     "fontFamily": "monospace", "fontSize": "11px"}),
                ]
            else:
                master = [
                    html.Span("◯", style={"color": _DIM, "marginRight": "6px"}),
                    html.Span("IDLE", style={"color": _DIM, "fontWeight": "700",
                                              "fontFamily": "monospace", "fontSize": "11px"}),
                ]

        # Traffic light cards
        tl_cards = [_tl_card(t) for t in _TOOLS]

        # Live log
        log_items = []
        for line in _SCAN_STATE["log"][-80:]:
            color = (_GREEN  if "SUCCESS" in line or "✅" in line else
                     _RED    if "ERROR" in line or "❌" in line else
                     _ORANGE if "WARN" in line or "⚠" in line else
                     _CYAN)
            log_items.append(html.Div(line, style={
                "color": color, "fontSize": "10px", "fontFamily": "monospace",
                "padding": "1px 0", "borderBottom": f"1px solid {_BORDER}22",
            }))
        if not log_items:
            log_items = [html.Div("— Enter a target and click Launch Scan —",
                                   style={"color": _DIM, "fontStyle": "italic"})]

        # Findings summary
        results = _SCAN_STATE["results"]
        findings = []
        for tid, res in results.items():
            out = res.get("output", "")
            tool = next((t for t in _TOOLS if t["id"] == tid), None)
            if not out or not tool:
                continue
            lines = [l for l in out.split("\n") if l.strip()]
            findings.append(html.Div([
                html.Span(f"{tool['icon']} {tool['label']}", style={
                    "color": tool["color"], "fontWeight": "700", "fontSize": "11px",
                }),
                html.Span(f" — {len(lines)} lines output", style={
                    "color": _DIM, "fontSize": "10px", "marginLeft": "8px",
                }),
                html.Pre("\n".join(lines[:10]), style={
                    "color": "#ccc", "fontSize": "9px", "fontFamily": "monospace",
                    "background": _DARK, "padding": "8px", "borderRadius": "6px",
                    "maxHeight": "80px", "overflowY": "auto", "margin": "6px 0 0 0",
                }),
            ], style={
                "marginBottom": "12px", "padding": "10px",
                "border": f"1px solid {_BORDER}", "borderRadius": "6px",
            }))

        if not findings:
            findings = [html.Div("Run a scan to see findings.",
                                  style={"color": _DIM, "fontStyle": "italic"})]

        return master, tl_cards, log_items, findings
