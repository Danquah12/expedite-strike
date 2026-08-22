"""
PoC Evidence Panel + Launch Exploit Callback
=============================================
Adds to the Exploitation tab:
  • Per-exploit ▶ Launch button in the Active Exploits table rows
  • "Exploitation Evidence" panel showing PoC results per host
  • Offcanvas with full raw command output per result
"""

import datetime
from dash import callback, Output, Input, State, ALL, ctx, html, dcc, no_update
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate


def _now():
    return datetime.datetime.now().strftime("%H:%M:%S")


# ── Colour helpers ─────────────────────────────────────────────────────────────
VERDICT_COLORS = {
    "COMPROMISED":    "#ff2244",
    "CODE_EXECUTION": "#ff6600",
    "AUTHENTICATED":  "#ff9900",
    "DATA_ACCESS":    "#cc88ff",
    "VULN_CONFIRMED": "#ffdd00",
    "BLOCKED":        "#ff6644",
    "STOPPED":        "#aa4400",
    "FAILED":         "#555",
    "UNREACHABLE":    "#444",
    "TIMEOUT":        "#444",
    "NOT_VULNERABLE": "#22bb55",
    "UNKNOWN":        "#666",
}

_DK = "#0d1117"


# ══════════════════════════════════════════════════════════════════════════════
# Evidence panel layout (injected into layout_exploitation)
# ══════════════════════════════════════════════════════════════════════════════
def build_poc_panel():
    """Returns the full PoC Evidence section to embed in the Exploitation tab."""
    return html.Div([

        # Header row
        dbc.Row([
            dbc.Col([
                html.H5("🔬 Exploitation Evidence", style={"color": "#e0e0e0", "marginBottom": "4px"}),
                html.Small("Live proof-of-concept results from executed exploit modules",
                           style={"color": "#666"}),
            ], width=8),
            dbc.Col([
                dbc.Button("⬇ Export Report", id="poc-export-btn", color="secondary",
                           size="sm", style={"float": "right"}),
            ], width=4),
        ], className="mb-3"),

        # Summary stats
        html.Div(id="poc-stats-row"),

        # Evidence table
        html.Div(id="poc-evidence-table", style={"marginTop": "12px"}),

        # Raw output offcanvas
        dbc.Offcanvas(
            id="poc-output-offcanvas",
            title="Raw Exploit Output",
            placement="end",
            style={"width": "55%", "backgroundColor": "#0d1117"},
            children=[
                html.Div(id="poc-output-content",
                         style={"fontFamily": "monospace", "fontSize": "0.78rem",
                                "color": "#a8ff78", "whiteSpace": "pre-wrap",
                                "backgroundColor": "#0d1117", "padding": "12px",
                                "borderRadius": "8px", "maxHeight": "80vh",
                                "overflowY": "auto"})
            ]
        ),

        # Hidden store for selected PoC id
        dcc.Store(id="poc-selected-id"),
        dcc.Store(id="poc-launch-sink"),
        dcc.Store(id="poc-refresh-sink"),

    ], style={"backgroundColor": "#161b22", "borderRadius": "10px",
              "padding": "18px", "marginTop": "18px"})


# ══════════════════════════════════════════════════════════════════════════════
# Helper: render PoC evidence table from runner.poc_results
# ══════════════════════════════════════════════════════════════════════════════
def _build_results_table(results: list):
    if not results:
        return html.Div("No exploit attempts yet — click ▶ Launch on an active exploit.",
                        style={"color": "#555", "textAlign": "center", "padding": "20px"})

    rows = []
    for poc in reversed(results):
        verdict   = poc.get("verdict", "UNKNOWN")
        color     = VERDICT_COLORS.get(verdict, "#555")
        icon      = poc.get("icon", "❓")
        ts_raw    = poc.get("ts", "")
        ts_fmt    = ts_raw[11:19] if len(ts_raw) >= 19 else ts_raw
        dry_tag   = " [SIM]" if poc.get("dry_run") else ""

        rows.append(
            dbc.Row([
                dbc.Col(html.Span(icon, style={"fontSize": "1.1rem"}), width=1),
                dbc.Col([
                    html.Div(poc.get("ip", "?"), style={"color": "#e0e0e0", "fontWeight": "600",
                                                        "fontSize": "0.9rem"}),
                    html.Small(f"Port {poc.get('port','?')} · {poc.get('msf_title','?')[:40]}",
                               style={"color": "#666"}),
                ], width=4),
                dbc.Col(
                    html.Span(f"{verdict}{dry_tag}",
                              style={"color": color, "fontWeight": "700",
                                     "fontSize": "0.8rem"}),
                    width=3
                ),
                dbc.Col(html.Small(f"Conf: {poc.get('confidence','?')} · {ts_fmt}",
                                   style={"color": "#555", "fontSize": "0.75rem"}), width=2),
                dbc.Col(
                    dbc.Button("📋 View Output", id={"type": "poc-view-btn", "index": poc["id"]},
                               size="sm", color="link",
                               style={"color": "#58a6ff", "padding": "0"}),
                    width=2
                ),
            ], className="mb-2 align-items-center",
               style={"backgroundColor": "#0d1117", "borderRadius": "6px",
                      "padding": "8px 12px",
                      "borderLeft": f"3px solid {color}"})
        )

    return html.Div(rows)


def _build_stats(results: list):
    if not results:
        return html.Div()
    c = sum(1 for r in results if r["verdict"] == "COMPROMISED")
    a = sum(1 for r in results if r["verdict"] == "AUTHENTICATED")
    v = sum(1 for r in results if r["verdict"] == "VULN_CONFIRMED")
    f = sum(1 for r in results if not r["success"])

    def stat(label, val, color):
        return dbc.Col(html.Div([
            html.Div(str(val), style={"fontSize": "1.8rem", "fontWeight": "800", "color": color}),
            html.Small(label, style={"color": "#666"}),
        ], style={"textAlign": "center", "backgroundColor": "#0d1117",
                  "borderRadius": "8px", "padding": "10px"}),
        )

    return dbc.Row([
        stat("💀 Compromised",   c, "#ff2244"),
        stat("🔑 Authenticated", a, "#ff9900"),
        stat("⚠️ Vuln Confirmed", v, "#ffdd00"),
        stat("❌ Failed",         f, "#555"),
    ], className="g-2 mb-3")


# ══════════════════════════════════════════════════════════════════════════════
# Callbacks
# ══════════════════════════════════════════════════════════════════════════════

# 1. Launch button → fire exploit in background thread
@callback(
    Output("poc-launch-sink", "data"),
    Input({"type": "apt-launch-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def launch_exploit(n_clicks_list):
    if not any(n for n in (n_clicks_list or []) if n):
        raise PreventUpdate

    from cyber_range.services.simulation_engine import SimulationEngine
    from cyber_range.services.exploit_runner import ExploitRunner

    engine = SimulationEngine()
    runner = ExploitRunner()

    triggered = ctx.triggered_id
    if not triggered:
        raise PreventUpdate

    exploit_id = triggered.get("index")
    active     = engine.pentest_state.get("active_exploits", [])
    entry      = next((ex for ex in active if ex.get("id") == exploit_id), None)
    if not entry:
        raise PreventUpdate

    # Launch async (dry_run=False — real execution; set True for simulation)
    runner.launch(entry, dry_run=False, async_=True)
    return datetime.datetime.now().isoformat()


# 2. Refresh PoC panel on timer
@callback(
    Output("poc-evidence-table", "children"),
    Output("poc-stats-row",      "children"),
    Input("apt-exploit-timer",   "n_intervals"),
    prevent_initial_call=True,
)
def refresh_poc_panel(n):
    from cyber_range.services.exploit_runner import ExploitRunner
    runner  = ExploitRunner()
    results = runner.poc_results
    return _build_results_table(results), _build_stats(results)


# 3. View Output button → open offcanvas
@callback(
    Output("poc-output-offcanvas", "is_open"),
    Output("poc-output-content",   "children"),
    Input({"type": "poc-view-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def view_poc_output(n_clicks_list):
    if not any(n for n in (n_clicks_list or []) if n):
        raise PreventUpdate

    from cyber_range.services.exploit_runner import ExploitRunner
    runner     = ExploitRunner()
    triggered  = ctx.triggered_id
    if not triggered:
        raise PreventUpdate

    exploit_id = triggered.get("index")
    poc        = next((r for r in runner.poc_results if r["id"] == exploit_id), None)
    if not poc:
        raise PreventUpdate

    header = (
        f"Target   : {poc['ip']}:{poc['port']}\n"
        f"Module   : {poc['module']}\n"
        f"Exploit  : {poc['msf_title']}\n"
        f"Command  : {poc['command']}\n"
        f"Verdict  : {poc['icon']}\n"
        f"Confidence: {poc['confidence']}\n"
        f"Timestamp: {poc['ts']}\n"
        f"{'[SIMULATED OUTPUT]' if poc['dry_run'] else '[LIVE OUTPUT]'}\n"
        + "─" * 60 + "\n\n"
    )
    return True, header + (poc.get("output") or "(no output captured)")
