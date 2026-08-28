#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — External Assessment  (Standalone Application)
======================================================
Runs the External Penetration Testing UI independently on port 9012,
completely decoupled from the main Ægis SOC platform.

Shared backend:
  • cyber_range.services.ext_pentest_engine  — scan state / tools
  • cyber_range.services.pt_pdf_generator    — PDF report builder

Usage:
  python external_assessment_app.py            # production
  python external_assessment_app.py --debug    # dev mode

The main Ægis app (port 9011) is NOT affected by running this service.
"""

import sys
import os
from pathlib import Path

# ── Ensure project root & user local packages are on sys.path ───────────────
_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

_EXTRA = "/home/kali/.local/lib/python3.13/site-packages"
if _EXTRA not in sys.path:
    sys.path.insert(0, _EXTRA)

# ── Load .env ────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(os.path.join(str(_APP_DIR), ".env"), override=True)

# Suppress proxy env vars
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ[_k] = ""

# ── Core Dash imports ────────────────────────────────────────────────────────
from dash import Dash, html, dcc
import dash_bootstrap_components as dbc

# ── Build the standalone Dash app ────────────────────────────────────────────
# NOTE: assets/ folder in the same directory is auto-served by Dash.
#       external_assessment.css is picked up automatically from assets/.
app = Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
    ],
    suppress_callback_exceptions=True,
    title="Ægis — External Assessment",
    meta_tags=[
        {"name": "viewport",    "content": "width=device-width, initial-scale=1.0"},
        {"name": "theme-color", "content": "#0d1117"},
        {"name": "description", "content": "Ægis External Penetration Assessment — standalone"},
        {"name": "apple-mobile-web-app-capable", "content": "yes"},
        {"name": "apple-mobile-web-app-status-bar-style", "content": "black-translucent"},
    ],
)

server = app.server
server.secret_key = os.environ.get("FLASK_SECRET", "ext-assess-secret-2026-!@#")

# ── Import UI module AFTER app is created (registers all callbacks) ──────────
from cyber_range.moduls import ui_external_pentest  # noqa: E402

# ── Header bar ───────────────────────────────────────────────────────────────
_header = html.Div([
    html.Span("🎯", style={"fontSize": "22px"}),
    html.Div([
        html.Span("ÆGIS", style={
            "color": "#00c88c", "fontWeight": "900", "fontSize": "15px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
            "letterSpacing": "4px",
        }),
        html.Span("  ·  EXTERNAL ASSESSMENT", style={
            "color": "#546e8a", "fontWeight": "700", "fontSize": "11px",
            "letterSpacing": "3px",
            "fontFamily": "'JetBrains Mono', 'Courier New', monospace",
        }),
    ]),
    html.Div(style={"flex": "1"}),  # spacer
    
    html.A([
        html.Span("🚀", style={"fontSize": "13px", "marginRight": "6px"}),
        html.Span("Launch Pad", style={
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1px", "color": "#a855f7",
        }),
    ],
    href="http://localhost:9000/",
    target="_blank",
    style={
        "textDecoration": "none",
        "display": "flex", "alignItems": "center",
        "background": f"#a855f710",
        "border": f"1px solid #a855f730",
        "borderRadius": "20px",
        "padding": "5px 14px",
        "marginRight": "10px",
        "transition": "all .2s ease",
    },
    id="header-launchpad-btn",
    ),
    html.Div([
        html.Span("●", style={"color": "#00c88c", "marginRight": "6px", "fontSize": "10px"}),
        html.Span("STANDALONE  •  PORT 9012", style={
            "color": "#546e8a", "fontSize": "10px", "fontWeight": "700",
            "letterSpacing": "1.5px",
        }),
    ], style={
        "background": "#0d1a14", "border": "1px solid #00c88c33",
        "borderRadius": "20px", "padding": "5px 14px",
    }),
], style={
    "background": "linear-gradient(90deg, #080c14 0%, #0d1420 60%, #0a0f1a 100%)",
    "borderBottom": "2px solid rgba(0,200,140,0.25)",
    "padding": "12px 24px",
    "display": "flex",
    "alignItems": "center",
    "gap": "14px",
    "position": "sticky",
    "top": "0",
    "zIndex": "999",
    "boxShadow": "0 4px 24px rgba(0,0,0,0.6)",
})

# ── App layout ───────────────────────────────────────────────────────────────
app.layout = html.Div([
    # Header
    _header,

    # External Pen Test UI (loads all stores, intervals, callbacks)
    html.Div(
        id="ext-standalone-content",
        children=ui_external_pentest.layout(),
        style={"padding": "0", "minHeight": "100vh"},
    ),
], style={"background": "#080c14", "minHeight": "100vh"})


# ── Floating progress strip — injected via Dash index_string ─────────────────
# This avoids any callback conflicts with ui_external_pentest's own callbacks.
_STRIP_JS = """
<script>
(function(){
  var ID='aegis-floating-strip';
  function mk(){
    if(document.getElementById(ID)) return;
    var e=document.createElement('div'); e.id=ID;
    e.innerHTML='<span style="font-size:14px;margin-right:8px">&#128225;</span>'
      +'<span id="afp-phase" style="color:#00c88c;font-size:12px;font-weight:900;letter-spacing:1px;margin-right:18px">SCANNING</span>'
      +'<span style="color:#555;font-size:8px;font-weight:700;letter-spacing:1px;margin-right:4px">TOOL</span>'
      +'<span id="afp-tool" style="color:#00e5ff;font-size:12px;font-weight:900;margin-right:14px">&mdash;</span>'
      +'<span id="afp-pct" style="color:#ffd700;font-size:12px;font-weight:900;margin-right:18px">0%</span>'
      +'<span style="flex:1"></span>'
      +'<div style="width:240px;height:6px;background:#1a2030;border-radius:4px;overflow:hidden">'
        +'<div id="afp-bar" style="width:0%;height:100%;border-radius:4px;background:linear-gradient(90deg,#00c88c,#00e5ff);transition:width .6s ease"></div>'
      +'</div>';
    document.body.appendChild(e);
    function sync(){
      var isR=false, pct=0;
      var pb=document.getElementById('ext-pentest-progress-bar');
      if(pb){pct=parseInt(pb.getAttribute('aria-valuenow'))||0; if(pct>0&&pct<100)isR=true;}
      var sb=document.getElementById('ext-status-bar');
      if(sb){var t=sb.textContent.toLowerCase(); if(t.indexOf('scanning')>=0||t.indexOf('running')>=0)isR=true;}
      var amP=document.getElementById('ext-am-phase');
      if(amP){var p2=amP.textContent.toLowerCase(); if(p2.indexOf('recon')>=0||p2.indexOf('vuln')>=0||p2.indexOf('exploit')>=0||p2.indexOf('post')>=0)isR=true;}
      var bar=document.getElementById(ID);
      if(!bar)return;
      if(isR){bar.classList.add('afp-show');}else{bar.classList.remove('afp-show');return;}
      var d;
      d=document.getElementById('afp-phase'); if(d&&amP) d.textContent=amP.textContent||'SCANNING';
      var amT=document.getElementById('ext-am-tool'); d=document.getElementById('afp-tool'); if(d&&amT) d.textContent=amT.textContent||'\u2014';
      var amPct=document.getElementById('ext-am-pct'); d=document.getElementById('afp-pct');
      if(d){if(amPct&&amPct.textContent)d.textContent=amPct.textContent; else d.textContent=pct+'%';}
      d=document.getElementById('afp-bar'); if(d) d.style.width=pct+'%';
    }
    setInterval(sync,500);
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',function(){setTimeout(mk,1000);});
  else setTimeout(mk,1000);
})();
</script>
"""

app.index_string = (
    "<!DOCTYPE html>"
    "<html>"
    "    <head>"
    "        {%metas%}"
    "        <title>{%title%}</title>"
    "        {%favicon%}"
    "        {%css%}"
    "    </head>"
    "    <body>"
    "        {%app_entry%}"
    "        <footer>"
    "            {%config%}"
    "            {%scripts%}"
    "            {%renderer%}"
    "        </footer>"
    + _STRIP_JS +
    "    </body>"
    "</html>"
)


# ── PDF report route ─────────────────────────────────────────────────────────
def _handle_pentest_report(scan_id: str):
    """Generate and serve a PDF pentest report for the given scan_id."""
    import tempfile as _tmp
    from flask import send_file, make_response as _mkr
    from datetime import datetime as _dt_rpt

    _NOT_FOUND = (
        "<!DOCTYPE html><html><head><title>ÆGIS — Report Not Found</title>"
        "<style>body{background:#0a0d14;color:#ccc;font-family:monospace;display:flex;"
        "align-items:center;justify-content:center;min-height:100vh;margin:0}"
        ".box{background:#0f1420;border:1px solid #1e2a3a;border-left:4px solid #ff4444;"
        "border-radius:12px;padding:40px 48px;max-width:520px;text-align:center}"
        "h1{color:#ff4444;font-size:20px;letter-spacing:2px;margin:0 0 12px}"
        "p{color:#888;font-size:13px;line-height:1.6;margin:8px 0}"
        "a{display:inline-block;margin-top:20px;padding:10px 28px;"
        "background:linear-gradient(135deg,#00c88c,#006644);color:#001a0f;"
        "border-radius:8px;text-decoration:none;font-weight:700;font-size:12px}"
        "</style></head><body><div class='box'>"
        f"<h1>📄 REPORT NOT AVAILABLE</h1>"
        f"<p>Scan ID <code style='color:#ffd700'>{scan_id}</code> was not found.</p>"
        "<p>Reports are held in memory while the app is running.<br>"
        "Run the scan again to generate a new report.</p>"
        "<a href='javascript:window.close()'>✕ Close</a>"
        "</div></body></html>"
    )

    try:
        from cyber_range.services import ext_pentest_engine as _eng
        scan = _eng.get_all(scan_id)
        if not scan:
            resp = _mkr(_NOT_FOUND, 404)
            resp.headers["Content-Type"] = "text/html; charset=utf-8"
            return resp

        # Flatten multi-target results
        _flat: dict = {}
        _exploit_db_data = None
        for _tgt_key, _tgt_phases in scan.get("results", {}).items():
            if not isinstance(_tgt_phases, dict):
                continue
            for _phase_key, _phase_list in _tgt_phases.items():
                if not isinstance(_phase_list, list):
                    continue
                for _item in _phase_list:
                    if not isinstance(_item, dict):
                        continue
                    _tool = _item.get("tool", "")
                    _data = _item.get("data", {})
                    if _tool:
                        if _tool not in _flat:
                            _flat[_tool] = _data
                        else:
                            for _mk in ("findings", "results", "subdomains",
                                        "live_subdomains", "open_ports",
                                        "hosts", "urls", "directories"):
                                if isinstance(_data.get(_mk), list):
                                    _flat[_tool].setdefault(_mk, []).extend(_data[_mk])
                    if _tool == "EXPLOIT_DB" and not _exploit_db_data:
                        _exploit_db_data = _data

        _tgts = scan.get("targets", [scan.get("target", "unknown")])
        if isinstance(_tgts, str): _tgts = [_tgts]
        _tgt_label = ", ".join(_tgts[:3]) + ("…" if len(_tgts) > 3 else "")
        ts    = _dt_rpt.now().strftime("%Y%m%d_%H%M%S")
        tgt   = _tgt_label.replace(".", "_").replace("/", "_")[:30]
        fname = f"pentest_{tgt}_{ts}.pdf"

        # ── 1. Primary: Comprehensive 10-Section Enterprise Pentest Report ────
        try:
            from cyber_range.services.pentest_report_pdf import generate_pdf_report
            from cyber_range.services.ext_pentest_engine import build_report_state
            from cyber_range.services.workspace_manager import WorkspaceManager
            _tmp_dir  = _tmp.mkdtemp()
            _pdf_path = os.path.join(_tmp_dir, fname)
            report_state = build_report_state(scan)
            ws_cfg = WorkspaceManager.get_report_config(_tgt_label)
            generate_pdf_report(
                report_state,
                output_path=_pdf_path,
                config=ws_cfg
            )
            return send_file(_pdf_path, mimetype="application/pdf",
                             as_attachment=True, download_name=fname)
        except Exception as _pdf_err:
            print(f"[EXT-REPORT] Primary 10-section PDF generation error: {_pdf_err}")

        # ── 2. Fallback: Standard PTES PDF ────────────────────────────────────
        try:
            from cyber_range.services.pt_pdf_generator import generate_pdf
            _ts_str = _dt_rpt.now().strftime("%Y-%m-%d %H:%M")
            _pdf_schema = {
                "target":      _tgt_label,
                "targets":     _tgts,
                "timestamp":   _ts_str,
                "phases_run":  list({ph for ph in scan.get("results", {})}) or
                               ["passive", "active", "vuln"],
                "data":        _flat,
            }
            _tmp_dir  = _tmp.mkdtemp()
            _pdf_path = os.path.join(_tmp_dir, fname)
            generate_pdf(_pdf_schema, _pdf_path)
            return send_file(_pdf_path, mimetype="application/pdf",
                             as_attachment=True, download_name=fname)
        except Exception as _fb_err:
            print(f"[EXT-REPORT] Fallback PDF generation error: {_fb_err}")
            raise _fb_err

    except Exception as ex:
        resp = _mkr(f"<h3>PDF generation error: {ex}</h3>", 500)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp


@server.route("/app/pentest-report/<scan_id>")
def pentest_report_route(scan_id):
    return _handle_pentest_report(scan_id)


@server.before_request
def _intercept_pentest_report():
    from flask import request as _req
    if _req.path.startswith("/app/pentest-report/"):
        _sid = _req.path.split("/app/pentest-report/", 1)[1].split("/")[0].split("?")[0]
        if _sid:
            return _handle_pentest_report(_sid)


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ægis External Assessment — Standalone Dash App"
    )
    parser.add_argument("--host",  default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port",  default=9012, type=int, help="Port (default: 9012)")
    parser.add_argument("--debug", action="store_true",    help="Enable Dash debug mode")
    args = parser.parse_args()

    print(f"""
====================================================================
   Expedite Strike — External Assessment (Standalone Server)
====================================================================
   URL   ->  http://{args.host}:{args.port}/
   Debug ->  {str(args.debug):<54}
====================================================================
""")

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        threaded=True,
    )
