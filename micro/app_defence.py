import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — Defence Service  |  Port 9015"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/defence/", "Defence — ÆGIS")

def _content():
    from cyber_range.moduls import ui_forensics, ui_dfir_case, ui_threat_hunting, ui_edr_gaps, ui_honeypot, ui_ir_playbooks
    tabs = [
        dcc.Tab(label="🔬 Forensics",      children=ui_forensics.layout() if callable(getattr(ui_forensics,"layout",None)) else html.Div()),
        dcc.Tab(label="🚨 DFIR Case",      children=ui_dfir_case.layout() if callable(getattr(ui_dfir_case,"layout",None)) else html.Div()),
        dcc.Tab(label="🎯 Threat Hunting", children=ui_threat_hunting.layout() if callable(getattr(ui_threat_hunting,"layout",None)) else html.Div()),
        dcc.Tab(label="🛡 EDR Gaps",       children=ui_edr_gaps.layout() if callable(getattr(ui_edr_gaps,"layout",None)) else html.Div()),
        dcc.Tab(label="🍯 Honeypot",       children=ui_honeypot.honeypot_tab() if callable(getattr(ui_honeypot,"honeypot_tab",None)) else html.Div()),
        dcc.Tab(label="📖 IR Playbooks",   children=ui_ir_playbooks.layout() if callable(getattr(ui_ir_playbooks,"layout",None)) else html.Div()),
    ]
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#00dd88","background":"#0d1117"})

app.layout = wrap_layout("🛡️ Defence", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9015, debug=False)
