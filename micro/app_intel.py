import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — Intel Service  |  Port 9016"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/intel/", "Threat Intel — ÆGIS")

def _content():
    from cyber_range.moduls import ui_threat_intel, ui_darkweb, ui_supply_chain, ui_phishing
    tabs = [
        dcc.Tab(label="📡 Threat Intel",  children=ui_threat_intel.layout() if callable(getattr(ui_threat_intel,"layout",None)) else html.Div()),
        dcc.Tab(label="🌑 Dark Web",      children=ui_darkweb.layout() if callable(getattr(ui_darkweb,"layout",None)) else html.Div()),
        dcc.Tab(label="⛓ Supply Chain",  children=ui_supply_chain.layout() if callable(getattr(ui_supply_chain,"layout",None)) else html.Div()),
        dcc.Tab(label="🎣 Phishing",      children=ui_phishing.layout() if callable(getattr(ui_phishing,"layout",None)) else html.Div()),
    ]
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#aa44ff","background":"#0d1117"})

app.layout = wrap_layout("📡 Intel", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9016, debug=False)
