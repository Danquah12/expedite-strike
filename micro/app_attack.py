import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — Attack Surface Service  |  Port 9014"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/attack/", "Attack Surface — ÆGIS")

def _content():
    from cyber_range.moduls import ui_osint, ui_mitre, ui_mitre_advanced, ui_attack_chain, ui_killchain
    tabs = [
        dcc.Tab(label="🔍 OSINT",         children=ui_osint.layout() if callable(getattr(ui_osint,"layout",None)) else html.Div()),
        dcc.Tab(label="🗺 MITRE ATT&CK",  children=ui_mitre.generate_mitre_layout() if callable(getattr(ui_mitre,"generate_mitre_layout",None)) else html.Div()),
        dcc.Tab(label="🎭 Threat Actors", children=ui_mitre_advanced.generate_threat_actor_layout() if callable(getattr(ui_mitre_advanced,"generate_threat_actor_layout",None)) else html.Div()),
        dcc.Tab(label="⛓ Kill Chain",    children=ui_killchain.killchain_tab() if callable(getattr(ui_killchain,"killchain_tab",None)) else html.Div()),
    ]
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#ff8800","background":"#0d1117"})

app.layout = wrap_layout("🎯 Attack", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9014, debug=False)
