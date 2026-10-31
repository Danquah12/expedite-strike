import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — GRC Service  |  Port 9017"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/grc/", "GRC & Reports — ÆGIS")

def _content():
    from cyber_range.moduls import ui_compliance, ui_grc_executive, ui_vuln_mgmt, ui_fleet_reports, ui_pingcastle
    tabs = [
        dcc.Tab(label="📊 Compliance",    children=ui_compliance.layout() if callable(getattr(ui_compliance,"layout",None)) else html.Div()),
        dcc.Tab(label="👔 GRC Executive", children=ui_grc_executive.layout() if callable(getattr(ui_grc_executive,"layout",None)) else html.Div()),
        dcc.Tab(label="🐛 Vuln Mgmt",    children=ui_vuln_mgmt.layout() if callable(getattr(ui_vuln_mgmt,"layout",None)) else html.Div()),
        dcc.Tab(label="📋 Fleet Reports",children=ui_fleet_reports.layout() if callable(getattr(ui_fleet_reports,"layout",None)) else html.Div()),
        dcc.Tab(label="🏰 PingCastle",   children=ui_pingcastle.layout_pingcastle_live() if callable(getattr(ui_pingcastle,"layout_pingcastle_live",None)) else html.Div()),
    ]
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#ffcc00","background":"#0d1117"})

app.layout = wrap_layout("📊 GRC", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9017, debug=False)
