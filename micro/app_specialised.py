import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — Specialised Service  |  Port 9018"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/specialised/", "Specialised — ÆGIS")

def _content():
    from cyber_range.moduls import (ui_iot_security, ui_mobile_security,
                                    ui_container_security, ui_cloud_security,
                                    ui_sast, ui_api_assessment, ui_bloodhound)
    tabs = [
        dcc.Tab(label="🌐 IoT",          children=ui_iot_security.layout() if callable(getattr(ui_iot_security,"layout",None)) else html.Div()),
        dcc.Tab(label="📱 Mobile",       children=ui_mobile_security.layout() if callable(getattr(ui_mobile_security,"layout",None)) else html.Div()),
        dcc.Tab(label="🐳 Container",    children=ui_container_security.layout() if callable(getattr(ui_container_security,"layout",None)) else html.Div()),
        dcc.Tab(label="☁️ Cloud",        children=ui_cloud_security.layout() if callable(getattr(ui_cloud_security,"layout",None)) else html.Div()),
        dcc.Tab(label="🔍 SAST",         children=ui_sast.layout_sast_dashboard() if callable(getattr(ui_sast,"layout_sast_dashboard",None)) else html.Div()),
        dcc.Tab(label="🩸 BloodHound",   children=ui_bloodhound.layout_bh_dashboard() if callable(getattr(ui_bloodhound,"layout_bh_dashboard",None)) else html.Div()),
    ]
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#00aadd","background":"#0d1117"})

app.layout = wrap_layout("🔬 Specialised", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9018, debug=False)
