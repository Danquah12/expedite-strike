import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — Assessment Service  |  Port 9012"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/assessment/", "Assessment — ÆGIS")

def _content():
    from cyber_range.moduls import ui_assessment, ui_api_assessment
    return dcc.Tabs([
        dcc.Tab(label="📋 SCAP Scanner",
                children=ui_assessment.scanner_card
                         if hasattr(ui_assessment,"scanner_card")
                         else ui_assessment.layout() if callable(getattr(ui_assessment,"layout",None))
                         else html.Div("SCAP Scanner ready.")),
        dcc.Tab(label="🔌 API Assessment",
                children=ui_api_assessment.layout() if callable(getattr(ui_api_assessment,"layout",None))
                         else html.Div()),
    ], colors={"border":"#1a1a28","primary":"#00d4ff","background":"#0d1117"})

app.layout = wrap_layout("📋 Assessment", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9012, debug=False)
