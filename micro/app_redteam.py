import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — Red Team Service  |  Port 9013"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/redteam/", "Red Team — ÆGIS")

def _content():
    from cyber_range.moduls import ui_pentest, ui_external_pentest, ui_red_team_ops, ui_exploit_ai, ui_postex
    tabs = []
    if hasattr(ui_pentest, "layout_automated_pt"):
        tabs.append(dcc.Tab(label="🎯 Automated PT", children=ui_pentest.layout_automated_pt()))
    if callable(getattr(ui_external_pentest,"layout",None)):
        tabs.append(dcc.Tab(label="🌐 External PT", children=ui_external_pentest.layout()))
    if callable(getattr(ui_red_team_ops,"layout",None)):
        tabs.append(dcc.Tab(label="🔴 Red Team Ops", children=ui_red_team_ops.layout()))
    if callable(getattr(ui_exploit_ai,"exploit_ai_tab",None)):
        tabs.append(dcc.Tab(label="💥 Exploit AI", children=ui_exploit_ai.exploit_ai_tab()))
    if callable(getattr(ui_postex,"postex_layout",None)):
        tabs.append(dcc.Tab(label="🕵 Post-Exploit", children=ui_postex.postex_layout()))
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#ff4444","background":"#0d1117"})

app.layout = wrap_layout("🔴 Red Team", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9013, debug=False)
