import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — Admin Service  |  Port 9020"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/admin-panel/", "Admin — ÆGIS")

def _content():
    from cyber_range.moduls import ui_admin_dashboard, ui_admin_panel, ui_plugins
    tabs = [
        dcc.Tab(label="📊 Dashboard",   children=ui_admin_dashboard.layout() if callable(getattr(ui_admin_dashboard,"layout",None)) else html.Div()),
        dcc.Tab(label="⚙️ Admin Panel", children=ui_admin_panel.layout() if callable(getattr(ui_admin_panel,"layout",None)) else html.Div()),
        dcc.Tab(label="🔌 Plugins",     children=ui_plugins.layout() if callable(getattr(ui_plugins,"layout",None)) else html.Div()),
    ]
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#ff8800","background":"#0d1117"})

app.layout = wrap_layout("⚙️ Admin", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9020, debug=False)
