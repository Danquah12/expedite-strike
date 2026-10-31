# Expedite Strike — GRC & Reports Standalone Page  |  URL: /app/grc
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/grc", title="GRC & Reports — ÆGIS", name="GRC & Reports", order=6)

def layout():
    g = auth_gate()
    if g: return g
    try:
        from cyber_range.moduls import (ui_compliance, ui_grc_executive,
                                        ui_vuln_mgmt, ui_fleet_reports)
        tabs = dcc.Tabs([
            dcc.Tab(label="📊 Compliance",       children=ui_compliance.layout() if callable(getattr(ui_compliance,"layout",None)) else html.Div()),
            dcc.Tab(label="👔 GRC Executive",    children=ui_grc_executive.layout() if callable(getattr(ui_grc_executive,"layout",None)) else html.Div()),
            dcc.Tab(label="🐛 Vuln Mgmt",        children=ui_vuln_mgmt.layout() if callable(getattr(ui_vuln_mgmt,"layout",None)) else html.Div()),
            dcc.Tab(label="📋 Fleet Reports",    children=ui_fleet_reports.layout() if callable(getattr(ui_fleet_reports,"layout",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#ffcc00","background":"#0d1117"})
        return html.Div([html.H4("📊 GRC & Reports", className="mb-3",
                                  style={"color":"#ffcc00","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "GRC")
