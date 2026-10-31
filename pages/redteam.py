# Expedite Strike — Red Team Standalone Page  |  URL: /app/redteam
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/redteam", title="Red Team — ÆGIS", name="Red Team", order=2)

def layout():
    g = auth_gate()
    if g: return g
    try:
        from cyber_range.moduls import (ui_pentest, ui_external_pentest,
                                        ui_red_team_ops, ui_exploit_ai)
        tabs = dcc.Tabs([
            dcc.Tab(label="🎯 Pentest",       children=ui_pentest.layout_automated_pt() if hasattr(ui_pentest,"layout_automated_pt") else html.Div()),
            dcc.Tab(label="🌐 External PT",   children=ui_external_pentest.layout() if callable(getattr(ui_external_pentest,"layout",None)) else html.Div()),
            dcc.Tab(label="🔴 Red Team Ops",  children=ui_red_team_ops.layout() if callable(getattr(ui_red_team_ops,"layout",None)) else html.Div()),
            dcc.Tab(label="💥 Exploit AI",    children=ui_exploit_ai.exploit_ai_tab() if callable(getattr(ui_exploit_ai,"exploit_ai_tab",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#ff4444","background":"#0d1117"})
        return html.Div([html.H4("🔴 Red Team Operations", className="mb-3",
                                  style={"color":"#ff4444","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "Red Team")
