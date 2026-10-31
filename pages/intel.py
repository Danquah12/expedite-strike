# Expedite Strike — Threat Intel Standalone Page  |  URL: /app/intel
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/intel", title="Threat Intel — ÆGIS", name="Threat Intel", order=5)

def layout():
    g = auth_gate()
    if g: return g
    try:
        from cyber_range.moduls import (ui_threat_intel, ui_darkweb,
                                        ui_supply_chain, ui_phishing)
        tabs = dcc.Tabs([
            dcc.Tab(label="📡 Threat Intel",    children=ui_threat_intel.layout() if callable(getattr(ui_threat_intel,"layout",None)) else html.Div()),
            dcc.Tab(label="🌑 Dark Web",         children=ui_darkweb.layout() if callable(getattr(ui_darkweb,"layout",None)) else html.Div()),
            dcc.Tab(label="⛓ Supply Chain",     children=ui_supply_chain.layout() if callable(getattr(ui_supply_chain,"layout",None)) else html.Div()),
            dcc.Tab(label="🎣 Phishing",         children=ui_phishing.layout() if callable(getattr(ui_phishing,"layout",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#aa44ff","background":"#0d1117"})
        return html.Div([html.H4("📡 Intelligence", className="mb-3",
                                  style={"color":"#aa44ff","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "Intel")
