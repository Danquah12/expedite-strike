# Expedite Strike — Defence Standalone Page  |  URL: /app/defence
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/defence", title="Defence — ÆGIS", name="Defence", order=4)

def layout():
    g = auth_gate()
    if g: return g
    try:
        from cyber_range.moduls import (ui_forensics, ui_dfir_case,
                                        ui_threat_hunting, ui_edr_gaps)
        tabs = dcc.Tabs([
            dcc.Tab(label="🔬 Forensics",       children=ui_forensics.layout() if callable(getattr(ui_forensics,"layout",None)) else html.Div()),
            dcc.Tab(label="🚨 DFIR Case",        children=ui_dfir_case.layout() if callable(getattr(ui_dfir_case,"layout",None)) else html.Div()),
            dcc.Tab(label="🎯 Threat Hunting",   children=ui_threat_hunting.layout() if callable(getattr(ui_threat_hunting,"layout",None)) else html.Div()),
            dcc.Tab(label="🛡 EDR Gaps",         children=ui_edr_gaps.layout() if callable(getattr(ui_edr_gaps,"layout",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#00dd88","background":"#0d1117"})
        return html.Div([html.H4("🛡️ Defence & Response", className="mb-3",
                                  style={"color":"#00dd88","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "Defence")
