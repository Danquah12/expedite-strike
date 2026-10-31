# Expedite Strike — Attack Surface Standalone Page  |  URL: /app/attack
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/attack", title="Attack Surface — ÆGIS", name="Attack Surface", order=3)

def layout():
    g = auth_gate()
    if g: return g
    try:
        from cyber_range.moduls import ui_osint, ui_mitre, ui_mitre_advanced
        tabs = dcc.Tabs([
            dcc.Tab(label="🔍 OSINT",        children=ui_osint.layout() if callable(getattr(ui_osint,"layout",None)) else html.Div()),
            dcc.Tab(label="🗺 MITRE ATT&CK", children=ui_mitre.generate_mitre_layout() if callable(getattr(ui_mitre,"generate_mitre_layout",None)) else html.Div()),
            dcc.Tab(label="🎭 Threat Actors", children=ui_mitre_advanced.generate_threat_actor_layout() if callable(getattr(ui_mitre_advanced,"generate_threat_actor_layout",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#ff8800","background":"#0d1117"})
        return html.Div([html.H4("🎯 Attack Surface", className="mb-3",
                                  style={"color":"#ff8800","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "Attack Surface")
