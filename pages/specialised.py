# Expedite Strike — Specialised Standalone Page  |  URL: /app/specialised
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/specialised", title="Specialised — ÆGIS", name="Specialised", order=7)

def layout():
    g = auth_gate()
    if g: return g
    try:
        from cyber_range.moduls import (ui_iot_security, ui_mobile_security,
                                        ui_container_security, ui_cloud_security,
                                        ui_sast, ui_api_assessment)
        tabs = dcc.Tabs([
            dcc.Tab(label="🌐 IoT",          children=ui_iot_security.layout() if callable(getattr(ui_iot_security,"layout",None)) else html.Div()),
            dcc.Tab(label="📱 Mobile",       children=ui_mobile_security.layout() if callable(getattr(ui_mobile_security,"layout",None)) else html.Div()),
            dcc.Tab(label="🐳 Container",    children=ui_container_security.layout() if callable(getattr(ui_container_security,"layout",None)) else html.Div()),
            dcc.Tab(label="☁️ Cloud",        children=ui_cloud_security.layout() if callable(getattr(ui_cloud_security,"layout",None)) else html.Div()),
            dcc.Tab(label="🔍 SAST",         children=ui_sast.layout_sast_dashboard() if callable(getattr(ui_sast,"layout_sast_dashboard",None)) else html.Div()),
            dcc.Tab(label="🔌 API Security", children=ui_api_assessment.layout() if callable(getattr(ui_api_assessment,"layout",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#00aadd","background":"#0d1117"})
        return html.Div([html.H4("🔬 Specialised Security", className="mb-3",
                                  style={"color":"#00aadd","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "Specialised")
