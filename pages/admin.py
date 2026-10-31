# Expedite Strike — Admin Standalone Page  |  URL: /app/admin
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/admin-panel", title="Admin — ÆGIS", name="Admin", order=9)

def layout():
    from flask import session as _s
    user = _s.get("admin_user") or _s.get("username")
    if not user:
        return auth_gate()
    try:
        from cyber_range.moduls import ui_admin_dashboard, ui_admin_panel, ui_plugins
        tabs = dcc.Tabs([
            dcc.Tab(label="📊 Dashboard",  children=ui_admin_dashboard.layout() if callable(getattr(ui_admin_dashboard,"layout",None)) else html.Div()),
            dcc.Tab(label="⚙️ Admin Panel", children=ui_admin_panel.layout() if callable(getattr(ui_admin_panel,"layout",None)) else html.Div()),
            dcc.Tab(label="🔌 Plugins",    children=ui_plugins.layout() if callable(getattr(ui_plugins,"layout",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#ff8800","background":"#0d1117"})
        return html.Div([html.H4("⚙️ Administration", className="mb-3",
                                  style={"color":"#ff8800","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "Admin")
