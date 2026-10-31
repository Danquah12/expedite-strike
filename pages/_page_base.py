# Shared auth gate helper for all standalone pages
from dash import html

def auth_gate():
    from flask import session as _s
    u = _s.get("admin_user") or _s.get("username")
    if not u:
        return html.Div(html.Div([
            html.I(className="fas fa-lock", style={"fontSize":"48px","color":"#cc0000","marginBottom":"16px"}),
            html.H4("Login Required", style={"color":"#ff4444"}),
            html.P("You must be logged in to access this module.", style={"color":"#888","fontSize":"13px"}),
            html.A("← Back to Login", href="/", style={"color":"#00aadd","fontWeight":"700","marginTop":"8px","display":"inline-block"}),
        ], style={"textAlign":"center","padding":"80px 40px","background":"#0a0a12",
                  "border":"1px solid #1a1a28","borderRadius":"8px","maxWidth":"420px","margin":"80px auto"}))
    return None

def err(msg, tab):
    return html.Div([
        html.H5(f"⚠ {tab} load error", style={"color":"#ffaa00"}),
        html.Pre(str(msg), style={"color":"#888","fontSize":"11px"}),
    ], style={"padding":"20px"})
