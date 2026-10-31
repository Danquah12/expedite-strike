# -*- coding: utf-8 -*-
"""Expedite Strike Hub — Port 9011 — Navigation entry point (lightweight, always-on)"""
import sys; sys.path.insert(0, "/opt/vuln_intel/app")
from dotenv import load_dotenv; load_dotenv("/opt/vuln_intel/app/.env")
from dash import Dash, html, dcc
from micro.shared_config import SECRET_KEY, EXTERNAL_STYLESHEETS, micro_navbar, NAV_LINKS

app = Dash(__name__, external_stylesheets=EXTERNAL_STYLESHEETS,
           suppress_callback_exceptions=True, url_base_pathname="/app/")
server = app.server
server.secret_key = SECRET_KEY

app.layout = html.Div([
    micro_navbar(),
    html.Div([
        html.H2("⬡ ÆGIS Security Operations Centre",
                style={"color":"#00d4ff","fontWeight":"900","letterSpacing":"2px","marginBottom":"8px"}),
        html.P("Select a module below to begin your operation.",
               style={"color":"#888","fontSize":"14px","marginBottom":"32px"}),
        html.Div([
            html.A([html.Div(item["label"], style={"fontSize":"16px","fontWeight":"700","color":"#00d4ff"}),
                    html.Div("→", style={"fontSize":"20px","color":"#333","marginTop":"8px"})],
                   href=item["href"],
                   style={"display":"block","padding":"24px 28px","background":"#0d1117",
                          "border":"1px solid #1a1a28","borderRadius":"10px","textDecoration":"none",
                          "transition":"all 0.2s","minWidth":"160px"})
            for item in NAV_LINKS
        ], style={"display":"flex","flexWrap":"wrap","gap":"16px","justifyContent":"center"}),
    ], style={"maxWidth":"900px","margin":"80px auto","textAlign":"center","padding":"0 20px"}),
], style={"background":"#070b0f","minHeight":"100vh"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9011, debug=False)
