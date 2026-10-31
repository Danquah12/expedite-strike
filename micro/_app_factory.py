# -*- coding: utf-8 -*-
"""
Factory that every micro app uses to create a Dash instance.
Handles: secret key, assets, suppress_callback_exceptions, error boundary.
"""
import sys; sys.path.insert(0, "/opt/vuln_intel/app")
from dotenv import load_dotenv; load_dotenv("/opt/vuln_intel/app/.env")
from dash import Dash, html, dcc
import dash_bootstrap_components as dbc
from micro.shared_config import (SECRET_KEY, EXTERNAL_STYLESHEETS,
                                  ASSETS_DIR, micro_navbar, dash_auth_gate, error_card)

def make_app(name, base_path, title):
    """Create a standalone Dash app for one module group."""
    app = Dash(
        name,
        external_stylesheets=EXTERNAL_STYLESHEETS,
        suppress_callback_exceptions=True,
        url_base_pathname=base_path,
        assets_folder=ASSETS_DIR,
        title=title,
    )
    app.server.secret_key = SECRET_KEY
    return app

def wrap_layout(navbar_label, content_fn):
    """Return a Dash layout function with nav bar + auth gate + error boundary."""
    def layout():
        gate = dash_auth_gate(navbar_label)
        if gate:
            return gate
        try:
            content = content_fn()
        except Exception as e:
            content = error_card(navbar_label, e)
        return html.Div([
            micro_navbar(active_label=navbar_label),
            html.Div(content, style={"padding":"20px"}),
        ], style={"background":"#070b0f","minHeight":"100vh"})
    return layout
