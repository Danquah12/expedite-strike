# -*- coding: utf-8 -*-
"""Expedite Strike — Assessment Standalone Page  |  URL: /app/assessment"""
import dash
from dash import html

dash.register_page(__name__, path="/assessment", title="Assessment — ÆGIS", name="Assessment", order=1)

def _gate():
    from flask import session as _s
    u = _s.get("admin_user") or _s.get("username")
    if not u:
        return html.Div(html.Div([
            html.I(className="fas fa-lock", style={"fontSize":"48px","color":"#cc0000","marginBottom":"16px"}),
            html.H4("Login Required", style={"color":"#ff4444"}),
            html.A("Go to Login →", href="/", style={"color":"#00aadd","fontWeight":"700"}),
        ], style={"textAlign":"center","padding":"80px 40px","background":"#0a0a12",
                  "border":"1px solid #1a1a28","borderRadius":"8px","maxWidth":"420px","margin":"80px auto"}))
    return None

def layout():
    g = _gate()
    if g: return g
    try:
        from app import assessment_tab
        return html.Div([html.H4("📋 Assessment", className="mb-3",
                                  style={"color":"#00d4ff","fontWeight":"700"}), assessment_tab], className="p-3")
    except Exception as e:
        try:
            from cyber_range.moduls import ui_assessment
            return html.Div([html.H4("📋 Assessment", className="mb-3",
                                      style={"color":"#00d4ff","fontWeight":"700"}),
                             ui_assessment.layout() if callable(getattr(ui_assessment,"layout",None))
                             else html.Div("Assessment module ready.")], className="p-3")
        except Exception as e2:
            return html.Div(f"Error: {e2}", style={"color":"#ff4444","padding":"20px"})
