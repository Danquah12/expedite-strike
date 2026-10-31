import sys; sys.path.insert(0, "/opt/vuln_intel/app")
# -*- coding: utf-8 -*-
"""Expedite Strike — AI & Research Service  |  Port 9019"""
from micro._app_factory import make_app, wrap_layout
from dash import html, dcc

app = make_app(__name__, "/app/ai/", "AI & Research — ÆGIS")

def _content():
    from cyber_range.moduls import (ui_phd_comparison, ui_phd_advanced,
                                    ui_voice_enhanced, ui_ai_hardening, ui_wargame_ai)
    tabs = [
        dcc.Tab(label="🎓 PhD Comparison", children=ui_phd_comparison.generate_phd_comparison_layout() if callable(getattr(ui_phd_comparison,"generate_phd_comparison_layout",None)) else html.Div()),
        dcc.Tab(label="🔬 PhD Advanced",   children=ui_phd_advanced.generate_phd_advanced_layout() if callable(getattr(ui_phd_advanced,"generate_phd_advanced_layout",None)) else html.Div()),
        dcc.Tab(label="🎙 Voice Sim",      children=ui_voice_enhanced.generate_voice_enhanced_layout() if callable(getattr(ui_voice_enhanced,"generate_voice_enhanced_layout",None)) else html.Div()),
        dcc.Tab(label="🔐 AI Hardening",   children=ui_ai_hardening.layout() if callable(getattr(ui_ai_hardening,"layout",None)) else html.Div()),
        dcc.Tab(label="⚔️ Wargame AI",    children=ui_wargame_ai.wargame_tab() if callable(getattr(ui_wargame_ai,"wargame_tab",None)) else html.Div()),
    ]
    return dcc.Tabs(tabs, colors={"border":"#1a1a28","primary":"#ff44cc","background":"#0d1117"})

app.layout = wrap_layout("🤖 AI", _content)
server = app.server

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9019, debug=False)
