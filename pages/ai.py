# Expedite Strike — AI & Research Standalone Page  |  URL: /app/ai
import dash; from dash import html, dcc
from pages._page_base import auth_gate, err
dash.register_page(__name__, path="/ai", title="AI & Research — ÆGIS", name="AI & Research", order=8)

def layout():
    g = auth_gate()
    if g: return g
    try:
        from cyber_range.moduls import (ui_phd_comparison, ui_phd_advanced,
                                        ui_voice_enhanced, ui_ai_hardening,
                                        ui_wargame_ai)
        tabs = dcc.Tabs([
            dcc.Tab(label="🎓 PhD Comparison",  children=ui_phd_comparison.generate_phd_comparison_layout() if callable(getattr(ui_phd_comparison,"generate_phd_comparison_layout",None)) else html.Div()),
            dcc.Tab(label="🔬 PhD Advanced",     children=ui_phd_advanced.generate_phd_advanced_layout() if callable(getattr(ui_phd_advanced,"generate_phd_advanced_layout",None)) else html.Div()),
            dcc.Tab(label="🎙 Voice",            children=ui_voice_enhanced.generate_voice_enhanced_layout() if callable(getattr(ui_voice_enhanced,"generate_voice_enhanced_layout",None)) else html.Div()),
            dcc.Tab(label="🔐 AI Hardening",    children=ui_ai_hardening.layout() if callable(getattr(ui_ai_hardening,"layout",None)) else html.Div()),
            dcc.Tab(label="⚔️ Wargame AI",      children=ui_wargame_ai.wargame_tab() if callable(getattr(ui_wargame_ai,"wargame_tab",None)) else html.Div()),
        ], colors={"border":"#1a1a28","primary":"#ff44cc","background":"#0d1117"})
        return html.Div([html.H4("🤖 AI & Research", className="mb-3",
                                  style={"color":"#ff44cc","fontWeight":"700"}), tabs], className="p-3")
    except Exception as e:
        return err(e, "AI & Research")
