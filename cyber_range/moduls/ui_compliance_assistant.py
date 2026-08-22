"""
ui_compliance_assistant.py
==========================
AI Compliance Assistant — Chat interface for GRC questions.

Users can ask:
  - Explain this vulnerability
  - Generate AC-2 implementation statement
  - What evidence is required for IA-5?

AI uses: NIST 800-53 · FedRAMP · STIG · RMF guidance

Layout function: layout_compliance_assistant()
Callbacks: auto-registered on import
"""
from __future__ import annotations

import json
from datetime import datetime

from dash import callback, dcc, html, Input, Output, State, ctx, no_update, ALL
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

# ── Style tokens ──────────────────────────────────────────────────
DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
ACCENT    = "#00d4ff"
ACCENT2   = "#7c3aed"
USER_CLR  = "#1a73e8"
AI_CLR    = "#1a1d24"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "8px", "fontSize": "14px"}
BTN_STY   = {"borderRadius": "8px", "fontSize": "13px", "fontWeight": "600"}

# Quick-action templates
QUICK_ACTIONS = [
    {"label": "📋 Explain Vulnerability", "id": "qa-explain",
     "prompt": "Explain this vulnerability and its compliance impact: "},
    {"label": "📝 Implementation Statement", "id": "qa-implement",
     "prompt": "Generate an SSP implementation statement for NIST control: "},
    {"label": "📎 Evidence Requirements", "id": "qa-evidence",
     "prompt": "What evidence artifacts are required for NIST control: "},
    {"label": "🔒 FedRAMP Baseline", "id": "qa-fedramp",
     "prompt": "What are the FedRAMP Moderate requirements for: "},
    {"label": "⚔️ STIG Guidance", "id": "qa-stig",
     "prompt": "Provide STIG hardening guidance for: "},
    {"label": "📊 Risk Assessment", "id": "qa-risk",
     "prompt": "Assess the risk and impact of: "},
]


def _chat_bubble(text: str, is_user: bool, ts: str = "") -> html.Div:
    """Creates a styled chat message bubble."""
    return html.Div([
        html.Div([
            html.Div(
                "You" if is_user else "🤖 Compliance AI",
                style={
                    "fontSize": "11px", "fontWeight": "700",
                    "color": ACCENT if not is_user else "#8e9eb0",
                    "marginBottom": "4px",
                    "textTransform": "uppercase",
                    "letterSpacing": "0.5px",
                }
            ),
            dcc.Markdown(
                text,
                style={
                    "fontSize": "13.5px", "lineHeight": "1.6",
                    "color": "#e0e0e0", "margin": "0",
                },
                dangerously_allow_html=True,
            ),
            html.Div(
                ts or datetime.now().strftime("%I:%M %p"),
                style={"fontSize": "10px", "color": "#555", "marginTop": "6px", "textAlign": "right"}
            ),
        ], style={
            "background": USER_CLR if is_user else AI_CLR,
            "borderRadius": "12px",
            "padding": "12px 16px",
            "maxWidth": "85%",
            "border": f"1px solid {'#2563eb' if is_user else '#1e2230'}",
            "boxShadow": "0 2px 8px rgba(0,0,0,0.3)",
        })
    ], style={
        "display": "flex",
        "justifyContent": "flex-end" if is_user else "flex-start",
        "marginBottom": "12px",
    })


def layout_compliance_assistant() -> html.Div:
    """Build the AI Compliance Assistant chat UI."""
    return html.Div([
        # Header
        html.Div([
            html.Div([
                html.Span("🤖 ", style={"fontSize": "28px"}),
                html.Span("AI Compliance Assistant",
                          style={"fontSize": "20px", "fontWeight": "700", "color": "#fff"}),
            ], style={"display": "flex", "alignItems": "center", "gap": "8px"}),
            html.P(
                "Ask about NIST 800-53 · FedRAMP · STIGs · RMF · POA&M · Evidence Requirements",
                style={"color": "#8e9eb0", "fontSize": "12px", "margin": "4px 0 0 0"}
            ),
        ], style={
            "background": f"linear-gradient(135deg, {CARD_BG}, #151820)",
            "padding": "16px 20px",
            "borderRadius": "12px 12px 0 0",
            "borderBottom": f"2px solid {ACCENT}",
        }),

        # Quick action buttons
        html.Div([
            html.Div("Quick Actions", style={
                "color": "#8e9eb0", "fontSize": "11px", "fontWeight": "700",
                "textTransform": "uppercase", "letterSpacing": "0.5px", "marginBottom": "8px",
            }),
            html.Div([
                dbc.Button(
                    qa["label"],
                    id={"type": "grc-qa-btn", "index": qa["id"]},
                    size="sm",
                    outline=True,
                    color="info",
                    style={
                        "borderRadius": "20px", "fontSize": "11px", "padding": "4px 12px",
                        "borderColor": "#1e2230", "color": "#8e9eb0",
                        "transition": "all 0.2s",
                    },
                    className="me-1 mb-1",
                ) for qa in QUICK_ACTIONS
            ], style={"display": "flex", "flexWrap": "wrap", "gap": "4px"}),
        ], style={
            "background": CARD_BG, "padding": "12px 16px",
            "borderBottom": BORDER,
        }),

        # Run Agents button
        html.Div([
            dbc.Button([
                html.I(className="fas fa-robot me-2"),
                "Run Full Agent Pipeline",
            ], id="grc-run-agents-btn", color="primary", size="sm",
               style={"borderRadius": "8px", "fontSize": "12px", "width": "100%",
                       "background": f"linear-gradient(135deg, {ACCENT2}, #5b21b6)",
                       "border": "none", "fontWeight": "600"}),
            html.Div(id="grc-agent-status", style={
                "fontSize": "11px", "color": ACCENT, "marginTop": "6px", "textAlign": "center",
            }),
        ], style={
            "background": CARD_BG, "padding": "10px 16px",
            "borderBottom": BORDER,
        }),

        # Chat history
        html.Div(
            id="grc-chat-history",
            children=[
                _chat_bubble(
                    "Hello! I'm your **AI Compliance Assistant**. I can help with:\n\n"
                    "- 📋 **Explain vulnerabilities** and their compliance impact\n"
                    "- 📝 **Generate implementation statements** for NIST 800-53 controls\n"
                    "- 📎 **List evidence requirements** for any control\n"
                    "- 🔒 **FedRAMP baseline** guidance\n"
                    "- ⚔️ **STIG hardening** recommendations\n\n"
                    "Try a **Quick Action** above or type your question below!",
                    is_user=False,
                    ts=datetime.now().strftime("%I:%M %p"),
                )
            ],
            style={
                "height": "420px", "overflowY": "auto", "padding": "16px",
                "background": DARK_BG,
                "scrollBehavior": "smooth",
            },
        ),

        # Input area
        html.Div([
            dbc.InputGroup([
                dbc.Input(
                    id="grc-chat-input",
                    placeholder="Ask about NIST controls, FedRAMP, vulnerabilities, evidence...",
                    type="text",
                    style={
                        **INPUT_STY,
                        "height": "44px",
                        "borderRight": "none",
                        "borderTopRightRadius": "0",
                        "borderBottomRightRadius": "0",
                    },
                    debounce=True,
                ),
                dbc.Button(
                    [html.I(className="fas fa-paper-plane me-1"), " Send"],
                    id="grc-chat-send",
                    color="primary",
                    style={
                        "borderRadius": "0 8px 8px 0",
                        "background": f"linear-gradient(135deg, {ACCENT}, #0091d5)",
                        "border": "none", "fontWeight": "600",
                        "padding": "0 20px",
                    },
                ),
            ], style={"maxWidth": "100%"}),
            html.Div([
                html.Span("Powered by GPT-4o · ", style={"color": "#555", "fontSize": "10px"}),
                html.Span("NIST 800-53 Rev 5 · FedRAMP · DISA STIGs",
                          style={"color": "#555", "fontSize": "10px"}),
            ], style={"textAlign": "center", "marginTop": "6px"}),
        ], style={
            "background": CARD_BG, "padding": "12px 16px",
            "borderRadius": "0 0 12px 12px",
            "borderTop": BORDER,
        }),

        # Hidden stores
        dcc.Store(id="grc-chat-store", data=[]),
        dcc.Loading(
            id="grc-chat-loading",
            type="circle",
            color=ACCENT,
            children=html.Div(id="grc-chat-loading-target"),
        ),
    ], style={
        "background": CARD_BG,
        "borderRadius": "12px",
        "border": BORDER,
        "boxShadow": "0 4px 24px rgba(0,0,0,0.4)",
        "maxWidth": "100%",
        "overflow": "hidden",
    })


# ── Callbacks ────────────────────────────────────────────────────

@callback(
    Output("grc-chat-history", "children"),
    Output("grc-chat-store", "data"),
    Output("grc-chat-input", "value"),
    Output("grc-chat-loading-target", "children"),
    Input("grc-chat-send", "n_clicks"),
    Input("grc-chat-input", "n_submit"),
    Input({"type": "grc-qa-btn", "index": ALL}, "n_clicks"),
    State("grc-chat-input", "value"),
    State("grc-chat-store", "data"),
    State("grc-chat-history", "children"),
    prevent_initial_call=True,
)
def _handle_chat(send_clicks, enter_submit, qa_clicks, user_input, store, history):
    """Handle chat send, enter key, and quick-action button clicks."""
    triggered = ctx.triggered_id
    if not triggered:
        raise PreventUpdate

    # Determine message source
    message = ""

    # Quick action button
    if isinstance(triggered, dict) and triggered.get("type") == "grc-qa-btn":
        qa_id = triggered["index"]
        for qa in QUICK_ACTIONS:
            if qa["id"] == qa_id:
                message = qa["prompt"]
                break
        # If user typed something, append it to the prompt
        if user_input and user_input.strip():
            message += user_input.strip()
        elif message.endswith(": "):
            # No user input — show placeholder
            message += "[please specify a control ID or vulnerability]"
    else:
        # Regular send
        message = (user_input or "").strip()

    if not message:
        raise PreventUpdate

    history = history or []
    store = store or []
    ts = datetime.now().strftime("%I:%M %p")

    # Add user message
    history.append(_chat_bubble(message, is_user=True, ts=ts))
    store.append({"role": "user", "content": message, "ts": ts})

    # Call AI
    try:
        from cyber_range.services.grc_agents import compliance_chat
        answer = compliance_chat(message)
    except Exception as e:
        answer = f"⚠️ Error: {e}"

    ts2 = datetime.now().strftime("%I:%M %p")
    history.append(_chat_bubble(answer, is_user=False, ts=ts2))
    store.append({"role": "assistant", "content": answer, "ts": ts2})

    return history, store, "", ""


@callback(
    Output("grc-agent-status", "children"),
    Input("grc-run-agents-btn", "n_clicks"),
    prevent_initial_call=True,
)
def _run_agent_pipeline(n_clicks):
    """Run the full 5-agent GRC pipeline and display summary."""
    if not n_clicks:
        raise PreventUpdate

    try:
        from cyber_range.services.grc_agents import run_grc_pipeline
        result = run_grc_pipeline(system_id=1)
        summary = result.get("summary", {})

        return html.Div([
            html.Div("✅ Pipeline Complete", style={
                "fontWeight": "700", "color": "#27ae60", "marginBottom": "6px",
            }),
            html.Div([
                html.Span(f"🖥️ {len(result.get('assets', []))} assets  "),
                html.Span(f"🔓 {len(result.get('vulnerabilities', []))} vulns  "),
                html.Span(f"📋 {len(result.get('poam_items', []))} POA&Ms  "),
                html.Span(f"⚠️ {len(result.get('risks', []))} risks  "),
                html.Span(f"📊 {summary.get('compliance_coverage', 0)}% coverage"),
            ], style={"fontSize": "11px", "color": "#8e9eb0"}),
        ])
    except Exception as e:
        return html.Div(f"❌ Error: {e}", style={"color": "#e74c3c"})
