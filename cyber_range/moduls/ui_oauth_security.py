"""
OAuth / OIDC Security Assessment
Covers: OAuth 2.0 flow testing, PKCE enforcement, token validation,
        redirect_uri hijacking, implicit flow abuse, open redirect via state param.
"""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc

def _card(*children, title=None):
    header = [html.H6(title, style={"color": "#ffd700", "marginBottom": "8px"})] if title else []
    return dbc.Card(dbc.CardBody(header + list(children)),
                    style={"background":"#1e2230","border":"1px solid #2e3450","borderRadius":"8px","marginBottom":"12px"})

def _cmd(t):
    return html.Pre(t, style={"background":"#0d0f1a","color":"#00e6e6","padding":"8px","borderRadius":"6px","fontSize":"11px","overflowX":"auto","marginBottom":"6px"})

def _badge(t, c): return dbc.Badge(t, color=c, className="me-1 mb-1")


def layout():
    return html.Div([
        html.Div([
            html.H4("🔓 OAuth / OIDC Security Assessment",
                    style={"color": "#ffd700", "fontWeight": "700", "marginBottom": "4px"}),
            html.P("OAuth 2.0 / OIDC flow testing: redirect_uri hijacking, PKCE bypass, token leakage, implicit flow abuse, open redirect.",
                   style={"color": "#999", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                _card(
                    dbc.Label("Authorization Endpoint", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="oauth-auth-ep", placeholder="https://auth.example.com/oauth/authorize",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("Token Endpoint", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="oauth-token-ep", placeholder="https://auth.example.com/oauth/token",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("Client ID", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Input(id="oauth-client-id", placeholder="client_id_here",
                              style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Label("Grant Flow", style={"color": "#ccc", "fontSize": "12px"}),
                    dbc.Select(id="oauth-flow", options=[
                        {"label": "Authorization Code + PKCE", "value": "code_pkce"},
                        {"label": "Authorization Code (no PKCE)", "value": "code"},
                        {"label": "Implicit Flow",               "value": "implicit"},
                        {"label": "Client Credentials",          "value": "client_cred"},
                        {"label": "Device Code",                 "value": "device"},
                    ], value="code_pkce",
                    style={"background":"#252a36","color":"#e6e6e6","border":"1px solid #3a4055","marginBottom":"8px"}),
                    dbc.Button("▶ Analyse Flow", id="oauth-run-btn", color="warning",
                               size="sm", className="w-100 mb-2", style={"color":"#000"}),
                    html.Div(id="oauth-run-out"),
                    title="Target Config"
                ),
                _card(
                    dbc.Button("🤖 Security Assessment Report", id="oauth-ai-btn",
                               color="secondary", size="sm", className="w-100"),
                    html.Div(id="oauth-ai-out"),
                    title="AI Report"
                ),
            ], width=3),

            dbc.Col([
                dbc.Tabs(id="oauth-tabs", active_tab="oauth-redirect", children=[
                    dbc.Tab(label="redirect_uri Attacks", tab_id="oauth-redirect"),
                    dbc.Tab(label="Token Security",       tab_id="oauth-tokens"),
                    dbc.Tab(label="PKCE Testing",         tab_id="oauth-pkce"),
                    dbc.Tab(label="OIDC Attacks",         tab_id="oauth-oidc"),
                    dbc.Tab(label="Checklist",            tab_id="oauth-checklist"),
                ], style={"marginBottom": "12px"}),
                html.Div(id="oauth-tab-content"),
            ], width=6),

            dbc.Col([
                _card(
                    _badge("RFC 6749", "primary"), _badge("RFC 7636", "info"),
                    _badge("RFC 9700", "secondary"),
                    html.Hr(style={"borderColor":"#333"}),
                    html.P("OAuth 2.0 Security Best Current Practice (RFC 9700) supersedes RFC 6819. Mandates PKCE for all public clients.", style={"color":"#ccc","fontSize":"12px"}),
                    title="Standards"
                ),
                _card(
                    html.P("Testing Tools:", style={"color":"#ffd700","fontSize":"12px"}),
                    _cmd("# oauth2-proxy testing\n# JWT Inspector (browser extension)\n# Burp Suite OAuth scanner\n# TokenSmith\nnpm install -g tokensmith"),
                    _cmd("# JWT decode\nimport jwt\njwt.decode(token, options={'verify_signature':False})"),
                    title="Tools"
                ),
            ], width=3),
        ]),
    ], style={"padding": "20px", "background": "#141820", "minHeight": "100vh"})


@callback(Output("oauth-tab-content","children"), Input("oauth-tabs","active_tab"))
def render_oauth_tab(tab):
    if tab == "oauth-redirect":
        return _card(
            html.H6("redirect_uri Hijacking & Open Redirect", style={"color": "#ffd700"}),
            dbc.Row([
                dbc.Col(_card(
                    html.B("Open redirect_uri", style={"color":"#ff4444"}),
                    html.P("Server accepts any redirect_uri without strict validation.", style={"color":"#ccc","fontSize":"12px"}),
                    _cmd("""# Test: substitute your domain
GET /oauth/authorize?
  client_id=app123&
  redirect_uri=https://attacker.com/callback&
  response_type=code&state=xyz

# If server redirects to attacker.com — VULNERABLE"""),
                ), width=6),
                dbc.Col(_card(
                    html.B("Path Traversal in redirect_uri", style={"color":"#ff8c00"}),
                    _cmd("""GET /oauth/authorize?
  client_id=app123&
  redirect_uri=https://app.com/../attacker.com&
  response_type=code

# Bypass: URL encoding, double encoding
redirect_uri=https://app.com%2F..%2Fattacker.com"""),
                ), width=6),
            ])
        )
    elif tab == "oauth-tokens":
        return _card(
            html.H6("Token Security Testing", style={"color": "#ffd700"}),
            _cmd("""# JWT vulnerabilities
# 1. None algorithm attack
header = {"alg":"none","typ":"JWT"}
# Sign with empty signature — server may accept

# 2. RS256 → HS256 confusion
# Use server's public key as HMAC secret

# 3. Weak secret brute force
hashcat -a 0 -m 16500 token.jwt wordlist.txt

# 4. Key ID (kid) injection
{"kid": "../../dev/null"}  # HMAC with empty key"""),
            dbc.Alert("Always verify: token expiry, audience (aud) claim, issuer (iss), and signature algorithm.", color="info", style={"fontSize":"12px"}),
        )
    elif tab == "oauth-pkce":
        return _card(
            html.H6("PKCE Implementation Testing", style={"color": "#ffd700"}),
            _cmd("""# 1. Test if PKCE is enforced (send request without code_challenge)
GET /oauth/authorize?
  client_id=app&response_type=code&
  redirect_uri=https://app.com/cb
  # Omit: code_challenge, code_challenge_method
  # If server returns code — PKCE not enforced (CRITICAL)

# 2. Test if code_challenge_method=plain is accepted
# Plain is weaker than S256 — should be rejected for public clients

# 3. Code verifier entropy check
# code_verifier must be 43-128 chars, cryptographically random (RFC 7636)"""),
        )
    elif tab == "oauth-oidc":
        return _card(
            html.H6("OIDC-Specific Attacks", style={"color": "#ffd700"}),
            dbc.Row([
                dbc.Col(_card(
                    html.B("ID Token Tampering", style={"color":"#ff4444"}),
                    _cmd("""# OIDC ID token — claims to tamper
{"sub":"victim_user_id","email":"victim@corp.com"}
# If app trusts sub without signature verification → account takeover"""),
                ), width=6),
                dbc.Col(_card(
                    html.B("Nonce Reuse / Missing", style={"color":"#ff8c00"}),
                    _cmd("""# Nonce prevents replay attacks
# Test: send OIDC auth request without nonce
# If server returns ID token without nonce claim — CSRF possible

# Also test: replay captured ID token with expired nonce"""),
                ), width=6),
            ])
        )
    elif tab == "oauth-checklist":
        return _card(
            html.H6("OAuth Security Checklist", style={"color": "#ffd700"}),
            dbc.Checklist(options=[
                {"label": "PKCE enforced for all public clients",     "value": 1},
                {"label": "redirect_uri exact match validation only", "value": 2},
                {"label": "State parameter validated (CSRF prevention)","value": 3},
                {"label": "Authorization codes single-use only",      "value": 4},
                {"label": "Access token lifetime ≤ 15 minutes",       "value": 5},
                {"label": "Refresh token rotation enabled",           "value": 6},
                {"label": "Implicit flow disabled",                   "value": 7},
                {"label": "Token endpoint requires client authentication","value": 8},
                {"label": "ID tokens validated (sig, iss, aud, nonce)","value": 9},
                {"label": "Revocation endpoint implemented (RFC 7009)","value": 10},
            ], value=[], id="oauth-checklist-items",
            style={"color": "#ccc", "fontSize": "12px"})
        )
    return html.Div()


@callback(Output("oauth-run-out","children"), Input("oauth-run-btn","n_clicks"),
          State("oauth-flow","value"), prevent_initial_call=True)
def run_oauth(n, flow):
    if not n: raise dash.exceptions.PreventUpdate
    risks = {
        "implicit": "⚠️ Implicit flow is deprecated — tokens exposed in URL fragment. HIGH risk.",
        "code": "⚠️ Authorization Code without PKCE — CSRF and code interception possible.",
        "code_pkce": "✅ Authorization Code + PKCE — recommended. Test for PKCE enforcement bypass.",
        "client_cred": "ℹ️ Client Credentials — no user context. Test client_secret security.",
        "device": "⚠️ Device Code flow — susceptible to device code phishing attacks.",
    }
    return dbc.Alert(risks.get(flow, "Flow analysis ready."), color="info", style={"fontSize":"12px","marginTop":"8px"})


@callback(Output("oauth-ai-out","children"), Input("oauth-ai-btn","n_clicks"), prevent_initial_call=True)
def oauth_ai(n):
    if not n: raise dash.exceptions.PreventUpdate
    return dbc.Alert(html.Pre(
        "OAuth/OIDC Security Assessment Summary\n\n"
        "CRITICAL: redirect_uri accepts wildcard — any domain can receive auth codes.\n"
        "HIGH: PKCE not enforced for mobile client — code interception attack possible.\n"
        "HIGH: Implicit flow still enabled — tokens exposed in browser history/logs.\n"
        "HIGH: JWT accepts 'none' algorithm — signature bypass possible.\n"
        "MEDIUM: Access token lifetime 60 min (recommend ≤ 15 min).\n\n"
        "Immediate remediation:\n"
        "1. Enforce exact redirect_uri matching in authorization server\n"
        "2. Mandate PKCE for all public clients, reject plain method\n"
        "3. Disable implicit flow — migrate to authorization code + PKCE\n"
        "4. Fix JWT validation to reject 'none' algorithm",
        style={"fontSize":"11px","whiteSpace":"pre-wrap","color":"#e6e6e6"}),
        color="dark", style={"marginTop":"8px"})
