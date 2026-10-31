"""
Standalone Admin RBAC Panel
============================
Completely outside the tab system.
Accessible at URL /admin-panel (via dcc.Location routing).

Features:
- User management (add/edit/delete users)
- Tab permission matrix (least-privilege mapping)
- Role assignment
- "View as user" mode
- All changes saved to user_permissions.json
"""

import sys
sys.path.insert(0, "/home/kali/.local/lib/python3.13/site-packages")

import os, json, time
from dash import html, dcc, callback, Input, Output, State, no_update, ctx
import dash_bootstrap_components as dbc

PERM_FILE = os.path.join(os.path.dirname(__file__), "../../user_permissions.json")

# ─── Permission store helpers ──────────────────────────────────────────────────
def _load():
    try:
        return json.load(open(PERM_FILE))
    except Exception:
        return {"users": {}, "all_tabs": []}

def _save(data):
    try:
        json.dump(data, open(PERM_FILE,"w"), indent=2)
        return True
    except Exception:
        return False

def _all_tabs():
    return _load().get("all_tabs", [])

def _user_tabs(username):
    data  = _load()
    users = data.get("users", {})
    if username not in users:
        return []
    tabs = users[username].get("tabs", [])
    return tabs  # ["all"] means all tabs

# ─── Layout helpers ────────────────────────────────────────────────────────────
def _role_badge(role):
    color_map = {"admin":"#ff4444","analyst":"#00aaff","viewer":"#888","manager":"#ff8800"}
    c = color_map.get(role,"#888")
    return dbc.Badge(role.upper(), style={"backgroundColor":c+"22","color":c,
                                           "border":f"1px solid {c}44","fontSize":"9px",
                                           "padding":"2px 8px","letterSpacing":"1px"})

def _user_row(username, udata, selected):
    role    = udata.get("role","viewer")
    display = udata.get("display_name", username)
    tabs    = udata.get("tabs",[])
    ntabs   = "ALL" if "all" in tabs else str(len(tabs))
    is_sel  = (username == selected)
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.Div(display, style={"color":"#fff" if is_sel else "#ccc",
                                          "fontWeight":"bold" if is_sel else "normal",
                                          "fontSize":"12px"}),
                html.Div(f"@{username}", style={"color":"#555","fontSize":"9px"}),
            ], md=6),
            dbc.Col(_role_badge(role), md=3),
            dbc.Col(html.Span(f"{ntabs} tabs",
                              style={"color":"#44ff88" if is_sel else "#555","fontSize":"10px"}),
                    md=3),
        ], align="center"),
    ], id={"type":"admin-user-row","index":username},
       n_clicks=0,
       style={"padding":"10px 14px","cursor":"pointer",
              "backgroundColor":"#1a2a1a" if is_sel else "#0d0d0d",
              "borderLeft":f"3px solid {'#44ff88' if is_sel else '#1a1a1a'}",
              "borderBottom":"1px solid #141414",
              "transition":"all 0.15s"},
       className="admin-user-row-item")

# ─── Main layout ───────────────────────────────────────────────────────────────
def generate_admin_panel_layout():
    data    = _load()
    users   = data.get("users", {})
    all_tabs = data.get("all_tabs", [])
    now     = time.strftime("%Y-%m-%d %H:%M:%S")

    # Default selected user
    first_user = next(iter(users), None) if users else None

    return html.Div([
        dcc.Store(id="admin-selected-user", data=first_user),
        dcc.Store(id="admin-perms-store",   data=data),

        # ── AUDIT LOG MODAL ────────────────────────────────────────────────────
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("📊 Audit Log — Recent Events"),
                            style={"backgroundColor":"#0a0a0a","borderBottom":"1px solid #222"}),
            dbc.ModalBody(
                html.Div(id="admin-audit-log-body",
                         style={"maxHeight":"60vh","overflowY":"auto"}),
                style={"backgroundColor":"#0d0d0d","padding":"0"}
            ),
            dbc.ModalFooter(
                dbc.Button("Close", id="admin-audit-close", color="secondary", size="sm"),
                style={"backgroundColor":"#0a0a0a","borderTop":"1px solid #222"}
            ),
        ], id="admin-audit-modal", is_open=False, size="xl",
           style={"fontFamily":"'Inter',monospace"},
           backdrop="static"),

        # ── TOP HEADER ─────────────────────────────────────────────────────────
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Span("🛡️", style={"fontSize":"24px","marginRight":"8px"}),
                        html.Div([
                            html.Div("VULN INTEL",
                                     style={"color":"#ff2222","fontWeight":"900","fontSize":"16px",
                                            "letterSpacing":"3px","lineHeight":"1"}),
                            html.Div("ADMIN CONTROL CENTRE",
                                     style={"color":"#444","fontSize":"9px","letterSpacing":"4px"}),
                        ]),
                    ], style={"display":"flex","alignItems":"center"}),
                ], md=4),
                dbc.Col([
                    html.Div([
                        html.Span("🔑 ADMIN", style={"color":"#ffcc00","fontWeight":"bold","fontSize":"12px","letterSpacing":"2px"}),
                        html.Span("  ·  ", style={"color":"#333"}),
                        html.Span(now, style={"color":"#444","fontSize":"10px"}),
                    ], style={"textAlign":"center"}),
                ], md=4),
                dbc.Col([
                    html.Div([
                        html.Span("● LIVE", style={"color":"#44ff88","fontWeight":"bold","fontSize":"10px","marginRight":"12px"}),
                        dbc.Button("📊 Audit Log", id="admin-audit-btn", color="outline-info",
                                   size="sm", style={"fontSize":"11px","marginRight":"8px"}),
                        dbc.Button("← Back to App", href="/", color="outline-secondary",
                                   size="sm", external_link=True,
                                   style={"fontSize":"11px","marginRight":"8px"}),
                        dbc.Button("➕ Add User", id="admin-add-user-btn", color="success",
                                   size="sm", style={"fontSize":"11px"}),
                    ], style={"display":"flex","alignItems":"center","justifyContent":"flex-end"}),
                ], md=4),
            ], align="center"),
        ], style={"backgroundColor":"#060606","borderBottom":"2px solid #ff2222",
                  "padding":"14px 24px"}),

        # ── BODY ───────────────────────────────────────────────────────────────
        html.Div([

            # LEFT PANEL: User List
            html.Div([
                html.Div("USERS", style={"color":"#444","fontSize":"9px","letterSpacing":"3px",
                                          "padding":"12px 14px 6px 14px"}),
                html.Div(id="admin-user-list",
                         children=[_user_row(u, d, first_user) for u,d in users.items()]),

                html.Hr(style={"borderColor":"#1a1a1a","margin":"8px 14px"}),

                # Add user form (collapsed by default)
                dbc.Collapse([
                    html.Div([
                        html.Div("ADD NEW USER", style={"color":"#44ff88","fontSize":"9px",
                                                         "letterSpacing":"3px","marginBottom":"10px"}),
                        dbc.Input(id="admin-new-username",  placeholder="username",
                                  style={"backgroundColor":"#111","color":"#fff","border":"1px solid #222",
                                         "fontSize":"11px","marginBottom":"6px"}),
                        dbc.Input(id="admin-new-displayname", placeholder="Display Name",
                                  style={"backgroundColor":"#111","color":"#fff","border":"1px solid #222",
                                         "fontSize":"11px","marginBottom":"6px"}),
                        dbc.Input(id="admin-new-password", placeholder="Password", type="password",
                                  style={"backgroundColor":"#111","color":"#fff","border":"1px solid #222",
                                         "fontSize":"11px","marginBottom":"6px"}),
                        dcc.Dropdown(id="admin-new-role",
                                     options=[{"label":"👑 Admin",  "value":"admin"},
                                              {"label":"🔍 Analyst","value":"analyst"},
                                              {"label":"👁️ Viewer", "value":"viewer"},
                                              {"label":"📋 Manager","value":"manager"}],
                                     value="viewer", clearable=False,
                                     style={"backgroundColor":"#111","color":"#ccc",
                                            "border":"1px solid #222","fontSize":"11px",
                                            "marginBottom":"8px"}),
                        dbc.Button("Create User", id="admin-create-user-btn", color="success",
                                   size="sm", className="w-100"),
                        html.Div(id="admin-create-status",
                                 style={"color":"#44ff88","fontSize":"10px","marginTop":"6px"}),
                    ], style={"padding":"10px 14px"}),
                ], id="admin-add-user-collapse", is_open=False),

            ], style={"width":"240px","minWidth":"240px","backgroundColor":"#080808",
                      "borderRight":"1px solid #141414","display":"flex","flexDirection":"column",
                      "overflowY":"auto"}),

            # CENTRE PANEL: Permission Matrix
            html.Div([
                # Selected user header
                html.Div(id="admin-user-header",
                         style={"backgroundColor":"#0a0a0a","borderBottom":"1px solid #1a1a1a",
                                "padding":"14px 20px"}),

                # Tab groups permission matrix
                html.Div([
                    html.Div(id="admin-permission-matrix",
                             style={"padding":"16px"}),

                    html.Div([
                        dbc.Button("💾 Save Permissions", id="admin-save-btn",
                                   color="success", className="fw-bold",
                                   style={"fontSize":"14px","padding":"10px 24px",
                                          "letterSpacing":"1px","marginRight":"12px"}),
                        dbc.Button("🗑️ Delete User", id="admin-delete-btn",
                                   color="danger", outline=True,
                                   style={"fontSize":"12px","padding":"10px 20px"}),
                        html.Span(id="admin-save-status",
                                  style={"marginLeft":"16px","fontSize":"11px","color":"#44ff88"}),
                    ], style={"padding":"16px","borderTop":"1px solid #1a1a1a",
                              "backgroundColor":"#0a0a0a"}),
                ], style={"overflowY":"auto","flex":"1"}),

            ], style={"flex":"1","display":"flex","flexDirection":"column","overflow":"hidden"}),

            # RIGHT PANEL: Role Info + Summary
            html.Div([
                html.Div("ROLE REFERENCE", style={"color":"#444","fontSize":"9px",
                                                   "letterSpacing":"3px","padding":"12px 14px 8px"}),
                _role_info_card("👑 Admin",   "admin",   "All tabs. Full system control.", "#ff4444"),
                _role_info_card("📋 Manager", "manager", "All tabs except Admin settings.", "#ff8800"),
                _role_info_card("🔍 Analyst", "analyst", "Recon, Attack, Defence tabs.", "#00aaff"),
                _role_info_card("👁️ Viewer",  "viewer",  "Read-only. Home + System only.", "#888"),

                html.Hr(style={"borderColor":"#1a1a1a","margin":"8px 14px"}),

                html.Div("SYSTEM STATS", style={"color":"#444","fontSize":"9px",
                                                  "letterSpacing":"3px","padding":"8px 14px 6px"}),
                html.Div([
                    html.Div(f"{len(users)} Users", style={"color":"#fff","fontWeight":"bold","fontSize":"11px"}),
                    html.Div(f"{len(all_tabs)} Tabs available", style={"color":"#555","fontSize":"10px"}),
                    html.Div(f"Last updated: {now}", style={"color":"#333","fontSize":"9px","marginTop":"4px"}),
                ], style={"padding":"4px 14px 14px"}),
            ], style={"width":"200px","minWidth":"200px","backgroundColor":"#080808",
                      "borderLeft":"1px solid #141414","overflowY":"auto"}),

        ], style={"display":"flex","flex":"1","overflow":"hidden",
                  "minHeight":"calc(100vh - 55px)"}),

    ], style={"display":"flex","flexDirection":"column","minHeight":"100vh",
              "backgroundColor":"#050505","fontFamily":"'Inter',sans-serif"})


# ─── Callback: Audit log modal open/close ────────────────────────────────────
@callback(
    Output("admin-audit-modal",    "is_open"),
    Output("admin-audit-log-body", "children"),
    Input("admin-audit-btn",   "n_clicks"),
    Input("admin-audit-close", "n_clicks"),
    State("admin-audit-modal", "is_open"),
    prevent_initial_call=True,
)
def toggle_audit_modal(open_n, close_n, is_open):
    if ctx.triggered_id == "admin-audit-close":
        return False, no_update

    # Fetch rows from Postgres
    try:
        from cyber_range.services.pg_engine import get_recent_audit
        rows = get_recent_audit(limit=150)
    except Exception as e:
        rows = []

    if not rows:
        body = html.Div([
            html.Div("⚠️  No audit records found.",
                     style={"color":"#888","padding":"20px","textAlign":"center"}),
            html.Div("PostgreSQL may not be configured yet, or no actions have been "
                     "recorded. Run the setup script to initialise the database.",
                     style={"color":"#555","fontSize":"12px","textAlign":"center","padding":"0 40px"}),
        ])
        return True, body

    SEV_COLOR = {"login":"#44ff88","logout":"#888","exploit_run":"#ff4444",
                 "run_scan":"#ffc107","delete":"#ff6b35"}

    header = html.Div([
        html.Span("Timestamp",  style={"flex":"2","color":"#555","fontSize":"10px"}),
        html.Span("User",       style={"flex":"1","color":"#555","fontSize":"10px"}),
        html.Span("Action",     style={"flex":"1","color":"#555","fontSize":"10px"}),
        html.Span("Module",     style={"flex":"1","color":"#555","fontSize":"10px"}),
        html.Span("Target",     style={"flex":"2","color":"#555","fontSize":"10px"}),
        html.Span("Result",     style={"width":"60px","color":"#555","fontSize":"10px"}),
    ], style={"display":"flex","padding":"8px 16px","borderBottom":"1px solid #1a1a1a",
              "backgroundColor":"#0a0a0a","position":"sticky","top":"0","zIndex":"10"})

    trows = []
    for r in rows:
        ts     = str(r.get("ts",""))[:19]
        user   = r.get("username","?")
        action = r.get("action","?")
        module = r.get("module") or "—"
        target = r.get("target") or "—"
        ok     = r.get("success", True)
        trows.append(html.Div([
            html.Span(ts,     style={"flex":"2","color":"#777","fontSize":"11px","fontFamily":"monospace"}),
            html.Span(user,   style={"flex":"1","color":"#aaa","fontSize":"11px"}),
            html.Span(action, style={"flex":"1","color":SEV_COLOR.get(action,"#ffd740"),"fontSize":"11px","fontWeight":"600"}),
            html.Span(module, style={"flex":"1","color":"#888","fontSize":"11px"}),
            html.Span(str(target)[:40], style={"flex":"2","color":"#aaa","fontSize":"11px","fontFamily":"monospace"}),
            dbc.Badge("✓" if ok else "✗",
                      color="success" if ok else "danger",
                      style={"width":"40px","textAlign":"center","fontSize":"10px"}),
        ], style={"display":"flex","padding":"7px 16px","borderBottom":"1px solid #0f0f0f",
                  "backgroundColor":"#0d0d0d" if len(trows)%2==0 else "#0a0a0a",
                  "alignItems":"center"}))

    body = html.Div([header] + trows)
    return True, body


def _role_info_card(label, role, desc, color):
    return html.Div([
        html.Div([
            html.Span(label, style={"color":color,"fontWeight":"bold","fontSize":"10px"}),
        ]),
        html.Div(desc, style={"color":"#555","fontSize":"9px","marginTop":"2px"}),
    ], style={"padding":"8px 14px","borderLeft":f"2px solid {color}44",
              "marginLeft":"14px","marginBottom":"6px"})


# ─── Callback: Select user from list ─────────────────────────────────────────
@callback(
    Output("admin-selected-user",     "data"),
    Input({"type":"admin-user-row","index":__import__("dash").ALL}, "n_clicks"),
    State({"type":"admin-user-row","index":__import__("dash").ALL}, "id"),
    prevent_initial_call=True,
)
def select_user(n_clicks_list, id_list):
    triggered = ctx.triggered_id
    if triggered and isinstance(triggered, dict):
        return triggered["index"]
    return no_update


# ─── Callback: Render user header + permission matrix ──────────────────────────
@callback(
    Output("admin-user-header",      "children"),
    Output("admin-permission-matrix","children"),
    Output("admin-user-list",        "children"),
    Input("admin-selected-user",     "data"),
    Input("admin-perms-store",       "data"),
    prevent_initial_call=False,
)
def render_user_panel(selected, stored_data):
    data   = stored_data or _load()
    users  = data.get("users", {})
    all_tabs = data.get("all_tabs", [])

    # User list (re-rendered to show selection)
    user_list = [_user_row(u, d, selected) for u, d in users.items()]

    if not selected or selected not in users:
        header = html.Div("← Select a user from the list",
                          style={"color":"#444","fontSize":"13px"})
        matrix = html.Div()
        return header, matrix, user_list

    udata   = users[selected]
    role    = udata.get("role","viewer")
    display = udata.get("display_name", selected)
    utabs   = udata.get("tabs",[])
    has_all = "all" in utabs

    # Header
    header = dbc.Row([
        dbc.Col([
            html.Div([
                html.Span(display, style={"color":"#fff","fontWeight":"bold","fontSize":"16px",
                                           "marginRight":"10px"}),
                _role_badge(role),
            ]),
            html.Div(f"@{selected}", style={"color":"#555","fontSize":"10px","marginTop":"2px"}),
        ], md=6),
        dbc.Col([
            dbc.Switch(id="admin-grant-all-switch",
                       label="Grant ALL tabs (admin override)",
                       value=has_all,
                       style={"color":"#888","fontSize":"11px"}),
        ], md=4),
        dbc.Col([
            dbc.Select(id="admin-role-select",
                       options=[{"label":"👑 Admin",  "value":"admin"},
                                {"label":"📋 Manager","value":"manager"},
                                {"label":"🔍 Analyst","value":"analyst"},
                                {"label":"👁️ Viewer", "value":"viewer"}],
                       value=role,
                       style={"backgroundColor":"#111","color":"#ccc","border":"1px solid #222",
                              "fontSize":"11px"}),
        ], md=2),
    ], align="center")

    # Permission matrix — grouped by category
    groups = {}
    for t in all_tabs:
        g = t.get("group","Other")
        groups.setdefault(g, []).append(t)

    matrix_rows = []
    for group, tabs in groups.items():
        # Group header
        matrix_rows.append(
            html.Div(group.upper(),
                     style={"color":"#333","fontSize":"9px","letterSpacing":"3px",
                            "padding":"12px 0 6px 0","borderBottom":"1px solid #111",
                            "marginBottom":"8px"})
        )
        # Tab toggle cards
        tab_cards = []
        for t in tabs:
            tid    = t["id"]
            tlab   = t["label"]
            is_on  = has_all or (tid in utabs)
            card   = html.Div([
                html.Div([
                    dbc.Switch(
                        id={"type":"admin-tab-switch","index":tid},
                        label="",
                        value=is_on,
                        style={"marginBottom":"0"},
                    ),
                ], style={"marginRight":"8px"}),
                html.Div([
                    html.Div(tlab, style={"color":"#fff" if is_on else "#555",
                                          "fontSize":"11px","fontWeight":"bold" if is_on else "normal"}),
                    html.Div(tid, style={"color":"#333","fontSize":"9px"}),
                ]),
            ], style={"display":"flex","alignItems":"center",
                      "padding":"8px 12px","backgroundColor":"#0d1a0d" if is_on else "#0d0d0d",
                      "border":f"1px solid {'#1a3a1a' if is_on else '#141414'}",
                      "borderRadius":"4px","marginBottom":"6px","cursor":"pointer"})
            tab_cards.append(tab_card_col := dbc.Col(card, md=4, className="mb-1"))
        matrix_rows.append(dbc.Row(tab_cards, className="g-2 mb-2"))

    return header, html.Div(matrix_rows), user_list


# ─── Callback: Save permissions ───────────────────────────────────────────────
@callback(
    Output("admin-save-status",  "children"),
    Output("admin-perms-store",  "data"),
    Input("admin-save-btn",      "n_clicks"),
    State("admin-selected-user", "data"),
    State("admin-perms-store",   "data"),
    State({"type":"admin-tab-switch","index":__import__("dash").ALL}, "value"),
    State({"type":"admin-tab-switch","index":__import__("dash").ALL}, "id"),
    State("admin-grant-all-switch","value"),
    State("admin-role-select",   "value"),
    prevent_initial_call=True,
)
def save_permissions(_, selected, stored_data, switch_vals, switch_ids, grant_all, new_role):
    if not selected:
        return "⚠️ No user selected", no_update

    data = stored_data or _load()
    if selected not in data["users"]:
        return "⚠️ User not found", no_update

    if grant_all:
        allowed = ["all"]
    else:
        allowed = [s["index"] for s, v in zip(switch_ids, switch_vals) if v]

    data["users"][selected]["tabs"] = allowed
    if new_role:
        data["users"][selected]["role"] = new_role

    _save(data)
    ts = time.strftime("%H:%M:%S")
    return f"✅ Saved at {ts}", data


# ─── Callback: Add user toggle ────────────────────────────────────────────────
@callback(
    Output("admin-add-user-collapse","is_open"),
    Input("admin-add-user-btn",      "n_clicks"),
    State("admin-add-user-collapse","is_open"),
    prevent_initial_call=True,
)
def toggle_add_user(_, is_open):
    return not is_open


# ─── Callback: Create user ────────────────────────────────────────────────────
@callback(
    Output("admin-create-status","children"),
    Output("admin-perms-store",  "data", allow_duplicate=True),
    Input("admin-create-user-btn","n_clicks"),
    State("admin-new-username",   "value"),
    State("admin-new-displayname","value"),
    State("admin-new-password",   "value"),
    State("admin-new-role",       "value"),
    State("admin-perms-store",    "data"),
    prevent_initial_call=True,
)
def create_user(_, username, display, password, role, stored_data):
    if not username or not username.strip():
        return "⚠️ Username required", no_update
    data = stored_data or _load()
    uname = username.strip().lower()
    if uname in data["users"]:
        return f"⚠️ User '{uname}' already exists", no_update
    data["users"][uname] = {
        "password":    password or "changeme",
        "role":        role or "viewer",
        "tabs":        ["system"],
        "display_name": display or uname,
    }
    _save(data)
    return f"✅ User '{uname}' created", data


# ─── Callback: Delete user ────────────────────────────────────────────────────
@callback(
    Output("admin-save-status",  "children", allow_duplicate=True),
    Output("admin-perms-store",  "data",     allow_duplicate=True),
    Output("admin-selected-user","data",     allow_duplicate=True),
    Input("admin-delete-btn",    "n_clicks"),
    State("admin-selected-user", "data"),
    State("admin-perms-store",   "data"),
    prevent_initial_call=True,
)
def delete_user(_, selected, stored_data):
    if not selected:
        return "⚠️ No user selected", no_update, no_update
    if selected == "admin":
        return "⚠️ Cannot delete admin user", no_update, no_update
    data = stored_data or _load()
    data["users"].pop(selected, None)
    _save(data)
    next_user = next(iter(data["users"]), None)
    return f"🗑️ Deleted '{selected}'", data, next_user
