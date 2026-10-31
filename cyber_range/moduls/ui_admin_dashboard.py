"""
Admin Dashboard
===============
Premium dark-themed admin panel with:
- Left sidebar navigation (collapsible sections)
- Live KPI stats cards from Neo4j
- Analytics charts (severity trends, host exposure, source breakdown)
- Recent activity feed (latest CVEs, system alerts, session log)
- Search bar, notification bell, profile menu in top nav
"""

import sys
sys.path.insert(0, "/home/kali/.local/lib/python3.13/site-packages")

import os, time, platform
from dash import html, dcc, callback, Input, Output, State, no_update
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

# ─── Neo4j helper ──────────────────────────────────────────────────────────────
def _neo(cypher, params=None):
    try:
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","Adomaa12@"))
        with drv.session() as s:
            rows = s.run(cypher, params or {}).data()
        drv.close()
        return rows
    except Exception:
        return []

# ─── Data loaders ──────────────────────────────────────────────────────────────
def _load_kpis():
    rows = _neo("""
        MATCH (f:Finding) WHERE f.cve IS NOT NULL
        WITH f, toFloat(coalesce(toString(f.cvss),'0')) AS score
        RETURN count(f)                                        AS total,
               count(CASE WHEN score>=9  THEN 1 END)          AS critical,
               count(CASE WHEN score>=7 AND score<9 THEN 1 END) AS high,
               count(CASE WHEN f.exploitable=true THEN 1 END) AS exploitable,
               count(DISTINCT f.host)                         AS hosts,
               round(avg(score)*10)/10                        AS avg_cvss,
               count(DISTINCT f.source)                       AS sources
    """)
    return rows[0] if rows else {}

def _load_recent(limit=12):
    return _neo("""
        MATCH (f:Finding) WHERE f.cve IS NOT NULL
        WITH f, toFloat(coalesce(toString(f.cvss),'0')) AS score
        RETURN f.cve AS cve, toString(score) AS cvss,
               coalesce(f.host,'?') AS host,
               coalesce(f.source,'unknown') AS source,
               f.exploitable AS exp
        ORDER BY score DESC LIMIT $limit
    """, {"limit": limit})

def _load_severity_counts():
    return _neo("""
        MATCH (f:Finding) WHERE f.cve IS NOT NULL
        WITH toFloat(coalesce(toString(f.cvss),'0')) AS score
        RETURN
          count(CASE WHEN score>=9            THEN 1 END) AS Critical,
          count(CASE WHEN score>=7 AND score<9 THEN 1 END) AS High,
          count(CASE WHEN score>=4 AND score<7 THEN 1 END) AS Medium,
          count(CASE WHEN score>=1 AND score<4 THEN 1 END) AS Low,
          count(CASE WHEN score=0             THEN 1 END) AS Info
    """)

def _load_top_hosts():
    return _neo("""
        MATCH (f:Finding) WHERE f.host IS NOT NULL AND f.cve IS NOT NULL
        WITH f.host AS host, count(f) AS n,
             max(toFloat(coalesce(toString(f.cvss),'0'))) AS max_cvss
        RETURN host, n, round(max_cvss*10)/10 AS max_cvss
        ORDER BY n DESC LIMIT 8
    """)

def _load_sources():
    return _neo("""
        MATCH (f:Finding) WHERE f.source IS NOT NULL
        RETURN f.source AS name, count(f) AS n
        ORDER BY n DESC LIMIT 6
    """)

# ─── Figures ───────────────────────────────────────────────────────────────────
DARK = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")

def _fig_severity_bar(sev):
    if not sev: sev = [{}]
    s = sev[0]
    cats   = ["Critical","High","Medium","Low","Info"]
    vals   = [s.get(c,0) for c in cats]
    colors = ["#ff2222","#ff8800","#ffcc00","#44aaff","#888"]
    fig = go.Figure(go.Bar(x=cats, y=vals, marker_color=colors,
                           text=vals, textposition="outside", textfont=dict(color="#aaa",size=11)))
    fig.update_layout(**DARK, xaxis=dict(color="#555",gridcolor="#1a1a1a"),
                      yaxis=dict(color="#555",gridcolor="#1a1a1a"),
                      height=220, margin=dict(t=5,b=10,l=10,r=10), showlegend=False)
    return fig

def _fig_host_horizontal(hosts):
    if not hosts:
        return go.Figure().update_layout(**DARK, height=220)
    hs   = [h["host"][:20] for h in hosts]
    ns   = [h["n"] for h in hosts]
    cvss = [h["max_cvss"] for h in hosts]
    cols = ["#ff2222" if c>=9 else "#ff8800" if c>=7 else "#ffcc00" for c in cvss]
    fig  = go.Figure(go.Bar(y=hs, x=ns, orientation="h",
                            marker_color=cols,
                            text=ns, textposition="outside", textfont=dict(color="#aaa",size=9)))
    fig.update_layout(**DARK, xaxis=dict(color="#444",gridcolor="#1a1a1a"),
                      yaxis=dict(color="#bbb",gridcolor="rgba(0,0,0,0)"),
                      height=260, margin=dict(t=5,b=5,l=10,r=40), showlegend=False)
    return fig

def _fig_source_pie(sources):
    if not sources:
        return go.Figure().update_layout(**DARK, height=220)
    names  = [s["name"] or "?" for s in sources]
    counts = [s["n"] for s in sources]
    colors = ["#ff4444","#ff8800","#ffcc00","#44aaff","#bf79ff","#44ff88"]
    fig = go.Figure(go.Pie(
        labels=names, values=counts, hole=0.5,
        marker=dict(colors=colors, line=dict(color="#050505",width=2)),
        textinfo="percent+label", textfont=dict(size=10,color="#fff"),
    ))
    fig.update_layout(**DARK, showlegend=False, height=220,
                      margin=dict(t=10,b=10,l=10,r=10))
    return fig

def _fig_cvss_donut(kpis):
    t = int(kpis.get("total",1)) or 1
    c = int(kpis.get("critical",0))
    h = int(kpis.get("high",0))
    m = int(kpis.get("total",0)) - c - h - int(kpis.get("exploitable",0))
    avg = kpis.get("avg_cvss",0)
    fig = go.Figure(go.Pie(
        labels=["Critical","High","Other","Exploitable"],
        values=[c, h, max(0,m), int(kpis.get("exploitable",0))],
        hole=0.65, marker=dict(colors=["#ff2222","#ff8800","#333","#ff5500"],
                               line=dict(color="#050505",width=2)),
        textinfo="none",
    ))
    fig.add_annotation(text=f"CVSS<br><b>{avg}</b>",
                       font=dict(size=14,color="#fff"), showarrow=False, x=0.5, y=0.5)
    fig.update_layout(**DARK, showlegend=False, height=180,
                      margin=dict(t=5,b=5,l=5,r=5))
    return fig

# ─── UI helpers ────────────────────────────────────────────────────────────────
def _kpi_card(icon, title, value, color, sub=""):
    return dbc.Col(html.Div([
        html.Div([
            html.Div(icon, style={"fontSize":"22px","marginBottom":"2px"}),
            html.Div(f"{value:,}" if isinstance(value,int) else str(value),
                     style={"color":color,"fontSize":"28px","fontWeight":"900","lineHeight":"1.1"}),
            html.Div(title, style={"color":"#888","fontSize":"10px","letterSpacing":"1px","textTransform":"uppercase"}),
            html.Div(sub, style={"color":"#555","fontSize":"9px","marginTop":"2px"}) if sub else html.Div(),
        ], style={"padding":"14px 16px"}),
    ], style={"backgroundColor":"#0d0d0d","border":f"1px solid {color}33",
              "borderTop":f"3px solid {color}","borderRadius":"6px",
              "height":"100%"}))

def _sidebar_item(icon, label, sub_id, color="#888"):
    return html.Div([
        html.Span(icon, style={"marginRight":"10px","fontSize":"14px"}),
        html.Span(label, style={"fontSize":"13px"}),
    ], id=f"admin-nav-{sub_id}",
       style={"padding":"10px 20px","color":color,"cursor":"pointer",
              "borderLeft":"3px solid transparent",
              "transition":"all 0.2s",
              "display":"flex","alignItems":"center"},
       className="admin-nav-item")

def _section_card(title, body, border="#333", icon=""):
    return dbc.Card([
        dbc.CardHeader(
            f"{icon} {title}",
            style={"backgroundColor":"#0a0a0a","color":"#ccc",
                   "fontWeight":"bold","fontSize":"11px","letterSpacing":"2px",
                   "borderBottom":f"1px solid {border}","padding":"10px 14px"}),
        dbc.CardBody(body, style={"backgroundColor":"#080808","padding":"12px"}),
    ], style={"border":f"1px solid {border}22","backgroundColor":"#080808",
              "borderRadius":"6px","marginBottom":"16px"})

# ─── Main Layout ───────────────────────────────────────────────────────────────
def generate_admin_dashboard_layout():
    kpis    = _load_kpis()
    recent  = _load_recent(12)
    sev     = _load_severity_counts()
    hosts   = _load_top_hosts()
    sources = _load_sources()
    now     = time.strftime("%Y-%m-%d %H:%M:%S")
    node    = platform.node()

    total    = int(kpis.get("total",0))
    critical = int(kpis.get("critical",0))
    exp_n    = int(kpis.get("exploitable",0))
    h_count  = int(kpis.get("hosts",0))
    avg_cvss = kpis.get("avg_cvss",0)
    src_n    = int(kpis.get("sources",0))

    # Recent activity rows
    activity_rows = []
    for i, r in enumerate(recent):
        cvss_f = float(r["cvss"])
        sev_c  = "#ff2222" if cvss_f>=9 else "#ff8800" if cvss_f>=7 else "#ffcc00"
        sev_l  = "CRIT" if cvss_f>=9 else "HIGH" if cvss_f>=7 else "MED"
        exp_ic = html.Span("⚡LIVE",style={"color":"#ff4444","fontSize":"9px","fontWeight":"bold"}) if r.get("exp") else html.Span("○",style={"color":"#333"})
        activity_rows.append(html.Tr([
            html.Td(html.Span(sev_l,style={"color":sev_c,"fontWeight":"bold","fontSize":"10px"}),
                    style={"padding":"5px 10px","whiteSpace":"nowrap"}),
            html.Td(html.Span(r["cve"],style={"color":"#ffcc00","fontWeight":"bold","fontSize":"11px"}),
                    style={"padding":"5px 10px"}),
            html.Td(r["cvss"],style={"color":sev_c,"textAlign":"center","fontWeight":"bold","fontSize":"11px","padding":"5px 8px"}),
            html.Td(r["host"],style={"color":"#aaa","fontSize":"10px","padding":"5px 8px"}),
            html.Td(r["source"],style={"color":"#555","fontSize":"10px","padding":"5px 8px"}),
            html.Td(exp_ic,style={"textAlign":"center","padding":"5px 8px"}),
        ], style={"backgroundColor":"#0d0d0d" if i%2 else "#111",
                  "borderBottom":"1px solid #1a1a1a"}))

    # Sidebar
    sidebar = html.Div([
        # Branding
        html.Div([
            html.Span("🛡️",style={"fontSize":"22px","marginRight":"6px"}),
            html.Div([
                html.Div("VULN INTEL",style={"color":"#fff","fontWeight":"900","fontSize":"13px","letterSpacing":"2px"}),
                html.Div("ADMIN PORTAL",style={"color":"#555","fontSize":"9px","letterSpacing":"3px"}),
            ]),
        ], style={"display":"flex","alignItems":"center","padding":"18px 20px",
                  "borderBottom":"1px solid #1a1a1a","marginBottom":"8px"}),

        html.Div("MAIN MENU", style={"color":"#333","fontSize":"9px","letterSpacing":"3px",
                                      "padding":"6px 20px 4px 20px"}),
        _sidebar_item("📊","Dashboard",        "dash",   "#ffcc00"),
        _sidebar_item("🖥️","Host Inventory",   "hosts",  "#ccc"),
        _sidebar_item("🔍","CVE Intelligence", "cve",    "#ccc"),
        _sidebar_item("📡","Data Sources",     "src",    "#ccc"),
        _sidebar_item("🚨","Security Alerts",  "alerts", "#ccc"),

        html.Div("ANALYSIS", style={"color":"#333","fontSize":"9px","letterSpacing":"3px",
                                     "padding":"14px 20px 4px 20px"}),
        _sidebar_item("📈","Analytics",         "analytics","#ccc"),
        _sidebar_item("🗺️","Attack Surface",   "surface",  "#ccc"),
        _sidebar_item("🧬","Risk Matrix",       "risk",     "#ccc"),

        html.Div("SYSTEM", style={"color":"#333","fontSize":"9px","letterSpacing":"3px",
                                   "padding":"14px 20px 4px 20px"}),
        _sidebar_item("📋","Audit Logs",   "logs",     "#ccc"),
        _sidebar_item("⚙️","Settings",    "settings", "#ccc"),
        _sidebar_item("🔌","API Status",  "api",      "#ccc"),

        # System health at bottom
        html.Div([
            html.Hr(style={"borderColor":"#1a1a1a","margin":"12px 0"}),
            html.Div([
                html.Span("●",style={"color":"#44ff88","marginRight":"6px","fontSize":"10px"}),
                html.Span("Neo4j Connected",style={"color":"#666","fontSize":"10px"}),
            ], style={"padding":"4px 20px"}),
            html.Div([
                html.Span("●",style={"color":"#44ff88","marginRight":"6px","fontSize":"10px"}),
                html.Span("App Running",style={"color":"#666","fontSize":"10px"}),
            ], style={"padding":"4px 20px"}),
            html.Div(node, style={"color":"#333","fontSize":"9px","padding":"2px 20px 10px 20px"}),
        ]),
    ], style={"width":"210px","minWidth":"210px","backgroundColor":"#080808",
              "borderRight":"1px solid #141414","height":"100%","overflowY":"auto",
              "display":"flex","flexDirection":"column"})

    # Top nav bar
    topnav = html.Div([
        dbc.Row([
            dbc.Col([
                dbc.InputGroup([
                    dbc.InputGroupText("🔍",
                        style={"backgroundColor":"#111","border":"1px solid #222","color":"#888"}),
                    dbc.Input(placeholder="Search CVEs, hosts, sources…",
                              id="admin-search-input",
                              style={"backgroundColor":"#111","border":"1px solid #222",
                                     "color":"#fff","fontSize":"12px"}),
                ], size="sm"),
            ], md=5),
            dbc.Col([
                html.Div([
                    # Notification bell
                    html.Span([
                        "🔔",
                        dbc.Badge(str(critical), color="danger",
                                  style={"fontSize":"9px","position":"relative","top":"-8px","left":"-4px"})
                        if critical else html.Span(),
                    ], style={"cursor":"pointer","marginRight":"16px","fontSize":"18px","opacity":"0.8"}),

                    # Status dot
                    html.Span([
                        html.Span("●",style={"color":"#44ff88","fontSize":"10px","marginRight":"4px"}),
                        html.Span("LIVE",style={"color":"#44ff88","fontWeight":"bold",
                                                "fontSize":"10px","letterSpacing":"2px"}),
                    ], style={"marginRight":"16px"}),

                    # Admin profile
                    dbc.DropdownMenu([
                        dbc.DropdownMenuItem("👤 Profile",  header=False),
                        dbc.DropdownMenuItem("⚙️ Settings", header=False),
                        dbc.DropdownMenuItem(divider=True),
                        dbc.DropdownMenuItem("🔓 Logout",   id="admin-logout-btn", href="/"),
                    ], label="🔐 Admin", color="dark", size="sm", align_end=True,
                       toggle_style={"backgroundColor":"#111","border":"1px solid #222",
                                     "color":"#ccc","fontSize":"12px"}),
                ], style={"display":"flex","alignItems":"center","justifyContent":"flex-end"}),
            ], md=7),
        ], align="center"),
    ], style={"backgroundColor":"#060606","borderBottom":"1px solid #141414",
              "padding":"10px 20px"})

    # Refresh interval
    refresh = dcc.Interval(id="admin-refresh-interval", interval=60_000, n_intervals=0)

    # Main content
    content = html.Div([

        # Page title bar
        html.Div([
            html.Div([
                html.H5("📊 Dashboard Overview",
                         style={"color":"#fff","margin":"0","fontSize":"15px","fontWeight":"bold"}),
                html.Small(f"Last updated: {now}  ·  {total:,} findings tracked",
                           style={"color":"#555","fontSize":"10px"}),
            ]),
            dbc.Button("🔄 Refresh", id="admin-refresh-btn", color="outline-secondary",
                       size="sm", style={"fontSize":"11px"}),
        ], style={"display":"flex","justifyContent":"space-between","alignItems":"center",
                  "marginBottom":"18px"}),

        # ── KPI Cards ─────────────────────────────────────────────────────────
        dbc.Row([
            _kpi_card("🔍","Total Findings",  total,    "#ff6666"),
            _kpi_card("💀","Critical CVEs",   critical, "#ff2222","CVSS ≥ 9"),
            _kpi_card("🎯","Exploitable",     exp_n,    "#ff4444","Active risk"),
            _kpi_card("🖥️","Hosts at Risk",  h_count,  "#00aaff","Unique hosts"),
            _kpi_card("📊","Average CVSS",    avg_cvss, "#ffcc00",f"{src_n} sources"),
        ], className="mb-4 g-2"),

        # ── Charts Row 1 ──────────────────────────────────────────────────────
        dbc.Row([
            dbc.Col(
                _section_card("SEVERITY DISTRIBUTION",
                    dcc.Graph(id="admin-sev-bar",figure=_fig_severity_bar(sev),
                              config={"displayModeBar":False}),
                    border="#ff4444", icon="🔥"),
            md=5),
            dbc.Col(
                _section_card("RISK OVERVIEW",
                    dcc.Graph(id="admin-risk-donut",figure=_fig_cvss_donut(kpis),
                              config={"displayModeBar":False}),
                    border="#ffcc00", icon="⚡"),
            md=3),
            dbc.Col(
                _section_card("DATA SOURCES",
                    dcc.Graph(id="admin-source-pie",figure=_fig_source_pie(sources),
                              config={"displayModeBar":False}),
                    border="#00aaff", icon="📡"),
            md=4),
        ], className="mb-2"),

        # ── Charts Row 2: Host Exposure ────────────────────────────────────
        _section_card("MOST EXPOSED HOSTS — LIVE RANKING",
            dcc.Graph(id="admin-host-bar",figure=_fig_host_horizontal(hosts),
                      config={"displayModeBar":False}),
            border="#00aaff", icon="🖥️"),

        # ── Recent Activity ───────────────────────────────────────────────
        _section_card("RECENT SECURITY ACTIVITY — LIVE FROM NEO4J",
            html.Div([
                html.Table([
                    html.Thead(html.Tr([
                        html.Th(h, style={"color":"#444","fontSize":"9px",
                                          "padding":"5px 10px","fontWeight":"normal",
                                          "textTransform":"uppercase","letterSpacing":"1px"})
                        for h in ["SEV","CVE","CVSS","HOST","SOURCE","STATUS"]
                    ], style={"borderBottom":"1px solid #1a1a1a"})),
                    html.Tbody(activity_rows),
                ], style={"width":"100%","borderCollapse":"collapse"}),
            ], style={"overflowX":"auto"}),
            border="#1a3a1a", icon="🚨"),

        # ── System & DB info ─────────────────────────────────────────────
        dbc.Row([
            dbc.Col(
                _section_card("DATABASE STATUS",
                    html.Div([
                        _stat_row("Neo4j",       "Connected",         "#44ff88"),
                        _stat_row("Total Nodes", f"{total:,}",        "#ffcc00"),
                        _stat_row("Bolt URI",    "bolt://localhost:7687","#888"),
                        _stat_row("Sources",     str(src_n),          "#00aaff"),
                    ]),
                    border="#44ff88", icon="🗄️"),
            md=4),
            dbc.Col(
                _section_card("SYSTEM HEALTH",
                    html.Div([
                        _stat_row("Hostname",    node,          "#aaa"),
                        _stat_row("Platform",    platform.system(),"#aaa"),
                        _stat_row("App Port",    "8050",        "#44ff88"),
                        _stat_row("Uptime",      "Running",     "#44ff88"),
                    ]),
                    border="#00aaff", icon="💻"),
            md=4),
            dbc.Col(
                _section_card("QUICK ACTIONS",
                    html.Div([
                        dbc.Button("🔁 Refresh All Data",  color="outline-warning",   className="w-100 mb-2 fw-bold",size="sm",id="admin-qa-refresh"),
                        dbc.Button("📋 Export CSV",        color="outline-info",       className="w-100 mb-2",size="sm",id="admin-qa-csv"),
                        dbc.Button("🚨 Alert Patching Team",color="outline-danger",    className="w-100 mb-2",size="sm",id="admin-qa-alert"),
                        dbc.Button("📊 Run New Scan",      color="outline-success",   className="w-100",size="sm",id="admin-qa-scan"),
                    ]),
                    border="#888", icon="⚡"),
            md=4),
        ]),

    ], style={"flex":"1","overflowY":"auto","padding":"20px 24px",
              "backgroundColor":"#050505"})

    # Full layout: topnav + (sidebar | content) flex row
    return html.Div([
        refresh,
        dcc.Store(id="admin-section-store", data="dash"),

        # Topnav
        topnav,

        # Body
        html.Div([
            sidebar,
            content,
        ], style={"display":"flex","flex":"1","overflow":"hidden",
                  "minHeight":"calc(100vh - 50px)"}),

    ], style={"display":"flex","flexDirection":"column",
              "backgroundColor":"#050505","minHeight":"100vh"})


def _stat_row(label, value, col="#ccc"):
    return html.Div([
        html.Span(label+":", style={"color":"#444","fontSize":"11px","marginRight":"8px","minWidth":"90px","display":"inline-block"}),
        html.Span(value,     style={"color":col,"fontSize":"11px","fontWeight":"bold"}),
    ], style={"marginBottom":"6px"})


# ─── CSS for sidebar hover ─────────────────────────────────────────────────────
ADMIN_CSS = """
.admin-nav-item:hover {
    color: #fff !important;
    background: rgba(255,255,255,0.04) !important;
    border-left: 3px solid #ffcc00 !important;
}
.admin-nav-item:first-child {
    border-left: 3px solid #ffcc00 !important;
    color: #ffcc00 !important;
    background: rgba(255,204,0,0.06) !important;
}
"""


# ─── Callbacks ─────────────────────────────────────────────────────────────────
@callback(
    Output("admin-sev-bar",    "figure"),
    Output("admin-risk-donut", "figure"),
    Output("admin-source-pie", "figure"),
    Output("admin-host-bar",   "figure"),
    Input("admin-refresh-btn",      "n_clicks"),
    Input("admin-refresh-interval", "n_intervals"),
    Input("admin-qa-refresh",       "n_clicks"),
    prevent_initial_call=True,
)
def refresh_admin_charts(*_):
    kpis    = _load_kpis()
    sev     = _load_severity_counts()
    hosts   = _load_top_hosts()
    sources = _load_sources()
    return (_fig_severity_bar(sev), _fig_cvss_donut(kpis),
            _fig_source_pie(sources), _fig_host_horizontal(hosts))
