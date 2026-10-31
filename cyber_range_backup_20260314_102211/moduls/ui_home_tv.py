import cyber_range.moduls.ui_anchor_avatar as ui_anchor_avatar
"""
CyberTV Home Station — Fixed Version
=====================================
Layout is data-only at generation time.
AI anchor summaries are loaded via callback after the page renders.
"""

import sys
sys.path.insert(0, "/home/kali/.local/lib/python3.13/site-packages")

import os, time
from dash import html, dcc, callback, Input, Output, State, no_update
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

# ─── Neo4j helper ──────────────────────────────────────────────────────────────
def _neo(cypher, params=None):
    try:
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","Adomaa12@"))
        with drv.session() as s:
            result = s.run(cypher, params or {}).data()
        drv.close()
        return result
    except Exception:
        return []

def _fetch_broadcast_data():
    stats_rows = _neo("""
        MATCH (f:Finding) WHERE f.cve IS NOT NULL
        WITH f, toFloat(coalesce(toString(f.cvss),'0')) AS score
        RETURN count(f) AS total,
               count(CASE WHEN score>=9  THEN 1 END) AS critical,
               count(CASE WHEN score>=7 AND score<9 THEN 1 END) AS high,
               count(CASE WHEN score>=4 AND score<7 THEN 1 END) AS medium,
               count(CASE WHEN f.exploitable=true THEN 1 END) AS exploitable,
               round(avg(score)*10)/10 AS avg_cvss
    """)
    top_cves = _neo("""
        MATCH (f:Finding) WHERE f.cve IS NOT NULL
        WITH f, toFloat(coalesce(toString(f.cvss),'0')) AS score
        RETURN f.cve AS cve, toString(score) AS cvss,
               coalesce(f.host,'?') AS host,
               coalesce(f.source,'?') AS source,
               f.exploitable AS exp
        ORDER BY score DESC LIMIT 8
    """)
    hosts = _neo("""
        MATCH (f:Finding) WHERE f.host IS NOT NULL AND f.cve IS NOT NULL
        WITH f.host AS host, count(f) AS n,
             max(toFloat(coalesce(toString(f.cvss),'0'))) AS max_cvss
        RETURN host, n, round(max_cvss*10)/10 AS max_cvss
        ORDER BY max_cvss DESC LIMIT 6
    """)
    sources = _neo("""
        MATCH (f:Finding) WHERE f.source IS NOT NULL
        RETURN f.source AS src, count(f) AS n ORDER BY n DESC LIMIT 5
    """)
    return stats_rows[0] if stats_rows else {}, top_cves, hosts, sources

# ─── Figures ───────────────────────────────────────────────────────────────────
def _severity_donut(stats):
    total    = stats.get("total",1) or 1
    critical = stats.get("critical",0)
    high     = stats.get("high",0)
    medium   = stats.get("medium",0)
    other    = max(0, total - critical - high - medium)
    avg      = stats.get("avg_cvss","?")
    fig = go.Figure(go.Pie(
        labels=["Critical","High","Medium","Other"],
        values=[critical, high, medium, other], hole=0.6,
        marker=dict(colors=["#ff2222","#ff8800","#ffcc00","#333"],
                    line=dict(color="#050505",width=2)),
        textinfo="percent+label", textfont=dict(size=10,color="#fff"),
    ))
    fig.add_annotation(text=f"AVG<br><b>{avg}</b>",
                       font=dict(size=13,color="#fff"),showarrow=False,x=0.5,y=0.5)
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                      showlegend=False,height=260,margin=dict(t=5,b=5,l=5,r=5))
    return fig

def _host_bar(hosts):
    if not hosts:
        return go.Figure().update_layout(paper_bgcolor="rgba(0,0,0,0)",height=260)
    hs   = [h["host"][:20] for h in hosts]
    ns   = [h["n"] for h in hosts]
    cvss = [h["max_cvss"] for h in hosts]
    cols = ["#ff2222" if c>=9 else "#ff8800" if c>=7 else "#ffcc00" for c in cvss]
    fig  = go.Figure(go.Bar(y=hs,x=ns,orientation="h",
                             marker=dict(color=cols),
                             text=[f"CVSS {c}" for c in cvss],
                             textposition="outside",textfont=dict(size=9,color="#aaa")))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                      xaxis=dict(color="#444",gridcolor="#1a1a1a"),
                      yaxis=dict(color="#aaa",gridcolor="rgba(0,0,0,0)"),
                      height=260,margin=dict(t=5,b=5,l=5,r=60),showlegend=False)
    return fig

def _threat_gauge(avg_cvss):
    avg = float(avg_cvss) if avg_cvss else 0
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=avg,
        number=dict(font=dict(color="#fff",size=34)),
        gauge=dict(
            axis=dict(range=[0,10],tickfont=dict(color="#555",size=8)),
            bar=dict(color="#ff4444" if avg>=9 else "#ff8800" if avg>=7 else "#ffcc00"),
            bgcolor="#111",borderwidth=1,bordercolor="#222",
            steps=[dict(range=[0,4],color="#0a1a0a"),
                   dict(range=[4,7],color="#1a1a00"),
                   dict(range=[7,9],color="#1a0800"),
                   dict(range=[9,10],color="#1a0000")],
        ),
        title=dict(text="Overall Risk",font=dict(color="#888",size=11)),
    ))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",height=220,
                      margin=dict(t=40,b=5,l=20,r=20))
    return fig

def _source_radar(sources):
    if not sources:
        return go.Figure().update_layout(paper_bgcolor="rgba(0,0,0,0)",height=220)
    names  = [str(s.get("src") or "?") for s in sources]
    counts = [s.get("n",0) for s in sources]
    mx     = max(counts) if counts else 1
    norm   = [round(c/mx*10,1) for c in counts]
    # close the polygon
    names_c  = names  + [names[0]]
    norm_c   = norm   + [norm[0]]
    fig = go.Figure(go.Scatterpolar(
        r=norm_c, theta=names_c, fill="toself",
        line=dict(color="#00aaff",width=2),
        fillcolor="rgba(0,170,255,0.15)",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        polar=dict(bgcolor="rgba(0,0,0,0)",
                   radialaxis=dict(visible=True,range=[0,10],color="#333",
                                   gridcolor="#1a1a1a",tickfont=dict(size=7,color="#555")),
                   angularaxis=dict(color="#888",gridcolor="#1a1a1a",
                                    tickfont=dict(size=10,color="#ccc"))),
        height=230,margin=dict(t=10,b=10,l=30,r=30),showlegend=False,
    )
    return fig

# ─── Landscape metric bar ──────────────────────────────────────────────────────
def _landscape_row(label, your_val, baseline, color):
    delta     = round(your_val - baseline, 2)
    delta_col = "#ff4444" if delta > 0 else "#44ff88"
    delta_txt = f"+{delta}" if delta > 0 else str(delta)
    bar_yours = min(100, int(your_val / 10 * 100))
    bar_base  = min(100, int(baseline  / 10 * 100))
    return html.Div([
        html.Div([
            html.Span(label,       style={"color":"#aaa","fontSize":"11px"}),
            html.Span(f" {your_val}",style={"color":color,"fontWeight":"bold","fontSize":"13px","marginLeft":"8px"}),
            html.Span(f"  {delta_txt} vs baseline",style={"color":delta_col,"fontSize":"10px","marginLeft":"8px"}),
        ], style={"marginBottom":"3px"}),
        html.Div([
            html.Div(style={"height":"5px","width":f"{bar_base}%","backgroundColor":"#333",
                            "position":"absolute","borderRadius":"3px"}),
            html.Div(style={"height":"5px","width":f"{bar_yours}%","backgroundColor":color,
                            "position":"absolute","borderRadius":"3px","opacity":"0.9"}),
        ], style={"position":"relative","height":"5px","backgroundColor":"#111",
                  "borderRadius":"3px","marginBottom":"12px"}),
    ])

# ─── Main layout (data-only, AI deferred to callback) ──────────────────────────
def generate_home_tv_layout():
    try:
        stats, top_cves, hosts, sources = _fetch_broadcast_data()
    except Exception as e:
        return html.Div(f"⚠️ Data fetch error: {e}", style={"color":"#ff4444","padding":"20px"})

    now      = time.strftime("%A %d %B %Y · %H:%M:%S")
    total    = int(stats.get("total",0))
    critical = int(stats.get("critical",0))
    high     = int(stats.get("high",0))
    exp_n    = int(stats.get("exploitable",0))
    avg_cvss = float(stats.get("avg_cvss",0) or 0)

    # KPI card helper
    def kpi(icon, label, value, color):
        return dbc.Col(dbc.Card([dbc.CardBody([
            html.Div(icon,  style={"fontSize":"20px","lineHeight":"1"}),
            html.Div(f"{value:,}" if isinstance(value,int) else f"{value}",
                     style={"color":color,"fontSize":"28px","fontWeight":"bold","lineHeight":"1.1"}),
            html.Small(label, style={"color":"#666","fontSize":"10px","letterSpacing":"1px"}),
        ], style={"textAlign":"center","padding":"10px 6px"})],
            style={"border":f"1px solid {color}44","borderTop":f"3px solid {color}",
                   "backgroundColor":"#080808"}))

    # Ticker content
    ticker_parts = []
    for r in top_cves:
        col = "#ff2222" if float(r["cvss"])>=9 else "#ff8800" if float(r["cvss"])>=7 else "#ffcc00"
        ticker_parts.append(
            html.Span(f"  🔴 {r['cve']}  CVSS {r['cvss']}  ·  HOST: {r['host']}  ◆ ",
                      style={"color":col,"fontWeight":"bold","fontSize":"12px"}))

    # Headlines table rows
    tbl_rows = []
    for i, r in enumerate(top_cves):
        cvss_f  = float(r["cvss"])
        sc      = "#ff2222" if cvss_f>=9 else "#ff8800" if cvss_f>=7 else "#ffcc00"
        sl      = "CRITICAL" if cvss_f>=9 else "HIGH" if cvss_f>=7 else "MEDIUM"
        tbl_rows.append(html.Tr([
            html.Td(sl,         style={"color":sc,"fontWeight":"bold","fontSize":"11px","padding":"6px 10px","whiteSpace":"nowrap"}),
            html.Td(html.B(r["cve"], style={"color":"#ffcc00","fontSize":"12px"}), style={"padding":"6px 10px"}),
            html.Td(r["cvss"],  style={"color":sc,"textAlign":"center","fontWeight":"bold","padding":"6px 10px"}),
            html.Td(r["host"],  style={"color":"#aaa","fontSize":"11px","padding":"6px 10px"}),
            html.Td(r["source"],style={"color":"#555","fontSize":"10px","padding":"6px 10px"}),
            html.Td("🔴" if r.get("exp") else "⚪", style={"textAlign":"center","padding":"6px 10px"}),
        ], style={"backgroundColor":"#0d0d0d" if i%2 else "#111","borderBottom":"1px solid #1a1a1a"}))

    # Landscape verdict
    if avg_cvss >= 9:
        verdict_txt = "🔴 CRITICAL: Significantly above industry average. Immediate action required."
        verdict_col = "#ff4444"
    elif avg_cvss >= 7:
        verdict_txt = "🟠 ELEVATED: Above industry baseline. Prioritise patching now."
        verdict_col = "#ff8800"
    else:
        verdict_txt = "🟢 BASELINE: Risk comparable to industry average. Maintain vigilance."
        verdict_col = "#44ff88"

    return html.Div([
        dcc.Interval(id="tv-refresh-interval", interval=300_000, n_intervals=0),
        dcc.Store(id="tv-data-store", data={"total":total,"critical":critical,
                                             "high":high,"exp":exp_n,"avg_cvss":avg_cvss,
                                             "top3":[r["cve"] for r in top_cves[:3]],
                                             "hosts":[r["host"] for r in top_cves[:3]]}),

        # ── HEADER ────────────────────────────────────────────────────────────
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Span("🛡️ CYBER", style={"color":"#ff2222","fontWeight":"900","fontSize":"30px","letterSpacing":"3px"}),
                    html.Span("INTEL",     style={"color":"#fff",   "fontWeight":"900","fontSize":"30px","letterSpacing":"3px"}),
                    html.Span(" TV",       style={"color":"#ffcc00","fontWeight":"900","fontSize":"30px","letterSpacing":"3px"}),
                    html.Div("LIVE THREAT INTELLIGENCE BROADCAST",
                             style={"color":"#555","fontSize":"10px","letterSpacing":"4px","marginTop":"2px"}),
                ], md=5),
                dbc.Col([
                    html.Div([
                        html.Span("● LIVE", className="tv-live",
                                  style={"color":"#ff2222","fontWeight":"bold","fontSize":"12px","marginRight":"10px"}),
                        html.Span(now, style={"color":"#666","fontSize":"11px"}),
                    ]),
                    html.Div([
                        dbc.Badge(f"🔴 {critical:,} CRITICAL", style={"backgroundColor":"#ff2222","color":"#fff","fontSize":"10px","marginRight":"5px","padding":"3px 8px"}),
                        dbc.Badge(f"🟠 {high:,} HIGH",         style={"backgroundColor":"#ff8800","color":"#000","fontSize":"10px","marginRight":"5px","padding":"3px 8px"}),
                        dbc.Badge(f"⚡ {exp_n:,} EXPLOITABLE", style={"backgroundColor":"#1a0000","color":"#ff8888","border":"1px solid #ff4444","fontSize":"10px","padding":"3px 8px"}),
                    ], className="mt-2"),
                ], md=5),
                dbc.Col([
                    dbc.Button("🔄 Refresh Broadcast", id="tv-refresh-btn", color="warning",
                               outline=True, size="sm", className="w-100 fw-bold"),
                ], md=2, className="d-flex align-items-center"),
            ], align="center"),
        ], style={"backgroundColor":"#080808","padding":"18px 28px","borderBottom":"2px solid #ff2222"}),

        # ── TICKER ────────────────────────────────────────────────────────────
        html.Div([
            html.Span("⚡ BREAKING",
                      style={"backgroundColor":"#ff2222","color":"#fff","fontWeight":"bold",
                             "padding":"3px 10px","marginRight":"8px","fontSize":"11px","whiteSpace":"nowrap"}),
            html.Div(
                # Double the items to make it loop smoothly
                html.Div(ticker_parts + ticker_parts,
                         style={"display":"inline-flex","animation":"ticker 50s linear infinite",
                                "whiteSpace":"nowrap","willChange":"transform"}),
                style={"overflow":"hidden","flex":"1"}),
        ], style={"display":"flex","alignItems":"center","overflow":"hidden",
                  "backgroundColor":"#0a0000","borderBottom":"1px solid #330000",
                  "padding":"5px 0","height":"30px"}),

        # ── CONTENT ───────────────────────────────────────────────────────────
        html.Div([

            # KPI Row
            dbc.Row([
                kpi("🔍","TOTAL FINDINGS", total,    "#ff6666"),
                kpi("💀","CRITICAL CVEs",  critical, "#ff2222"),
                kpi("⚠️","HIGH SEVERITY",  high,     "#ff8800"),
                kpi("🎯","EXPLOITABLE",    exp_n,    "#ff4444"),
                kpi("📊","AVG CVSS",       avg_cvss, "#ffcc00"),
                kpi("🖥️","HOSTS AT RISK",  len(hosts),"#00aaff"),
            ], className="mb-4 g-2"),

            # Headlines + Donut
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("🚨 BREAKING — TOP CVE HEADLINES (LIVE NEO4J)",
                                       style={"backgroundColor":"#0a0000","color":"#ff4444",
                                              "fontWeight":"bold","fontSize":"11px","letterSpacing":"2px"}),
                        dbc.CardBody(html.Table([
                            html.Thead(html.Tr([
                                html.Th(h, style={"color":"#444","fontSize":"9px","padding":"5px 10px"})
                                for h in ["SEV","CVE ID","CVSS","HOST","SOURCE","STATUS"]
                            ], style={"borderBottom":"1px solid #1a1a1a"})),
                            html.Tbody(tbl_rows),
                        ], style={"width":"100%","borderCollapse":"collapse"}), style={"padding":"0"}),
                    ], style={"border":"1px solid #330000","backgroundColor":"#050505"}),
                ], md=8),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("🍩 SEVERITY MIX",
                                       style={"backgroundColor":"#0a0000","color":"#ff8888",
                                              "fontWeight":"bold","fontSize":"11px","letterSpacing":"2px"}),
                        dbc.CardBody(dcc.Graph(id="tv-donut",figure=_severity_donut(stats),
                                               config={"displayModeBar":False}),
                                     style={"padding":"4px"}),
                    ], style={"border":"1px solid #330000","backgroundColor":"#050505"}),
                ], md=4),
            ], className="mb-4"),

            # Gauge + Host Bar + Source Radar
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("⚡ RISK LEVEL",
                                       style={"backgroundColor":"#0a0500","color":"#ff8800",
                                              "fontWeight":"bold","fontSize":"11px","letterSpacing":"2px"}),
                        dbc.CardBody(dcc.Graph(id="tv-gauge",figure=_threat_gauge(avg_cvss),
                                               config={"displayModeBar":False}),
                                     style={"padding":"4px"}),
                    ], style={"border":"1px solid #ff880033","backgroundColor":"#050505"}),
                ], md=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("🖥️ MOST EXPOSED HOSTS",
                                       style={"backgroundColor":"#00001a","color":"#00aaff",
                                              "fontWeight":"bold","fontSize":"11px","letterSpacing":"2px"}),
                        dbc.CardBody(dcc.Graph(id="tv-host-bar",figure=_host_bar(hosts),
                                               config={"displayModeBar":False}),
                                     style={"padding":"4px"}),
                    ], style={"border":"1px solid #00aaff33","backgroundColor":"#050505"}),
                ], md=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("📡 DATA SOURCES",
                                       style={"backgroundColor":"#001a1a","color":"#00ffcc",
                                              "fontWeight":"bold","fontSize":"11px","letterSpacing":"2px"}),
                        dbc.CardBody(dcc.Graph(id="tv-source-radar",figure=_source_radar(sources),
                                               config={"displayModeBar":False}),
                                     style={"padding":"4px"}),
                    ], style={"border":"1px solid #00ffcc33","backgroundColor":"#050505"}),
                ], md=4),
            ], className="mb-4"),

            # Threat landscape
            dbc.Card([
                dbc.CardHeader("🌐 YOUR ENVIRONMENT vs INDUSTRY BASELINE (NVD 2024)",
                               style={"backgroundColor":"#000a00","color":"#44ff88",
                                      "fontWeight":"bold","fontSize":"11px","letterSpacing":"2px"}),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            _landscape_row("Avg CVSS",      avg_cvss,                             6.5, "#ffcc00"),
                            _landscape_row("% Critical",    round(critical/total*100,1) if total else 0, 15.0,"#ff4444"),
                            _landscape_row("% Exploitable", round(exp_n/total*100,1) if total else 0,    25.0,"#ff8800"),
                        ], md=7),
                        dbc.Col([
                            dbc.Alert(verdict_txt,
                                      style={"backgroundColor":"#0a0a0a","border":f"1px solid {verdict_col}",
                                             "color":verdict_col,"fontWeight":"bold","fontSize":"12px"},
                                      color="dark"),
                            html.Small("Baseline: Avg CVSS 6.5 · 15% Critical · 25% exploitable (NVD 2024 annual stats)",
                                       style={"color":"#444","fontSize":"10px"}),
                        ], md=5),
                    ]),
                ]),
            ], style={"border":"1px solid #1a3a1a","backgroundColor":"#050505","marginBottom":"20px"}),

            # AI News Anchors (loaded by callback)
            html.Div([
                html.Div("🎙️ AI NEWS ANCHORS — ON-AIR ANALYSIS",
                         style={"color":"#ffcc00","fontWeight":"bold","fontSize":"12px",
                                "letterSpacing":"3px","marginBottom":"12px",
                                "borderLeft":"4px solid #ffcc00","paddingLeft":"10px"}),
                dbc.Row([
                    dbc.Col(dbc.Card([
                        dbc.CardHeader([
                            html.Span("🎙️ ANCHOR 1 · Local AI",
                                      style={"color":"#ffaa00","fontWeight":"bold","fontSize":"11px","letterSpacing":"1px"}),
                        ], style={"backgroundColor":"#0a0700","borderBottom":"2px solid #ffaa00"}),
                        dbc.CardBody(dcc.Loading(
                            html.Pre(id="tv-anchor-local",
                                     children="🔄 Loading broadcast...",
                                     style={"fontSize":"11px","color":"#ffaa00","whiteSpace":"pre-wrap",
                                            "lineHeight":"1.6","margin":"0","minHeight":"120px",
                                            "fontFamily":"Georgia,serif"}),
                            color="#ffaa00"),
                            style={"backgroundColor":"#050505"}),
                    ], style={"border":"1px solid #ffaa0033","height":"100%"}), md=4),

                    dbc.Col(dbc.Card([
                        dbc.CardHeader([
                            html.Span("🎙️ ANCHOR 2 · ChatGPT",
                                      style={"color":"#00aaff","fontWeight":"bold","fontSize":"11px","letterSpacing":"1px"}),
                        ], style={"backgroundColor":"#000a1a","borderBottom":"2px solid #00aaff"}),
                        dbc.CardBody(dcc.Loading(
                            html.Pre(id="tv-anchor-gpt",
                                     children="🔄 Loading broadcast...",
                                     style={"fontSize":"11px","color":"#00aaff","whiteSpace":"pre-wrap",
                                            "lineHeight":"1.6","margin":"0","minHeight":"120px",
                                            "fontFamily":"Georgia,serif"}),
                            color="#00aaff"),
                            style={"backgroundColor":"#050505"}),
                    ], style={"border":"1px solid #00aaff33","height":"100%"}), md=4),

                    dbc.Col(dbc.Card([
                        dbc.CardHeader([
                            html.Span("🎙️ ANCHOR 3 · Claude",
                                      style={"color":"#bf79ff","fontWeight":"bold","fontSize":"11px","letterSpacing":"1px"}),
                        ], style={"backgroundColor":"#0a0015","borderBottom":"2px solid #bf79ff"}),
                        dbc.CardBody(dcc.Loading(
                            html.Pre(id="tv-anchor-claude",
                                     children="🔄 Loading broadcast...",
                                     style={"fontSize":"11px","color":"#bf79ff","whiteSpace":"pre-wrap",
                                            "lineHeight":"1.6","margin":"0","minHeight":"120px",
                                            "fontFamily":"Georgia,serif"}),
                            color="#bf79ff"),
                            style={"backgroundColor":"#050505"}),
                    ], style={"border":"1px solid #bf79ff33","height":"100%"}), md=4),
                ], className="g-3"),

                dbc.Row([
                    dbc.Col(dbc.Button("🎙️ Load AI Anchor Broadcasts",
                                       id="tv-anchor-btn", color="success",
                                       className="fw-bold w-100 mt-3",
                                       style={"fontSize":"14px","padding":"12px","letterSpacing":"1px"}),
                            md=6),
                    dbc.Col(html.Small("AI anchors analyse your live Neo4j data and broadcast a news summary. "
                                       "Calls ChatGPT + Claude — click when ready.",
                                       style={"color":"#555","fontSize":"11px","display":"block","marginTop":"20px"}),
                            md=6),
                ]),
            ], className="mb-4"),

            # AI News Anchor section
        ui_anchor_avatar.generate_anchor_section(),

        html.Small(f"📡 {total:,} findings · {len(hosts)} assets · {now}",
                       style={"color":"#222","fontSize":"10px","display":"block","textAlign":"right"}),
        ], style={"padding":"22px"}),

    ], style={"backgroundColor":"#050505","minHeight":"100vh"})


# ─── Callbacks ─────────────────────────────────────────────────────────────────

@callback(
    Output("tv-anchor-local",  "children"),
    Output("tv-anchor-gpt",    "children"),
    Output("tv-anchor-claude", "children"),
    Input("tv-anchor-btn",     "n_clicks"),
    Input("tv-refresh-btn",    "n_clicks"),
    State("tv-data-store",     "data"),
    prevent_initial_call=True,
)
def load_anchors(_, __, data):
    if not data:
        return "No data available.", "No data available.", "No data available."

    total    = data.get("total",0)
    critical = data.get("critical",0)
    avg_cvss = data.get("avg_cvss",0)
    exp_n    = data.get("exp",0)
    top3     = ", ".join(data.get("top3",[])[:3]) or "N/A"
    host_str = ", ".join(data.get("hosts",[])[:3]) or "unknown"

    prompt = (
        f"You are a cybersecurity TV news anchor. Deliver a 5-sentence live news broadcast "
        f"in a professional, dramatic news anchor style. Cite specific data.\n\n"
        f"🔴 LIVE INTEL:\n"
        f"• {total:,} vulnerabilities in the network\n"
        f"• {critical:,} rated CRITICAL (CVSS≥9)\n"
        f"• {exp_n:,} actively exploitable\n"
        f"• Average CVSS: {avg_cvss}\n"
        f"• Top CVEs: {top3}\n"
        f"• Hosts at risk: {host_str}\n"
    )

    # Local AI
    try:
        from llm_engine import call_llm
        local_out = call_llm(prompt)
    except Exception as e:
        local_out = (f"📡 LIVE REPORT — {total:,} vulnerabilities detected across the network. "
                     f"{critical:,} are rated CRITICAL with an average CVSS of {avg_cvss}. "
                     f"{exp_n:,} vulnerabilities are actively exploitable. "
                     f"Top affected CVEs include: {top3}. Hosts under siege: {host_str}.")

    # ChatGPT
    try:
        from openai import OpenAI as _OAI
        rsp = _OAI(api_key=os.environ.get("OPENAI_API_KEY","")).chat.completions.create(
            model="gpt-4o-mini", max_tokens=250,
            messages=[{"role":"system","content":"You are a dramatic cybersecurity TV news anchor. Be concise."},
                      {"role":"user","content":prompt}])
        gpt_out = rsp.choices[0].message.content
    except Exception as e:
        gpt_out = f"⚠️ ChatGPT unavailable: {e}"

    # Claude
    try:
        import anthropic as _ant
        ac = _ant.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY",""))
        msg = None
        for m in ["claude-sonnet-4-6","claude-sonnet-4-5-20250929","claude-haiku-4-5-20251001"]:
            try:
                msg = ac.messages.create(model=m, max_tokens=250,
                    system="You are a dramatic cybersecurity TV news anchor. Be concise.",
                    messages=[{"role":"user","content":prompt}])
                break
            except Exception: continue
        claude_out = msg.content[0].text if msg else "⚠️ No Claude model available."
    except Exception as e:
        claude_out = f"⚠️ Claude unavailable: {e}"

    return local_out, gpt_out, claude_out
