"""
Executive Dashboard — Platform Home Screen
==========================================
CISO-level KPI overview: aggregate risk score, finding counts by severity,
module activity, 30-day trend chart, recent findings table, MTTD/MTTR.
Auto-refreshes every 60 seconds via dcc.Interval.
"""
import plotly.graph_objects as go
import plotly.express as px
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc

from cyber_range.services import findings_service as fs

# ── NOTE: demo seed disabled — only real scanner findings shown ────────
# To re-seed manually: python3 -c "from cyber_range.services import findings_service as fs; fs.seed_demo_data()"


# ── Neo4j host enrichment (one batch query, all storage patterns) ──────
_HOST_CYPHER = """
    // ─────────────────────────────────────────────────────────────────────
    // Path 1: Asset (nmap) → Service → Finding
    //   nmap ingestion stores hosts as :Asset {host: "192.168.x.x"}
    MATCH (a:Asset)-[:RUNS_SERVICE]->(srv:Service)-[:HAS_FINDING]->(f:Finding)
    WHERE coalesce(a.host, '') <> ''
    WITH coalesce(f.name, f.alertRef, toString(f.pluginid), '') AS fname,
         a.host AS hip
    WHERE fname <> ''
    RETURN fname, hip

    UNION

    // Path 2: Asset → Service → Vulnerability
    MATCH (a:Asset)-[:RUNS_SERVICE]->(srv:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    WHERE coalesce(a.host, '') <> ''
    WITH coalesce(v.name, v.id, v.cve, '') AS fname,
         a.host AS hip
    WHERE fname <> ''
    RETURN fname, hip

    UNION

    // Path 3: Host (ZAP / manual) → Service → Finding
    MATCH (h:Host)-[:RUNS_SERVICE]->(srv:Service)-[:HAS_FINDING]->(f:Finding)
    WHERE coalesce(h.ip, h.host, '') <> ''
    WITH coalesce(f.name, f.alertRef, toString(f.pluginid), '') AS fname,
         coalesce(h.ip, h.host) AS hip
    WHERE fname <> ''
    RETURN fname, hip

    UNION

    // Path 4: bare Finding with host property (AegisProbe / ZAP direct)
    MATCH (f:Finding)
    WHERE coalesce(f.host, '') <> ''
    WITH coalesce(f.name, f.alertRef, '') AS fname, f.host AS hip
    WHERE fname <> '' AND hip <> ''
    RETURN fname, hip

    UNION

    // Path 5: Service with host or ip property (fallback for scan engines)
    MATCH (srv:Service)-[:HAS_FINDING]->(f:Finding)
    WHERE coalesce(srv.host, srv.ip, '') <> ''
    WITH coalesce(f.name, f.alertRef, toString(f.pluginid), '') AS fname,
         coalesce(srv.host, srv.ip) AS hip
    WHERE fname <> '' AND hip <> ''
    RETURN fname, hip
"""

def _neo4j_host_map() -> dict:
    """
    Returns a dict keyed by finding name (lower-cased) → sorted list of
    unique host IPs sourced from Neo4j across all storage patterns.
    """
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as s:
            rows = s.run(_HOST_CYPHER).data()
        driver.close()

        result: dict = {}
        for r in rows:
            key = (r.get("fname") or "").lower().strip()
            hip = (r.get("hip") or "").strip()
            if key and hip:
                result.setdefault(key, set()).add(hip)
        return {k: sorted(v) for k, v in result.items()}
    except Exception as ex:
        print(f"[exec-dash Neo4j host-map] {ex}")
        return {}


# ── Source label → human module name ──────────────────────────────────
_SOURCE_MODULE = {
    "nmap":        "Nmap",
    "zap":         "ZAP",
    "burp":        "Burp Suite",
    "nuclei":      "Nuclei",
    "openvas":     "OpenVAS",
    "bloodhound":  "BloodHound",
    "aegis":       "AegisProbe",
    "aegisprobe":  "AegisProbe",
    "nvd":         "NVD",
    "cwe":         "ZAP",         # ZAP CWE refs
}

# ZAP riskcode → severity label
_ZAP_SEV = {"3": "High", "2": "Medium", "1": "Low", "0": "Information"}
# nmap CVSS thresholds
def _cvss_sev(cvss):
    try:
        c = float(cvss)
        if c >= 9.0: return "Critical"
        if c >= 7.0: return "High"
        if c >= 4.0: return "Medium"
        if c > 0:    return "Low"
    except Exception:
        pass
    return "Medium"


def _neo4j_scanner_findings(limit: int = 50) -> list[dict]:
    """
    Pull the most recent scanner findings from Neo4j across ALL sources
    (nmap, ZAP, Nuclei, Burp, OpenVAS, BloodHound …).
    Returns a list of dicts shaped like SQLite findings so they can be
    merged directly into the Recent Findings table.
    """
    _SCANNER_CYPHER = f"""
        // ── All Finding nodes with their host and source ──────────────
        MATCH (f:Finding)
        OPTIONAL MATCH (a:Asset)-[:RUNS_SERVICE|EXPOSES*1..2]->(srv:Service)-[:HAS_FINDING]->(f)
        OPTIONAL MATCH (h:Host)-[:RUNS_SERVICE*1..2]->(srv2:Service)-[:HAS_FINDING]->(f)
        OPTIONAL MATCH (f)-[:INSTANCE_OF]->(v:Vulnerability)
        WITH
            coalesce(f.name, f.alertRef, v.name, f.cve, toString(f.pluginid), 'Unknown Finding') AS title,
            coalesce(f.source, srv.source, a.source, h.source, v.source, 'unknown')             AS source,
            coalesce(f.host, a.host, h.ip, h.host, srv.host, srv2.host, '')                      AS host,
            coalesce(f.cvss, v.cvss)                                                              AS cvss,
            coalesce(f.riskcode, f.severity)                                                      AS riskcode,
            v.name                                                                                 AS vuln_name,
            f.description                                                                          AS description,
            f.cve                                                                                  AS cve
        WHERE title <> 'Unknown Finding'
        RETURN title, source, host, cvss, riskcode, cve, description
        LIMIT {limit}
    """
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as s:
            rows = s.run(_SCANNER_CYPHER).data()
        driver.close()

        results = []
        for r in rows:
            src    = (r.get("source") or "unknown").lower().strip()
            module = _SOURCE_MODULE.get(src, src.title())
            # Determine severity
            riskcode = str(r.get("riskcode") or "")
            cvss_raw = r.get("cvss")
            if riskcode in _ZAP_SEV:
                sev = _ZAP_SEV[riskcode]
            elif cvss_raw is not None:
                sev = _cvss_sev(cvss_raw)
            else:
                sev = "Medium"

            results.append({
                "module":     module,
                "title":      (r.get("title") or "").strip(),
                "severity":   sev,
                "host":       (r.get("host") or "").strip(),
                "status":     "Open",
                "mitre_id":   r.get("cve") or "",
                "created_at": "",
                "_neo4j":     True,       # flag so we can badge it
            })
        return results
    except Exception as ex:
        print(f"[exec-dash scanner-findings] {ex}")
        return []


# ── Design tokens ─────────────────────────────────────────────────────
_DARK       = "#0d1117"
_CARD_BG    = "#161b27"
_CARD_BDR   = "#252d42"
_GOLD       = "#ffd700"
_GLOW_GOLD  = "0 0 12px #ffd70055"

SEV_COLORS = {
    "Critical": "#ff4444",
    "High":     "#ff8c00",
    "Medium":   "#00bcd4",
    "Low":      "#4caf50",
}

# Card: glassmorphic dark panel with subtle inner glow
_CARD_STYLE = {
    "background":    "linear-gradient(145deg, #1c2232 0%, #161b27 100%)",
    "border":        f"1px solid {_CARD_BDR}",
    "borderRadius":  "14px",
    "padding":       "18px",
    "marginBottom":  "14px",
    "boxShadow":     "0 4px 24px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04)",
}




# ── KPI Card: animated glow border with gradient number ────────────────
def _kpi_card(label, value, color, icon, sub=None):
    sub_el = html.Div(sub, style={"fontSize":"10px","color":"#555","marginTop":"2px"}) if sub else html.Span()
    glow = f"0 0 0 1px {color}33, 0 0 20px {color}22"
    return html.Div([
        html.Div(icon, style={"fontSize":"22px","marginBottom":"5px","lineHeight":"1"}),
        html.Div(str(value),
                 style={"fontSize":"38px","fontWeight":"800","color":color,
                        "letterSpacing":"-1px","lineHeight":"1","fontFamily":"monospace"}),
        html.Div(label, style={"fontSize":"11px","color":"#888","marginTop":"5px",
                               "letterSpacing":"1px","textTransform":"uppercase"}),
        sub_el,
    ], className="exec-kpi-card", style={
        "background":    f"linear-gradient(145deg, #1c2232 0%, #161b27 100%)",
        "border":        f"1px solid {color}44",
        "borderTop":     f"3px solid {color}",
        "borderRadius":  "12px",
        "padding":       "14px 10px",
        "textAlign":     "center",
        "boxShadow":     glow,
        "cursor":        "default",
        "height":        "100%",
        "transition":    "transform 0.25s ease",
    })



# ── Risk gauge ────────────────────────────────────────────────────────
def _build_gauge(score: int) -> go.Figure:
    color = ("#ff4444" if score >= 70 else
             "#ff8c00" if score >= 40 else
             "#ffd700" if score >= 20 else "#4caf50")
    label = ("CRITICAL" if score >= 70 else "ELEVATED" if score >= 40
             else "MODERATE" if score >= 20 else "HEALTHY")
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        delta={"reference": 50, "font": {"size": 12, "color": "#666"}},
        title={"text": f"Platform Risk Score<br><span style='font-size:11px;color:{color}'>{label}</span>",
               "font": {"color": "#aaa", "size": 13}},
        number={"font": {"color": color, "size": 44}, "suffix": ""},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#333",
                     "tickfont": {"color": "#444", "size": 9}},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "#0d1117",
            "borderwidth": 0,
            "steps": [
                {"range": [0,  20],  "color": "#0d2010"},
                {"range": [20, 40],  "color": "#1a2010"},
                {"range": [40, 70],  "color": "#1e1208"},
                {"range": [70, 100], "color": "#200808"},
            ],
            "threshold": {"line": {"color": color, "width": 4},
                         "thickness": 0.85, "value": score},
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=16, r=16, t=54, b=4), height=210,
        font={"color": "#ccc"},
    )
    return fig



# ── Trend chart ───────────────────────────────────────────────────────
def _build_trend(trend_data: list[dict]) -> go.Figure:
    if not trend_data:
        # Empty placeholder
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor=_DARK, plot_bgcolor=_DARK,
            title={"text": "No trend data yet — save some findings!", "font": {"color": "#555"}},
            margin=dict(l=20, r=20, t=40, b=20), height=220,
            xaxis={"color": "#555"}, yaxis={"color": "#555"},
        )
        return fig

    days   = [r["day"]      for r in trend_data]
    crits  = [r["critical"] for r in trend_data]
    highs  = [r["high"]     for r in trend_data]
    meds   = [r["medium"]   for r in trend_data]
    lows   = [r["low"]      for r in trend_data]

    fig = go.Figure()
    for label, values, color, fill_clr in [
        ("Critical", crits, "#ff4444", "rgba(255,68,68,0.10)"),
        ("High",     highs, "#ff8c00", "rgba(255,140,0,0.08)"),
        ("Medium",   meds,  "#00bcd4", "rgba(0,188,212,0.08)"),
        ("Low",      lows,  "#4caf50", "rgba(76,175,80,0.08)"),
    ]:
        fig.add_trace(go.Scatter(
            x=days, y=values, name=label,
            line=dict(color=color, width=2.5, shape="spline"),
            fill="tozeroy", fillcolor=fill_clr,
            mode="lines",
        ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,17,24,0.8)",
        title={"text": "New Findings ― Last 30 Days",
               "font": {"color": _GOLD, "size": 13}, "x": 0.01},
        legend={"font": {"color": "#666", "size": 10}, "bgcolor": "rgba(0,0,0,0)",
                "orientation": "h", "y": 1.14},
        margin=dict(l=30, r=10, t=46, b=20), height=240,
        xaxis={"gridcolor": "#1e2436", "color": "#444", "tickfont": {"size": 9}},
        yaxis={"gridcolor": "#1e2436", "color": "#444", "tickfont": {"size": 9}},
        hovermode="x unified",
    )
    return fig



# ── Module heatmap ────────────────────────────────────────────────────
def _build_module_bar(module_stats: dict) -> go.Figure:
    if not module_stats:
        fig = go.Figure()
        fig.update_layout(paper_bgcolor=_DARK, plot_bgcolor=_DARK,
                          margin=dict(l=10,r=10,t=30,b=10), height=200)
        return fig

    modules = list(module_stats.keys())
    fig = go.Figure()
    for sev, color in SEV_COLORS.items():
        fig.add_trace(go.Bar(
            name=sev,
            x=modules,
            y=[module_stats[m].get(sev, 0) for m in modules],
            marker_color=color,
        ))
    fig.update_layout(
        barmode="stack",
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,17,24,0.8)",
        title={"text": "Open Findings by Module",
               "font": {"color": _GOLD, "size": 13}, "x": 0.01},
        legend={"font": {"color": "#666", "size": 10}, "bgcolor": "rgba(0,0,0,0)",
                "orientation": "h", "y": 1.14},
        margin=dict(l=20, r=10, t=46, b=20), height=240,
        xaxis={"gridcolor": "#1e2436", "color": "#444",
               "tickangle": -25, "tickfont": {"size": 9}},
        yaxis={"gridcolor": "#1e2436", "color": "#444", "tickfont": {"size": 9}},
    )
    return fig



# ── Recent findings table ─────────────────────────────────────────────
def _recent_table(findings: list[dict], neo4j_hosts: dict | None = None):
    if not findings:
        return html.P("No findings yet. Save findings from any module to see them here.",
                      style={"color": "#555", "fontSize": "12px", "textAlign": "center",
                             "padding": "20px"})

    def _sev_badge(s):
        c = {"Critical": "danger", "High": "warning", "Medium": "info", "Low": "success"}.get(s, "secondary")
        return dbc.Badge(s, color=c, className="me-1")

    def _host_cell(sqlite_host: str, title: str) -> html.Td:
        """Build the Host cell merging SQLite value with Neo4j lookup."""
        parts = []
        # Primary SQLite host
        primary = (sqlite_host or "").strip()
        if primary:
            parts.append(
                html.Span(primary, style={
                    "color": "#33ccff", "fontSize": "11px",
                    "fontFamily": "monospace", "fontWeight": "600"
                })
            )
        # Neo4j additional hosts
        extra = []
        if neo4j_hosts:
            key = title.lower().strip()
            neo_ips = neo4j_hosts.get(key, [])
            # Also try partial match on first 30 chars
            if not neo_ips:
                short = key[:30]
                neo_ips = next(
                    (v for k, v in neo4j_hosts.items() if short in k or k in short),
                    []
                )
            for ip in neo_ips:
                if ip != primary:   # skip if already shown as SQLite host
                    extra.append(
                        dbc.Badge(
                            ip, color="dark",
                            style={"fontSize": "9px", "color": "#33ccff",
                                   "border": "1px solid #33ccff",
                                   "marginLeft": "3px", "marginTop": "2px",
                                   "display": "inline-block", "fontFamily": "monospace"}
                        )
                    )
        if not parts and not extra:
            return html.Td(html.Span("—", style={"color": "#555", "fontSize": "11px"}))
        return html.Td(html.Div([*parts, *extra],
                                style={"maxWidth": "160px", "lineHeight": "1.6"}))

    _MOD_CLR = {
        "Nmap":       "#00ff88",
        "ZAP":        "#ff9900",
        "Nuclei":     "#cc44ff",
        "Burp Suite": "#ff4466",
        "OpenVAS":    "#ffcc00",
        "BloodHound": "#ff6633",
        "AegisProbe": "#33ccff",
    }
    _SEV_CLR = {
        "Critical": "#ff4444", "High": "#ff8c00",
        "Medium": "#00bcd4",   "Low": "#4caf50",
    }
    rows = []
    for i, f in enumerate(findings):
        mod       = f.get("module", "")
        sev       = f.get("severity", "")
        is_neo4j  = f.get("_neo4j", False)
        clr       = _MOD_CLR.get(mod, "#aaa")
        sev_clr   = _SEV_CLR.get(sev, "#555")
        row_bg    = "#131825" if i % 2 == 0 else "#161c2a"
        neo_chip  = [dbc.Badge("Neo4j", style={
            "fontSize":"8px","color":"#33ccff","background":"transparent",
            "border":"1px solid #33ccff55","marginLeft":"4px","padding":"1px 5px",
        })] if is_neo4j else []
        mod_cell  = html.Td(html.Div(
            [html.Span(mod, style={"color": clr, "fontSize": "11px", "fontWeight": "700",
                                   "fontFamily": "monospace"})] + neo_chip,
        ), style={"borderLeft": f"3px solid {sev_clr}", "paddingLeft": "8px"})
        sev_pill  = html.Span(sev, style={
            "background": f"{sev_clr}22", "color": sev_clr,
            "border": f"1px solid {sev_clr}55", "borderRadius": "10px",
            "padding": "2px 8px", "fontSize": "10px", "fontWeight": "700",
        })
        rows.append(html.Tr([
            mod_cell,
            html.Td(f.get("title", ""),    style={"color": "#d8d8d8", "fontSize": "11px"}),
            _host_cell(f.get("host", ""), f.get("title", "")),
            html.Td(sev_pill),
            html.Td(f.get("status", ""),   style={"color": "#666", "fontSize": "10px"}),
            html.Td(f.get("mitre_id", ""), style={"color": "#00cccc", "fontSize": "10px",
                                                    "fontFamily": "monospace"}),
            html.Td(f.get("created_at", "")[:10] if f.get("created_at") else "",
                    style={"color": "#444", "fontSize": "10px"}),
        ], className="exec-finding-row",
           style={"backgroundColor": row_bg, "transition": "background .2s"}))

    _TH = lambda t: html.Th(t, style={
        "color": _GOLD, "fontSize": "11px", "fontWeight": "700",
        "letterSpacing": "0.5px", "textTransform": "uppercase",
        "borderBottom": f"1px solid {_GOLD}33", "padding": "8px 8px",
        "background": "#0f1320",
    })
    return dbc.Table(
        [html.Thead(html.Tr([
            _TH("Module"),
            _TH("Finding"),
            html.Th(html.Span(["Host ", dbc.Badge("+ Neo4j", color="info",
                     style={"fontSize": "8px", "verticalAlign": "middle"})]),
                    style={"color": _GOLD, "fontSize": "11px", "background": "#0f1320",
                           "borderBottom": f"1px solid {_GOLD}33", "padding": "8px"}),
            _TH("Severity"), _TH("Status"), _TH("CVE/MITRE"), _TH("Date"),
        ], style={"background": "#0f1320"})),
        html.Tbody(rows)],
        bordered=False, hover=False, size="sm",
        style={"fontSize": "11px", "borderRadius": "10px", "overflow": "hidden",
               "border": "1px solid #1e2640"},
    )



# ── Layout ────────────────────────────────────────────────────────────
def layout():
    stats    = fs.get_summary_stats()
    score    = fs.get_risk_score()
    trend    = fs.get_trend_data(30)
    mod_stat = fs.get_module_stats()
    recent   = fs.get_recent_findings(25)
    mttd, mttr = fs.get_mttd_mttr()
    neo4j_hm  = _neo4j_host_map()           # host enrichment map
    neo4j_sc  = _neo4j_scanner_findings(50) # all scanner findings from Neo4j
    # Merge: SQLite findings first (authoritative), then Neo4j scanner findings,
    # deduplicated by (module+title) so AegisProbe findings aren't doubled
    _seen = {(f["module"], f["title"]) for f in recent}
    merged = list(recent) + [f for f in neo4j_sc if (f["module"], f["title"]) not in _seen]

    total    = stats["total"]
    critical = stats["Critical"]
    high     = stats["High"]
    medium   = stats["Medium"]
    low      = stats["Low"]

    from datetime import datetime as _dt
    now_str = _dt.now().strftime("%Y-%m-%d %H:%M")
    active_scanners = sorted({f.get("module","") for f in merged if f.get("module","")})

    return html.Div([
        # Auto-refresh interval
        dcc.Interval(id="exec-dash-interval", interval=36_000_000, n_intervals=0),  # 10 hours

        # ── HERO HEADER BANNER ────────────────────────────────────────────
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Span("\U0001f6e1\ufe0f ", style={"fontSize": "22px"}),
                        html.Span("AEGIS", style={
                            "background": "linear-gradient(90deg,#ffd700,#ff8c00,#ff4444,#ffd700)",
                            "backgroundSize": "300% auto",
                            "WebkitBackgroundClip": "text",
                            "WebkitTextFillColor": "transparent",
                            "fontWeight": "900", "fontSize": "24px",
                            "letterSpacing": "4px",
                        }),
                        html.Span(" Executive Security Dashboard", style={
                            "color": "#ddd", "fontWeight": "700", "fontSize": "18px",
                            "marginLeft": "6px",
                        }),
                    ]),
                    html.Div([
                        html.Span("\u25cf LIVE ", style={"color": "#00ff88", "fontSize": "10px",
                                                          "fontWeight": "700"}),
                        html.Span(f"Synced {now_str} UTC",
                                  style={"color": "#444", "fontSize": "11px"}),
                    ], style={"marginTop": "5px"}),
                ], width=9),
                dbc.Col([
                    dbc.Button([
                        html.Span("\U0001f4fa", style={"fontSize": "18px", "marginRight": "6px"}),
                        html.Span("CyberTV", style={"fontWeight": "800", "letterSpacing": "2px",
                                                     "fontSize": "13px"}),
                        html.Span(" \u25cf LIVE", style={"fontSize": "9px", "color": "#ff6666",
                                                          "marginLeft": "6px", "fontWeight": "700"}),
                    ],
                    id="exec-goto-cybertv", n_clicks=0,
                    style={
                        "background":   "linear-gradient(135deg,#1a0000,#3d0000)",
                        "border":       "1px solid #ff3333",
                        "color":        "#ff4444",
                        "fontFamily":   "monospace",
                        "padding":      "10px 16px",
                        "borderRadius": "8px",
                        "width":        "100%",
                        "boxShadow":    "0 0 18px #ff222255",
                        "transition":   "box-shadow .3s",
                    }),
                ], width=3, className="d-flex align-items-center justify-content-end"),
            ], align="center"),
            html.Div(style={"height": "2px",
                            "background": "linear-gradient(90deg,#ffd700,#ff8c00,#ff4444,transparent)",
                            "marginTop": "12px", "borderRadius": "2px"}),
        ], style={
            "background": "linear-gradient(135deg,#0f1620 0%,#1a1f2e 60%,#0f1620 100%)",
            "padding": "18px 22px 16px", "marginBottom": "8px",
            "borderRadius": "14px", "border": "1px solid #1e2440",
            "boxShadow": "0 4px 32px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.04)",
        }),

        # ── LIVE SCANNER STATUS RIBBON ────────────────────────────────────
        html.Div([
            html.Span("📡 Active Scanners: ",
                      style={"color":"#555","fontSize":"10px","marginRight":"6px"}),
            *[dbc.Badge(s, style={
                "marginRight":"5px","fontSize":"9px","padding":"3px 8px",
                "backgroundColor": {
                    "Nmap":"#003d1e","ZAP":"#2d1e00","Nuclei":"#1e003d",
                    "Burp Suite":"#3d0010","OpenVAS":"#3d2e00",
                    "AegisProbe":"#00303d","BloodHound":"#2d1500",
                }.get(s,"#1a1f2e"),
                "border":"1px solid #334",
                "color": {
                    "Nmap":"#00ff88","ZAP":"#ff9900","Nuclei":"#cc44ff",
                    "Burp Suite":"#ff4466","OpenVAS":"#ffcc00",
                    "AegisProbe":"#33ccff","BloodHound":"#ff6633",
                }.get(s,"#aaa"),
              }) for s in (active_scanners or ["AegisProbe"])
            ],
            html.Span(f"  · {len(merged)} findings loaded",
                      style={"color":"#333","fontSize":"10px","marginLeft":"6px"}),
        ], style={"padding":"4px 4px 10px","marginBottom":"4px"}),


        # ── Row 1: Risk Gauge + KPI Cards + MTTD/MTTR ───────────────────
        dbc.Row([
            # Gauge
            dbc.Col([
                html.Div(
                    dcc.Graph(id="exec-gauge", figure=_build_gauge(score),
                              config={"displayModeBar": False}),
                    style={**_CARD_STYLE, "padding": "8px"},
                )
            ], width=3),

            # KPI cards
            dbc.Col([
                dbc.Row([
                    dbc.Col(_kpi_card("Critical",  critical, "#ff4444", "🔴",
                                      sub="Immediate action"), width=3),
                    dbc.Col(_kpi_card("High",      high,     "#ff8c00", "🟠",
                                      sub="Review & patch"),  width=3),
                    dbc.Col(_kpi_card("Medium",    medium,   "#00bcd4", "🔵",
                                      sub="Monitor closely"), width=3),
                    dbc.Col(_kpi_card("Low",       low,      "#4caf50", "🟢",
                                      sub="Informational"),   width=3),
                ], className="g-2"),
                dbc.Row([
                    dbc.Col(_kpi_card("Total Open",  total, "#e6e6e6", "📋",
                                      sub="All severities"), width=4),
                    dbc.Col(_kpi_card("MTTD (hrs)",  mttd,  "#ffd700", "⏱️",
                                      sub="Detection time"), width=4),
                    dbc.Col(_kpi_card("MTTR (hrs)",  mttr,  "#ffd700", "🛠️",
                                      sub="Response time"),  width=4),
                ], className="g-2 mt-2"),
            ], width=9),
        ], className="mb-3"),

        # ── Row 2: Trend Chart + Module Bar ──────────────────────────────
        dbc.Row([
            dbc.Col([
                html.Div(
                    dcc.Graph(id="exec-trend", figure=_build_trend(trend),
                              config={"displayModeBar": False}),
                    style={**_CARD_STYLE, "padding": "8px"},
                )
            ], width=7),
            dbc.Col([
                html.Div(
                    dcc.Graph(id="exec-modules", figure=_build_module_bar(mod_stat),
                              config={"displayModeBar": False}),
                    style={**_CARD_STYLE, "padding": "8px"},
                )
            ], width=5),
        ], className="mb-3"),

        # ── Row 3: Recent Findings Table + Filters ────────────────────────
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Label("🔍 Scanner", style={"color":"#aaa","fontSize":"11px","marginBottom":"4px"}),
                    dcc.Dropdown(
                        id="exec-scanner-filter",
                        options=[
                            {"label": "★ All Scanners",    "value": "__all__"},
                            {"label": "📊 Nmap",           "value": "Nmap"},
                            {"label": "🛡️ ZAP",            "value": "ZAP"},
                            {"label": "⚡ Nuclei",         "value": "Nuclei"},
                            {"label": "🔥 Burp Suite",     "value": "Burp Suite"},
                            {"label": "🟡 OpenVAS",        "value": "OpenVAS"},
                            {"label": "🦴 BloodHound",     "value": "BloodHound"},
                            {"label": "🧭 AegisProbe",     "value": "AegisProbe"},
                            {"label": "🧠 IAM Red Team",   "value": "IAM Red Team"},
                            {"label": "🤖 LLM Red Team",   "value": "LLM Red Team"},
                            {"label": "💼 EDR Gaps",       "value": "EDR Gaps"},
                        ],
                        value="__all__",
                        clearable=False,
                        style={"backgroundColor":"#1a1e2c","color":"#e6e6e6",
                               "border":"1px solid #2e3450","fontSize":"12px"},
                    ),
                ], width=5),
                dbc.Col([
                    html.Label("🟠 Severity", style={"color":"#aaa","fontSize":"11px","marginBottom":"4px"}),
                    dcc.Dropdown(
                        id="exec-sev-filter",
                        options=[
                            {"label": "★ All",      "value": "__all__"},
                            {"label": "🔴 Critical", "value": "Critical"},
                            {"label": "🟠 High",     "value": "High"},
                            {"label": "🟡 Medium",   "value": "Medium"},
                            {"label": "🟢 Low",      "value": "Low"},
                        ],
                        value="__all__",
                        clearable=False,
                        style={"backgroundColor":"#1a1e2c","color":"#e6e6e6",
                               "border":"1px solid #2e3450","fontSize":"12px"},
                    ),
                ], width=4),
                dbc.Col([
                    html.Div([
                        html.Span("● LIVE", style={"fontSize":"11px","color":"#00ff88",
                                                    "fontWeight":"700","marginTop":"22px","display":"block"}),
                        html.Span("Neo4j + SQLite", style={"fontSize":"9px","color":"#555"}),
                    ])
                ], width=3),
            ], className="mb-2 align-items-end"),
            html.H6("📋 Recent Findings", style={"color": _GOLD, "marginBottom": "6px",
                                                  "marginTop": "4px"}),
            html.Div(id="exec-findings-table", children=_recent_table(merged, neo4j_hm)),
        ], style=_CARD_STYLE),

        # ── Row 4: Top Risks ──────────────────────────────────────────────
        html.Div([
            html.H6("🔥 Top Critical Open Findings", style={"color": _GOLD, "marginBottom": "10px"}),
            html.Div(id="exec-top-risks", children=_top_risks_list(neo4j_hm, merged)),
        ], style=_CARD_STYLE),

    ], style={"padding": "20px", "background": _DARK, "minHeight": "100vh"})


def _top_risks_list(neo4j_hosts: dict | None = None,
                    all_findings: list | None = None):
    # Prefer merged findings list (SQLite + Neo4j); fallback to DB query
    if all_findings:
        crits = [f for f in all_findings
                 if f.get("severity") == "Critical" and f.get("status", "Open") == "Open"][:5]
    else:
        crits = fs.get_findings(severity="Critical", status="Open", limit=5)
    if not crits:
        return html.P("No critical findings — great posture! 🎉",
                      style={"color": "#4caf50", "fontSize": "13px"})
    items = []
    for i, f in enumerate(crits, 1):
        sqlite_host = (f.get("host") or "").strip()
        # Neo4j extra hosts
        neo_ips = []
        if neo4j_hosts:
            key = (f.get("title") or "").lower().strip()
            neo_ips = neo4j_hosts.get(key, [])
            if not neo_ips:
                short = key[:30]
                neo_ips = next(
                    (v for k, v in neo4j_hosts.items() if short in k or k in short), []
                )
        # Build host display: primary + extra badges
        host_parts = []
        shown = set()
        if sqlite_host:
            host_parts.append(
                html.Span(sqlite_host, style={"color": "#33ccff", "fontSize": "10px",
                                             "fontFamily": "monospace", "fontWeight": "600"})
            )
            shown.add(sqlite_host)
        for ip in neo_ips:
            if ip not in shown:
                host_parts.append(
                    dbc.Badge(ip, color="dark",
                              style={"fontSize": "9px", "color": "#33ccff",
                                     "border": "1px solid #33ccff",
                                     "marginLeft": "4px", "fontFamily": "monospace"})
                )
                shown.add(ip)
        if not host_parts:
            host_parts = [html.Span("—", style={"color": "#555", "fontSize": "10px"})]

        items.append(
            dbc.ListGroupItem([
                html.Span(f"#{i} ", style={"color": "#ff4444", "fontWeight": "700"}),
                html.B(f.get("title", ""), style={"color": "#e6e6e6"}),
                html.Span(f"  [{f.get('module','')}]",
                          style={"color": "#888", "fontSize": "11px", "marginLeft": "6px"}),
                dbc.Badge(f.get("mitre_id", "") or "—",
                          color="secondary", className="ms-2", style={"fontSize": "10px"}),
                html.Span(
                    [html.Span(" | Host: ", style={"color": "#555", "fontSize": "10px"})] + host_parts,
                    style={"marginLeft": "8px"}
                ),
            ], style={"background": "#1a1e2c", "border": "1px solid #2e3450",
                      "marginBottom": "4px", "borderRadius": "4px"})
        )
    return dbc.ListGroup(items, style={"fontSize": "12px"})


# ── Callback: auto-refresh every 10 hours ─────────────────────────────
@callback(
    Output("exec-gauge",          "figure"),
    Output("exec-trend",          "figure"),
    Output("exec-modules",        "figure"),
    Output("exec-findings-table", "children"),
    Output("exec-top-risks",      "children"),
    Input("exec-dash-interval",   "n_intervals"),
    State("exec-scanner-filter",  "value"),
    State("exec-sev-filter",      "value"),
)
def refresh_dashboard(_n, scanner_filt, sev_filt):
    stats      = fs.get_summary_stats()
    score      = fs.get_risk_score()
    trend      = fs.get_trend_data(30)
    mod_stat   = fs.get_module_stats()
    recent     = fs.get_recent_findings(25)
    neo4j_hm   = _neo4j_host_map()
    neo4j_sc   = _neo4j_scanner_findings(50)
    _seen = {(f["module"], f["title"]) for f in recent}
    merged = list(recent) + [f for f in neo4j_sc if (f["module"], f["title"]) not in _seen]
    # Apply active filters
    filtered = _apply_filters(merged, scanner_filt, sev_filt)
    return (
        _build_gauge(score),
        _build_trend(trend),
        _build_module_bar(mod_stat),
        _recent_table(filtered, neo4j_hm),
        _top_risks_list(neo4j_hm, merged),          # top risks always unfiltered
    )


# ── Callback: filter dropdown → instant table update ──────────────────
@callback(
    Output("exec-findings-table", "children", allow_duplicate=True),
    Input("exec-scanner-filter",  "value"),
    Input("exec-sev-filter",      "value"),
    prevent_initial_call=True,
)
def filter_findings_table(scanner_filt, sev_filt):
    recent   = fs.get_recent_findings(50)
    neo4j_hm = _neo4j_host_map()
    neo4j_sc = _neo4j_scanner_findings(100)
    _seen = {(f["module"], f["title"]) for f in recent}
    merged   = list(recent) + [f for f in neo4j_sc if (f["module"], f["title"]) not in _seen]
    filtered = _apply_filters(merged, scanner_filt, sev_filt)
    return _recent_table(filtered, neo4j_hm)


def _apply_filters(findings: list, scanner: str | None, severity: str | None) -> list:
    """Filter findings by scanner module and/or severity."""
    result = findings
    if scanner and scanner != "__all__":
        result = [f for f in result if f.get("module", "") == scanner]
    if severity and severity != "__all__":
        result = [f for f in result if f.get("severity", "") == severity]
    return result


# ── Callback: 📺 CyberTV button → navigate to CyberTV home tab ────────
@callback(
    Output("tabs", "active_tab"),
    Input("exec-goto-cybertv", "n_clicks"),
    prevent_initial_call=True,
)
def goto_cybertv(n_clicks):
    """Switch the main tab to CyberTV when the button is pressed."""
    if n_clicks:
        return "home"
    from dash import no_update
    return no_update
