"""
Clickable Post-Exploitation Panels
====================================
Populates pe-cred-div, pe-exfil2-div, pe-blind-div from Neo4j with
clickable buttons. On click, opens pe-panel-detail-offcanvas with a
per-item drill-down (hosts affected, CVEs, CVSS, remediation steps).
"""
import dash
from dash import callback, Output, Input, State, html, no_update
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate


_SEV_CLR = {
    "Critical": "#dc3545", "High": "#ff6b35",
    "Medium":   "#ffc107", "Low":  "#28a745",
    "Info":     "#6c757d",
}

# ── Helpers ────────────────────────────────────────────────────────────────────
def _neo4j():
    from cyber_range.services.neo4j_engine import Neo4jEngine
    return Neo4jEngine()


def _click_btn(label, store_val, color="#1f6feb", count=None):
    """A slim, clickable button row item for the panel."""
    badge = dbc.Badge(str(count), color="secondary",
                      style={"fontSize":"9px","marginLeft":"6px"}) if count is not None else None
    return html.Div(
        dbc.Button(
            [html.Span(label, style={"fontSize":"11px"}), badge or ""],
            id={"type":"pe-panel-btn","index": store_val},
            color="link",
            style={"color":"#58a6ff","padding":"2px 0","fontSize":"11px",
                   "textDecoration":"none","textAlign":"left",
                   "display":"block","width":"100%"},
            n_clicks=0,
        ),
        style={"borderBottom":"1px solid #21262d","padding":"3px 0"}
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Populate the three panels on every timer tick
# ══════════════════════════════════════════════════════════════════════════════
@callback(
    Output("pe-cred-div",    "children"),
    Output("pe-exfil2-div",  "children"),
    Output("pe-blind-div",   "children"),
    Input("apt-exploit-timer","n_intervals"),
    prevent_initial_call=False,
)
def update_clickable_panels(n):
    cred_rows  = []
    exfil_rows = []
    blind_rows = []

    try:
        ng = _neo4j()
        with ng.driver.session() as s:

            # ── Credential Harvesting — group by auth protocol type ────────
            cred_data = s.run("""
                MATCH (f:Finding)
                WHERE f.name IS NOT NULL
                WITH
                  CASE
                    WHEN toLower(f.name) CONTAINS 'smb'    OR toLower(f.name) CONTAINS 'ntlm'
                         THEN 'SMB/NTLM'
                    WHEN toLower(f.name) CONTAINS 'kerberos'   THEN 'Kerberos'
                    WHEN toLower(f.name) CONTAINS 'ssh'         THEN 'SSH'
                    WHEN toLower(f.name) CONTAINS 'ldap'  OR toLower(f.name) CONTAINS 'active directory'
                         THEN 'LDAP/AD'
                    WHEN toLower(f.name) CONTAINS 'ftp'         THEN 'FTP'
                    WHEN toLower(f.name) CONTAINS 'rdp'         THEN 'RDP'
                    ELSE NULL
                  END AS proto,
                  f
                WHERE proto IS NOT NULL
                RETURN proto, count(f) AS cnt
                ORDER BY cnt DESC
            """).data()

            total_crit = s.run("""
                MATCH (f:Finding) WHERE f.severity = 'Critical' RETURN count(f) AS n
            """).single()["n"]

            all_cred = s.run("""
                MATCH (f:Finding)
                WHERE toLower(f.name) CONTAINS 'smb' OR toLower(f.name) CONTAINS 'ntlm'
                   OR toLower(f.name) CONTAINS 'kerberos' OR toLower(f.name) CONTAINS 'ssh'
                   OR toLower(f.name) CONTAINS 'ldap' OR toLower(f.name) CONTAINS 'ftp'
                   OR toLower(f.name) CONTAINS 'rdp'
                RETURN count(f) AS n
            """).single()["n"]

            for row in cred_data:
                proto = row["proto"]
                cnt   = row["cnt"]
                cred_rows.append(
                    html.Div([
                        _click_btn(f"🔑 {proto} Findings", f"cred::{proto}", count=cnt),
                    ])
                )

            if not cred_data:
                cred_rows.append(html.Div("No credential findings in Neo4j.",
                                          style={"color":"#555","fontSize":"10px","fontStyle":"italic"}))

            cred_rows.append(html.Div([
                html.Span(f"🔴 Total Critical: ", style={"color":"#555","fontSize":"10px"}),
                html.Span(str(total_crit), style={"color":"#dc3545","fontWeight":"700"}),
                html.Span("  |  Auth-related: ", style={"color":"#555","fontSize":"10px","marginLeft":"8px"}),
                html.Span(str(all_cred), style={"color":"#ff6b35","fontWeight":"700"}),
            ], style={"marginTop":"8px","padding":"4px 0","borderTop":"1px solid #21262d"}))

            cred_rows.append(html.Div(
                f"🔍 {all_cred} credential / auth findings identified in Neo4j",
                style={"color":"#555","fontSize":"9px","marginTop":"4px","fontStyle":"italic"}
            ))

            # ── Data Access & Exfiltration — group by service/port ─────────
            exfil_data = s.run("""
                MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                      -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                WHERE svc.port IS NOT NULL
                WITH svc.name AS svc_name,
                     svc.port AS port,
                     count(DISTINCT f) AS finding_cnt,
                     count(DISTINCT h) AS host_cnt,
                     collect(DISTINCT f.severity)[0] AS worst_sev
                RETURN svc_name, port, finding_cnt, host_cnt, worst_sev
                ORDER BY finding_cnt DESC LIMIT 10
            """).data()

            for row in exfil_data:
                sname = row.get("svc_name") or "unknown"
                port  = row.get("port","?")
                fcnt  = row.get("finding_cnt", 0)
                hcnt  = row.get("host_cnt", 0)
                wsev  = row.get("worst_sev","Info")
                sev_clr = _SEV_CLR.get(wsev,"#6c757d")
                store_key = f"exfil::{sname}::{port}"
                exfil_rows.append(html.Div([
                    _click_btn(f"{sname}:{port}", store_key, count=fcnt),
                    html.Div([
                        html.Span(f"{fcnt:,} findings", style={"color":"#8b949e","fontSize":"9px"}),
                        html.Span("  ·  ", style={"color":"#333"}),
                        html.Span(f"{hcnt} host(s)", style={"color":"#6e7681","fontSize":"9px"}),
                        dbc.Progress(value=min(fcnt, 100), max=max(fcnt, 1),
                                     style={"height":"3px","marginTop":"2px",
                                            "backgroundColor":"#21262d"},
                                     color="danger" if wsev=="Critical" else
                                           "warning" if wsev=="High" else "info"),
                        dbc.Badge(wsev, style={"fontSize":"8px","backgroundColor":sev_clr,
                                               "marginTop":"2px","display":"inline-block"}),
                    ], style={"marginLeft":"4px","marginBottom":"4px"}),
                ]))

            if not exfil_data:
                exfil_rows.append(html.Div("No service findings in Neo4j.",
                                           style={"color":"#555","fontSize":"10px","fontStyle":"italic"}))

            # ── Defensive Blind Spots — group real high/crit finding types ──
            blind_data = s.run("""
                MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                      -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                WHERE f.severity IN ['Critical','High']
                WITH
                  CASE
                    WHEN toLower(f.name) CONTAINS 'remote code' OR toLower(f.name) CONTAINS 'rce'
                         THEN 'Remote Code Execution'
                    WHEN toLower(f.name) CONTAINS 'buffer' OR toLower(f.name) CONTAINS 'overflow'
                         THEN 'Buffer Overflow'
                    WHEN toLower(f.name) CONTAINS 'injection'   THEN 'Injection Vulnerability'
                    WHEN toLower(f.name) CONTAINS 'backdoor'    THEN 'Known Backdoor / Exploit'
                    WHEN toLower(f.name) CONTAINS 'privilege' OR toLower(f.name) CONTAINS 'escalat'
                         THEN 'Privilege Escalation'
                    WHEN toLower(f.name) CONTAINS 'bypass'      THEN 'Security Control Bypass'
                    WHEN toLower(f.name) CONTAINS 'traversal'   THEN 'Path Traversal'
                    WHEN toLower(f.name) CONTAINS 'xxe'         THEN 'XML External Entity'
                    WHEN toLower(f.name) CONTAINS 'ssrf'        THEN 'SSRF'
                    ELSE 'Other High/Critical'
                  END AS category,
                  count(DISTINCT f) AS cnt,
                  count(DISTINCT h) AS hosts
                RETURN category, cnt, hosts
                ORDER BY cnt DESC LIMIT 8
            """).data()

            for row in blind_data:
                cat   = row["category"]
                cnt   = row["cnt"]
                hosts = row["hosts"]
                blind_rows.append(
                    _click_btn(f"• {cat}", f"blind::{cat}", count=cnt)
                )
                blind_rows.append(html.Div(
                    f"  {hosts} host(s) affected",
                    style={"color":"#555","fontSize":"9px","marginLeft":"10px","marginBottom":"2px"}
                ))

            if not blind_data:
                blind_rows.append(html.Div("No high/critical blind spots found.",
                                           style={"color":"#555","fontSize":"10px","fontStyle":"italic"}))

            total_crit_blind = sum(r["cnt"] for r in blind_data)
            total_hosts_blind = sum(r["hosts"] for r in blind_data)
            blind_rows.append(html.Div(
                f"⚠ {total_crit_blind} Critical/High findings across {total_hosts_blind} hosts need remediation",
                style={"color":"#ffc107","fontSize":"9px","marginTop":"8px",
                       "borderTop":"1px solid #21262d","paddingTop":"4px"}
            ))

        ng.driver.close()

    except Exception as e:
        err = html.Div(f"Neo4j error: {e}", style={"color":"red","fontSize":"10px"})
        cred_rows  = [err]
        exfil_rows = [err]
        blind_rows = [err]

    return cred_rows, exfil_rows, blind_rows


# ══════════════════════════════════════════════════════════════════════════════
# 2. Open offcanvas on button click + populate with Neo4j detail
# ══════════════════════════════════════════════════════════════════════════════
@callback(
    Output("pe-panel-detail-offcanvas", "is_open"),
    Output("pe-panel-detail-offcanvas", "title"),
    Output("pe-panel-detail-body",      "children"),
    Input({"type":"pe-panel-btn","index": dash.ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def open_panel_detail(all_clicks):
    from dash import ctx
    if not any(c for c in (all_clicks or []) if c):
        raise PreventUpdate

    triggered = ctx.triggered_id
    if not triggered:
        raise PreventUpdate

    key = triggered.get("index","")
    parts = key.split("::")
    kind  = parts[0]

    title = "🔍 Detail"
    body  = []

    try:
        ng = _neo4j()
        with ng.driver.session() as s:

            # ── Credential detail ────────────────────────────────────────────
            if kind == "cred" and len(parts) >= 2:
                proto = parts[1]
                title  = f"🔑 {proto} Credential Findings"
                kw = proto.lower().split("/")
                where_clauses = " OR ".join(
                    f"toLower(f.name) CONTAINS '{k}'" for k in kw
                )
                rows = s.run(f"""
                    MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                          -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                    WHERE {where_clauses}
                    RETURN
                      coalesce(h.host, h.ip) AS host,
                      h.ip                   AS ip,
                      svc.port               AS port,
                      svc.name               AS service,
                      f.severity             AS severity,
                      f.name                 AS finding,
                      coalesce(f.cve,'—')    AS cve,
                      coalesce(toString(f.cvss),'—') AS cvss,
                      coalesce(f.scanner,'—')        AS scanner
                    ORDER BY host, severity
                    LIMIT 50
                """).data()

                body = _finding_table(rows, proto)

            # ── Exfil / Service detail ───────────────────────────────────────
            elif kind == "exfil" and len(parts) >= 3:
                svc_name = parts[1]
                port     = parts[2]
                title    = f"📡 {svc_name}:{port} — Findings Detail"
                rows = s.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                          -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                    WHERE svc.name = $svc AND toString(svc.port) = $port
                    RETURN
                      coalesce(h.host, h.ip) AS host,
                      h.ip                   AS ip,
                      svc.port               AS port,
                      svc.name               AS service,
                      f.severity             AS severity,
                      f.name                 AS finding,
                      coalesce(f.cve,'—')    AS cve,
                      coalesce(toString(f.cvss),'—') AS cvss,
                      coalesce(f.scanner,'—')        AS scanner
                    ORDER BY host, severity
                    LIMIT 50
                """, {"svc": svc_name, "port": str(port)}).data()

                body = _finding_table(rows, f"{svc_name}:{port}")

            # ── Blind spot detail ────────────────────────────────────────────
            elif kind == "blind" and len(parts) >= 2:
                category = parts[1]
                title    = f"⚠ {category} — Affected Systems"

                # Map category back to keyword(s)
                kw_map = {
                    "Remote Code Execution":   ["remote code", "rce"],
                    "Buffer Overflow":         ["buffer", "overflow"],
                    "Injection Vulnerability": ["injection"],
                    "Known Backdoor / Exploit":["backdoor"],
                    "Privilege Escalation":    ["privilege", "escalat"],
                    "Security Control Bypass": ["bypass"],
                    "Path Traversal":          ["traversal"],
                    "XML External Entity":     ["xxe"],
                    "SSRF":                    ["ssrf"],
                    "Other High/Critical":     [],    # catch-all
                }
                kws = kw_map.get(category, [category.lower()])

                if kws:
                    where = " OR ".join(f"toLower(f.name) CONTAINS '{k}'" for k in kws)
                    severity_filter = "AND f.severity IN ['Critical','High']"
                else:
                    # Other High/Critical — exclude all known categories
                    exclude_kws = ["remote code","rce","buffer","overflow","injection",
                                   "backdoor","privilege","escalat","bypass","traversal","xxe","ssrf"]
                    where = " AND ".join(
                        f"NOT toLower(f.name) CONTAINS '{k}'" for k in exclude_kws
                    )
                    severity_filter = "AND f.severity IN ['Critical','High']"

                rows = s.run(f"""
                    MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                          -[:HAS_FINDING|HAS_VULN]->(f:Finding)
                    WHERE ({where}) {severity_filter}
                    RETURN
                      coalesce(h.host, h.ip) AS host,
                      h.ip                   AS ip,
                      svc.port               AS port,
                      svc.name               AS service,
                      f.severity             AS severity,
                      f.name                 AS finding,
                      coalesce(f.cve,'—')    AS cve,
                      coalesce(toString(f.cvss),'—') AS cvss,
                      coalesce(f.scanner,'—')        AS scanner
                    ORDER BY host, severity LIMIT 50
                """).data()

                body = _finding_table(rows, category)

        ng.driver.close()

    except Exception as e:
        body = [html.Div(f"Neo4j error: {e}", style={"color":"red"})]

    return True, title, body


# ── Shared table renderer ──────────────────────────────────────────────────────
def _finding_table(rows, label):
    if not rows:
        return [html.Div(f"No Neo4j findings matched for '{label}'.",
                         style={"color":"#555","fontStyle":"italic","padding":"20px"})]

    header = html.Tr([
        html.Th("Host",     style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
        html.Th("Service",  style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
        html.Th("Port",     style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
        html.Th("Severity", style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
        html.Th("Finding",  style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
        html.Th("CVE",      style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
        html.Th("CVSS",     style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
        html.Th("Scanner",  style={"color":"#58a6ff","fontSize":"9px","padding":"3px 6px"}),
    ], style={"borderBottom":"1px solid #21262d","backgroundColor":"#0d1117"})

    trows = []
    for r in rows:
        sev_clr = _SEV_CLR.get(r.get("severity","Info"), "#6c757d")
        cve = r.get("cve","—")
        cve_link = (
            html.A(cve,
                   href=f"https://nvd.nist.gov/vuln/detail/{cve}",
                   target="_blank",
                   style={"color":"#58a6ff","fontSize":"9px","textDecoration":"none"})
            if cve not in ("—","None","") else html.Span("—", style={"color":"#555","fontSize":"9px"})
        )
        trows.append(html.Tr([
            html.Td(r.get("host","?"),   style={"fontSize":"9px","color":"#adbac7","padding":"3px 6px","fontFamily":"monospace"}),
            html.Td(r.get("service","—"),style={"fontSize":"9px","color":"#8b949e","padding":"3px 6px"}),
            html.Td(r.get("port","—"),   style={"fontSize":"9px","color":"#8b949e","padding":"3px 6px"}),
            html.Td(html.Span(r.get("severity","—"),
                              style={"color":sev_clr,"fontWeight":"700","fontSize":"9px"}),
                    style={"padding":"3px 6px"}),
            html.Td(r.get("finding","—") or "",
                    style={"fontSize":"9px","color":"#cdd9e5","padding":"3px 6px",
                           "maxWidth":"180px","overflow":"hidden","textOverflow":"ellipsis",
                           "whiteSpace":"nowrap"}),
            html.Td(cve_link, style={"padding":"3px 6px"}),
            html.Td(r.get("cvss","—"), style={"fontSize":"9px","color":"#8b949e","padding":"3px 6px"}),
            html.Td(r.get("scanner","—"), style={"fontSize":"9px","color":"#555","padding":"3px 6px"}),
        ], style={"borderBottom":"1px solid #161b22"}))

    return [
        html.Div(f"{len(rows)} finding(s) from Neo4j",
                 style={"color":"#8b949e","fontSize":"9px","padding":"8px 10px",
                        "borderBottom":"1px solid #21262d"}),
        html.Div(
            html.Table(
                [html.Thead(header), html.Tbody(trows)],
                style={"width":"100%","borderCollapse":"collapse"}
            ),
            style={"overflowX":"auto"}
        )
    ]
