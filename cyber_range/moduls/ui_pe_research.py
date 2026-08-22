"""
Research & Intelligence Activity Callback
Populates pe-research-intel-table with per-host research steps, scripts used,
and tool references (ExploitDB, GitHub, SearchSploit, Metasploit, NVD/CVE).
"""
import dash
from dash import callback, Output, Input, html
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate

# Tool reference colours / logos
_TOOL_STYLES = {
    "ExploitDB":    {"bg":"#dc354520","border":"#dc3545","color":"#f77","icon":"💥"},
    "SearchSploit": {"bg":"#ffc10720","border":"#ffc107","color":"#ffc107","icon":"🔍"},
    "GitHub":       {"bg":"#33333330","border":"#555","color":"#adbac7","icon":"🐙"},
    "Metasploit":   {"bg":"#0d6efd20","border":"#0d6efd","color":"#6ea8fe","icon":"🛡"},
    "NVD/CVE":      {"bg":"#6c757d20","border":"#6c757d","color":"#adb5bd","icon":"📋"},
    "Shodan":       {"bg":"#ff000020","border":"#a00","color":"#f88","icon":"📡"},
    "Censys":       {"bg":"#20c99720","border":"#20c997","color":"#5eead4","icon":"🌐"},
}

_SEV_CLR = {
    "Critical": "#dc3545", "High": "#ff6b35",
    "Medium":   "#ffc107", "Low":  "#28a745",
    "Info":     "#6c757d", "-":    "#6c757d",
}

STEP_ICONS = {
    "Reconnaissance":       "🔭",
    "Vulnerability Scan":   "🔎",
    "Exploit Research":     "🧪",
    "Payload Staged":       "💣",
    "Exploit Launched":     "🚀",
    "Foothold Established": "🏴",
    "Persistence":          "🔒",
    "Lateral Movement":     "↔️",
    "Privilege Escalation": "⬆️",
    "Exfiltration":         "📤",
}


def _tool_badge(name):
    st = _TOOL_STYLES.get(name, {"bg":"#33333330","border":"#555","color":"#adb5bd","icon":"🔧"})
    return html.Span(
        [html.Span(st["icon"]+" ", style={"fontSize":"9px"}),
         html.Span(name, style={"fontSize":"9px","fontWeight":"600"})],
        style={"backgroundColor":st["bg"],"border":f"1px solid {st['border']}",
               "color":st["color"],"borderRadius":"4px","padding":"1px 6px",
               "marginRight":"4px","display":"inline-block","lineHeight":"1.5"}
    )


def _step_row(step_name, detail, color="#8b949e", scripts=None):
    icon = STEP_ICONS.get(step_name, "▸")
    children = [
        html.Div([
            html.Span(icon+" ", style={"fontSize":"11px"}),
            html.Span(step_name, style={"color":color,"fontWeight":"700","fontSize":"10px"}),
        ]),
        html.Div(detail, style={"color":"#8b949e","fontSize":"9px","marginLeft":"18px","lineHeight":"1.5"}),
    ]
    if scripts:
        children.append(
            html.Div([
                html.Span("Script/Command: ", style={"color":"#555","fontSize":"9px"}),
                html.Code(scripts, style={"color":"#58a6ff","fontSize":"9px",
                                          "backgroundColor":"#0d1117","padding":"1px 5px","borderRadius":"3px"}),
            ], style={"marginLeft":"18px","marginTop":"2px"})
        )
    return html.Div(children, style={"marginBottom":"6px"})


@callback(
    Output("pe-research-intel-table", "children"),
    Input("apt-exploit-timer",        "n_intervals"),
    prevent_initial_call=False,
)
def update_research_intel_table(n):
    """Build per-host research intelligence rows from Neo4j."""
    host_blocks = []
    try:
        from cyber_range.services.neo4j_engine import Neo4jEngine
        ng = Neo4jEngine()
        with ng.driver.session() as s:

            # All targeted hosts with their findings and services
            hosts = s.run("""
                MATCH (h:Host)
                WHERE h.ip IS NOT NULL
                OPTIONAL MATCH (h)-[:RUNS_SERVICE|EXPOSES|HasService]->(svc:Service)
                OPTIONAL MATCH (svc)-[:HAS_FINDING|HAS_VULN]->(f:Finding)
                RETURN
                  coalesce(h.host, h.ip)         AS host,
                  h.ip                           AS ip,
                  h.os                           AS os,
                  h.compromised                  AS compromised,
                  collect(DISTINCT {
                      name:     coalesce(f.name,'-'),
                      severity: coalesce(f.severity,'-'),
                      cve:      coalesce(f.cve,'-'),
                      cvss:     coalesce(toString(f.cvss),'-'),
                      scanner:  coalesce(f.scanner,'-'),
                      service:  coalesce(svc.name,'-'),
                      port:     coalesce(toString(svc.port),'-'),
                      exploit_ref: coalesce(f.exploit_ref,''),
                      github_ref:  coalesce(f.github_ref,''),
                      msf_module:  coalesce(f.msf_module,''),
                      script:      coalesce(f.script, f.command,'')
                  }) AS findings
                ORDER BY h.ip
            """).data()

        ng.driver.close()

        if not hosts:
            return html.Div("No targets found in Neo4j.",
                            style={"color":"#555","fontSize":"11px","padding":"20px","textAlign":"center"})

        for row in hosts:
            ip        = row.get("ip","?")
            hostname  = row.get("host", ip)
            os_str    = row.get("os","")
            comp      = row.get("compromised", False)
            findings  = [f for f in (row.get("findings") or []) if f.get("name","-") != "-"]

            # Determine research tools referenced
            has_edb   = any(f.get("exploit_ref","").startswith("EDB") for f in findings)
            has_gh    = any(f.get("github_ref","") for f in findings)
            has_msf   = any(f.get("msf_module","") for f in findings)
            has_cve   = any(f.get("cve","-") != "-" for f in findings)
            has_ss    = any("searchsploit" in (f.get("scanner","")).lower() for f in findings)
            scanner_set = set(f.get("scanner","-") for f in findings) - {"-",""}

            # Severity distribution
            sev_counts = {}
            for f in findings:
                s = f.get("severity","-")
                sev_counts[s] = sev_counts.get(s,0)+1
            worst = next((s for s in ["Critical","High","Medium","Low","Info"]
                          if s in sev_counts), None)

            # Compromise badge
            status_badge = dbc.Badge(
                "COMPROMISED" if comp else "RESEARCHING",
                color="danger" if comp else "warning",
                style={"fontSize":"8px","verticalAlign":"middle","marginLeft":"6px"}
            )

            # Build research steps from findings
            steps = []
            # Step 1 – Recon
            svc_names = list({f.get("service","-") for f in findings if f.get("service","-") != "-"})
            steps.append(_step_row(
                "Reconnaissance",
                f"Host {ip} discovered — services: {', '.join(svc_names) or 'scan pending'}. "
                f"OS: {os_str or 'unknown'}.",
                "#42b9f5",
                scripts=f"nmap -sV -sC -p- {ip}"
            ))
            # Step 2 – Vuln Scan
            if findings:
                sev_summary = ", ".join(f"{k}:{v}" for k,v in sev_counts.items())
                steps.append(_step_row(
                    "Vulnerability Scan",
                    f"{len(findings)} finding(s) identified ({sev_summary}). "
                    f"Scanners: {', '.join(scanner_set) or 'internal scanner'}.",
                    "#ffc107",
                    scripts=f"nuclei -u {ip} -severity critical,high,medium"
                ))
            # Step 3 – Exploit Research
            research_tools_used = []
            if has_cve:
                research_tools_used.append(f"NVD lookup for: "
                    f"{', '.join(f['cve'] for f in findings if f.get('cve','-')!='-')[:80]}")
            if has_edb:
                refs = [f["exploit_ref"] for f in findings if f.get("exploit_ref","").startswith("EDB")]
                research_tools_used.append(f"ExploitDB refs: {', '.join(refs[:3])}")
            if has_ss:
                research_tools_used.append("SearchSploit confirmed local exploit copy")
            if has_msf:
                mods = [f["msf_module"] for f in findings if f.get("msf_module","")]
                research_tools_used.append(f"Metasploit modules: {', '.join(mods[:2])}")
            if has_gh:
                research_tools_used.append("GitHub PoC referenced in finding metadata")
            if research_tools_used or has_cve:
                cvss_max = max(
                    (float(f["cvss"]) for f in findings if f.get("cvss","-") not in ("-","None","")),
                    default=0.0
                )
                steps.append(_step_row(
                    "Exploit Research",
                    f"CVSS max: {cvss_max} | {' · '.join(research_tools_used) or 'manual research performed'}",
                    "#c084fc",
                    scripts=(
                        f"searchsploit {', '.join(f['cve'] for f in findings if f.get('cve','-')!='-')[:50]}"
                        if has_cve else "searchsploit <service-name>"
                    )
                ))
            # Step 4 – Payload / Exploit launched
            if worst in ("Critical","High") or comp:
                scripts_used = next(
                    (f["script"] for f in findings if f.get("script","")), None
                ) or f"msfconsole -q -x 'use exploit/...; set RHOSTS {ip}; run'"
                steps.append(_step_row(
                    "Exploit Launched",
                    f"Exploit triggered against {ip} targeting {worst or 'High'}-severity vector.",
                    "#ff4444",
                    scripts=scripts_used
                ))
            # Step 5 – Post-Exploitation Status
            if comp:
                steps.append(_step_row(
                    "Foothold Established",
                    f"Host {ip} is compromised. Session active — persistence, lateral movement, "
                    f"and exfiltration paths are being enumerated.",
                    "#dc3545",
                    scripts=f"meterpreter > run post/multi/manage/shell_to_meterpreter"
                ))

            # Tool badges row
            tool_badges = []
            if has_cve:   tool_badges.append(_tool_badge("NVD/CVE"))
            if has_edb:   tool_badges.append(_tool_badge("ExploitDB"))
            if has_ss or scanner_set:
                          tool_badges.append(_tool_badge("SearchSploit"))
            if has_msf:   tool_badges.append(_tool_badge("Metasploit"))
            if has_gh:    tool_badges.append(_tool_badge("GitHub"))
            if not tool_badges:
                tool_badges = [_tool_badge("SearchSploit"), _tool_badge("ExploitDB"),
                               _tool_badge("NVD/CVE")]

            # Collapsible finding details
            finding_rows = []
            for f in findings[:8]:
                sev_clr = _SEV_CLR.get(f.get("severity","-"),"#6c757d")
                finding_rows.append(html.Tr([
                    html.Td(f.get("service","-"), style={"fontSize":"9px","color":"#8b949e","padding":"2px 6px"}),
                    html.Td(f.get("port","-"),    style={"fontSize":"9px","color":"#8b949e","padding":"2px 6px"}),
                    html.Td(html.Span(f.get("severity","-"),
                                     style={"color":sev_clr,"fontWeight":"700","fontSize":"9px"}),
                            style={"padding":"2px 6px"}),
                    html.Td(f.get("name","-")[:55], style={"fontSize":"9px","color":"#adbac7","padding":"2px 6px"}),
                    html.Td([
                        html.A(f.get("cve","-"), href=f"https://nvd.nist.gov/vuln/detail/{f.get('cve','')}",
                               target="_blank",
                               style={"color":"#58a6ff","fontSize":"9px","textDecoration":"none"})
                        if f.get("cve","-") != "-" else html.Span("-",style={"color":"#555","fontSize":"9px"})
                    ], style={"padding":"2px 6px"}),
                    html.Td(f.get("scanner","-"), style={"fontSize":"9px","color":"#555","padding":"2px 6px"}),
                ], style={"borderBottom":"1px solid #21262d"}))

            host_block = html.Div([
                # Host header
                html.Div([
                    html.Div([
                        html.Span("🖥 ", style={"fontSize":"12px"}),
                        html.Span(hostname, style={"color":"#fff","fontWeight":"700","fontSize":"12px","fontFamily":"monospace"}),
                        html.Span(f" ({ip})", style={"color":"#555","fontSize":"10px","marginLeft":"4px"}),
                        status_badge,
                        html.Span(f"  OS: {os_str}" if os_str else "",
                                  style={"color":"#555","fontSize":"9px","marginLeft":"10px"}),
                    ], style={"display":"flex","alignItems":"center","flexWrap":"wrap"}),
                    html.Div(tool_badges, style={"marginTop":"4px"}),
                ], style={"backgroundColor":"#111921","padding":"8px 14px",
                           "borderBottom":"1px solid #21262d"}),

                # Steps & findings in two columns
                dbc.Row([
                    # Kill chain steps (left)
                    dbc.Col([
                        html.Div([
                            html.Div("📍 Research Activity Log",
                                     style={"color":"#6e7681","fontSize":"9px","fontWeight":"700",
                                            "marginBottom":"6px","letterSpacing":"0.5px"}),
                            *steps,
                        ], style={"padding":"10px 14px"}),
                    ], md=5, style={"borderRight":"1px solid #161b22"}),

                    # Findings table (right)
                    dbc.Col([
                        html.Div([
                            html.Div("📊 Findings Researched",
                                     style={"color":"#6e7681","fontSize":"9px","fontWeight":"700",
                                            "marginBottom":"6px","letterSpacing":"0.5px"}),
                            html.Table([
                                html.Thead(html.Tr([
                                    html.Th("Service", style={"fontSize":"9px","color":"#555","padding":"2px 6px","fontWeight":"700"}),
                                    html.Th("Port",    style={"fontSize":"9px","color":"#555","padding":"2px 6px","fontWeight":"700"}),
                                    html.Th("Severity",style={"fontSize":"9px","color":"#555","padding":"2px 6px","fontWeight":"700"}),
                                    html.Th("Finding", style={"fontSize":"9px","color":"#555","padding":"2px 6px","fontWeight":"700"}),
                                    html.Th("CVE",     style={"fontSize":"9px","color":"#555","padding":"2px 6px","fontWeight":"700"}),
                                    html.Th("Scanner", style={"fontSize":"9px","color":"#555","padding":"2px 6px","fontWeight":"700"}),
                                ]), style={"borderBottom":"1px solid #21262d"}),
                                html.Tbody(finding_rows if finding_rows else [
                                    html.Tr([html.Td("No findings recorded yet", colSpan=6,
                                                     style={"color":"#555","fontSize":"9px","padding":"6px","textAlign":"center"})])
                                ]),
                            ], style={"width":"100%","borderCollapse":"collapse"}),
                        ], style={"padding":"10px 14px"}),
                    ], md=7),
                ], style={"margin":"0"}),
            ], style={"marginBottom":"4px","borderBottom":"2px solid #0d1117"})

            host_blocks.append(host_block)

    except Exception as e:
        print(f"[pe-research] Neo4j error: {e}")
        return html.Div(f"Unable to load research intelligence: {e}",
                        style={"color":"#555","fontSize":"11px","padding":"20px","textAlign":"center"})

    if not host_blocks:
        return html.Div("No targets in Neo4j yet. Run a scan to populate.",
                        style={"color":"#555","fontSize":"11px","padding":"20px","textAlign":"center"})

    return html.Div(host_blocks)
