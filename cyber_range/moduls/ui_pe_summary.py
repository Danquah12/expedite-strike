"""
Post-Exploitation Success Summary Callback
Populates the summary panel below the live lateral movement / privesc feeds.
"""
import dash
from dash import callback, Output, Input, html
from dash.exceptions import PreventUpdate


@callback(
    Output("pe-sum-lateral-count",  "children"),
    Output("pe-sum-lateral-detail", "children"),
    Output("pe-sum-privesc-count",  "children"),
    Output("pe-sum-privesc-detail", "children"),
    Output("pe-sum-postex-count",   "children"),
    Output("pe-sum-postex-detail",  "children"),
    Output("pe-sum-exec-text",      "children"),
    Input("apt-exploit-timer",      "n_intervals"),
    prevent_initial_call=False,
)
def update_pe_success_summary(n):
    """Populate the dual-audience Post-Exploitation Success Summary panel."""
    lat_count, priv_count, pex_count = 0, 0, 0
    proto_tally  = {}
    unique_priv  = []
    action_tally = {}

    try:
        from cyber_range.services.neo4j_engine import Neo4jEngine
        ng = Neo4jEngine()
        with ng.driver.session() as s:

            # ── Lateral Movement ──────────────────────────────────────────────
            lat_data = s.run("""
                MATCH (src:Host)-[r:LATERAL_MOVE|PIVOTED_TO|CONNECTED_TO]->(dst:Host)
                RETURN src.ip AS src, dst.ip AS dst,
                       coalesce(r.protocol, r.method, 'Unknown') AS proto,
                       coalesce(r.success, true) AS success
                ORDER BY src
            """).data()
            lat_succ  = [r for r in lat_data if r.get("success", True)]
            lat_count = len(set(r["dst"] for r in lat_succ))
            for r in lat_succ:
                p = (r.get("proto") or "Unknown").upper()
                proto_tally[p] = proto_tally.get(p, 0) + 1

            # ── Privilege Escalation ──────────────────────────────────────────
            priv_data = s.run("""
                MATCH (h:Host)-[r:ESCALATED_TO|PRIVESC|HAS_ROOT]->(n)
                RETURN h.ip AS host,
                       coalesce(r.technique, r.method, 'Unknown') AS technique,
                       coalesce(r.from_user, '?')             AS from_user,
                       coalesce(r.to_user,   'root/SYSTEM')   AS to_user
                UNION
                MATCH (h:Host)
                WHERE h.root_access = true OR h.admin_access = true
                RETURN h.ip AS host, 'Confirmed root/admin access' AS technique,
                       '-' AS from_user, 'root/SYSTEM' AS to_user
            """).data()
            seen_priv = set()
            for r in priv_data:
                key = r.get("host", "")
                if key not in seen_priv:
                    seen_priv.add(key)
                    unique_priv.append(r)
            priv_count = len(seen_priv)

            # ── Post-Exploitation ─────────────────────────────────────────────
            pex_data = s.run("""
                MATCH (h:Host)
                WHERE h.compromised = true
                   OR EXISTS {MATCH (h)-[:COMPROMISED_VIA]->()}
                   OR EXISTS {MATCH (h)-[:HAS_FINDING]->(f:Finding)
                              WHERE f.severity IN ['Critical','High']}
                OPTIONAL MATCH (h)-[r:HAS_SESSION|EXFILTRATED|PERSISTED]->(x)
                RETURN h.ip AS host, collect(DISTINCT type(r)) AS actions
                ORDER BY host
            """).data()
            pex_count = len(set(r["host"] for r in pex_data if r.get("host")))
            for r in pex_data:
                for a in (r.get("actions") or []):
                    action_tally[a] = action_tally.get(a, 0) + 1

        ng.driver.close()
    except Exception as e:
        print(f"[pe-summary] Neo4j error: {e}")

    # ── Helper ──────────────────────────────────────────────────────────────────
    def _bullet(label, val, color="#8b949e"):
        return html.Div([
            html.Span("- ", style={"color": color}),
            html.Span(f"{label}: ", style={"color":"#adbac7"}),
            html.Span(str(val), style={"color": color, "fontWeight":"600"}),
        ], style={"fontSize":"10px","lineHeight":"1.7"})

    # ── Lateral detail ──────────────────────────────────────────────────────────
    if proto_tally:
        lat_detail = [_bullet(p, f"{c} pivot(s)", "#f5a742") for p, c in proto_tally.items()]
        lat_detail += [_bullet("Unique hosts reached", lat_count, "#f5a742")]
    else:
        lat_detail = [html.Div("No lateral movement detected yet.",
                               style={"fontSize":"10px","color":"#555","fontStyle":"italic"})]

    # ── PrivEsc detail ──────────────────────────────────────────────────────────
    if unique_priv:
        techs = {}
        for r in unique_priv:
            t = r.get("technique","Unknown")
            techs[t] = techs.get(t, 0) + 1
        priv_detail = [_bullet(t, f"{c} host(s)", "#c084fc") for t, c in techs.items()]
        priv_detail += [_bullet("Achieved SYSTEM/root on", priv_count, "#c084fc")]
    else:
        priv_detail = [html.Div("No privilege escalation recorded.",
                                style={"fontSize":"10px","color":"#555","fontStyle":"italic"})]

    # ── Post-Exploitation detail ────────────────────────────────────────────────
    if action_tally:
        pex_detail = [_bullet(a.replace("_"," ").title(), f"{c} host(s)", "#ff4444")
                      for a, c in action_tally.items()]
        pex_detail += [_bullet("Fully compromised hosts", pex_count, "#ff4444")]
    else:
        pex_detail = [_bullet("Hosts meeting compromise criteria", pex_count, "#ff4444"),
                      html.Div("(h.compromised / critical findings criteria)",
                               style={"fontSize":"9px","color":"#555","fontStyle":"italic"})]

    # ── Executive Summary ───────────────────────────────────────────────────────
    if pex_count == 0 and lat_count == 0 and priv_count == 0:
        exec_txt = (
            "No successful post-exploitation activity has been recorded. "
            "The red team has not yet achieved lateral movement, privilege escalation, "
            "or host compromise. The environment appears resilient to the tested attack paths."
        )
    else:
        parts = []
        if lat_count:
            protos = ", ".join(proto_tally.keys()) or "unknown protocol"
            parts.append(
                f"The red team successfully pivoted to {lat_count} host(s) via {protos}, "
                f"demonstrating that internal network segmentation can be bypassed."
            )
        if priv_count:
            parts.append(
                f"Privilege escalation to root / SYSTEM was confirmed on {priv_count} host(s), "
                f"meaning an attacker has gained full administrative control over those machines."
            )
        if pex_count:
            parts.append(
                f"{pex_count} host(s) are classified as fully compromised — "
                f"the attacker at this stage has persistent access and the ability to "
                f"exfiltrate data, deploy ransomware, or propagate further undetected."
            )
        if not parts:
            parts = ["Activity detected but no definitive success criteria met yet."]
        exec_txt = "  ".join(parts)

    return (
        str(lat_count),  lat_detail,
        str(priv_count), priv_detail,
        str(pex_count),  pex_detail,
        exec_txt,
    )
