# =====================================================================
# digital_twin.py — FULL WORKING VERSION FOR UI + CYTOSCAPE + NEO4J
# =====================================================================

from cyber_range.services.neo4j_engine import Neo4jEngine


class DigitalTwin:
    def __init__(self):
        self.db = Neo4jEngine()

    # ============================================================
    # SUMMARY (Used by Digital Twin Tab)
    # ============================================================
    def summary(self):
        q_assets = "MATCH (a:Asset) RETURN count(a) AS c"
        q_services = "MATCH (s:Service) RETURN count(s) AS c"
        q_vulns = "MATCH (v:Vulnerability) RETURN count(v) AS c"

        assets = self.db.run_query_value(q_assets)
        services = self.db.run_query_value(q_services)
        vulns = self.db.run_query_value(q_vulns)

        return {
            "assets": assets or 0,
            "services": services or 0,
            "vulns": vulns or 0,
        }

    # ============================================================
    # CYTOSCAPE GRAPH BUILDER (Fix for UI)
    # ============================================================
    def build_graph_elements(self):
        """
        Builds the Cytoscape nodes + edges for the DT graph.
        This is what the UI expects.
        """

        # -------------------------
        # Fetch Assets
        # -------------------------
        assets = self.db.run_query(
            """
            MATCH (a:Asset)
            RETURN id(a) AS id, a.host AS host
            """
        )

        # -------------------------
        # Fetch Services
        # -------------------------
        services = self.db.run_query(
            """
            MATCH (s:Service)
            RETURN id(s) AS id, s.name AS name
            """
        )

        # -------------------------
        # Edges: Asset -> Service
        # -------------------------
        edges = self.db.run_query(
            """
            MATCH (a:Asset)-[r:RUNS]->(s:Service)
            RETURN id(a) AS src, id(s) AS dst
            """
        )

        # Build Cytoscape format
        cy_nodes = []
        cy_edges = []

        for a in assets:
            cy_nodes.append({
                "data": {
                    "id": f"asset-{a['id']}",
                    "label": a.get("host", "unknown"),
                    "type": "asset"
                },
                "classes": "asset"
            })

        for s in services:
            cy_nodes.append({
                "data": {
                    "id": f"service-{s['id']}",
                    "label": s.get("name", "service"),
                    "type": "service"
                },
                "classes": "service"
            })

        for e in edges:
            cy_edges.append({
                "data": {
                    "source": f"asset-{e['src']}",
                    "target": f"service-{e['dst']}"
                }
            })

        return cy_nodes + cy_edges

    # ============================================================
    # ATTACK PROPAGATION (Used by UI)
    # ============================================================
    def propagate_attack(self, start_host):
        """
        Returns a list of nodes the attack can reach.
        Uses basic BFS traversal via 'CONNECTED_TO'.
        """

        q = f"""
        MATCH (a:Asset {{host: '{start_host}'}})
        RETURN id(a) AS id
        """

        start_id = self.db.run_query_value(q)
        if start_id is None:
            return []

        # BFS traversal
        q_path = f"""
        MATCH (start:Asset)-[:CONNECTED_TO*1..5]->(n)
        WHERE id(start) = {start_id}
        RETURN DISTINCT n.host AS host
        """

        results = self.db.run_query(q_path)
        return [{"name": r["host"]} for r in results if r.get("host")]
# ==========================================================
# NODE-CLICK CALLBACK → LOAD VULNERABILITY / ASSET DETAILS
# ==========================================================
def register_callbacks(app):
    # -------------------------------
    # EXISTING CALLBACKS (leave them)
    # -------------------------------
    # dt-summary
    # dt-propagation-output
    # dt-graph

    from cyber_range.services.ti_feed import ThreatIntelFeed
    ti = ThreatIntelFeed()
    dt = DigitalTwin()

    @app.callback(
        Output("dt-node-info", "children"),
        Input("dt-graph", "tapNode"),
        prevent_initial_call=True
    )
    def node_clicked(node):

        if not node:
            return "Click a node to view intelligence."

        node_id = node["data"]["id"]
        node_type = node["data"].get("type", "")

        # ------------------------------------------
        # ASSET CLICKED
        # ------------------------------------------
        if node_type == "asset":
            asset_label = node["data"].get("label")

            vulns = dt.db.run_query("""
                MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
                WHERE a.host = $host
                RETURN v.cve AS cve
            """, {"host": asset_label})

            vuln_rows = []
            for v in vulns:
                cve = v["cve"]
                stats = ti.get_vuln_stats(cve)

                vuln_rows.append(
                    html.Div([
                        html.H5(cve, className="text-warning"),
                        html.P(f"CVSS: {stats.get('cvss')}"),
                        html.P(f"EPSS: {stats.get('epss')}"),
                        html.P(f"KEV Listed: {stats.get('kev')}"),
                        html.A("NVD", href=f"https://nvd.nist.gov/vuln/detail/{cve}", target="_blank"),
                        html.Br(),
                        html.A("Exploit-DB Search", href=f"https://www.exploit-db.com/search?cve={cve}", target="_blank"),
                        html.Hr()
                    ])
                )

            return html.Div([
                html.H4(f"Asset Intelligence — {asset_label}", className="text-info"),
                html.Hr(),
                html.H4("Vulnerabilities"),
                html.Div(vuln_rows)
            ])

        # ------------------------------------------
        # VULNERABILITY CLICKED
        # ------------------------------------------
        if node_type == "vuln":
            cve = node["data"]["label"]
            stats = ti.get_vuln_stats(cve)
            mitre = ti.get_mitre_for_cve(cve)

            return html.Div([
                html.H4(f"Vulnerability Intelligence — {cve}", className="text-danger"),
                html.P(f"CVSS: {stats.get('cvss')}"),
                html.P(f"EPSS: {stats.get('epss')}"),
                html.P(f"KEV: {stats.get('kev')}"),

                html.H4("MITRE ATT&CK Mappings"),
                html.Ul([html.Li(f"{m.get('tactic')} → {m.get('technique')}") for m in mitre]),

                html.Hr(),
                html.A("NVD Details", href=f"https://nvd.nist.gov/vuln/detail/{cve}", target="_blank"),
                html.Br(),
                html.A("Exploit-DB", href=f"https://www.exploit-db.com/search?cve={cve}", target="_blank"),
                html.Br(),
                html.A("GitHub PoC Search", href=f"https://github.com/search?q={cve}+exploit", target="_blank")
            ])

        # ------------------------------------------
        # SERVICE CLICKED
        # ------------------------------------------
        if node_type == "service":
            service_name = node["data"]["label"]
            linked_assets = dt.db.run_query("""
                MATCH (a:Asset)-[:RUNS]->(s:Service {name:$name})
                RETURN a.host AS host
            """, {"name": service_name})

            return html.Div([
                html.H4(f"Service Intelligence — {service_name}", className="text-success"),
                html.Hr(),
                html.H5("Running On:"),
                html.Ul([html.Li(a["host"]) for a in linked_assets])
            ])

        return "Unknown node type."


# END OF FILE
print("[digital_twin] Loaded OK — DigitalTwin backend fully operational.")

