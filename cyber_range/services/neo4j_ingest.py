# cyber_range/services/neo4j_ingest.py

from cyber_range.services.neo4j_engine import Neo4jEngine
from cyber_range.services.ti_feed import ThreatIntelFeed

ti = ThreatIntelFeed()


class Neo4jIngestor:

    def __init__(self):
        self.db = Neo4jEngine()

    # ==========================================================
    # MAIN ENTRY: INGEST PARSED DATAFRAME
    # ==========================================================
    def ingest_dataframe(self, df):
        """
        DataFrame must contain columns:
        - asset  (IP / hostname)
        - name/plugin/service
        - severity
        - cve (optional)

        After ingestion, CONNECTED edges will be built between
        assets on the same /24 subnet.
        """

        discovered_hosts = set()

        for _, row in df.iterrows():
            asset = str(row.get("asset", "Unknown")).strip()
            name  = str(row.get("name") or row.get("plugin") or row.get("service") or "Unknown").replace("'", "")
            sev   = str(row.get("severity", "unknown"))
            cve   = row.get("cve", None)

            discovered_hosts.add(asset)

            # --------------------------------------------------
            # ASSET NODE — use HOST, never IP
            # --------------------------------------------------
            self.db.run_query(f"""
                MERGE (a:Asset {{host:'{asset}'}})
                ON CREATE SET a.first_seen = timestamp()
                SET a.last_seen = timestamp();
            """)

            # --------------------------------------------------
            # VULNERABILITY NODE
            # --------------------------------------------------
            self.db.run_query(f"""
                MERGE (v:Vulnerability {{name:'{name}'}})
                SET v.severity = '{sev}';
            """)

            # --------------------------------------------------
            # RELATIONSHIP: Asset -> Vulnerability
            # --------------------------------------------------
            self.db.run_query(f"""
                MATCH (a:Asset {{host:'{asset}'}})
                MATCH (v:Vulnerability {{name:'{name}'}})
                MERGE (a)-[:HAS_VULN]->(v);
            """)

            # --------------------------------------------------
            # CVE Mapping + MITRE Integration
            # --------------------------------------------------
            if cve and cve != "None":
                kev = ti.check_kev(cve)
                epss_score = ti.get_epss(cve) or 0.0
                mitre_techs = ti.map_cve_to_mitre(cve)

                # CVE Node
                self.db.run_query(f"""
                    MERGE (c:CVE {{id:'{cve}'}})
                    SET c.epss={epss_score},
                        c.kev={kev},
                        c.last_seen = timestamp();
                """)

                # Link Vulnerability → CVE
                self.db.run_query(f"""
                    MATCH (v:Vulnerability {{name:'{name}'}})
                    MATCH (c:CVE {{id:'{cve}'}})
                    MERGE (v)-[:HAS_CVE]->(c);
                """)

                # Map CVE → MITRE Techniques
                for tech in mitre_techs:
                    self.db.run_query(f"""
                        MERGE (t:Technique {{id:'{tech}'}})
                        MERGE (c:CVE {{id:'{cve}'}})
                        MERGE (c)-[:MAPS_TO]->(t);
                    """)

        # ------------------------------------------------------
        # BUILD CONNECTED EDGES (Digital Twin)
        # ------------------------------------------------------
        self.build_connected_edges(list(discovered_hosts))

        return True

    # ==========================================================
    # NETWORK GRAPH — CONNECTED EDGES
    # ==========================================================
    def build_connected_edges(self, hosts):
        """
        Simple heuristic:
        All hosts in the same /24 subnet are CONNECTED.
        """

        if len(hosts) < 2:
            return

        from itertools import combinations

        try:
            base_subnet = hosts[0].rsplit(".", 1)[0]
        except Exception:
            return

        same_subnet = [h for h in hosts if h.startswith(base_subnet)]

        for a, b in combinations(same_subnet, 2):
            self.db.run_query("""
                MATCH (x:Asset {host:$a}), (y:Asset {host:$b})
                MERGE (x)-[:CONNECTED]->(y)
                MERGE (y)-[:CONNECTED]->(x);
            """, {"a": a, "b": b})

        print(f"[+] CONNECTED relationships created for {len(same_subnet)} hosts in subnet {base_subnet}.")
        return True

    # ==========================================================
    # CLEAR GRAPH
    # ==========================================================
    def clear_graph(self):
        self.db.run_query("MATCH (n) DETACH DELETE n;")
        print("[+] Neo4j graph wiped clean.")
