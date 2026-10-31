# cyber_range/services/neo4j_engine.py

from neo4j import GraphDatabase
import os


class Neo4jEngine:
    def __init__(self):
        # ── Credentials from Vault (falls back to env / .env / hardcoded) ──
        try:
            from cyber_range.services.vault_client import get_neo4j_creds
            uri, user, pwd = get_neo4j_creds()
        except Exception:
            uri  = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
            user = os.getenv("NEO4J_USER",      "neo4j")
            pwd  = os.getenv("NEO4J_PASSWORD",  "Adomaa12@")

        self.driver = GraphDatabase.driver(uri, auth=(user, pwd))

    # ==============================================================
    # RAW QUERY – accepts params dict OR keyword args
    # ==============================================================
    def run_query(self, query, params=None, **kwargs):
        """
        Execute a Cypher query.

        Supports:
          - run_query(query, {"host": host})
          - run_query(query, host=host, v=vuln, cve=cve)
          - run_query(query, params_dict, extra=value)

        Returns a list of Neo4j Record objects.
        """
        final_params = {}

        if params:
            if not isinstance(params, dict):
                raise ValueError("params must be a dict if provided")
            final_params.update(params)

        if kwargs:
            final_params.update(kwargs)

        with self.driver.session() as session:
            return list(session.run(query, final_params))

    # ==============================================================
    # SIMPLE QUERY – flattened values (same param handling)
    # ==============================================================
    def run_query_simple(self, query, params=None, **kwargs):
        final_params = {}

        if params:
            if not isinstance(params, dict):
                raise ValueError("params must be a dict if provided")
            final_params.update(params)

        if kwargs:
            final_params.update(kwargs)

        with self.driver.session() as session:
            results = []
            for record in session.run(query, final_params):
                results.extend(record.values())
            return results

    # ==============================================================
    # BACKWARD-COMPATIBILITY WRAPPERS
    # ==============================================================
    def query(self, query, params=None, **kwargs):
        return self.run_query(query, params, **kwargs)

    def query_simple(self, query, params=None, **kwargs):
        return self.run_query_simple(query, params, **kwargs)

    # ==============================================================
    # SHORTEST PATH (used by Exploit AI and Wargame AI)
    # ==============================================================
    def get_shortest_path(self, start_host, target_host):
        cypher = """
        MATCH (a:Host {ip:$start})
        MATCH (b:Host {ip:$target})
        OPTIONAL MATCH p = shortestPath((a)-[:CONNECTED*1..10]->(b))
        RETURN p AS path
        """

        result = self.run_query(
            cypher,
            start=start_host,
            target=target_host
        )

        return result[0].get("path") if result else None

    # ==============================================================
    # GET FULL GRAPH (used by Wargame AI)
    # ==============================================================
    def get_full_graph(self):
        cypher = """
        MATCH (n)-[r]->(m)
        RETURN n, type(r) AS r, m LIMIT 500
        """
        return self.run_query(cypher)

    # ==============================================================
    # GET DIRECT NEIGHBORS
    # ==============================================================
    def get_neighbors(self, host):
        cypher = """
        MATCH (a:Asset {host:$host})-[:CONNECTED]->(b)
        RETURN b.host AS neighbor
        """
        return self.run_query_simple(cypher, host=host)

    # ==============================================================
    # GET CONNECTED ASSETS
    # ==============================================================
    def get_connected_assets(self, host, depth=4):
        cypher = f"""
        MATCH (a:Asset {{host:$host}})
        MATCH p = (a)-[:CONNECTED*1..{depth}]->(b)
        RETURN DISTINCT b.host AS host
        """
        return self.run_query_simple(cypher, host=host)

    # ==============================================================
    # TEST CONNECTION
    # ==============================================================
    def test_connection(self):
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS ok").single()
                print("[Neo4j] Connected OK")
                return result["ok"] == 1
        except Exception as e:
            print(f"[Neo4j] Connection failed: {e}")
            return False


# ==============================================================
# DEFAULT ENGINE INSTANCE
# ==============================================================
neo4j = Neo4jEngine()
