# cyber_range/services/neo4j_engine.py
# Auto-falls-back to MockNeo4jEngine when bolt:7687 is unreachable.

import os
import socket


def _neo4j_reachable(host="127.0.0.1", port=7687, timeout=1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Neo4jEngine:
    def __init__(self):
        uri  = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER",      "neo4j")
        pwd  = os.getenv("NEO4J_PASSWORD",  "Adomaa12@")

        try:
            from cyber_range.services.vault_client import get_neo4j_creds
            uri, user, pwd = get_neo4j_creds()
        except Exception:
            pass

        # Parse host/port from bolt URI for reachability check
        _uri_host = uri.replace("bolt://", "").split(":")[0]
        _uri_port = int(uri.replace("bolt://", "").split(":")[-1]) if ":" in uri.replace("bolt://","") else 7687

        if not _neo4j_reachable(_uri_host, _uri_port):
            from cyber_range.services.neo4j_mock import MockNeo4jEngine
            self._delegate = MockNeo4jEngine()
            self._mock = True
            print("[Neo4j] ⚠ Bolt unreachable — using in-memory mock graph (demo data)")
            return

        from neo4j import GraphDatabase
        self.driver = GraphDatabase.driver(uri, auth=(user, pwd))
        self._delegate = None
        self._mock = False

    # ── Delegation helpers ──────────────────────────────────────────────────────
    def _is_mock(self):
        return getattr(self, "_mock", False)

    # ── RAW QUERY ───────────────────────────────────────────────────────────────
    def run_query(self, query, params=None, **kwargs):
        if self._is_mock():
            return self._delegate.run_query(query, params, **kwargs)
        final = {**(params or {}), **kwargs}
        with self.driver.session() as session:
            return list(session.run(query, final))

    def run_query_simple(self, query, params=None, **kwargs):
        if self._is_mock():
            return self._delegate.run_query_simple(query, params, **kwargs)
        final = {**(params or {}), **kwargs}
        with self.driver.session() as session:
            out = []
            for record in session.run(query, final):
                out.extend(record.values())
            return out

    # ── COMPAT WRAPPERS ─────────────────────────────────────────────────────────
    def query(self, query, params=None, **kwargs):
        return self.run_query(query, params, **kwargs)

    def query_simple(self, query, params=None, **kwargs):
        return self.run_query_simple(query, params, **kwargs)

    # ── SPECIAL QUERIES ─────────────────────────────────────────────────────────
    def get_shortest_path(self, start_host, target_host):
        if self._is_mock():
            return self._delegate.get_shortest_path(start_host, target_host)
        cypher = """
        MATCH (a:Host {ip:$start})
        MATCH (b:Host {ip:$target})
        OPTIONAL MATCH p = shortestPath((a)-[:CONNECTED*1..10]->(b))
        RETURN p AS path
        """
        result = self.run_query(cypher, start=start_host, target=target_host)
        return result[0].get("path") if result else None

    def get_full_graph(self):
        if self._is_mock():
            return self._delegate.get_full_graph()
        return self.run_query("MATCH (n)-[r]->(m) RETURN n, type(r) AS r, m LIMIT 500")

    def get_neighbors(self, host):
        if self._is_mock():
            return self._delegate.get_neighbors(host)
        cypher = "MATCH (a:Asset {host:$host})-[:CONNECTED]->(b) RETURN b.host AS neighbor"
        return self.run_query_simple(cypher, host=host)

    def get_connected_assets(self, host, depth=4):
        if self._is_mock():
            return [h["ip"] for h in self._delegate.get_mock_hosts() if h["ip"] != host]
        cypher = f"""
        MATCH (a:Asset {{host:$host}})
        MATCH p = (a)-[:CONNECTED*1..{depth}]->(b)
        RETURN DISTINCT b.host AS host
        """
        return self.run_query_simple(cypher, host=host)

    def test_connection(self):
        if self._is_mock():
            return False
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS ok").single()
                print("[Neo4j] Connected OK")
                return result["ok"] == 1
        except Exception as e:
            print(f"[Neo4j] Connection failed: {e}")
            return False

    @property
    def is_mock(self):
        return self._is_mock()


# ── Singleton ───────────────────────────────────────────────────────────────────
neo4j = Neo4jEngine()
