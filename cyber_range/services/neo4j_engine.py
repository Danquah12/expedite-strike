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

    def sync_findings_and_topology(self, hosts=None, findings=None, attack_paths=None):
        """Sync discovered hosts, open ports, vulnerabilities, and attack paths to Neo4j."""
        if self._is_mock():
            return False
        try:
            with self.driver.session() as session:
                # 1. Ingest Hosts & Ports
                for h in (hosts or []):
                    ip = h.get("ip", "")
                    if not ip: continue
                    hostname = h.get("hostname", ip)
                    os_name = h.get("os", "Windows / Linux Host")
                    session.run("""
                        MERGE (h:Host {ip: $ip})
                        SET h:Asset, h.host = $ip, h.name = $hostname, h.hostname = $hostname, h.os = $os_name, h.last_seen = datetime()
                    """, ip=ip, hostname=hostname, os_name=os_name)

                    for p in h.get("ports", []):
                        port_num = p.get("port", p) if isinstance(p, dict) else p
                        svc_name = p.get("service", f"port-{port_num}") if isinstance(p, dict) else f"port-{port_num}"
                        session.run("""
                            MATCH (h:Host {ip: $ip})
                            MERGE (s:Service {port: $port, host: $ip})
                            SET s.name = $svc_name, s.service = $svc_name
                            MERGE (h)-[:RUNS_SERVICE]->(s)
                            MERGE (h)-[:EXPOSES]->(s)
                            MERGE (h)-[:HasService]->(s)
                        """, ip=ip, port=port_num, svc_name=svc_name)

                # 2. Ingest Findings
                for f in (findings or []):
                    host_raw = f.get("host", "127.0.0.1")
                    host_clean = str(host_raw).replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]
                    if not host_clean: continue

                    title = f.get("title", "Vulnerability Finding")
                    sev = f.get("severity", "Medium")
                    cvss_val = float(f.get("cvss", 10.0 if sev == "Critical" else 7.5 if sev == "High" else 5.0 if sev == "Medium" else 2.0))
                    mitre_id = f.get("mitre_id", "T1046")
                    src = str(f.get("module", f.get("scanner", "autopentest"))).lower()
                    cve_val = f.get("cve", title if "CVE-" in title else None)

                    session.run("""
                        MERGE (h:Host {ip: $host})
                        SET h:Asset, h.host = $host, h.last_seen = datetime()

                        MERGE (f:Finding {title: $title, host: $host})
                        SET f:Vulnerability, f.name = $title, f.severity = $sev, f.cvss = $cvss_val,
                            f.source = $src, f.description = $desc, f.mitre_id = $mitre_id,
                            f.exploitable = ($status = 'CONFIRMED' OR $sev IN ['Critical', 'High']),
                            f.cve = $cve_val, f.first_seen = datetime()

                        MERGE (h)-[:HAS_FINDING]->(f)
                        MERGE (h)-[:HAS_VULN]->(f)
                        MERGE (h)-[:HAS_VULNERABILITY]->(f)
                    """, host=host_clean, title=title, sev=sev, cvss_val=cvss_val,
                         src=src, desc=f.get("description", ""), mitre_id=mitre_id,
                         status=f.get("status", "POTENTIAL"), cve_val=cve_val)

                    if mitre_id and mitre_id.startswith("T"):
                        session.run("""
                            MATCH (f:Finding {title: $title, host: $host})
                            MERGE (t:Technique {id: $mitre_id})
                            SET t.name = $mitre_id
                            MERGE (f)-[:USES_TECHNIQUE]->(t)
                        """, title=title, host=host_clean, mitre_id=mitre_id)

                # 3. Create Network Interconnections between scanned subnet hosts
                session.run("""
                    MATCH (a:Host), (b:Host)
                    WHERE a.ip <> b.ip AND a.ip STARTS WITH split(b.ip, '.')[0] + '.' + split(b.ip, '.')[1] + '.' + split(b.ip, '.')[2]
                    MERGE (a)-[:CONNECTED]-(b)
                """)

                # 4. Attack Paths
                for path in (attack_paths or []):
                    src = path.get("source", path.get("src", ""))
                    dst = path.get("target", path.get("dst", ""))
                    tech = path.get("technique", "Lateral Movement")
                    if src and dst:
                        session.run("""
                            MATCH (a:Host {ip: $src}), (b:Host {ip: $dst})
                            MERGE (a)-[r:ATTACK_PATH {technique: $tech}]->(b)
                        """, src=src, dst=dst, tech=tech)
            return True
        except Exception as e:
            print(f"[Neo4j Sync] Error: {e}")
            return False

    @property
    def is_mock(self):
        return self._is_mock()


# ── Singleton ───────────────────────────────────────────────────────────────────
neo4j = Neo4jEngine()
