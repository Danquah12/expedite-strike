"""
graph_ingest.py
───────────────
Unified Neo4j ingestion engine — normalises PingCastle, Nmap, and BloodHound
data into a single graph model:

  (:User)   (:Computer)  (:Group)  (:Domain)
  (:Vulnerability)  (:Port)  (:Service)

  (:User)-[:MEMBER_OF]->(:Group)
  (:User)-[:HAS_ACCESS_TO]->(:Computer)
  (:User)-[:HAS_VULN]->(:Vulnerability)
  (:Computer)-[:HAS_PORT]->(:Port)
  (:Port)-[:RUNS]->(:Service)
  (:Computer)-[:HAS_VULN]->(:Vulnerability)
"""

from __future__ import annotations
import os
import logging
from datetime import datetime
from neo4j import GraphDatabase

log = logging.getLogger("graph_ingest")

NEO4J_URI  = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "Adomaa12@")


class GraphIngest:
    """Merge multi-tool scan data into the unified Neo4j graph."""

    def __init__(self, uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    # ── Schema bootstrap ──────────────────────────────────────────────────────
    def init_schema(self):
        """Create constraints + indexes for the unified graph."""
        with self.driver.session() as s:
            for stmt in [
                "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User)          REQUIRE u.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Computer)      REQUIRE c.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (g:Group)         REQUIRE g.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain)        REQUIRE d.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability)  REQUIRE v.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Port)           REQUIRE (p.host, p.port) IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (sv:Service)       REQUIRE sv.id IS UNIQUE",
            ]:
                try:
                    s.run(stmt)
                except Exception as e:
                    log.debug(f"Schema note: {e}")
        log.info("✅ Unified graph schema initialised")

    # ── PingCastle ingestion ──────────────────────────────────────────────────
    def ingest_pingcastle(self, risks: list, domain: str = "expedite.local"):
        """
        risks = [{"id": "S-C-Kerberoast", "level": "Critical", "title": "...", "score": 10}]
        """
        if not risks:
            return
        ts = datetime.utcnow().isoformat()
        with self.driver.session() as s:
            # Ensure Domain node exists
            s.run("""
                MERGE (d:Domain {id: $domain})
                SET d.name = $domain, d.updated = $ts
            """, domain=domain, ts=ts)

            for r in risks:
                s.run("""
                    MERGE (v:Vulnerability {id: $id})
                    SET v.title      = $title,
                        v.level      = $level,
                        v.score      = $score,
                        v.source     = 'PingCastle',
                        v.updated    = $ts
                    WITH v
                    MATCH (d:Domain {id: $domain})
                    MERGE (d)-[:HAS_VULN]->(v)
                """,
                id=r.get("id", r.get("title", "unknown")),
                title=r.get("title", ""),
                level=r.get("level", "Unknown"),
                score=r.get("score", 0),
                domain=domain, ts=ts)
        log.info(f"✅ PingCastle: {len(risks)} risks ingested into Neo4j")

    # ── Nmap ingestion ────────────────────────────────────────────────────────
    def ingest_nmap(self, ports: list):
        """
        ports = [{"host": "192.168.1.10", "port": "445", "service": "microsoft-ds",
                  "product": "Microsoft Windows", "version": ""}]
        """
        if not ports:
            return
        ts = datetime.utcnow().isoformat()
        # Ports that massively increase attack surface
        HIGH_RISK_PORTS = {"445", "389", "636", "88", "3389", "5985", "5986",
                           "23", "21", "2049", "1433", "3306"}
        with self.driver.session() as s:
            for p in ports:
                host    = p.get("host", "unknown")
                portnum = str(p.get("port", "0"))
                svc     = p.get("service", "unknown")
                product = p.get("product", "")
                version = p.get("version", "")
                risk    = "High" if portnum in HIGH_RISK_PORTS else "Medium"

                # Computer node
                s.run("""
                    MERGE (c:Computer {id: $host})
                    SET c.ip = $host, c.updated = $ts
                """, host=host, ts=ts)

                # Port node
                s.run("""
                    MERGE (pt:Port {host: $host, port: $port})
                    SET pt.risk = $risk, pt.updated = $ts
                    WITH pt
                    MATCH (c:Computer {id: $host})
                    MERGE (c)-[:HAS_PORT]->(pt)
                """, host=host, port=portnum, risk=risk, ts=ts)

                # Service node
                svc_id = f"{svc}:{portnum}"
                s.run("""
                    MERGE (sv:Service {id: $svcid})
                    SET sv.name = $svc, sv.product = $product, sv.version = $ver
                    WITH sv
                    MATCH (pt:Port {host: $host, port: $port})
                    MERGE (pt)-[:RUNS]->(sv)
                """, svcid=svc_id, svc=svc, product=product, ver=version,
                     host=host, port=portnum)
        log.info(f"✅ Nmap: {len(ports)} ports ingested into Neo4j")

    # ── BloodHound raw ingestion ──────────────────────────────────────────────
    def ingest_bloodhound(self, nodes: list, links: list):
        """
        nodes = [{"id": "user@domain", "type": "User", "name": "john.doe"}]
        links = [{"source": "user@domain", "target": "Domain Admins", "rel": "MemberOf"}]
        """
        if not nodes and not links:
            return
        ts = datetime.utcnow().isoformat()
        _TYPE_LABEL = {
            "User": "User", "Group": "Group", "Computer": "Computer",
            "Domain": "Domain", "GPO": "GPO", "OU": "OU",
        }
        with self.driver.session() as s:
            for n in nodes:
                ntype = _TYPE_LABEL.get(n.get("type", "User"), "User")
                s.run(f"""
                    MERGE (n:{ntype} {{id: $id}})
                    SET n.name    = $name,
                        n.source  = 'BloodHound',
                        n.updated = $ts
                """, id=n["id"], name=n.get("name", n["id"]), ts=ts)

            for lnk in links:
                rel = lnk.get("rel", "REL").replace(" ", "_")
                s.run(f"""
                    MATCH (a {{id: $src}}), (b {{id: $dst}})
                    MERGE (a)-[:{rel}]->(b)
                """, src=lnk["source"], dst=lnk["target"])
        log.info(f"✅ BloodHound: {len(nodes)} nodes, {len(links)} links ingested")

    # ── Query helpers ─────────────────────────────────────────────────────────
    def get_da_paths(self, limit: int = 10) -> list:
        """Return shortest paths from any User to Domain Admins."""
        with self.driver.session() as s:
            result = s.run("""
                MATCH p=shortestPath(
                    (u:User)-[*1..8]->(g:Group)
                )
                WHERE toLower(g.name) CONTAINS 'domain admin'
                   OR toLower(g.name) CONTAINS 'domain admins'
                RETURN [n IN nodes(p) | coalesce(n.name, n.id)] AS path,
                       length(p) AS hops
                ORDER BY hops ASC
                LIMIT $limit
            """, limit=limit)
            return [dict(r) for r in result]

    def get_high_risk_ports(self) -> list:
        """Computers with critical open ports."""
        with self.driver.session() as s:
            result = s.run("""
                MATCH (c:Computer)-[:HAS_PORT]->(pt:Port {risk:'High'})
                RETURN c.ip AS host, collect(pt.port) AS ports
                ORDER BY size(collect(pt.port)) DESC
                LIMIT 20
            """)
            return [dict(r) for r in result]

    def get_vuln_summary(self) -> dict:
        """Count vulnerabilities by level."""
        with self.driver.session() as s:
            result = s.run("""
                MATCH (v:Vulnerability)
                RETURN v.level AS level, count(v) AS cnt
            """)
            return {r["level"]: r["cnt"] for r in result}

    def get_total_node_counts(self) -> dict:
        """Quick summary of graph size."""
        with self.driver.session() as s:
            result = s.run("""
                MATCH (n)
                RETURN labels(n)[0] AS label, count(n) AS cnt
            """)
            return {r["label"]: r["cnt"] for r in result if r["label"]}
