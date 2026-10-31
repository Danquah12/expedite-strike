"""
web_enum_ingest.py
==================
Parses output from the WebEnumerationEngine stages and ingests
findings into Neo4j as:

  Asset {host: <target>}
  Service {id: <target:port>, port, protocol, name, source: 'web-enum'}
  Finding {id, name, severity, source: 'web-enum', url, path, tech, ...}

  Relationships:
    (Asset)-[:RUNS_SERVICE]->(Service)
    (Service)-[:HAS_FINDING]->(Finding)
"""

import hashlib
from datetime import datetime, timezone


class WebEnumIngest:
    """Ingest web recon results into Neo4j."""

    NEO4J_URI  = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASS = "Adomaa12@"

    def __init__(self):
        from neo4j import GraphDatabase
        self._drv = GraphDatabase.driver(
            self.NEO4J_URI, auth=(self.NEO4J_USER, self.NEO4J_PASS)
        )

    def ingest(
        self,
        target: str,
        url: str,
        techs: list[str],
        urls: list[str],
        nuclei_findings: list[dict],
        ffuf_findings: list[dict],
        on_output=print,
    ) -> int:
        """
        Ingest all web recon data. Returns total finding count written.
        """
        now = datetime.now(timezone.utc).isoformat()
        host = self._extract_host(url)
        port = "443" if url.startswith("https") else "80"
        proto = "https" if port == "443" else "http"
        svc_id = f"{host}:{port}:web-enum"
        count = 0

        with self._drv.session() as s:
            # ── Ensure Asset + Service nodes ─────────────────────────
            s.run("""
                MERGE (a:Asset {host: $host})
                SET a.last_seen = $now, a.source = 'web-enum'
                MERGE (sv:Service {id: $svc_id})
                SET sv.port = $port, sv.protocol = $proto,
                    sv.name = 'web', sv.source = 'web-enum',
                    sv.last_seen = $now
                MERGE (a)-[:RUNS_SERVICE]->(sv)
            """, host=host, svc_id=svc_id, port=port, proto=proto, now=now)

            # ── Store tech stack as a single informational finding ───
            if techs:
                tech_str = ", ".join(sorted(set(techs)))
                fid = f"web-enum:tech:{host}"
                s.run("""
                    MATCH (sv:Service {id: $svc_id})
                    MERGE (f:Finding {id: $fid})
                    SET f.name     = 'Technology Stack Detected',
                        f.severity = 'Information',
                        f.source   = 'web-enum',
                        f.host     = $host,
                        f.url      = $url,
                        f.tech     = $tech,
                        f.first_seen = $now
                    MERGE (sv)-[:HAS_FINDING]->(f)
                """, svc_id=svc_id, fid=fid, host=host, url=url,
                     tech=tech_str, now=now)
                count += 1

            # ── Nuclei findings ───────────────────────────────────────
            for nf in nuclei_findings:
                try:
                    info = nf.get("info", {})
                    matched_url = nf.get("matched-at", url)
                    fid = "web-enum:nuclei:" + hashlib.md5(
                        f"{host}:{info.get('name','')}:{matched_url}".encode()
                    ).hexdigest()[:12]

                    s.run("""
                        MATCH (sv:Service {id: $svc_id})
                        MERGE (f:Finding {id: $fid})
                        SET f.name       = $name,
                            f.severity   = $severity,
                            f.source     = 'web-enum',
                            f.scanner    = 'nuclei',
                            f.host       = $host,
                            f.url        = $url,
                            f.path       = $path,
                            f.template   = $template,
                            f.cve        = $cve,
                            f.description= $desc,
                            f.first_seen = $now
                        MERGE (sv)-[:HAS_FINDING]->(f)
                    """,
                    svc_id   = svc_id,
                    fid      = fid,
                    name     = info.get("name", "Nuclei Finding"),
                    severity = info.get("severity", "medium").capitalize(),
                    host     = host,
                    url      = matched_url,
                    path     = nf.get("path", ""),
                    template = nf.get("template-id", ""),
                    cve      = ", ".join(info.get("classification", {}).get("cve-id", [])),
                    desc     = info.get("description", ""),
                    now      = now,
                    )
                    count += 1
                except Exception:
                    pass

            # ── ffuf directory findings ───────────────────────────────
            for ff in ffuf_findings:
                try:
                    path  = ff.get("input", {}).get("FUZZ", ff.get("url", ""))
                    fid   = "web-enum:ffuf:" + hashlib.md5(
                        f"{host}:{path}".encode()
                    ).hexdigest()[:12]
                    scode = ff.get("status", 200)

                    s.run("""
                        MATCH (sv:Service {id: $svc_id})
                        MERGE (f:Finding {id: $fid})
                        SET f.name       = $name,
                            f.severity   = $severity,
                            f.source     = 'web-enum',
                            f.scanner    = 'ffuf',
                            f.host       = $host,
                            f.url        = $url,
                            f.path       = $path,
                            f.status_code= $status,
                            f.first_seen = $now
                        MERGE (sv)-[:HAS_FINDING]->(f)
                    """,
                    svc_id  = svc_id,
                    fid     = fid,
                    name    = f"Directory Found: /{path}",
                    severity= "Low" if scode in (200, 204) else "Information",
                    host    = host,
                    url     = f"{url}/{path}",
                    path    = f"/{path}",
                    status  = str(scode),
                    now     = now,
                    )
                    count += 1
                except Exception:
                    pass

            # ── Crawled URL inventory ─────────────────────────────────
            if urls:
                url_list = "\n".join(urls[:200])
                fid = f"web-enum:crawl:{host}"
                s.run("""
                    MATCH (sv:Service {id: $svc_id})
                    MERGE (f:Finding {id: $fid})
                    SET f.name       = 'Crawled URL Inventory',
                        f.severity   = 'Information',
                        f.source     = 'web-enum',
                        f.scanner    = 'katana',
                        f.host       = $host,
                        f.url        = $base_url,
                        f.evidence   = $urls,
                        f.first_seen = $now
                    MERGE (sv)-[:HAS_FINDING]->(f)
                """, svc_id=svc_id, fid=fid, host=host,
                     base_url=url, urls=url_list, now=now)
                count += 1

        return count

    @staticmethod
    def _extract_host(url: str) -> str:
        """Extract bare hostname from a URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.hostname or url
        except Exception:
            return url.replace("https://", "").replace("http://", "").split("/")[0]

    def close(self):
        self._drv.close()


__all__ = ["WebEnumIngest"]
