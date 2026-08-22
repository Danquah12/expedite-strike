import os
import json
import time
from pathlib import Path
from neo4j import GraphDatabase

SCAN_ROOT = "/mnt/scans/incoming"
PROCESSED_DIR = "/mnt/scans/processed"
FAILED_DIR = "/mnt/scans/failed"

NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

if not NEO4J_PASSWORD:
    import warnings
    warnings.warn("NEO4J_PASSWORD not set — Neo4jIngestor will be unavailable")


class Neo4jIngestor:
    def __init__(self):
        if not NEO4J_PASSWORD:
            raise RuntimeError("NEO4J_PASSWORD not set")
        self.driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
        )

        from cyber_range.services._safe_dirs import safe_makedirs
        for d in [PROCESSED_DIR, FAILED_DIR]:
            safe_makedirs(d)

    # =================================================
    # MAIN LOOP
    # =================================================
    def run(self):
        print("[*] Neo4j Ingestor started")

        while True:
            for meta in Path(SCAN_ROOT).rglob("*.meta.json"):
                try:
                    self.process_meta(meta)
                except Exception as e:
                    print(f"[!] Failed ingest {meta}: {e}")
                    self._move(meta, FAILED_DIR)
            time.sleep(5)

    # =================================================
    # PROCESS SINGLE SCAN
    # =================================================
    def process_meta(self, meta_path: Path):
        with open(meta_path) as f:
            meta = json.load(f)

        if meta.get("ingest", {}).get("status") == "completed":
            return

        scanner = meta["scanner"].lower()
        base_name = meta_path.name.replace(".meta.json", "")
        
        # Try finding the corresponding report file (JSON or XML)
        report_path_json = meta_path.parent / f"{base_name}.json"
        report_path_xml = meta_path.parent / f"{base_name}.xml"
        
        if report_path_json.exists():
            report_path = report_path_json
        elif report_path_xml.exists():
            report_path = report_path_xml
        else:
            # Fallback for openvas which might use different extensions or no extension
            report_path = meta_path.parent / base_name
            if not report_path.exists():
                raise RuntimeError(f"Report file missing for {meta_path.name}")

        print(f"[+] Ingesting {scanner}: {report_path.name}")

        if scanner == "zap":
            self.ingest_zap(report_path, meta)
        elif scanner == "nmap":
            self.ingest_nmap(report_path, meta)
        elif scanner == "nuclei":
            self.ingest_nuclei(report_path, meta)
        elif scanner in ["openvas", "gvm"]:
            self.ingest_openvas(report_path, meta)
        else:
            raise RuntimeError(f"Unknown scanner: {scanner}")

        meta["ingest"]["status"] = "completed"

        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        self._move(report_path, PROCESSED_DIR)
        self._move(meta_path, PROCESSED_DIR)

    # =================================================
    # INGEST: ZAP
    # =================================================
    def ingest_zap(self, report_path, meta):
        with open(report_path) as f:
            data = json.load(f)

        with self.driver.session() as s:
            for site in data.get("site", []):
                host = site.get("@host", site.get("@name"))
                port = site.get("@port", "80")
                
                s.run("""
                    MERGE (h:Host {ip:$host})
                    MERGE (srv:Service {id:$sid})
                    SET srv.port=$port
                    MERGE (h)-[:RUNS_SERVICE]->(srv)
                    """, host=host, port=port, sid=f"{host}:{port}")

                for alert in site.get("alerts", []):
                    fid = f"zap:{host}:{alert.get('alertRef')}"
                    riskdesc = alert.get("riskdesc", "Medium")
                    severity_text = riskdesc.split(" ")[0] if " " in riskdesc else riskdesc
                    riskcode = alert.get("riskcode", "1")
                    
                    s.run("""
                        MATCH (srv:Service {id:$sid})
                        MERGE (f:Finding {id:$id})
                        SET f.name        = $title,
                            f.title       = $title,
                            f.severity    = $severity,
                            f.riskcode    = $riskcode,
                            f.description = $desc,
                            f.solution    = $solution,
                            f.pluginid    = $pluginid,
                            f.source      = 'zap',
                            f.scanner     = 'zap',
                            f.host        = $host
                        MERGE (srv)-[:HAS_FINDING]->(f)
                        """,
                        sid=f"{host}:{port}",
                        id=fid,
                        title=alert.get("alert") or alert.get("name", ""),
                        severity=severity_text,
                        riskcode=str(riskcode),
                        desc=alert.get("desc", "")[:500],
                        solution=alert.get("solution", "")[:300],
                        pluginid=str(alert.get("pluginid", "")),
                        host=host,
                    )

    # =================================================
    # INGEST: NUCLEI
    # =================================================
    def ingest_nuclei(self, report_path, meta):
        """
        Nuclei writes one JSON object per line (JSONL). Each line contains:
          templateID, info.severity, host, matched-at, description, extracted-results, curl-command
        """
        import re as _re

        SEV_MAP = {
            "critical": "3", "high": "3", "medium": "2",
            "low": "1", "info": "0", "unknown": "1",
        }

        findings = []
        try:
            raw = open(report_path, "r", errors="replace").read().strip()
            if raw.startswith("["):
                # nuclei -je writes a JSON array
                data = json.loads(raw)
                findings = data if isinstance(data, list) else []
            else:
                # nuclei -json writes JSONL (one object per line)
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            raise RuntimeError(f"Nuclei JSON parse error: {e}")


        if not findings:
            return  # Empty file — nothing to ingest

        with self.driver.session() as s:
            for item in findings:
                template_id = item.get("template-id") or item.get("templateID") or "unknown"
                host        = item.get("host", "").split(":")[0] or "unknown"
                matched_at  = item.get("matched-at") or item.get("matched") or host
                info        = item.get("info", {})
                severity    = (info.get("severity") or "info").lower()
                name        = info.get("name") or template_id
                description = info.get("description") or ""
                tags        = ",".join(info.get("tags") or [])

                # CVE extraction from tags or reference field
                cve = ""
                for ref in (info.get("reference") or info.get("references") or []):
                    cve_m = _re.search(r"CVE-\d{4}-\d+", str(ref), _re.I)
                    if cve_m:
                        cve = cve_m.group(0).upper()
                        break
                if not cve:
                    cve_m = _re.search(r"CVE-\d{4}-\d+", template_id, _re.I)
                    if cve_m:
                        cve = cve_m.group(0).upper()

                riskcode  = SEV_MAP.get(severity, "1")
                fid       = f"nuclei:{host}:{template_id}:{matched_at}"

                # Extract port from matched_at (e.g. https://host:443/path)
                port_match = _re.search(r":(\/\/[^:]+:)?(\d{2,5})", matched_at)
                port = port_match.group(2) if port_match else "80"
                sid  = f"{host}:tcp:{port}"

                s.run("""
                    MERGE (h:Host {ip:$host})
                    MERGE (srv:Service {id:$sid})
                    ON CREATE SET srv.port=$port, srv.protocol='tcp',
                                  srv.host=$host, srv.source='nuclei'
                    ON MATCH SET  srv.host=$host, srv.source='nuclei'
                    MERGE (h)-[:RUNS_SERVICE]->(srv)
                    MERGE (f:Finding {id:$fid})
                    SET f.name        = $name,
                        f.title       = $name,
                        f.cve         = $cve,
                        f.riskcode    = $riskcode,
                        f.severity    = $sev_label,
                        f.description = $desc,
                        f.url         = $url,
                        f.tags        = $tags,
                        f.pluginid    = $template_id,
                        f.source      = 'nuclei',
                        f.scanner     = 'nuclei',
                        f.host        = $host,
                        f.port        = $port
                    MERGE (srv)-[:HAS_FINDING]->(f)
                    """,
                    host=host, sid=sid, port=port,
                    fid=fid, name=name, cve=cve,
                    riskcode=riskcode,
                    sev_label=severity.capitalize(),
                    desc=description[:500],
                    url=matched_at,
                    tags=tags,
                    template_id=template_id,
                )

    # =================================================
    # INGEST: NMAP
    # =================================================
    def ingest_nmap(self, report_path, meta):
        import xml.etree.ElementTree as ET
        tree = ET.parse(report_path)
        root = tree.getroot()

        with self.driver.session() as s:
            for host in root.findall("host"):
                addr_el = host.find("address")
                if addr_el is None:
                    continue
                addr = addr_el.attrib.get("addr", "unknown")

                # ── Host node ───────────────────────────────────────────
                s.run("MERGE (:Host {ip:$ip})", ip=addr)

                ports = host.findall(".//port")
                for port in ports:
                    portid = port.attrib.get("portid", "0")
                    proto  = port.attrib.get("protocol", "tcp")
                    sid    = f"{addr}:{proto}:{portid}"

                    svc_el   = port.find("service")
                    svc_name = svc_el.attrib.get("name", "") if svc_el is not None else ""
                    svc_ver  = svc_el.attrib.get("version", "") if svc_el is not None else ""
                    svc_prod = svc_el.attrib.get("product", "") if svc_el is not None else ""

                    # ── Service node ────────────────────────────────────
                    s.run("""
                        MERGE (h:Host {ip:$ip})
                        MERGE (srv:Service {id:$id})
                        ON CREATE SET
                            srv.port=$port, srv.protocol=$proto,
                            srv.name=$name, srv.version=$ver,
                            srv.product=$prod, srv.host=$ip,
                            srv.source='nmap'
                        ON MATCH SET
                            srv.port=$port, srv.protocol=$proto,
                            srv.host=$ip, srv.source='nmap'
                        MERGE (h)-[:RUNS_SERVICE]->(srv)
                        """,
                        ip=addr, id=sid, port=portid,
                        proto=proto, name=svc_name,
                        ver=svc_ver, prod=svc_prod,
                    )

                    # ── NSE scripts → Finding nodes ──────────────────────
                    for script in port.findall("script"):
                        script_id  = script.attrib.get("id", "")
                        script_out = script.attrib.get("output", "").strip()

                        # ── vulners script: each table entry is a separate CVE ──
                        if script_id == "vulners":
                            for table in script.findall(".//table"):
                                cve_id  = table.findtext("elem[@key='id']")  or ""
                                cvss    = table.findtext("elem[@key='cvss']") or ""
                                url     = table.findtext("elem[@key='url']")  or ""
                                if not cve_id:
                                    continue

                                fid = f"nmap:{addr}:{portid}:{cve_id}"
                                try:
                                    cvss_f = float(cvss)
                                except Exception:
                                    cvss_f = 0.0

                                riskcode = "3" if cvss_f >= 7.0 else ("2" if cvss_f >= 4.0 else "1")

                                s.run("""
                                    MATCH (srv:Service {id:$sid})
                                    MERGE (f:Finding {id:$fid})
                                    SET f.name = $name,
                                        f.cve  = $cve,
                                        f.cvss = $cvss,
                                        f.riskcode = $riskcode,
                                        f.url  = $url,
                                        f.source  = 'nmap',
                                        f.scanner = 'nmap',
                                        f.host    = $host,
                                        f.port    = $port,
                                        f.description = $cve + ' (CVSS: ' + $cvsskw + ')'
                                    MERGE (srv)-[:HAS_FINDING]->(f)
                                    """,
                                    sid=sid, fid=fid,
                                    name=cve_id,
                                    cve=cve_id,
                                    cvss=cvss_f,
                                    cvsskw=str(cvss_f),
                                    riskcode=riskcode,
                                    url=url,
                                    host=addr,
                                    port=portid,
                                )

                        # ── vuln script: structured vulnerability output ───────
                        elif script_id.startswith("http-vuln") or script_id.startswith("vuln") or script_id.startswith("smb-vuln") or script_id.startswith("ssl-") or script_id.startswith("ftp-vuln") or script_id.startswith("rdp-") or script_id.startswith("mysql-vuln"):
                            if not script_out or "NOT VULNERABLE" in script_out.upper():
                                continue

                            fid  = f"nmap:{addr}:{portid}:{script_id}"
                            # Try to pull CVE from output
                            import re
                            cves = re.findall(r"CVE-\d{4}-\d+", script_out)
                            cve  = cves[0] if cves else ""

                            # Map risk from script output keywords
                            out_upper = script_out.upper()
                            if any(w in out_upper for w in ("CRITICAL", "HIGH", "CVSS: 9", "CVSS: 8", "CVSS: 7")):
                                riskcode = "3"
                            elif any(w in out_upper for w in ("MEDIUM", "CVSS: 5", "CVSS: 6")):
                                riskcode = "2"
                            else:
                                riskcode = "1"

                            s.run("""
                                MATCH (srv:Service {id:$sid})
                                MERGE (f:Finding {id:$fid})
                                SET f.name        = $name,
                                    f.cve         = $cve,
                                    f.riskcode    = $riskcode,
                                    f.description = $desc,
                                    f.source      = 'nmap',
                                    f.scanner     = 'nmap',
                                    f.host        = $host,
                                    f.port        = $port,
                                    f.pluginid    = $script_id
                                MERGE (srv)-[:HAS_FINDING]->(f)
                                """,
                                sid=sid, fid=fid,
                                name=script_id.replace("-", " ").title(),
                                cve=cve,
                                riskcode=riskcode,
                                desc=script_out[:500],
                                host=addr,
                                port=portid,
                                script_id=script_id,
                            )

                        # ── Any other script with meaningful output → informational Finding ──
                        elif script_out and script_id not in ("ssh-hostkey", "banner"):
                            fid = f"nmap:{addr}:{portid}:{script_id}"
                            s.run("""
                                MATCH (srv:Service {id:$sid})
                                MERGE (f:Finding {id:$fid})
                                SET f.name        = $name,
                                    f.riskcode    = '0',
                                    f.description = $desc,
                                    f.source      = 'nmap',
                                    f.scanner     = 'nmap',
                                    f.host        = $host,
                                    f.port        = $port,
                                    f.pluginid    = $script_id
                                MERGE (srv)-[:HAS_FINDING]->(f)
                                """,
                                sid=sid, fid=fid,
                                name=f"[INFO] {script_id.replace('-', ' ').title()}",
                                desc=script_out[:500],
                                host=addr,
                                port=portid,
                                script_id=script_id,
                            )


    # =================================================
    # INGEST: OPENVAS
    # =================================================
    def ingest_openvas(self, report_path, meta):
        import xml.etree.ElementTree as ET
        tree = ET.parse(report_path)
        root = tree.getroot()

        with self.driver.session() as s:
            for result in root.findall(".//result"):
                host = result.findtext("host")
                port = result.findtext("port", "0")
                name = result.findtext("name")
                severity = result.findtext("severity")

                fid = f"openvas:{host}:{port}:{name}"
                sid = f"{host}:tcp:{port}"

                s.run("""
                    MERGE (h:Host {ip:$host})
                    MERGE (srv:Service {id:$sid})
                    SET srv.port=$port
                    MERGE (h)-[:RUNS_SERVICE]->(srv)
                    MERGE (f:Finding {id:$id})
                    SET f.title=$title,
                        f.severity=$severity,
                        f.scanner='OpenVAS'
                    MERGE (srv)-[:HAS_FINDING]->(f)
                    """,
                    host=host,
                    sid=sid,
                    port=port,
                    id=fid,
                    title=name,
                    severity=severity
                )

    def _move(self, path, dest_root):
        dest = Path(dest_root) / path.name
        path.rename(dest)


if __name__ == "__main__":
    Neo4jIngestor().run()
