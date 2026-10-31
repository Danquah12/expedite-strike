"""
nmap_xml_parser.py
==================
Parses nmap XML output files and ingests the results directly into Neo4j.
Creates Host → [:RUNS_SERVICE] → Service → [:HAS_FINDING] → Finding nodes
matching the schema expected by _build_host_report() in ui_pentest.py.
"""

import xml.etree.ElementTree as ET
import os
import re
from datetime import datetime, timezone


# ── Severity mapping from nmap riskcode / CVSS ───────────────────────
def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "Critical"
    if cvss >= 7.0: return "High"
    if cvss >= 4.0: return "Medium"
    if cvss >  0.0: return "Low"
    return "Info"


# ── Parse a single nmap XML file ─────────────────────────────────────
def parse_nmap_xml(xml_path: str) -> list[dict]:
    """
    Parse nmap XML and return a flat list of finding dicts ready for ingest.
    Each dict: host, port, service, product, version, name, severity,
                cve, evidence, source
    """
    findings = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[NmapXmlParser] XML parse error {xml_path}: {e}")
        return findings

    ts = datetime.now(timezone.utc).isoformat()

    for host_el in root.findall(".//host"):
        # ── IP address ────────────────────────────────────────────────
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue

        # ── Hostname (optional) ───────────────────────────────────────
        hostname_el = host_el.find(".//hostname")
        hostname = hostname_el.get("name", ip) if hostname_el is not None else ip

        # ── Open ports → services ─────────────────────────────────────
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid   = port_el.get("portid", "")
            protocol = port_el.get("protocol", "tcp")
            svc_el   = port_el.find("service")
            svc_name = svc_el.get("name", "unknown")    if svc_el is not None else "unknown"
            product  = svc_el.get("product", "")        if svc_el is not None else ""
            version  = svc_el.get("version", "")        if svc_el is not None else ""
            extra    = svc_el.get("extrainfo", "")      if svc_el is not None else ""

            # Base evidence from service banner
            banner_parts = [p for p in [product, version, extra] if p]
            base_evidence = f"Port {portid}/{protocol} open — " + (" ".join(banner_parts) if banner_parts else svc_name)

            # One "open port" finding per port (as baseline)
            findings.append({
                "host":     ip,
                "hostname": hostname,
                "port":     portid,
                "protocol": protocol,
                "service":  svc_name,
                "product":  product or svc_name,
                "name":     f"Open Port: {svc_name}:{portid}",
                "severity": "Info",
                "cve":      "",
                "evidence": base_evidence,
                "source":   "nmap",
                "ts":       ts,
            })

            # ── NSE script output → CVE findings ─────────────────────
            for script_el in port_el.findall("script"):
                script_id     = script_el.get("id", "")
                script_output = script_el.get("output", "")

                # Extract CVEs from vulners/vuln script output
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", script_output, re.IGNORECASE)
                cvss_matches = re.findall(r"(\d+\.\d+)\s+CVE", script_output)

                if cves:
                    for idx, cve in enumerate(set(cves)):
                        try:
                            cvss = float(cvss_matches[idx]) if idx < len(cvss_matches) else 5.0
                        except ValueError:
                            cvss = 5.0
                        sev = _cvss_to_severity(cvss)
                        findings.append({
                            "host":     ip,
                            "hostname": hostname,
                            "port":     portid,
                            "protocol": protocol,
                            "service":  svc_name,
                            "product":  product or svc_name,
                            "name":     f"{cve} on {svc_name}:{portid}",
                            "severity": sev,
                            "cve":      cve.upper(),
                            "evidence": f"[{script_id}] CVSS {cvss} — {script_output[:200]}",
                            "source":   "nmap",
                            "ts":       ts,
                        })
                elif script_output.strip() and script_id.startswith(("vuln", "http-vuln", "ssl", "smb")):
                    # NSE finding without explicit CVE
                    findings.append({
                        "host":     ip,
                        "hostname": hostname,
                        "port":     portid,
                        "protocol": protocol,
                        "service":  svc_name,
                        "product":  product or svc_name,
                        "name":     f"NSE: {script_id} on {svc_name}:{portid}",
                        "severity": "Medium",
                        "cve":      "",
                        "evidence": f"[{script_id}] {script_output[:200]}",
                        "source":   "nmap",
                        "ts":       ts,
                    })

    return findings


# ── Ingest parsed findings into Neo4j ────────────────────────────────
def ingest_to_neo4j(findings: list[dict], on_output=None) -> int:
    """
    Write findings to Neo4j using the Host → Service → Finding schema.
    Returns the number of findings written.
    """
    if not findings:
        return 0

    def _log(msg):
        if on_output:
            on_output(msg)
        else:
            print(msg)

    try:
        from neo4j import GraphDatabase
        password = os.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", password))

        count = 0
        with driver.session() as session:
            for f in findings:
                host     = f["host"]
                port     = str(f.get("port", ""))
                protocol = f.get("protocol", "tcp")
                svc_name = f.get("service", "unknown")
                product  = f.get("product", svc_name)
                name     = f.get("name", "Unknown Finding")
                severity = f.get("severity", "Info")
                cve      = f.get("cve", "")
                evidence = f.get("evidence", "")
                source   = f.get("source", "nmap")
                ts       = f.get("ts", datetime.now(timezone.utc).isoformat())

                sid = f"{host}:{port}:{protocol}"
                fid = f"nmap:{host}:{port}:{name[:40]}"

                session.run("""
                    MERGE (h:Host {ip: $ip})
                    SET   h.hostname = $hostname
                    MERGE (s:Service {id: $sid})
                    SET   s.name = $svc_name,
                          s.product = $product,
                          s.port = $port,
                          s.protocol = $protocol,
                          s.source = $source
                    MERGE (h)-[:RUNS_SERVICE]->(s)
                    MERGE (f:Finding {id: $fid})
                    ON CREATE SET f.first_seen = $ts
                    SET   f.name = $name,
                          f.severity = $severity,
                          f.cve = $cve,
                          f.evidence = $evidence,
                          f.description = $evidence,
                          f.source = $source,
                          f.scanner = $source,
                          f.last_seen = $ts
                    MERGE (s)-[:HAS_FINDING]->(f)
                """,
                    ip=host, hostname=f.get("hostname", host),
                    sid=sid, svc_name=svc_name, product=product,
                    port=port, protocol=protocol, source=source,
                    fid=fid, name=name, severity=severity,
                    cve=cve, evidence=evidence, ts=ts
                )
                count += 1

        driver.close()
        _log(f"[NmapXmlParser] ✓ Ingested {count} findings to Neo4j\n")
        return count

    except Exception as e:
        _log(f"[NmapXmlParser] ✗ Neo4j ingest error: {e}\n")
        return 0


# ── Main entry: parse XML and ingest ─────────────────────────────────
class NmapXmlParser:
    """Parse a nmap XML file and write results to Neo4j."""

    def parse_and_ingest(self, xml_path: str, on_output=None) -> int:
        """Returns number of findings ingested."""
        if not os.path.isfile(xml_path):
            return 0
        findings = parse_nmap_xml(xml_path)
        return ingest_to_neo4j(findings, on_output)


__all__ = ["NmapXmlParser", "parse_nmap_xml", "ingest_to_neo4j"]
