# neo4j_integration.py
import os
import re
import time
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import requests
from neo4j import GraphDatabase
import logging
from neo4j import GraphDatabase
from datetime import datetime

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# default config (will be overridden by app_config or env)
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "neo4j")
DEFAULT_NMAP_XML = os.getenv("NMAP_XML_PATH", "/root/vuln_intel/app/data/nmap_scan.xml")
NVD_API_KEY = os.getenv("NVD_API_KEY")

CVE_REGEX = re.compile(r'(CVE-\d{4}-\d{4,7})', flags=re.IGNORECASE)

def extract_cves(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return CVE_REGEX.findall(text)

def safe_int(v):
    try:
        return int(v)
    except Exception:
        return None

def parse_nmap_xml(xml_path: str) -> List[Dict[str, Any]]:
    xml_path = os.path.expanduser(xml_path)
    logger.info("Parsing Nmap XML: %s", xml_path)
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []
    for h in root.findall('host'):
        addr_el = h.find('address')
        if addr_el is None:
            continue
        ip = addr_el.get('addr')
        status_el = h.find('status')
        status = status_el.get('state') if status_el is not None else 'unknown'
        hostname_el = h.find('./hostnames/hostname')
        hostname = hostname_el.get('name') if hostname_el is not None else None
        traceroute = []
        tr = h.find('trace')
        if tr is not None:
            for hop in tr.findall('hop'):
                hop_addr = hop.get('ipaddr')
                if hop_addr:
                    traceroute.append(hop_addr)
        services = []
        for ports in h.findall('ports'):
            for p in ports.findall('port'):
                proto = p.get('protocol')
                portnum = safe_int(p.get('portid'))
                state_el = p.find('state')
                state = state_el.get('state') if state_el is not None else None
                svc_el = p.find('service')
                svc_name = svc_el.get('name') if svc_el is not None else None
                svc_product = svc_el.get('product') if svc_el is not None else None
                svc_version = svc_el.get('version') if svc_el is not None else None
                scripts = []
                for script in p.findall('script'):
                    scripts.append({
                        'id': script.get('id'),
                        'output': script.get('output')
                    })
                services.append({
                    'proto': proto,
                    'port': portnum,
                    'state': state,
                    'service': svc_name,
                    'product': svc_product,
                    'version': svc_version,
                    'scripts': scripts
                })
        host_scripts = []
        for hs in h.findall('hostscript/script'):
            host_scripts.append({'id': hs.get('id'), 'output': hs.get('output')})
        hosts.append({
            'ip': ip,
            'hostname': hostname,
            'status': status,
            'traceroute': traceroute,
            'services': services,
            'host_scripts': host_scripts
        })
    logger.info("Parsed %d hosts from nmap XML", len(hosts))
    return hosts

def import_nmap_hosts_to_neo4j(hosts: List[Dict[str, Any]],
                               neo4j_uri: str = NEO4J_URI,
                               user: str = NEO4J_USER,
                               password: str = NEO4J_PASS,
                               gds_project_name: Optional[str] = None,
                               connect_same_subnet: bool = True) -> None:
    driver = GraphDatabase.driver(neo4j_uri, auth=(user, password))
    logger.info("Connecting to Neo4j at %s as %s", neo4j_uri, user)
    port_priority = {22: 1.5, 3306: 1.2, 445: 1.3, 3389: 1.4, 80: 2.5, 443: 2.5}
    try:
        with driver.session() as session:
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.host IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE (s.host, s.port, s.proto) IS NODE KEY")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tool) REQUIRE t.name IS UNIQUE")
            for h in hosts:
                host = h['ip']
                hostname = h.get('hostname')
                status = h.get('status')
                session.run("""
                    MERGE (a:Asset {host:$host})
                    SET a.hostname = $hostname, a.status = $status
                """, host=host, hostname=hostname, status=status)
                for hs in h.get('host_scripts', []):
                    sid = f"nmap_hostscript:{host}:{hs.get('id')}"
                    out = hs.get('output') or ''
                    cves = extract_cves(out)
                    session.run("""
                        MERGE (v:Vulnerability {id:$vid})
                        ON CREATE SET v.source='nmap', v.title=$title, v.description=$descr
                        WITH v
                        MATCH (a:Asset {host:$host})
                        MERGE (a)-[r:EXPOSES_VULN]->(v)
                        ON CREATE SET r.detail=$out
                    """, vid=sid, title=hs.get('id'), descr=out[:2000], host=host, out=out)
                    for cve in cves:
                        session.run("""
                            MERGE (cv:Vulnerability {id:$cve})
                            ON CREATE SET cv.source='cve', cv.title=$cve
                            MERGE (v:Vulnerability {id:$vid})
                            MERGE (v)-[:RELATED_CVE]->(cv)
                        """, cve=cve, vid=sid)
                for svc in h.get('services', []):
                    proto = svc.get('proto') or 'tcp'
                    port = svc.get('port') or 0
                    svc_name = svc.get('service') or ''
                    product = svc.get('product') or ''
                    version = svc.get('version') or ''
                    state = svc.get('state') or ''
                    session.run("""
                        MERGE (s:Service {host:$host, port:$port, proto:$proto})
                        ON CREATE SET s.name=$svc_name, s.product=$product, s.version=$version, s.state=$state
                        WITH s
                        MATCH (a:Asset {host:$host})
                        MERGE (a)-[:RUNS_SERVICE]->(s)
                    """, host=host, port=port, proto=proto, svc_name=svc_name, product=product, version=version, state=state)
                    for script in svc.get('scripts', []):
                        sid = f"nmap_{host}_{port}_{script.get('id')}"
                        out = script.get('output') or ''
                        cves = extract_cves(out)
                        session.run("""
                            MERGE (v:Vulnerability {id:$vid})
                            ON CREATE SET v.source='nmap', v.title=$title, v.description=$descr
                            WITH v
                            MATCH (s:Service {host:$host, port:$port, proto:$proto})
                            MERGE (s)-[r:EXPOSES_VULN]->(v)
                            ON CREATE SET r.detail=$out
                        """, vid=sid, title=script.get('id'), descr=out[:2000], host=host, port=port, proto=proto, out=out)
                        for cve in cves:
                            session.run("""
                                MERGE (cv:Vulnerability {id:$cve})
                                ON CREATE SET cv.source='cve', cv.title=$cve
                                MERGE (v:Vulnerability {id:$vid})
                                MERGE (v)-[:RELATED_CVE]->(cv)
                            """, cve=cve, vid=sid)
            host_ips = [h['ip'] for h in hosts if h.get('ip')]
            for h in hosts:
                src = h['ip']
                for hop in h.get('traceroute', []):
                    if hop in host_ips:
                        session.run("""
                            MATCH (a:Asset {host:$src}), (b:Asset {host:$hop})
                            MERGE (a)-[:CONNECTS_TO {via:'traceroute'}]->(b)
                        """, src=src, hop=hop)
            if connect_same_subnet:
                subnet_map = {}
                for h in hosts:
                    ip = h.get('ip')
                    if not ip:
                        continue
                    parts = ip.split('.')
                    if len(parts) == 4:
                        net = '.'.join(parts[:3])
                        subnet_map.setdefault(net, []).append(ip)
                for net, members in subnet_map.items():
                    for a in members:
                        for b in members:
                            if a != b:
                                session.run("""
                                    MATCH (x:Asset {host:$a}), (y:Asset {host:$b})
                                    MERGE (x)-[:CONNECTS_TO {via:'same_subnet'}]->(y)
                                """, a=a, b=b)
            for h in hosts:
                host = h['ip']
                for svc in h.get('services', []):
                    port = svc.get('port') or 0
                    base = port_priority.get(port, 3.0)
                    has_cve = False
                    for script in svc.get('scripts', []):
                        if extract_cves(script.get('output','')):
                            has_cve = True
                    if has_cve:
                        base = base * 0.7
                    session.run("""
                        MATCH (s:Service {host:$host, port:$port})-[r:EXPOSES_VULN]->(v:Vulnerability)
                        SET r.risk_score = $score
                    """, host=host, port=port, score=float(base))
            logger.info("Import completed successfully.")
            if gds_project_name:
                try:
                    session.run(f"CALL gds.graph.drop('{gds_project_name}', false) YIELD graphName").consume()
                except Exception:
                    pass
                session.run(f"""
                    CALL gds.graph.project(
                      '{gds_project_name}',
                      ['Asset','Service','Vulnerability'],
                      {{
                        RUNS_SERVICE: {{orientation:'UNDIRECTED'}},
                        EXPOSES_VULN: {{orientation:'UNDIRECTED', properties:['risk_score']}},
                        CONNECTS_TO: {{orientation:'UNDIRECTED'}}
                      }}
                    )
                """)
                logger.info("GDS projection '%s' created.", gds_project_name)
    finally:
        driver.close()

def assessment_nmap_import_step(app_config: Dict[str, Any]) -> None:
    nmap_xml = app_config.get('nmap_xml_path', DEFAULT_NMAP_XML)
    neo_uri = app_config.get('neo4j_uri', NEO4J_URI)
    neo_user = app_config.get('neo4j_user', NEO4J_USER)
    neo_pass = app_config.get('neo4j_pass', NEO4J_PASS)
    gds_name = app_config.get('gds_project')
    if not os.path.exists(os.path.expanduser(nmap_xml)):
        logger.error("Nmap XML not found at %s — ensure the scan completed.", nmap_xml)
        return
    hosts = parse_nmap_xml(nmap_xml)
    import_nmap_hosts_to_neo4j(hosts, neo4j_uri=neo_uri, user=neo_user, password=neo_pass, gds_project_name=gds_name)

def enrich_cves_from_nvd(
    neo4j_uri: str = NEO4J_URI,
    user: str = NEO4J_USER,
    password: str = NEO4J_PASS,
    batch_limit: int = 25,
    delay: float = 1.2
) -> None:
    driver = GraphDatabase.driver(neo4j_uri, auth=(user, password))
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    with driver.session() as session:
        res = session.run("""
	MATCH (v:Vulnerability)
	WHERE (v.cve_id STARTS WITH 'CVE-' OR v.name STARTS WITH 'CVE-')
  	AND (v.cvss IS NULL OR v.last_updated IS NULL OR v.last_updated < date() - duration('P30D'))
	RETURN coalesce(v.cve_id, v.name) AS cve
	LIMIT $limit
        """, limit=batch_limit)
        cves = [r["cve"] for r in res]
        if not cves:
            logger.info("No CVEs needing enrichment.")
            return
        logger.info("Enriching %d CVEs from NVD…", len(cves))
        for cve_id in cves:
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                r = requests.get(url, headers=headers, timeout=12)
                if r.status_code != 200:
                    logger.warning("NVD API error for %s (%s)", cve_id, r.status_code)
                    time.sleep(delay)
                    continue
                data = r.json()
                vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
                metrics = (
                    vuln.get("metrics", {}).get("cvssMetricV31")
                    or vuln.get("metrics", {}).get("cvssMetricV30")
                    or []
                )
                cvss = None
                vector = None
                if metrics:
                    try:
                        cvss = float(metrics[0]["cvssData"].get("baseScore"))
                        vector = metrics[0]["cvssData"].get("vectorString")
                    except Exception:
                        cvss = None
                        vector = None
                descs = vuln.get("descriptions", [])
                summary = descs[0].get("value")[:1600] if descs else None
                session.run("""
                    MATCH (v:Vulnerability {id:$cve})
                    SET v.cvss = $cvss,
                        v.vector = $vector,
                        v.summary = $summary,
                        v.last_updated = date()
                """, cve=cve_id, cvss=cvss, vector=vector, summary=summary)
                if cvss is not None:
                    session.run("""
                        MATCH (:Service)-[r:EXPOSES_VULN]->(v:Vulnerability {id:$cve})
                        SET r.risk_score = 11 - toFloat($cvss)
                    """, cve=cve_id, cvss=cvss)
                logger.info("✓ Updated %s (cvss=%s)", cve_id, cvss)
                time.sleep(delay)
            except Exception as e:
                logger.warning("Error on %s: %s", cve_id, e)
                time.sleep(delay)
                continue
    driver.close()
    logger.info("NVD enrichment complete.")
