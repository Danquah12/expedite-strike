import sys, os, re

# ============================================================
# FORCE PYTHON TO SEE PROJECT ROOT
# ============================================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))  # /opt/vuln_intel/app

if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

# ============================================================
# IMPORT NEO4J ENGINE
# ============================================================
from cyber_range.services.neo4j_engine import Neo4jEngine
neo = Neo4jEngine()


# ============================================================
# HELPERS
# ============================================================
def normalize_ip(ip):
    return ip.strip() if ip else ip


def extract_cves(text):
    """
    Extract CVE identifiers from any string.
    """
    if not text:
        return []
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))


# ============================================================
# MERGE ASSET
# ============================================================
def merge_asset(ip):
    ip = normalize_ip(ip)
    query = """
    MERGE (a:Asset {ip: $ip})
    RETURN a
    """
    neo.run_query(query, ip=ip)


# ============================================================
# MERGE SERVICE
# ============================================================
def merge_service(ip, port, protocol=None, service=None):
    ip = normalize_ip(ip)
    query = """
    MATCH (a:Asset {ip: $ip})
    MERGE (s:Service {
        ip: $ip,
        port: $port,
        protocol: $protocol,
        name: $service
    })
    MERGE (a)-[:HAS_SERVICE]->(s)
    RETURN s
    """
    neo.run_query(
        query,
        ip=ip,
        port=str(port),
        protocol=protocol or "unknown",
        service=service or "unknown"
    )


# ============================================================
# MERGE VULNERABILITY
# ============================================================
def merge_vulnerability(ip, port, plugin_id, name, severity, description):
    ip = normalize_ip(ip)
    query = """
    MATCH (s:Service {ip: $ip, port: $port})
    MERGE (v:Vulnerability {plugin_id: $plugin_id})
    SET 
        v.name = $name,
        v.severity = $severity,
        v.description = $description
    MERGE (s)-[:HAS_VULN]->(v)
    RETURN v
    """
    neo.run_query(
        query,
        ip=ip,
        port=str(port),
        plugin_id=str(plugin_id),
        name=name,
        severity=str(severity),
        description=description
    )


# ============================================================
# LINK ASSET → VULN (NO PORT INFO)
# ============================================================
def link_asset_vuln(ip, plugin_id):
    ip = normalize_ip(ip)
    query = """
    MATCH (a:Asset {ip: $ip})
    MATCH (v:Vulnerability {plugin_id: $plugin_id})
    MERGE (a)-[:HAS_VULN]->(v)
    RETURN v
    """
    neo.run_query(query, ip=ip, plugin_id=str(plugin_id))


# ============================================================
# MERGE CVE
# ============================================================
def merge_cve(cve, vuln_id_or_name):
    if not cve:
        return

    query = """
    MERGE (c:CVE {id: $cve})
    WITH c
    MATCH (v:Vulnerability)
    WHERE v.plugin_id = $v OR v.name = $v
    MERGE (v)-[:HAS_CVE]->(c)
    RETURN c
    """
    neo.run_query(query, cve=cve, v=vuln_id_or_name)


# ============================================================
# DEBUG LOGGER
# ============================================================
def debug(msg):
    print(f"[Importer] {msg}")
