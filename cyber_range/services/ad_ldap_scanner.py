"""
AD LDAP Scanner Service
=======================
Pure-Python Active Directory security enumeration using ldap3.
No SharpHound or bloodhound-python required.

Functions:
  run_ad_scan()          - Full LDAP scan → Neo4j ingest → Postgres history
  get_last_scan_results()- Retrieve last scan findings from Postgres + Neo4j
  get_graph_elements()   - Fetch Cytoscape-compatible graph from Neo4j
"""

import socket
import datetime
import logging
import traceback

from cyber_range.services.neo4j_engine import neo4j

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# POSTGRES HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _pg_connect():
    """Return a psycopg2 connection using the app's shared credentials.
    Reads PG_PASSWORD from the environment or the .env file used by the app.
    """
    try:
        import psycopg2
    except ImportError:
        raise RuntimeError(
            "psycopg2 is not installed — PostgreSQL features are disabled. "
            "Run: pip install psycopg2-binary"
        )
    import os

    # Try env var first (set if app was launched with .env sourced)
    password = os.getenv("PG_PASSWORD", "")

    # If not set, load directly from the .env file
    if not password:
        env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
        env_path = os.path.normpath(env_path)
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PG_PASSWORD") and "=" in line:
                        password = line.split("=", 1)[1].strip().strip("'\"")
                        break
        except FileNotFoundError:
            pass

    if not password:
        # Hard fallback to known value from app .env
        password = "Adomaa12@"

    return psycopg2.connect(
        dbname="vuln_intel",
        user="vuln_user",
        password=password,
        host="127.0.0.1",
    )



def _ensure_history_table(cur):
    """Create the exposure_history table if it doesn't already exist."""
    cur.execute("""
        CREATE TABLE IF NOT EXISTS exposure_history (
            id        SERIAL PRIMARY KEY,
            score     INT,
            dc_ip     TEXT,
            domain    TEXT,
            findings  TEXT,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """)


# ─────────────────────────────────────────────────────────────────────────────
# LDAP HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _ldap_connect(dc_ip, username, password):
    """Open an authenticated LDAP3 connection to the domain controller."""
    try:
        from ldap3 import Server, Connection, ALL
    except ImportError:
        raise RuntimeError(
            "ldap3 is not installed in this Python environment. "
            "Run: pip install ldap3"
        )
    server = Server(dc_ip, get_info=ALL, connect_timeout=5)
    conn = Connection(server, user=username, password=password, auto_bind=True)
    return conn


def _base_dn(domain):
    """Convert 'corp.local' → 'DC=corp,DC=local'."""
    return ",".join(f"DC={part}" for part in domain.split("."))


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def _detect_asrep(conn, base_dn):
    """Find user accounts that do NOT require Kerberos pre-authentication (AS-REP Roastable)."""
    conn.search(
        base_dn,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        attributes=["sAMAccountName"]
    )
    return [str(e.sAMAccountName) for e in conn.entries if e.sAMAccountName]


def _detect_kerberoast(conn, base_dn):
    """Find user accounts with a Service Principal Name set (Kerberoastable)."""
    conn.search(
        base_dn,
        "(&(objectClass=user)(servicePrincipalName=*))",
        attributes=["sAMAccountName", "servicePrincipalName"]
    )
    results = []
    for e in conn.entries:
        try:
            results.append({
                "user": str(e.sAMAccountName),
                "spn": str(e.servicePrincipalName)
            })
        except Exception:
            pass
    return results


def _detect_unconstrained(conn, base_dn):
    """Find computer accounts with unconstrained delegation enabled."""
    conn.search(
        base_dn,
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        attributes=["name"]
    )
    return [str(e.name) for e in conn.entries if e.name]


def _check_spooler(dc_ip):
    """Probe port 445 to detect potential Print Spooler / PrintNightmare exposure."""
    try:
        socket.create_connection((dc_ip, 445), timeout=3)
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSURE SCORING
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_score(findings):
    """
    Tier-0 exposure score — weighted by finding severity:
      AS-REP accounts     : +10 each
      Kerberoastable accts: +5  each
      Unconstrained deleg : +20 each
      Print Spooler open  : +25 flat
    """
    score = 0
    score += len(findings.get("asrep", [])) * 10
    score += len(findings.get("kerberoast", [])) * 5
    score += len(findings.get("unconstrained", [])) * 20
    if findings.get("spooler"):
        score += 25
    return score


# ─────────────────────────────────────────────────────────────────────────────
# NEO4J INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def _push_to_neo4j(findings, domain):
    """Write AD vulnerability findings as nodes in Neo4j."""
    try:
        for user in findings.get("asrep", []):
            neo4j.run_query(
                "MERGE (u:User {name:$name, domain:$domain}) SET u.asrep_roastable = true",
                {"name": user, "domain": domain}
            )
        for entry in findings.get("kerberoast", []):
            neo4j.run_query(
                "MERGE (u:User {name:$name, domain:$domain}) SET u.kerberoastable = true, u.spn = $spn",
                {"name": entry["user"], "domain": domain, "spn": entry["spn"]}
            )
        for computer in findings.get("unconstrained", []):
            neo4j.run_query(
                "MERGE (c:Computer {name:$name, domain:$domain}) SET c.unconstrained_delegation = true",
                {"name": computer, "domain": domain}
            )
        logger.info("AD findings pushed to Neo4j successfully.")
    except Exception as e:
        logger.error(f"Neo4j push error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# POSTGRES HISTORY STORAGE
# ─────────────────────────────────────────────────────────────────────────────

def _store_history(score, dc_ip, domain, findings):
    """Persist the scan score and raw findings JSON into the Postgres history table."""
    import json
    try:
        conn = _pg_connect()
        cur = conn.cursor()
        _ensure_history_table(cur)
        cur.execute(
            "INSERT INTO exposure_history (score, dc_ip, domain, findings) VALUES (%s, %s, %s, %s)",
            (score, dc_ip, domain, json.dumps(findings, default=str))
        )
        conn.commit()
        conn.close()
        logger.info(f"Stored scan history: score={score} for {dc_ip}")
    except Exception as e:
        logger.warning(f"Postgres store_history failed (non-fatal): {e}")


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def run_ad_scan(dc_ip="192.168.1.10", username="Administrator",
                password="Password123!", domain="corp.local"):
    """
    Full AD security scan pipeline:
      1. LDAP connect → enumerate vulnerabilities
      2. Score the findings
      3. Push to Neo4j
      4. Store history in Postgres
    Returns a dict with status, score, and findings.
    """
    try:
        # Build LDAP username in DOMAIN\\user format if not already
        ldap_user = username if "\\" in username else f"{domain.split('.')[0]}\\{username}"
        base_dn = _base_dn(domain)

        logger.info(f"Starting AD scan against {dc_ip} ({domain})")
        conn = _ldap_connect(dc_ip, ldap_user, password)

        findings = {
            "asrep": _detect_asrep(conn, base_dn),
            "kerberoast": _detect_kerberoast(conn, base_dn),
            "unconstrained": _detect_unconstrained(conn, base_dn),
            "spooler": _check_spooler(dc_ip),
        }
        conn.unbind()

        score = _calculate_score(findings)
        _push_to_neo4j(findings, domain)
        _store_history(score, dc_ip, domain, findings)

        return {
            "status": "success",
            "score": score,
            "findings": findings,
            "dc_ip": dc_ip,
            "domain": domain,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        err = traceback.format_exc()
        logger.error(f"AD scan failed: {err}")
        return {"status": "error", "message": str(e), "score": 0, "findings": {}}


def get_last_scan_results():
    """
    Read the most recent scan row from Postgres and annotate with Neo4j node counts.
    Returns a dict with score, timestamp, domain, and flagged node lists.
    """
    import json
    try:
        conn = _pg_connect()
        cur = conn.cursor()
        _ensure_history_table(cur)
        cur.execute("""
            SELECT score, dc_ip, domain, findings, timestamp
            FROM exposure_history
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        row = cur.fetchone()
        conn.close()

        if not row:
            return {"status": "no_data", "message": "No scans have been run yet."}

        score, dc_ip, domain, findings_json, timestamp = row
        findings = json.loads(findings_json) if findings_json else {}

        # Annotate with live Neo4j counts
        flagged_users = []
        flagged_computers = []
        try:
            asrep_rows = neo4j.run_query(
                "MATCH (u:User) WHERE u.asrep_roastable = true RETURN u.name AS name"
            )
            kerb_rows = neo4j.run_query(
                "MATCH (u:User) WHERE u.kerberoastable = true RETURN u.name AS name, u.spn AS spn"
            )
            unc_rows = neo4j.run_query(
                "MATCH (c:Computer) WHERE c.unconstrained_delegation = true RETURN c.name AS name"
            )
            flagged_users = [
                {"name": r["name"], "type": "AS-REP Roastable"} for r in (asrep_rows or [])
            ] + [
                {"name": r["name"], "type": f"Kerberoastable ({r.get('spn','')})"} for r in (kerb_rows or [])
            ]
            flagged_computers = [
                {"name": r["name"], "type": "Unconstrained Delegation"} for r in (unc_rows or [])
            ]
        except Exception as neo4j_err:
            logger.warning(f"Neo4j annotation failed: {neo4j_err}")

        return {
            "status": "success",
            "score": score,
            "dc_ip": dc_ip,
            "domain": domain,
            "timestamp": str(timestamp),
            "findings": findings,
            "flagged_users": flagged_users,
            "flagged_computers": flagged_computers,
            "spooler": findings.get("spooler", False),
        }

    except Exception as e:
        err = traceback.format_exc()
        logger.error(f"get_last_scan_results failed: {err}")
        return {"status": "error", "message": str(e)}


def get_live_kpi():
    """
    Fast Neo4j-only KPI query — no Postgres required.
    Returns counts of each vulnerability type for the live stats bar.
    """
    kpi = {"asrep": 0, "kerberoast": 0, "unconstrained": 0, "spooler": False, "error": None}
    try:
        asrep = neo4j.run_query(
            "MATCH (u:User) WHERE u.asrep_roastable = true RETURN count(u) AS n"
        )
        kerb = neo4j.run_query(
            "MATCH (u:User) WHERE u.kerberoastable = true RETURN count(u) AS n"
        )
        unc = neo4j.run_query(
            "MATCH (c:Computer) WHERE c.unconstrained_delegation = true RETURN count(c) AS n"
        )
        kpi["asrep"]        = (asrep or [{}])[0].get("n", 0)
        kpi["kerberoast"]   = (kerb  or [{}])[0].get("n", 0)
        kpi["unconstrained"]= (unc   or [{}])[0].get("n", 0)
    except Exception as e:
        kpi["error"] = str(e)
    return kpi


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY REFERENCE DATABASE
# ─────────────────────────────────────────────────────────────────────────────

VULN_REFERENCES = {
    "asrep": {
        "title": "AS-REP Roasting",
        "description": (
            "AS-REP Roasting targets user accounts that have Kerberos pre-authentication disabled "
            "(UAC flag 0x400000). The DC responds to AS-REQ without credentials, returning a TGT "
            "encrypted with the user's password hash — crackable offline."
        ),
        "cvss": "7.5 (High)",
        "nvd_search": "AS-REP kerberos authentication",
        "cves": [
            {"id": "CVE-2014-6324",  "title": "MS14-068 — Kerberos Privilege Escalation",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-6324",
             "severity": "CRITICAL", "cvss": "9.0"},
            {"id": "CVE-2021-42278", "title": "Active Directory Domain Services Elevation of Privilege",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42278",
             "severity": "HIGH", "cvss": "8.8"},
            {"id": "CVE-2021-42287", "title": "sAMAccountName Spoofing / noPac (Kerberos Auth bypass)",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42287",
             "severity": "HIGH", "cvss": "8.8"},
        ],
        "exploitdb": [
            {"id": "50273", "title": "Active Directory - noPac Privilege Escalation (Python)",
             "url": "https://www.exploit-db.com/exploits/50273", "date": "2021-12-13"},
            {"id": "50690", "title": "Microsoft Active Directory - 'noPac' AD Privilege Escalation",
             "url": "https://www.exploit-db.com/exploits/50690", "date": "2022-02-07"},
        ],
        "github": [
            {"name": "Rubeus",         "desc": "Kerberos abuse toolkit — asreproast, kerberoast, PTT",
             "url": "https://github.com/GhostPack/Rubeus", "stars": "4k+", "lang": "C#"},
            {"name": "impacket/GetNPUsers", "desc": "Python AS-REP Roasting — GetNPUsers.py",
             "url": "https://github.com/SecureAuthCorp/impacket", "stars": "13k+", "lang": "Python"},
            {"name": "ASREPRoast",     "desc": "PowerShell AS-REP roast script",
             "url": "https://github.com/HarmJ0y/ASREPRoast", "stars": "500+", "lang": "PowerShell"},
        ],
        "mitigation_cmd": "Set-ADUser -Identity <user> -DoesNotRequirePreAuth:$False",
    },
    "kerberoast": {
        "title": "Kerberoasting",
        "description": (
            "Any authenticated domain user can request a Kerberos TGS ticket for any account with a "
            "Service Principal Name (SPN) registered. The ticket is encrypted with the account's NTLM "
            "hash and can be cracked offline. Service accounts often have weak passwords and high privileges."
        ),
        "cvss": "8.1 (High)",
        "nvd_search": "kerberos service principal name SPN",
        "cves": [
            {"id": "CVE-2020-17049", "title": "Kerberos Bronze Bit — Constrained Delegation Bypass",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-17049",
             "severity": "HIGH", "cvss": "7.2"},
            {"id": "CVE-2022-33647", "title": "Windows Kerberos Elevation of Privilege",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-33647",
             "severity": "HIGH", "cvss": "8.1"},
            {"id": "CVE-2022-33679", "title": "Windows Kerberos Elevation of Privilege (RC4 downgrade)",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-33679",
             "severity": "HIGH", "cvss": "8.1"},
        ],
        "exploitdb": [
            {"id": "40930", "title": "Microsoft Kerberos - AS-REP/TGS Roasting (Python)",
             "url": "https://www.exploit-db.com/exploits/40930", "date": "2016-12-07"},
            {"id": "48655", "title": "Kerberoast Attack — Service Account Hash Extraction",
             "url": "https://www.exploit-db.com/exploits/48655", "date": "2020-06-03"},
        ],
        "github": [
            {"name": "Rubeus",         "desc": "Full Kerberos attack suite — kerberoast, asreproast, s4u",
             "url": "https://github.com/GhostPack/Rubeus", "stars": "4k+", "lang": "C#"},
            {"name": "GetUserSPNs.py", "desc": "Impacket Kerberoasting — request + crack TGS tickets",
             "url": "https://github.com/SecureAuthCorp/impacket", "stars": "13k+", "lang": "Python"},
            {"name": "kerberoast",     "desc": "Original Kerberoast PowerShell scripts by Tim Medin",
             "url": "https://github.com/nidem/kerberoast", "stars": "1k+", "lang": "PowerShell"},
            {"name": "PyKerberoast",   "desc": "Pure Python Kerberoasting without Impacket",
             "url": "https://github.com/skelsec/minikerberos", "stars": "600+", "lang": "Python"},
        ],
        "mitigation_cmd": "Set-ADUser -Identity <svc_acct> -ServicePrincipalNames @{Remove='MSSQLSvc/...'} ; Use-gMSA",
    },
    "unconstrained": {
        "title": "Unconstrained Kerberos Delegation",
        "description": (
            "Computers with unconstrained delegation store the full TGT of every user that authenticates "
            "to them. An attacker who compromises such a machine can extract all cached TGTs and "
            "impersonate any user — including Domain Admins. Combined with PrinterBug/SpoolSample, "
            "this achieves domain compromise in minutes."
        ),
        "cvss": "9.0 (Critical)",
        "nvd_search": "kerberos unconstrained delegation",
        "cves": [
            {"id": "CVE-2021-36942", "title": "Windows LSA Spoofing (PetitPotam — NTLM relay to AD CS)",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-36942",
             "severity": "HIGH", "cvss": "9.8"},
            {"id": "CVE-2018-8581",  "title": "Exchange PrivExchange — NTLM relay to unconstrained hosts",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-8581",
             "severity": "HIGH", "cvss": "7.4"},
            {"id": "CVE-2019-1040",  "title": "NTLM Tampering — relay to unconstrained delegation machines",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-1040",
             "severity": "HIGH", "cvss": "7.1"},
        ],
        "exploitdb": [
            {"id": "46129", "title": "SpoolSample — Force DC Authentication for Delegation Abuse",
             "url": "https://www.exploit-db.com/exploits/46129", "date": "2019-01-17"},
            {"id": "50016", "title": "PetitPotam — Coerce NTLM Auth via MS-EFSRPC",
             "url": "https://www.exploit-db.com/exploits/50016", "date": "2021-07-26"},
        ],
        "github": [
            {"name": "SpoolSample",   "desc": "Coerce DC auth via PrinterBug for unconstrained delegation abuse",
             "url": "https://github.com/leechristensen/SpoolSample", "stars": "1.5k+", "lang": "C#"},
            {"name": "Rubeus monitor","desc": "Monitor + capture TGTs on unconstrained hosts in real-time",
             "url": "https://github.com/GhostPack/Rubeus", "stars": "4k+", "lang": "C#"},
            {"name": "PetitPotam",    "desc": "NTLM coercion via MS-EFSRPC — pairs with unconstrained delegation",
             "url": "https://github.com/topotam/PetitPotam", "stars": "2k+", "lang": "Python"},
            {"name": "Impacket secretsdump", "desc": "DCSync after TGT capture from unconstrained host",
             "url": "https://github.com/SecureAuthCorp/impacket", "stars": "13k+", "lang": "Python"},
        ],
        "mitigation_cmd": "Set-ADComputer -Identity <host> -TrustedForDelegation:$False",
    },
}


def get_vuln_detail(vuln_type):
    """
    Return the full reference data for a vulnerability type including:
      - Static CVE/ExploitDB/GitHub knowledge base
      - Live NVD API search results
      - Live Neo4j affected accounts/hosts
    """
    ref = dict(VULN_REFERENCES.get(vuln_type, {}))
    ref["live_cves"]   = []
    ref["affected"]    = []

    # ── Affected hosts from Neo4j ─────────────────────────────────────────────
    try:
        neo4j_queries = {
            "asrep": (
                "MATCH (u:User) WHERE u.asrep_roastable = true "
                "RETURN u.name AS name, u.domain AS domain, 'User' AS type",
                "asrep_roastable accounts"
            ),
            "kerberoast": (
                "MATCH (u:User) WHERE u.kerberoastable = true "
                "RETURN u.name AS name, u.domain AS domain, u.spn AS spn, 'User' AS type",
                "Kerberoastable accounts"
            ),
            "unconstrained": (
                "MATCH (c:Computer) WHERE c.unconstrained_delegation = true "
                "RETURN c.name AS name, c.domain AS domain, 'Computer' AS type",
                "Unconstrained delegation computers"
            ),
        }
        if vuln_type in neo4j_queries:
            cypher, _ = neo4j_queries[vuln_type]
            rows = neo4j.run_query(cypher) or []
            for r in rows:
                entry = {
                    "name":   r.get("name", "Unknown"),
                    "domain": r.get("domain", ""),
                    "type":   r.get("type",   "Unknown"),
                }
                if vuln_type == "kerberoast":
                    entry["spn"] = r.get("spn", "")
                ref["affected"].append(entry)
    except Exception as e:
        logger.warning(f"Neo4j affected host query failed: {e}")

    # ── Live NVD API ──────────────────────────────────────────────────────────
    try:
        import requests, urllib.parse
        query = urllib.parse.quote(ref.get("nvd_search", vuln_type))
        url   = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
        resp  = requests.get(url, timeout=6, headers={"User-Agent": "VulnIntel-ADScanner/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve    = item.get("cve", {})
                cve_id = cve.get("id", "")
                descs  = cve.get("descriptions", [])
                desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                metrics    = cve.get("metrics", {})
                cvss_score = ""
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    m = metrics.get(metric_key, [])
                    if m:
                        cvss_score = str(m[0].get("cvssData", {}).get("baseScore", ""))
                        break
                ref["live_cves"].append({
                    "id":    cve_id,
                    "title": desc[:120] + ("…" if len(desc) > 120 else ""),
                    "url":   f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "cvss":  cvss_score,
                })
    except Exception as e:
        logger.warning(f"NVD API fetch failed: {e}")
    return ref




def get_score_history(limit=50):
    """
    Return all historical scan scores from Postgres as a list of dicts:
      [{"timestamp": "...", "score": int, "domain": "...", "dc_ip": "..."}, ...]
    Ordered oldest → newest for charting.
    """
    try:
        conn = _pg_connect()
        cur  = conn.cursor()
        _ensure_history_table(cur)
        cur.execute("""
            SELECT score, dc_ip, domain, timestamp
            FROM exposure_history
            ORDER BY timestamp ASC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        return [
            {"score": r[0], "dc_ip": r[1], "domain": r[2], "timestamp": str(r[3])}
            for r in rows
        ]
    except Exception as e:
        logger.warning(f"get_score_history failed (non-fatal): {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# GRAPH VIEW MODE QUERIES
# ─────────────────────────────────────────────────────────────────────────────

_GRAPH_QUERIES = {
    "full": {
        "label": "🌐 Full AD Map",
        "cypher": """
            MATCH (n)-[r]->(m)
            WHERE any(l IN labels(n) WHERE l IN ['User','Group','Computer','Domain','GPO','OU'])
            RETURN n, r, m LIMIT 400
        """,
    },
    "attack_paths": {
        "label": "🔴 Attack Paths",
        "cypher": """
            MATCH (u)
            WHERE (u.asrep_roastable = true OR u.kerberoastable = true OR u.unconstrained_delegation = true)
            OPTIONAL MATCH (u)-[r]->(target)
            RETURN u AS n, r, target AS m LIMIT 200
        """,
        "optional_edges": True,
    },
    "admin": {
        "label": "👑 Admin Rights",
        "cypher": """
            MATCH (u)-[r:AdminTo]->(c)
            RETURN u AS n, r, c AS m LIMIT 200
        """,
    },
    "groups": {
        "label": "👥 Group Memberships",
        "cypher": """
            MATCH (u)-[r:MemberOf]->(g)
            RETURN u AS n, r, g AS m LIMIT 300
        """,
    },
    "computers": {
        "label": "🖥 Computer Trusts",
        "cypher": """
            MATCH (n)-[r]->(m)
            WHERE 'Computer' IN labels(n) OR 'Computer' IN labels(m)
            AND type(r) IN ['HasSession','AdminTo','AllowedToDelegate','TrustedBy']
            RETURN n, r, m LIMIT 200
        """,
    },
    "tier0": {
        "label": "🏰 Tier-0 Assets",
        "cypher": """
            MATCH (n)-[r]->(m)
            WHERE 'Domain' IN labels(n) OR 'Domain' IN labels(m)
               OR n.unconstrained_delegation = true
               OR m.unconstrained_delegation = true
            RETURN n, r, m LIMIT 200
        """,
    },
}

# Exposed for UI dropdowns
GRAPH_VIEW_OPTIONS = [
    {"label": v["label"], "value": k}
    for k, v in _GRAPH_QUERIES.items()
]


def get_graph_elements(view_mode="full"):
    """
    Query Neo4j for AD graph data using one of 6 view modes:
      full         - All AD nodes and relationships
      attack_paths - Only vulnerable/flagged nodes and their relationships
      admin        - AdminTo relationships
      groups       - MemberOf relationships
      computers    - Computer-centric trust relationships
      tier0        - Domain-level and unconstrained delegation nodes
    Returns a Cytoscape-compatible list of element dicts.
    """
    BH_LABELS = {"User", "Group", "Computer", "Domain", "GPO", "OU"}
    elements = []

    query_def = _GRAPH_QUERIES.get(view_mode, _GRAPH_QUERIES["full"])
    cypher = query_def["cypher"]
    optional_edges = query_def.get("optional_edges", False)

    try:
        results = neo4j.run_query(cypher)
        if not results:
            return []

        unique_nodes = set()

        def _add_node(node, node_id):
            if node_id in unique_nodes:
                return
            name = node.get("name", node_id)
            if "@" in name:
                name = name.split("@")[0]
            labels = [l for l in node.labels if l in BH_LABELS]
            lbl = labels[0] if labels else (list(node.labels)[0] if node.labels else "Unknown")
            extra = {}
            if node.get("asrep_roastable"):
                extra["flagged"] = "asrep"
            elif node.get("kerberoastable"):
                extra["flagged"] = "kerberoast"
            elif node.get("unconstrained_delegation"):
                extra["flagged"] = "unconstrained"
            elements.append({"data": {"id": node_id, "label": name, "type": lbl, **extra}})
            unique_nodes.add(node_id)

        for row in results:
            n_node = row["n"]
            r_rel  = row["r"]
            m_node = row["m"]
            n_id = str(n_node.element_id)
            _add_node(n_node, n_id)
            # Handle optional edges — m and r may be None (OPTIONAL MATCH rows)
            if optional_edges and (r_rel is None or m_node is None):
                continue
            m_id = str(m_node.element_id)
            _add_node(m_node, m_id)
            elements.append({"data": {"source": n_id, "target": m_id, "label": r_rel.type}})

        return elements

    except Exception as e:
        logger.error(f"get_graph_elements({view_mode}) failed: {traceback.format_exc()}")
        return []
