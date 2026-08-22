# ==============================================================
# digital_twin.py — SOC-GRADE DIGITAL TWIN  (live EPSS/KEV/MITRE)
# ==============================================================

import time
import requests
from cyber_range.services.neo4j_engine import Neo4jEngine

# ──────────────────────────────────────────────────────────────
# Module-level caches  (TTL in seconds)
# ──────────────────────────────────────────────────────────────
_EPSS_CACHE: dict  = {}   # cve_id → (score, ts)
_EPSS_TTL          = 300  # 5 min

_KEV_CACHE: set    = set()
_KEV_CACHE_TS: float = 0.0
_KEV_TTL           = 3600  # 1 hr


def _fetch_epss(cve_ids: list) -> list:
    """
    Fetch EPSS scores from api.first.org.
    Returns list of (cve_id, float_score) sorted descending.
    """
    now = time.time()
    missing = [c for c in cve_ids
               if c not in _EPSS_CACHE or now - _EPSS_CACHE[c][1] > _EPSS_TTL]
    if missing:
        try:
            url = "https://api.first.org/data/v1/epss"
            resp = requests.get(url, params={"cve": ",".join(missing)}, timeout=6)
            if resp.ok:
                for item in resp.json().get("data", []):
                    cve = item.get("cve", "")
                    score = float(item.get("epss", 0))
                    _EPSS_CACHE[cve] = (score, now)
        except Exception:
            pass
    result = []
    for c in cve_ids:
        score = _EPSS_CACHE.get(c, (0.0, 0))[0]
        result.append((c, score))
    return sorted(result, key=lambda x: x[1], reverse=True)


def _fetch_kev_set() -> set:
    """Return the CISA KEV CVE-ID set (cached 1hr)."""
    global _KEV_CACHE, _KEV_CACHE_TS
    now = time.time()
    if now - _KEV_CACHE_TS < _KEV_TTL and _KEV_CACHE:
        return _KEV_CACHE
    try:
        url = ("https://www.cisa.gov/sites/default/files/"
               "feeds/known_exploited_vulnerabilities.json")
        resp = requests.get(url, timeout=8)
        if resp.ok:
            data = resp.json().get("vulnerabilities", [])
            _KEV_CACHE = {v["cveID"] for v in data if "cveID" in v}
            _KEV_CACHE_TS = now
    except Exception:
        pass
    return _KEV_CACHE


# Keyword → (MITRE Technique ID, Technique Name)
_MITRE_KW = {
    "sql injection":      ("T1190",  "Exploit Public-Facing Application"),
    "sqli":               ("T1190",  "Exploit Public-Facing Application"),
    "remote code":        ("T1059",  "Command & Scripting Interpreter"),
    "rce":                ("T1059",  "Command & Scripting Interpreter"),
    "command injection":  ("T1059",  "Command & Scripting Interpreter"),
    "xss":                ("T1059.007", "XSS/JavaScript Injection"),
    "cross-site":         ("T1059.007", "XSS/JavaScript Injection"),
    "path traversal":     ("T1083",  "File & Directory Discovery"),
    "directory traversal":("T1083",  "File & Directory Discovery"),
    "lfi":                ("T1083",  "File & Directory Discovery"),
    "privilege":          ("T1068",  "Exploitation for Privilege Escalation"),
    "privesc":            ("T1068",  "Exploitation for Privilege Escalation"),
    "buffer overflow":    ("T1203",  "Exploitation for Client Execution"),
    "heap overflow":      ("T1203",  "Exploitation for Client Execution"),
    "use after free":     ("T1203",  "Exploitation for Client Execution"),
    "uaf":                ("T1203",  "Exploitation for Client Execution"),
    "ssrf":               ("T1602",  "Data from Config Repository (SSRF)"),
    "server-side request":("T1602",  "Data from Config Repository (SSRF)"),
    "xxe":                ("T1190",  "Exploit Public-Facing Application"),
    "deserialization":    ("T1190",  "Exploit Public-Facing Application"),
    "authentication":     ("T1078",  "Valid Accounts"),
    "credential":         ("T1078",  "Valid Accounts"),
    "brute force":        ("T1110",  "Brute Force"),
    "default password":   ("T1078.001","Default Accounts"),
    "smb":                ("T1021.002","SMB/Windows Admin Shares"),
    "pass-the-hash":      ("T1550.002","Pass the Hash"),
    "ldap":               ("T1018",  "Remote System Discovery"),
    "dns":                ("T1071.004","Application Layer Protocol: DNS"),
    "ftp":                ("T1071",  "Application Layer Protocol"),
    "ssh":                ("T1021.004","Remote Services: SSH"),
    "backdoor":           ("T1543",  "Create/Modify System Process"),
    "webshell":           ("T1505.003","Server Software Component: Web Shell"),
    "exfil":              ("T1041",  "Exfiltration Over C2 Channel"),
    "ransomware":         ("T1486",  "Data Encrypted for Impact"),
    "log4j":              ("T1190",  "Exploit Public-Facing Application"),
    "log4shell":          ("T1190",  "Exploit Public-Facing Application"),
    "heartbleed":         ("T1040",  "Network Sniffing"),
    "shellshock":         ("T1059.004","Unix Shell"),
    "spring4shell":       ("T1190",  "Exploit Public-Facing Application"),
    "eternalblue":        ("T1210",  "Exploitation of Remote Services"),
    "ms17":               ("T1210",  "Exploitation of Remote Services"),
    "bluekeep":           ("T1210",  "Exploitation of Remote Services"),
}


def _mitre_from_keywords(names_and_cves: list) -> list:
    """Map vulnerability/CVE names to MITRE ATT&CK technique strings."""
    combined = " ".join(str(x).lower() for x in names_and_cves)
    seen, result = set(), []
    for kw, (tid, tname) in _MITRE_KW.items():
        if kw in combined and tid not in seen:
            seen.add(tid)
            result.append(f"{tid} — {tname}")
    return result



class DigitalTwin:
    def __init__(self):
        self.db = Neo4jEngine()

    # ----------------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------------
    def summary(self):
        def count(q):
            r = self.db.run_query_simple(q)
            return r[0] if r else 0

        return {
            "assets": count("MATCH (a:Host) RETURN COUNT(a)"),
            "services": count("MATCH (s:Service) RETURN COUNT(s)"),
            "vulns": count("MATCH (v:Finding) RETURN COUNT(v)") + count("MATCH (v:Vulnerability) RETURN COUNT(v)"),
        }

    # ----------------------------------------------------------
    # GRAPH ELEMENTS
    # ----------------------------------------------------------
    def build_graph_elements(self):
        assets = self.db.run_query("""
            MATCH (a:Host)
            RETURN id(a) AS id, coalesce(a.host, a.ip, a.name, toString(id(a))) AS host
        """)

        edges = self.db.run_query("""
            MATCH (a:Host)-[:CONNECTED]-(b:Host)
            RETURN id(a) AS src, id(b) AS dst
        """)

        nodes = []
        links = []

        for a in assets:
            nodes.append({
                "data": {
                    "id": f"asset-{a['id']}",
                    "label": a["host"],
                    "type": "asset"
                }
            })

        for e in edges:
            links.append({
                "data": {
                    "source": f"asset-{e['src']}",
                    "target": f"asset-{e['dst']}"
                }
            })

        return nodes + links

    # ----------------------------------------------------------
    # PROPAGATION (PURE CYPHER)
    # ----------------------------------------------------------
    def propagate(self, start_host, depth):
        query = f"""
        MATCH (s:Host) WHERE s.host=$host OR s.ip=$host OR s.name=$host
        MATCH p = (s)-[:CONNECTED*1..{depth}]-(n:Host)
        RETURN DISTINCT coalesce(n.host, n.ip, n.name, 'Unknown') AS host, length(p) AS hops
        """

        rows = self.db.run_query(query, {"host": start_host})

        result = {start_host: 0}
        
        if not rows:
            return result
            
        for r in rows:
            h = r["host"]
            d = r["hops"]
            if h not in result or d < result[h]:
                result[h] = d

        return result

    # ----------------------------------------------------------
    # RISK + MITRE  (live enrichment)
    # ----------------------------------------------------------
    def asset_risk(self, host):
        """
        Returns (epss_data, kev_cves, mitre_techniques) where:
          epss_data   = list of (cve_id, float score) tuples
          kev_cves    = list of CVE IDs in CISA KEV
          mitre_techniques = list of "T####.### — Technique Name" strings
        """
        import time

        # ── Step 1: pull CVE IDs + vuln names from Neo4j ─────────────────
        q = """
        MATCH (a:Host) WHERE coalesce(a.host, a.ip, a.name) = $host
        OPTIONAL MATCH (a)-[*1..3]->(v)
          WHERE labels(v)[0] IN ['Finding','Vulnerability','Service']
        OPTIONAL MATCH (v)-[:HAS_CVE]->(c:CVE)
        WITH
          collect(DISTINCT coalesce(c.id, c.cve_id)) AS cve_ids,
          collect(DISTINCT v.name) AS vuln_names,
          collect(DISTINCT coalesce(v.cve, v.cve_id)) AS inline_cves
        RETURN
          [x IN cve_ids + inline_cves WHERE x IS NOT NULL AND x STARTS WITH 'CVE-'] AS cve_ids,
          vuln_names
        """
        rows = self.db.run_query(q, {"host": host})
        cve_ids   = []
        vuln_names = []
        if rows:
            cve_ids   = [c for c in (rows[0].get("cve_ids") or []) if c]
            vuln_names = [n for n in (rows[0].get("vuln_names") or []) if n]

        # ── Step 2: Fetch EPSS live ────────────────────────────────────────
        epss_data = []
        if cve_ids:
            epss_data = _fetch_epss(cve_ids)

        # ── Step 3: Fetch KEV live ─────────────────────────────────────────
        kev_set  = _fetch_kev_set()
        kev_cves = sorted(set(c for c in cve_ids if c in kev_set))
        # Also mark KEV if stored as boolean in Neo4j for this host
        if not kev_cves:
            q2 = """
            MATCH (a:Host) WHERE coalesce(a.host, a.ip, a.name) = $host
            OPTIONAL MATCH (a)-[*1..3]->(v)-[:HAS_CVE]->(c:CVE)
            WHERE c.kev = true OR c.kev = 'true'
            RETURN collect(DISTINCT coalesce(c.id, c.cve_id)) AS kev_from_db
            """
            r2 = self.db.run_query(q2, {"host": host})
            if r2:
                kev_cves = [c for c in (r2[0].get("kev_from_db") or []) if c]

        # ── Step 4: MITRE via keyword mapping ────────────────────────────
        mitre = _mitre_from_keywords(vuln_names + cve_ids)

        return epss_data, kev_cves, mitre


    # ----------------------------------------------------------
    # AI NEXT-HOP (HEURISTIC)
    # ----------------------------------------------------------
    def predict_next(self, current_host):
        query = """
        MATCH (a:Host)-[:CONNECTED]-(b:Host) WHERE coalesce(a.host, a.ip, a.name)=$host
        OPTIONAL MATCH (b)-[*1..2]->(v) WHERE labels(v)[0] IN ['Finding', 'Vulnerability']
        OPTIONAL MATCH (v)-[:HAS_CVE]->(c:CVE)
        RETURN coalesce(b.host, b.ip, b.name) AS host, max(c.epss) AS epss, max(c.kev) AS kev
        """

        rows = self.db.run_query(query, {"host": current_host})
        scored = []

        for r in rows:
            score = (r["epss"] or 0) * (2 if r["kev"] else 1)
            scored.append((r["host"], score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[0][0] if scored else None

    # ----------------------------------------------------------
    # NARRATIVE
    # ----------------------------------------------------------
    def narrative(self, start, propagation, techniques, predicted):
        lines = [
            f"Initial access occurred on {start}.",
            f"Lateral movement impacted {len(propagation) - 1} additional assets."
        ]

        if techniques:
            lines.append("MITRE ATT&CK techniques observed: " + ", ".join(techniques))

        if predicted:
            lines.append(f"AI predicts the next likely target is {predicted}.")

        return " ".join(lines)
