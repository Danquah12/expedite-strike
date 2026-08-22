"""
neo4j_mock.py — In-memory Mock Neo4j Graph
==========================================
Provides realistic demo data when Neo4j is unavailable.
All queries return plausible pentest data based on the query type.
"""
import re
import random
from datetime import datetime, timedelta

# ── Realistic demo dataset ─────────────────────────────────────────────────────
_HOSTS = [
    {"ip": "192.168.1.1",   "os": "Linux",   "os_family": "Linux",   "compromised": False, "hostname": "gateway"},
    {"ip": "192.168.1.10",  "os": "Windows", "os_family": "Windows", "compromised": True,  "hostname": "DC01",
     "exploited_by": "MS17-010 EternalBlue", "access_level": "SYSTEM", "compromised_at": "2026-04-20T10:15:00"},
    {"ip": "192.168.1.20",  "os": "Linux",   "os_family": "Linux",   "compromised": False, "hostname": "web01"},
    {"ip": "192.168.1.21",  "os": "Linux",   "os_family": "Linux",   "compromised": True,  "hostname": "web02",
     "exploited_by": "Apache Log4Shell CVE-2021-44228", "access_level": "User", "compromised_at": "2026-04-20T11:30:00"},
    {"ip": "192.168.1.30",  "os": "Windows", "os_family": "Windows", "compromised": False, "hostname": "WRK01"},
    {"ip": "192.168.1.31",  "os": "Windows", "os_family": "Windows", "compromised": False, "hostname": "WRK02"},
    {"ip": "192.168.1.50",  "os": "Linux",   "os_family": "Linux",   "compromised": False, "hostname": "db01"},
    {"ip": "192.168.1.100", "os": "Windows", "os_family": "Windows", "compromised": False, "hostname": "fileserver"},
    {"ip": "10.0.0.1",      "os": "Cisco IOS","os_family": "Network", "compromised": False, "hostname": "core-sw"},
    {"ip": "10.0.0.5",      "os": "FreeBSD",  "os_family": "BSD",    "compromised": False, "hostname": "ns1"},
]

_SERVICES = [
    {"host": "192.168.1.1",  "port": 22,   "name": "ssh",    "product": "OpenSSH",      "version": "8.4"},
    {"host": "192.168.1.1",  "port": 80,   "name": "http",   "product": "nginx",         "version": "1.18"},
    {"host": "192.168.1.10", "port": 445,  "name": "smb",    "product": "Samba",         "version": "3.0"},
    {"host": "192.168.1.10", "port": 3389, "name": "rdp",    "product": "Microsoft RDP", "version": ""},
    {"host": "192.168.1.10", "port": 389,  "name": "ldap",   "product": "Active Dir.",   "version": ""},
    {"host": "192.168.1.20", "port": 80,   "name": "http",   "product": "Apache",        "version": "2.4.49"},
    {"host": "192.168.1.20", "port": 443,  "name": "https",  "product": "Apache",        "version": "2.4.49"},
    {"host": "192.168.1.21", "port": 8080, "name": "http",   "product": "Apache Tomcat", "version": "9.0"},
    {"host": "192.168.1.50", "port": 3306, "name": "mysql",  "product": "MySQL",         "version": "5.7"},
    {"host": "192.168.1.50", "port": 5432, "name": "pgsql",  "product": "PostgreSQL",    "version": "13"},
]

_FINDINGS = [
    {"host": "192.168.1.10", "port": 445,  "service": "smb",   "severity": "Critical",
     "name": "MS17-010 EternalBlue - SMB Remote Code Execution",
     "cve": "CVE-2017-0144", "scanner": "nmap", "source": "nmap",
     "desc": "SMBv1 is enabled and exploitable via EternalBlue. Allows unauthenticated RCE.",
     "type": "Network"},
    {"host": "192.168.1.20", "port": 80,   "service": "http",  "severity": "Critical",
     "name": "Apache Path Traversal / RCE (CVE-2021-41773)",
     "cve": "CVE-2021-41773", "scanner": "nuclei", "source": "nuclei",
     "desc": "Path traversal in Apache 2.4.49 allows reading arbitrary files and executing code.",
     "type": "Web"},
    {"host": "192.168.1.21", "port": 8080, "service": "http",  "severity": "Critical",
     "name": "Log4Shell Remote Code Execution",
     "cve": "CVE-2021-44228", "scanner": "nuclei", "source": "nuclei",
     "desc": "Log4j 2.x JNDI injection allows unauthenticated RCE via crafted log messages.",
     "type": "Web"},
    {"host": "192.168.1.10", "port": 3389, "service": "rdp",   "severity": "High",
     "name": "BlueKeep - RDP Remote Code Execution",
     "cve": "CVE-2019-0708", "scanner": "nmap", "source": "nmap",
     "desc": "Pre-auth RCE vulnerability in RDP. Wormable.",
     "type": "Network"},
    {"host": "192.168.1.50", "port": 3306, "service": "mysql", "severity": "High",
     "name": "MySQL Remote Root Access",
     "cve": "", "scanner": "nmap", "source": "nmap",
     "desc": "MySQL accepts connections from any host with root credentials.",
     "type": "Database"},
    {"host": "192.168.1.20", "port": 443,  "service": "https", "severity": "Medium",
     "name": "SSL Certificate Expired",
     "cve": "", "scanner": "ssl-check", "source": "ssl-check",
     "desc": "TLS certificate expired 30 days ago. MITM risk.",
     "type": "SSL"},
    {"host": "192.168.1.1",  "port": 22,   "service": "ssh",   "severity": "Medium",
     "name": "SSH Weak Ciphers Enabled",
     "cve": "", "scanner": "nmap", "source": "nmap",
     "desc": "Server supports deprecated ciphers: arcfour, 3des-cbc.",
     "type": "Network"},
    {"host": "192.168.1.10", "port": 389,  "service": "ldap",  "severity": "High",
     "name": "LDAP Null Bind Allowed",
     "cve": "", "scanner": "pentest-engine", "source": "pentest-engine",
     "desc": "LDAP server allows anonymous bind, exposing directory structure.",
     "type": "Network"},
    {"host": "192.168.1.50", "port": 5432, "service": "pgsql", "severity": "Medium",
     "name": "PostgreSQL Public Schema Permissions",
     "cve": "CVE-2018-1058", "scanner": "nmap", "source": "nmap",
     "desc": "Public schema writable by all users allows privilege escalation.",
     "type": "Database"},
    {"host": "192.168.1.21", "port": 8080, "service": "http",  "severity": "Low",
     "name": "Server Version Header Exposed",
     "cve": "", "scanner": "nikto", "source": "nikto",
     "desc": "X-Powered-By header exposes Apache Tomcat 9.0 version.",
     "type": "Web"},
]

_TECHNIQUES = [
    {"tactic": "Initial Access",       "name": "Exploit Public-Facing Application", "n": 4},
    {"tactic": "Execution",            "name": "Command and Scripting Interpreter",  "n": 3},
    {"tactic": "Persistence",          "name": "Scheduled Task/Job",                "n": 2},
    {"tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts",   "n": 3},
    {"tactic": "Defense Evasion",      "name": "Indicator Removal on Host",         "n": 2},
    {"tactic": "Credential Access",    "name": "OS Credential Dumping",             "n": 4},
    {"tactic": "Lateral Movement",     "name": "Use Alternate Authentication Material", "n": 3},
    {"tactic": "Collection",           "name": "Data from Local System",            "n": 2},
    {"tactic": "Exfiltration",         "name": "Exfiltration Over Alternative Protocol", "n": 1},
    {"tactic": "Command and Control",  "name": "Web Protocols",                     "n": 2},
]

_ATTACK_PATHS = [
    {
        "nodes": [
            {"data": {"id": "192.168.1.20", "label": "192.168.1.20"}},
            {"data": {"id": "192.168.1.10", "label": "DC01 (192.168.1.10)"}},
            {"data": {"id": "192.168.1.50", "label": "db01 (192.168.1.50)"}},
        ],
        "edges": [
            {"data": {"source": "192.168.1.20", "target": "192.168.1.10"}},
            {"data": {"source": "192.168.1.10", "target": "192.168.1.50"}},
        ],
    }
]


class MockNeo4jResult:
    """Mimics a Neo4j Record dict accessor."""
    def __init__(self, data: dict):
        self._data = data
    def __getitem__(self, key):
        return self._data.get(key)
    def get(self, key, default=None):
        return self._data.get(key, default)
    def data(self):
        return self._data
    def values(self):
        return list(self._data.values())


class MockNeo4jEngine:
    """Drop-in replacement for Neo4jEngine when Neo4j is offline."""

    def _smart_query(self, query: str, **kwargs) -> list:
        q = query.lower()

        # Host queries
        if "host" in q and "return" in q:
            if "compromised" in q or "exploited" in q or "access_level" in q:
                return [MockNeo4jResult({
                    "ip": h["ip"], "os": h.get("os", "Unknown"),
                    "compromised": h.get("compromised", False),
                    "exploited_by": h.get("exploited_by", ""),
                    "access_level": h.get("access_level", ""),
                    "compromised_at": h.get("compromised_at", ""),
                }) for h in _HOSTS]
            if "hostname" in q:
                return [MockNeo4jResult({"ip": h["ip"], "hostname": h.get("hostname", h["ip"])}) for h in _HOSTS]
            return [MockNeo4jResult({"ip": h["ip"]}) for h in _HOSTS]

        # Service queries
        if "service" in q and "port" in q:
            entries = []
            for s in _SERVICES:
                h_match = [h for h in _HOSTS if h["ip"] == s["host"]]
                hostname = h_match[0]["hostname"] if h_match else s["host"]
                entries.append(MockNeo4jResult({
                    "host": s["host"], "hostname": hostname,
                    "port": str(s["port"]), "name": s["name"],
                    "product": s["product"], "version": s["version"],
                }))
            return entries

        # Finding queries
        if "finding" in q:
            if "count" in q:
                sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
                for f in _FINDINGS:
                    sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
                if "sev" in q:
                    return [MockNeo4jResult({"sev": k, "n": v}) for k, v in sev_counts.items()]
                return [MockNeo4jResult({"n": len(_FINDINGS)})]
            if "scanner" in q or "source" in q or "src" in q:
                from collections import Counter
                src_counts = Counter(f["scanner"] for f in _FINDINGS)
                return [MockNeo4jResult({"src": k, "n": v}) for k, v in src_counts.items()]
            return [MockNeo4jResult({
                "host": f["host"], "service": f["service"], "port": str(f["port"]),
                "name": f["name"], "severity": f["severity"],
                "scanner": f["scanner"], "source": f["source"],
                "cve": f["cve"], "desc": f["desc"], "finding_type": f["type"],
            }) for f in _FINDINGS]

        # Technique queries
        if "technique" in q:
            return [MockNeo4jResult(t) for t in _TECHNIQUES]

        # Shortest path / attack path
        if "shortestpath" in q or "connected" in q:
            src = kwargs.get("src") or kwargs.get("start") or "192.168.1.20"
            tgt = kwargs.get("target") or kwargs.get("dst") or "192.168.1.50"
            path = _ATTACK_PATHS[0]
            return [MockNeo4jResult({"p": path, "path": path})]

        # Compromised chain
        if "compromised_via" in q:
            return [MockNeo4jResult({
                "host": h["ip"], "via": h.get("exploited_by", "Unknown"),
                "level": h.get("access_level", "User"),
            }) for h in _HOSTS if h.get("compromised")]

        # Kill chain / lateral data
        if "lateral" in q or "pass" in q:
            return [MockNeo4jResult({"host": "192.168.1.10", "via": "Pass-the-Hash", "level": "Domain Admin"})]

        return []

    def run_query(self, query, params=None, **kwargs):
        all_kwargs = {**(params or {}), **kwargs}
        return self._smart_query(query, **all_kwargs)

    def query(self, query, params=None, **kwargs):
        return self.run_query(query, params, **kwargs)

    def run_query_simple(self, query, params=None, **kwargs):
        results = self.run_query(query, params, **kwargs)
        out = []
        for r in results:
            out.extend(r.values())
        return out

    def query_simple(self, query, params=None, **kwargs):
        return self.run_query_simple(query, params, **kwargs)

    def get_shortest_path(self, start_host, target_host):
        return _ATTACK_PATHS[0]

    def get_full_graph(self):
        nodes = [MockNeo4jResult({"n": h, "r": "CONNECTED", "m": _HOSTS[(i+1) % len(_HOSTS)]})
                 for i, h in enumerate(_HOSTS)]
        return nodes

    def get_neighbors(self, host):
        return [h["ip"] for h in _HOSTS if h["ip"] != host][:3]

    def test_connection(self):
        return False

    # Session context manager for direct driver.session() usage
    class _MockSession:
        def __enter__(self):    return self
        def __exit__(self, *_): pass
        def run(self, query, params=None):
            engine = MockNeo4jEngine()
            return engine._smart_query(query, **(params or {}))

    class _MockDriver:
        def session(self):
            return MockNeo4jEngine._MockSession()

    @property
    def driver(self):
        return self._MockDriver()


# ── Helper data accessors ──────────────────────────────────────────────────────
def get_mock_hosts():
    return _HOSTS

def get_mock_findings():
    return _FINDINGS

def get_mock_services():
    return _SERVICES

def get_mock_attack_path():
    return _ATTACK_PATHS[0]
