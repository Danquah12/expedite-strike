"""
risk_correlation.py
────────────────────
Multi-source risk correlation engine.

Pulls live data from Neo4j (PingCastle vulns, Nmap ports, BloodHound paths)
and computes:
  • Unified risk score  (0–100)
  • Critical findings list
  • Top attack paths to Domain Admin
  • Per-category breakdown
"""

from __future__ import annotations
import os
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any

log = logging.getLogger("risk_correlation")

NEO4J_URI  = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "Adomaa12@")


# ── Data classes ──────────────────────────────────────────────────────────────
@dataclass
class CorrelatedFinding:
    source:   str        # PingCastle | Nmap | BloodHound
    severity: str        # Critical | High | Medium | Info
    title:    str
    detail:   str = ""
    score:    int = 0


@dataclass
class CorrelationResult:
    unified_score:   int  = 0
    level:           str  = "LOW"      # LOW | MEDIUM | HIGH | CRITICAL
    findings:        List[CorrelatedFinding] = field(default_factory=list)
    attack_paths:    List[Dict]              = field(default_factory=list)
    top_path_str:    str  = ""
    by_source:       Dict[str, int]          = field(default_factory=dict)
    by_severity:     Dict[str, int]          = field(default_factory=dict)
    summary_json:    Dict[str, Any]          = field(default_factory=dict)
    timestamp:       str  = ""


# ── Weights ───────────────────────────────────────────────────────────────────
_LEVEL_WEIGHT = {
    "Critical":  10,
    "High":       6,
    "Medium":     3,
    "Low":        1,
    "Info":       0,
    "Unknown":    1,
}

_HIGH_RISK_PORTS = {"445", "389", "636", "88", "3389", "5985",
                    "5986", "23", "21", "2049", "1433", "3306", "5900"}

_PORT_LABELS = {
    "445":  "SMB — lateral movement / ransomware vector",
    "389":  "LDAP — AD enumeration",
    "636":  "LDAPS — AD enumeration (TLS)",
    "88":   "Kerberos — ticket attacks",
    "3389": "RDP — brute-force / BlueKeep",
    "5985": "WinRM — remote code execution",
    "5986": "WinRM (HTTPS) — remote code execution",
    "23":   "Telnet — cleartext credentials",
    "21":   "FTP — cleartext credentials",
    "2049": "NFS — unauthenticated mount",
    "1433": "MSSQL — database access",
    "3306": "MySQL — database access",
    "5900": "VNC — remote desktop",
}


# ── Main engine ───────────────────────────────────────────────────────────────
class RiskCorrelationEngine:

    def __init__(self, uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS):
        self._uri  = uri
        self._user = user
        self._pass = password

    def _driver(self):
        from neo4j import GraphDatabase
        return GraphDatabase.driver(self._uri, auth=(self._user, self._pass))

    def correlate(self) -> CorrelationResult:
        """Pull all data from Neo4j and compute the unified risk."""
        result = CorrelationResult(timestamp=datetime.utcnow().isoformat())
        raw_score = 0
        findings: List[CorrelatedFinding] = []

        try:
            driver = self._driver()
        except Exception as e:
            log.error(f"Neo4j connection failed: {e}")
            result.unified_score = 0
            result.level = "UNKNOWN"
            result.summary_json = {"error": str(e)}
            return result

        with driver.session() as s:

            # ── 1. PingCastle vulnerabilities ─────────────────────────────
            pc_rows = s.run("""
                MATCH (v:Vulnerability)
                WHERE v.source = 'PingCastle' OR v.level IS NOT NULL
                RETURN v.id AS id, v.title AS title,
                       v.level AS level, coalesce(v.score, 0) AS score
            """)
            pc_count = 0
            for r in pc_rows:
                lv  = r["level"] or "Unknown"
                wt  = _LEVEL_WEIGHT.get(lv, 1)
                raw_score += wt
                findings.append(CorrelatedFinding(
                    source="PingCastle", severity=lv,
                    title=r["title"] or r["id"] or "Unknown risk",
                    score=wt))
                pc_count += 1

            # ── 2. Nmap critical ports ─────────────────────────────────────
            pt_rows = s.run("""
                MATCH (c:Computer)-[:HAS_PORT]->(pt:Port)
                RETURN c.ip AS host, pt.port AS port, pt.risk AS risk
            """)
            port_seen: set = set()
            for r in pt_rows:
                port = str(r["port"] or "")
                host = r["host"] or "?"
                if port in _HIGH_RISK_PORTS and port not in port_seen:
                    port_seen.add(port)
                    raw_score += 5
                    label = _PORT_LABELS.get(port, f"Port {port} exposed")
                    findings.append(CorrelatedFinding(
                        source="Nmap", severity="High",
                        title=f"Critical port {port} open on {host}",
                        detail=label, score=5))

            # ── 3. BloodHound — attack paths ───────────────────────────────
            path_rows = s.run("""
                MATCH p=shortestPath(
                    (u:User)-[*1..8]->(g:Group)
                )
                WHERE toLower(g.name) CONTAINS 'domain admin'
                RETURN [n IN nodes(p) | coalesce(n.name, n.id, 'node')] AS path,
                       length(p) AS hops
                ORDER BY hops ASC
                LIMIT 10
            """)
            paths = [dict(r) for r in path_rows]

            for p in paths:
                hops    = p.get("hops", 1)
                p_score = max(20 - hops * 2, 8)   # shorter = worse
                raw_score += p_score
                path_str = " → ".join(p["path"])
                findings.append(CorrelatedFinding(
                    source="BloodHound", severity="Critical",
                    title=f"Path to Domain Admin ({hops} hops)",
                    detail=path_str, score=p_score))

            # ── 4. Cross-correlation bonuses ───────────────────────────────
            #    User with a path to DA AND a Kerberoastable vuln → bonus
            kerberoast_paths = s.run("""
                MATCH (u:User)-[:HAS_VULN]->(v:Vulnerability)
                WHERE toLower(v.title) CONTAINS 'kerberoast'
                   OR toLower(v.id)    CONTAINS 'kerberoast'
                WITH u
                MATCH (u)-[*1..6]->(g:Group)
                WHERE toLower(g.name) CONTAINS 'admin'
                RETURN count(u) AS cnt
            """)
            cross_cnt = list(kerberoast_paths)[0]["cnt"]
            if cross_cnt:
                raw_score += cross_cnt * 8
                findings.append(CorrelatedFinding(
                    source="Correlation", severity="Critical",
                    title=f"{cross_cnt} Kerberoastable user(s) with DA path",
                    detail="High-probability compromise vector",
                    score=cross_cnt * 8))

        driver.close()

        # ── Clamp + level ─────────────────────────────────────────────────
        result.unified_score = min(raw_score, 100)
        if result.unified_score >= 75:
            result.level = "CRITICAL"
        elif result.unified_score >= 50:
            result.level = "HIGH"
        elif result.unified_score >= 25:
            result.level = "MEDIUM"
        else:
            result.level = "LOW"

        result.findings    = findings
        result.attack_paths = paths

        if paths:
            result.top_path_str = " → ".join(paths[0].get("path", []))

        # Per-source + per-severity totals
        for f in findings:
            result.by_source[f.source]     = result.by_source.get(f.source, 0) + 1
            result.by_severity[f.severity] = result.by_severity.get(f.severity, 0) + 1

        result.summary_json = {
            "score":     result.unified_score,
            "level":     result.level,
            "top_path":  result.top_path_str,
            "findings":  [
                {"source": f.source, "severity": f.severity,
                 "title": f.title, "detail": f.detail}
                for f in findings
            ],
        }

        log.info(f"✅ Correlation complete: score={result.unified_score} level={result.level}")
        return result


# ── Attack path scorer ────────────────────────────────────────────────────────
def score_path(path_nodes: list) -> int:
    """Score a single attack path by node types (higher = more dangerous)."""
    score = 0
    for node in path_nodes:
        t = str(node).lower()
        if "vuln"  in t or "cve" in t:  score += 10
        elif "admin" in t:              score += 20
        elif "service" in t:            score += 5
        else:                           score += 2
    return score
