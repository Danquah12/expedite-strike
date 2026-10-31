"""
vuln_mgmt_sync.py
=================
Auto-sync scan Findings from Neo4j into the Vulnerability Management
dashboard (VmAsset / VmVulnerability nodes).

Called after each scan completes to bridge the gap between scanner
output and the Vuln Management SLA / patch-tracking workflow.
"""

import os
import logging
import requests
from datetime import datetime, timezone

_log = logging.getLogger("vuln_mgmt_sync")

# ── Neo4j connection ──────────────────────────────────────────────────────────
_NEO4J_URI  = "bolt://localhost:7687"
_NEO4J_USER = "neo4j"
_NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "Adomaa12@")


def _driver():
    from neo4j import GraphDatabase
    return GraphDatabase.driver(_NEO4J_URI, auth=(_NEO4J_USER, _NEO4J_PASS))


# ── CISA KEV lookup (cached) ─────────────────────────────────────────────────
_KEV_CACHE: set[str] = set()
_KEV_FETCHED = False


def _load_kev() -> set[str]:
    global _KEV_CACHE, _KEV_FETCHED
    if _KEV_FETCHED:
        return _KEV_CACHE
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15,
        )
        if r.ok:
            for v in r.json().get("vulnerabilities", []):
                _KEV_CACHE.add(v.get("cveID", ""))
    except Exception as e:
        _log.warning("KEV fetch failed: %s", e)
    _KEV_FETCHED = True
    return _KEV_CACHE


# ── EPSS lookup (batch) ──────────────────────────────────────────────────────
def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS exploit-probability scores for a batch of CVEs."""
    if not cve_ids:
        return {}
    scores: dict[str, float] = {}
    # EPSS API accepts up to 100 CVEs per call
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i + 100]
        try:
            r = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(batch)},
                timeout=15,
            )
            if r.ok:
                for item in r.json().get("data", []):
                    scores[item["cve"]] = float(item.get("epss", 0))
        except Exception as e:
            _log.warning("EPSS fetch failed for batch: %s", e)
    return scores


# ── Severity → CVSS helper ───────────────────────────────────────────────────
_SEV_SCORE = {
    "critical": "10.0", "high": "8.0", "medium": "5.0",
    "low": "2.0", "info": "0.0", "information": "0.0",
}


# ══════════════════════════════════════════════════════════════════════════════
#  Main sync function
# ══════════════════════════════════════════════════════════════════════════════
def sync_findings_to_vuln_mgmt(scanner_source: str = "", on_output=None) -> int:
    """
    Read Finding nodes from Neo4j and create/merge corresponding
    VmAsset + VmVulnerability nodes for the Vulnerability Management dashboard.

    Args:
        scanner_source: optional filter (e.g. "nmap"). Empty = all scanners.
        on_output: logging callback (same signature as scan_controller log).

    Returns:
        Number of VmVulnerability nodes created/updated.
    """
    def _log_msg(m):
        if on_output:
            on_output(m)
        else:
            print(m, end="")

    driver = _driver()
    now = datetime.now(timezone.utc).isoformat()

    # ── Step 1: Query all Host → Finding pairs ────────────────────────────
    src_filter = ""
    params: dict = {}
    if scanner_source:
        src_filter = "AND toLower(toString(f.source)) = $src"
        params["src"] = scanner_source.lower()

    q_findings = f"""
        MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(s:Service)
              -[:HAS_FINDING|HAS_VULN]->(f:Finding)
        WHERE f.name IS NOT NULL {src_filter}
        RETURN DISTINCT
            coalesce(h.host, h.ip, 'unknown')    AS host_ip,
            f.cve                                  AS cve,
            coalesce(f.name, 'Unknown')            AS name,
            coalesce(toString(f.severity), 'Info') AS severity,
            f.cvss                                 AS cvss,
            coalesce(f.description, f.evidence, '') AS description,
            coalesce(toString(f.source), 'unknown') AS source
    """

    try:
        with driver.session() as session:
            findings = session.run(q_findings, **params).data()
    except Exception as e:
        _log_msg(f"[VulnMgmt Sync] Neo4j query failed: {e}\n")
        driver.close()
        return 0

    if not findings:
        _log_msg("[VulnMgmt Sync] No findings to sync.\n")
        driver.close()
        return 0

    _log_msg(f"[VulnMgmt Sync] Found {len(findings)} findings across "
             f"{len(set(f['host_ip'] for f in findings))} hosts.\n")

    # ── Step 2: Collect unique CVEs for EPSS enrichment ───────────────────
    cve_ids = list({f["cve"] for f in findings if f.get("cve") and str(f["cve"]).startswith("CVE-")})

    _log_msg(f"[VulnMgmt Sync] Enriching {len(cve_ids)} CVEs with KEV + EPSS...\n")
    kev_set = _load_kev()
    epss_scores = _fetch_epss_batch(cve_ids)

    # ── Step 3: Create VmAsset + VmVulnerability nodes ────────────────────
    count = 0
    try:
        with driver.session() as session:
            # Unique hosts → VmAsset
            hosts_seen = set()
            for f in findings:
                host = f["host_ip"]
                if host not in hosts_seen:
                    hosts_seen.add(host)
                    session.run(
                        "MERGE (a:VmAsset {name: $name}) "
                        "ON CREATE SET a.type = 'server', a.criticality = 'medium', "
                        "              a.added_date = $now, a.vuln_count = 0, "
                        "              a.auto_synced = true "
                        "SET a.last_scan_sync = $now",
                        name=host, now=now,
                    )

            # Each finding → VmVulnerability
            for f in findings:
                cve = f.get("cve") or ""
                name = f.get("name", "Unknown")

                # Use CVE as the identifier if available, otherwise use finding name
                vuln_id = cve if cve and cve.startswith("CVE-") else name[:80]
                if not vuln_id:
                    continue

                host = f["host_ip"]
                sev_raw = str(f.get("severity", "Info")).lower()
                severity = sev_raw.capitalize() if sev_raw in _SEV_SCORE else "Medium"

                # Compute score: prefer CVSS from finding, then EPSS, then severity map
                score_str = ""
                if f.get("cvss"):
                    try:
                        score_str = str(float(f["cvss"]))
                    except (ValueError, TypeError):
                        pass
                if not score_str:
                    score_str = _SEV_SCORE.get(sev_raw, "5.0")

                # KEV and EPSS enrichment
                in_kev = cve in kev_set if cve else False
                epss = epss_scores.get(cve, 0.0) if cve else 0.0

                desc = str(f.get("description", ""))[:300]
                source = f.get("source", "unknown")

                session.run(
                    "MATCH (a:VmAsset {name: $host}) "
                    "MERGE (v:VmVulnerability {cve_id: $vid, asset_name: $host}) "
                    "ON CREATE SET v.assigned_date = $now "
                    "SET v.severity = $sev, v.score = $score, "
                    "    v.description = $desc, v.source = $source, "
                    "    v.in_kev = $in_kev, v.epss = $epss, "
                    "    v.last_sync = $now "
                    "MERGE (v)-[:ASSIGNED_TO]->(a)",
                    host=host, vid=vuln_id, sev=severity,
                    score=score_str, desc=desc, source=source,
                    in_kev=in_kev, epss=epss, now=now,
                )
                count += 1

            # Update vuln counts on each asset
            for host in hosts_seen:
                session.run(
                    "MATCH (a:VmAsset {name: $name}) "
                    "OPTIONAL MATCH (v:VmVulnerability)-[:ASSIGNED_TO]->(a) "
                    "WITH a, count(v) AS cnt SET a.vuln_count = cnt",
                    name=host,
                )

    except Exception as e:
        _log_msg(f"[VulnMgmt Sync] Write error: {e}\n")
    finally:
        driver.close()

    _log_msg(f"[VulnMgmt Sync] ✓ {count} vulnerabilities synced across "
             f"{len(hosts_seen)} assets.\n")
    return count


__all__ = ["sync_findings_to_vuln_mgmt"]
