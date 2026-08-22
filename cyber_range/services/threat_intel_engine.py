# ================================================================
# threat_intel_engine.py — Custom Threat Intelligence Platform
#
# Custom equivalents of:
#   1. MISP    → IOC sharing, threat event management, correlation
#   2. CrowdStrike → Endpoint threat detection, adversary tracking
#   3. Recorded Future → Risk scoring, threat feed aggregation
#
# All feed into the GRC risk scoring pipeline.
#
# Usage:
#   from cyber_range.services.threat_intel_engine import ThreatIntelEngine
#   engine = ThreatIntelEngine()
#   engine.ingest_ioc({"type": "ip", "value": "192.168.1.1", "threat_level": "high"})
#   score = engine.compute_risk_score("192.168.1.1")
#   report = engine.get_threat_landscape()
# ================================================================

import os
import re
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional

log = logging.getLogger(__name__)

# ── Threat Categories ─────────────────────────────────────────────
THREAT_CATEGORIES = {
    "malware":      {"weight": 9, "nist": "SI-3",  "label": "Malware"},
    "ransomware":   {"weight": 10,"nist": "SI-3",  "label": "Ransomware"},
    "phishing":     {"weight": 7, "nist": "AT-2",  "label": "Phishing"},
    "c2":           {"weight": 9, "nist": "SI-4",  "label": "Command & Control"},
    "botnet":       {"weight": 8, "nist": "SI-4",  "label": "Botnet"},
    "apt":          {"weight": 10,"nist": "RA-5",  "label": "Advanced Persistent Threat"},
    "exploit":      {"weight": 9, "nist": "SI-2",  "label": "Active Exploit"},
    "credential":   {"weight": 8, "nist": "IA-5",  "label": "Credential Theft"},
    "data_leak":    {"weight": 8, "nist": "SC-28", "label": "Data Leak/Exfiltration"},
    "recon":        {"weight": 5, "nist": "RA-5",  "label": "Reconnaissance"},
    "bruteforce":   {"weight": 6, "nist": "AC-7",  "label": "Brute Force"},
    "dos":          {"weight": 7, "nist": "SC-5",  "label": "Denial of Service"},
    "supply_chain": {"weight": 10,"nist": "SR-3",  "label": "Supply Chain Attack"},
    "zero_day":     {"weight": 10,"nist": "SI-2",  "label": "Zero-Day Exploit"},
}

# ── Known Adversary Groups (CrowdStrike-style) ───────────────────
ADVERSARY_GROUPS = {
    "FANCY BEAR":     {"origin": "Russia",  "targets": ["Government", "Military", "Energy"],  "ttps": ["T1566", "T1059", "T1071"]},
    "LAZARUS GROUP":  {"origin": "N. Korea","targets": ["Finance", "Crypto", "Defense"],      "ttps": ["T1566", "T1027", "T1486"]},
    "APT41":          {"origin": "China",   "targets": ["Healthcare", "Tech", "Telecom"],     "ttps": ["T1190", "T1059", "T1078"]},
    "COZY BEAR":      {"origin": "Russia",  "targets": ["Government", "Think Tanks", "IT"],   "ttps": ["T1195", "T1078", "T1071"]},
    "HAFNIUM":        {"origin": "China",   "targets": ["Government", "Education", "NGO"],    "ttps": ["T1190", "T1505", "T1136"]},
    "DARKSIDE":       {"origin": "Russia",  "targets": ["Energy", "Critical Infrastructure"], "ttps": ["T1486", "T1490", "T1048"]},
    "SANDWORM":       {"origin": "Russia",  "targets": ["Energy", "Government", "Ukraine"],   "ttps": ["T1059", "T1562", "T1498"]},
    "MUSTANG PANDA":  {"origin": "China",   "targets": ["Government", "NGO", "ASEAN"],        "ttps": ["T1566", "T1105", "T1053"]},
    "SCATTERED SPIDER": {"origin": "US/UK", "targets": ["Telecom", "Tech", "Finance"],        "ttps": ["T1566", "T1078", "T1621"]},
    "LOCKBIT":        {"origin": "Global",  "targets": ["All Sectors"],                        "ttps": ["T1486", "T1490", "T1027"]},
}


# ================================================================
# IOC (Indicator of Compromise) Store
# ================================================================
class IocStore:
    """In-memory IOC database (MISP equivalent)."""

    def __init__(self):
        self._iocs: dict[str, dict] = {}    # key = hash(type:value)
        self._events: list[dict] = []       # threat events
        self._feeds: dict[str, list] = {}   # external feed data

    def add_ioc(self, ioc_type: str, value: str, **kwargs) -> str:
        """Add an IOC to the store."""
        key = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:16]
        self._iocs[key] = {
            "id": key,
            "type": ioc_type,        # ip, domain, hash, url, email, cve
            "value": value,
            "threat_level": kwargs.get("threat_level", "medium"),
            "category": kwargs.get("category", "unknown"),
            "tags": kwargs.get("tags", []),
            "source": kwargs.get("source", "manual"),
            "confidence": kwargs.get("confidence", 70),
            "first_seen": kwargs.get("first_seen", datetime.now().isoformat()),
            "last_seen": datetime.now().isoformat(),
            "related_adversary": kwargs.get("adversary", ""),
            "ttl_days": kwargs.get("ttl_days", 90),
        }
        return key

    def search(self, value: str) -> list[dict]:
        """Search IOCs by value substring."""
        return [ioc for ioc in self._iocs.values() if value.lower() in ioc["value"].lower()]

    def get_by_type(self, ioc_type: str) -> list[dict]:
        """Get all IOCs of a given type."""
        return [ioc for ioc in self._iocs.values() if ioc["type"] == ioc_type]

    def get_active(self) -> list[dict]:
        """Get all non-expired IOCs."""
        now = datetime.now()
        active = []
        for ioc in self._iocs.values():
            first = datetime.fromisoformat(ioc["first_seen"])
            if (now - first).days <= ioc.get("ttl_days", 90):
                active.append(ioc)
        return active

    def add_event(self, title: str, description: str, ioc_ids: list[str], **kwargs) -> dict:
        """Create a threat event (MISP Event equivalent)."""
        event = {
            "id": f"EVT-{len(self._events)+1:05d}",
            "title": title,
            "description": description,
            "ioc_ids": ioc_ids,
            "category": kwargs.get("category", "unknown"),
            "threat_level": kwargs.get("threat_level", "medium"),
            "tlp": kwargs.get("tlp", "amber"),  # TLP marking
            "created": datetime.now().isoformat(),
            "source": kwargs.get("source", "internal"),
            "adversary": kwargs.get("adversary", ""),
        }
        self._events.append(event)
        return event

    def get_events(self, limit: int = 50) -> list[dict]:
        return sorted(self._events, key=lambda e: e["created"], reverse=True)[:limit]

    def get_stats(self) -> dict:
        types = {}
        categories = {}
        for ioc in self._iocs.values():
            types[ioc["type"]] = types.get(ioc["type"], 0) + 1
            categories[ioc["category"]] = categories.get(ioc["category"], 0) + 1
        return {
            "total_iocs": len(self._iocs),
            "total_events": len(self._events),
            "by_type": types,
            "by_category": categories,
        }


# Global IOC store
_ioc_store = IocStore()


# ================================================================
# Threat Feed Aggregator (Recorded Future equivalent)
# ================================================================
class ThreatFeedAggregator:
    """Aggregates threat intelligence from multiple sources."""

    # Public feeds that don't require API keys
    PUBLIC_FEEDS = {
        "abuse_ipdb": "https://api.abuseipdb.com/api/v2/blacklist",
        "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "mitre_attack": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "urlhaus": "https://urlhaus.abuse.ch/downloads/json_recent/",
    }

    def __init__(self):
        self._cache: dict[str, dict] = {}
        self._last_fetch: dict[str, str] = {}

    def fetch_cisa_kev(self) -> list[dict]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        log.info("[ThreatFeed] Fetching CISA KEV...")
        try:
            import requests
            resp = requests.get(self.PUBLIC_FEEDS["cisa_kev"], timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                kevs = []
                for v in vulns[:100]:  # latest 100
                    kev = {
                        "cve": v.get("cveID", ""),
                        "vendor": v.get("vendorProject", ""),
                        "product": v.get("product", ""),
                        "name": v.get("vulnerabilityName", ""),
                        "date_added": v.get("dateAdded", ""),
                        "due_date": v.get("dueDate", ""),
                        "action": v.get("requiredAction", ""),
                        "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                    }
                    kevs.append(kev)
                    # Auto-ingest as IOC
                    if kev["cve"]:
                        _ioc_store.add_ioc(
                            "cve", kev["cve"],
                            threat_level="critical" if kev["known_ransomware"] == "Known" else "high",
                            category="exploit",
                            source="cisa_kev",
                            tags=["kev", kev["vendor"].lower()],
                        )
                self._cache["cisa_kev"] = kevs
                self._last_fetch["cisa_kev"] = datetime.now().isoformat()
                log.info(f"[ThreatFeed] ✅ CISA KEV: {len(kevs)} entries")
                return kevs
        except Exception as e:
            log.error(f"[ThreatFeed] CISA KEV error: {e}")
        return []

    def fetch_feodo_ips(self) -> list[dict]:
        """Fetch Feodo Tracker botnet C2 IPs."""
        log.info("[ThreatFeed] Fetching Feodo C2 IPs...")
        try:
            import requests
            resp = requests.get(self.PUBLIC_FEEDS["feodo_tracker"], timeout=15)
            if resp.status_code == 200:
                ips = []
                for line in resp.text.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.append({"ip": line, "source": "feodo_tracker", "category": "c2"})
                        _ioc_store.add_ioc("ip", line, threat_level="high",
                                           category="c2", source="feodo_tracker", tags=["botnet", "c2"])
                self._cache["feodo"] = ips
                self._last_fetch["feodo"] = datetime.now().isoformat()
                log.info(f"[ThreatFeed] ✅ Feodo: {len(ips)} C2 IPs")
                return ips
        except Exception as e:
            log.error(f"[ThreatFeed] Feodo error: {e}")
        return []

    def fetch_urlhaus(self) -> list[dict]:
        """Fetch recent malware URLs from URLhaus."""
        log.info("[ThreatFeed] Fetching URLhaus...")
        try:
            import requests
            resp = requests.get(self.PUBLIC_FEEDS["urlhaus"], timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                urls = []
                for entry in list(data.get("urls", {}).values())[:100]:
                    urls.append({
                        "url": entry.get("url", ""),
                        "threat": entry.get("threat", ""),
                        "status": entry.get("url_status", ""),
                        "tags": entry.get("tags", []),
                    })
                    if entry.get("url"):
                        _ioc_store.add_ioc("url", entry["url"], threat_level="high",
                                           category="malware", source="urlhaus",
                                           tags=entry.get("tags", []))
                self._cache["urlhaus"] = urls
                self._last_fetch["urlhaus"] = datetime.now().isoformat()
                log.info(f"[ThreatFeed] ✅ URLhaus: {len(urls)} malware URLs")
                return urls
        except Exception as e:
            log.error(f"[ThreatFeed] URLhaus error: {e}")
        return []

    def fetch_all_feeds(self) -> dict:
        """Fetch all available threat feeds."""
        results = {}
        results["cisa_kev"] = self.fetch_cisa_kev()
        results["feodo_c2"] = self.fetch_feodo_ips()
        results["urlhaus"] = self.fetch_urlhaus()
        results["ioc_stats"] = _ioc_store.get_stats()
        results["timestamp"] = datetime.now().isoformat()
        return results

    def get_cached(self) -> dict:
        return {"cache": self._cache, "last_fetch": self._last_fetch}


# Global feed aggregator
_feed_aggregator = ThreatFeedAggregator()


# ================================================================
# Adversary Tracker (CrowdStrike equivalent)
# ================================================================
class AdversaryTracker:
    """Track threat actor groups and correlate with internal findings."""

    def __init__(self):
        self._sightings: list[dict] = []

    def get_adversary_profile(self, name: str) -> dict:
        """Get detailed adversary profile."""
        name_upper = name.upper()
        if name_upper in ADVERSARY_GROUPS:
            group = ADVERSARY_GROUPS[name_upper]
            return {
                "name": name_upper,
                "origin": group["origin"],
                "targets": group["targets"],
                "ttps": group["ttps"],
                "sightings": [s for s in self._sightings if s.get("adversary") == name_upper],
                "related_iocs": [
                    ioc for ioc in _ioc_store.get_active()
                    if ioc.get("related_adversary", "").upper() == name_upper
                ],
            }
        return {"name": name, "error": "Adversary not found in database"}

    def list_adversaries(self) -> list[dict]:
        """List all tracked adversary groups."""
        return [
            {"name": name, "origin": info["origin"],
             "targets": info["targets"], "ttp_count": len(info["ttps"])}
            for name, info in sorted(ADVERSARY_GROUPS.items())
        ]

    def record_sighting(self, adversary: str, indicator: str, context: str = "") -> dict:
        """Record a threat actor sighting."""
        sighting = {
            "id": f"SIGHT-{len(self._sightings)+1:05d}",
            "adversary": adversary.upper(),
            "indicator": indicator,
            "context": context,
            "timestamp": datetime.now().isoformat(),
        }
        self._sightings.append(sighting)
        return sighting

    def correlate_with_findings(self) -> list[dict]:
        """Correlate adversary TTPs with internal Neo4j findings."""
        correlations = []
        try:
            pw = os.environ.get("NEO4J_PASSWORD", "Adomaa12@")
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))
            with driver.session() as s:
                result = s.run("""
                    MATCH (f:Finding)
                    WHERE f.name IS NOT NULL
                    RETURN f.name AS name, f.severity AS severity,
                           f.source AS source, f.cve AS cve
                    LIMIT 200
                """)
                findings = [dict(r) for r in result]
            driver.close()

            # Match findings to adversary TTPs
            for finding in findings:
                name_lower = (finding.get("name") or "").lower()
                cve = finding.get("cve", "")
                for adv_name, adv_info in ADVERSARY_GROUPS.items():
                    # Check if finding relates to adversary targets/techniques
                    for target in adv_info["targets"]:
                        if target.lower() in name_lower:
                            correlations.append({
                                "finding": finding["name"],
                                "adversary": adv_name,
                                "match_type": "target_sector",
                                "confidence": 40,
                            })
                # Check IOC matches
                for ioc in _ioc_store.search(cve) if cve else []:
                    if ioc.get("related_adversary"):
                        correlations.append({
                            "finding": finding["name"],
                            "adversary": ioc["related_adversary"],
                            "match_type": "ioc_match",
                            "confidence": 80,
                            "ioc": ioc["value"],
                        })
        except Exception as e:
            log.error(f"[Adversary] Correlation error: {e}")

        return correlations


# Global adversary tracker
_adversary_tracker = AdversaryTracker()


# ================================================================
# Risk Scoring Engine (ties everything together)
# ================================================================
class ThreatIntelRiskScorer:
    """
    Compute enhanced risk scores using threat intelligence.
    Factors: CVSS + KEV status + adversary association + IOC matches + feed data
    """

    WEIGHTS = {
        "cvss_base":        0.30,
        "kev_status":       0.20,
        "adversary_link":   0.15,
        "ioc_matches":      0.15,
        "exploit_available": 0.10,
        "feed_mentions":    0.10,
    }

    def compute_risk_score(self, vuln: dict) -> dict:
        """
        Compute an enhanced risk score for a vulnerability.
        Returns: {"raw_score": float, "enhanced_score": float, "factors": dict}
        """
        cve = vuln.get("cve", "")
        host = vuln.get("host", "")
        cvss = float(vuln.get("cvss", 5.0) or 5.0)

        factors = {}

        # 1. CVSS base (0-10 → 0-1)
        factors["cvss_base"] = min(cvss / 10.0, 1.0)

        # 2. CISA KEV status
        kev_cache = _feed_aggregator._cache.get("cisa_kev", [])
        in_kev = any(k.get("cve") == cve for k in kev_cache) if cve else False
        factors["kev_status"] = 1.0 if in_kev else 0.0

        # 3. Adversary association
        iocs = _ioc_store.search(cve) if cve else []
        adversary_linked = any(ioc.get("related_adversary") for ioc in iocs)
        factors["adversary_link"] = 1.0 if adversary_linked else 0.0

        # 4. IOC matches (more matches = higher risk)
        host_iocs = _ioc_store.search(host) if host else []
        ioc_count = len(iocs) + len(host_iocs)
        factors["ioc_matches"] = min(ioc_count / 5.0, 1.0)

        # 5. Exploit available
        exploit_iocs = [i for i in iocs if i.get("category") == "exploit"]
        factors["exploit_available"] = 1.0 if exploit_iocs or in_kev else 0.0

        # 6. Feed mentions
        feed_mentions = 0
        for feed_name, feed_data in _feed_aggregator._cache.items():
            if isinstance(feed_data, list):
                for entry in feed_data:
                    if cve and cve in str(entry):
                        feed_mentions += 1
        factors["feed_mentions"] = min(feed_mentions / 3.0, 1.0)

        # Weighted score
        enhanced = sum(
            factors[k] * self.WEIGHTS[k]
            for k in self.WEIGHTS
        ) * 10  # scale to 0-10

        return {
            "raw_cvss": cvss,
            "enhanced_score": round(enhanced, 2),
            "risk_increase": round(enhanced - cvss, 2),
            "factors": factors,
            "in_kev": in_kev,
            "adversary_linked": adversary_linked,
            "ioc_matches": ioc_count,
        }

    def enrich_vulnerabilities(self, vulns: list[dict]) -> list[dict]:
        """Enrich a list of vulnerabilities with threat intel risk scores."""
        enriched = []
        for v in vulns:
            score = self.compute_risk_score(v)
            v["threat_intel_score"] = score["enhanced_score"]
            v["risk_factors"] = score["factors"]
            v["in_kev"] = score["in_kev"]
            v["adversary_linked"] = score["adversary_linked"]
            enriched.append(v)
        return sorted(enriched, key=lambda x: x.get("threat_intel_score", 0), reverse=True)


# Global risk scorer
_risk_scorer = ThreatIntelRiskScorer()


# ================================================================
# Unified Threat Intel Engine
# ================================================================
class ThreatIntelEngine:
    """Main interface for all threat intelligence operations."""

    def __init__(self):
        self.ioc_store = _ioc_store
        self.feeds = _feed_aggregator
        self.adversary = _adversary_tracker
        self.scorer = _risk_scorer

    # ── IOC Management (MISP-like) ───────────────────────────────
    def ingest_ioc(self, ioc: dict) -> str:
        return self.ioc_store.add_ioc(
            ioc.get("type", "ip"), ioc.get("value", ""),
            threat_level=ioc.get("threat_level", "medium"),
            category=ioc.get("category", "unknown"),
            tags=ioc.get("tags", []),
            source=ioc.get("source", "manual"),
            confidence=ioc.get("confidence", 70),
            adversary=ioc.get("adversary", ""),
        )

    def bulk_ingest(self, iocs: list[dict]) -> dict:
        count = 0
        for ioc in iocs:
            self.ingest_ioc(ioc)
            count += 1
        return {"ingested": count}

    def search_ioc(self, query: str) -> list[dict]:
        return self.ioc_store.search(query)

    def create_threat_event(self, title: str, description: str,
                             ioc_ids: list = None, **kwargs) -> dict:
        return self.ioc_store.add_event(title, description, ioc_ids or [], **kwargs)

    # ── Feed Management (Recorded Future-like) ───────────────────
    def refresh_feeds(self) -> dict:
        return self.feeds.fetch_all_feeds()

    def get_cisa_kev(self) -> list[dict]:
        return self.feeds.fetch_cisa_kev()

    # ── Adversary Tracking (CrowdStrike-like) ────────────────────
    def get_adversary(self, name: str) -> dict:
        return self.adversary.get_adversary_profile(name)

    def list_adversaries(self) -> list[dict]:
        return self.adversary.list_adversaries()

    def correlate_threats(self) -> list[dict]:
        return self.adversary.correlate_with_findings()

    # ── Risk Scoring ─────────────────────────────────────────────
    def compute_risk_score(self, vuln_or_value: str | dict) -> dict:
        if isinstance(vuln_or_value, str):
            vuln_or_value = {"cve": vuln_or_value}
        return self.scorer.compute_risk_score(vuln_or_value)

    def enrich_vulns(self, vulns: list[dict]) -> list[dict]:
        return self.scorer.enrich_vulnerabilities(vulns)

    # ── Dashboard Data ───────────────────────────────────────────
    def get_threat_landscape(self) -> dict:
        """Get complete threat landscape overview."""
        ioc_stats = self.ioc_store.get_stats()
        active_iocs = self.ioc_store.get_active()

        # Threat level breakdown
        threat_levels = {}
        for ioc in active_iocs:
            tl = ioc.get("threat_level", "medium")
            threat_levels[tl] = threat_levels.get(tl, 0) + 1

        return {
            "ioc_stats": ioc_stats,
            "threat_levels": threat_levels,
            "adversaries": self.list_adversaries(),
            "recent_events": self.ioc_store.get_events(10),
            "feed_status": self.feeds._last_fetch,
            "timestamp": datetime.now().isoformat(),
        }
