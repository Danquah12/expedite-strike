# ti_feed.py
"""
Threat Intelligence Feed Integration Engine
-------------------------------------------
Ingests external intelligence feeds such as:
 - CISA KEV
 - EPSS
 - MITRE ATT&CK
 - CVE/NVD
 - Abuse.ch
 - VirusTotal (safe mode)

Normalizes data and writes into the Digital Twin Neo4j graph.

This powers:
 - Attack predictions
 - AI wargames
 - Vulnerability prioritization
 - Threat actor modeling
"""

import requests
import openai
from datetime import datetime
from cyber_range.services.neo4j_engine import Neo4jEngine

class ThreatIntelFeed:

    def __init__(self):
        self.neo4j = Neo4jEngine()

    # ---------------------------------------------------------
    # Pull CISA Known Exploited Vulnerabilities
    # ---------------------------------------------------------
    def fetch_cisa_kev(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            data = requests.get(url, timeout=10).json()
            return data.get("vulnerabilities", [])
        except Exception:
            return []

    # ---------------------------------------------------------
    # Pull EPSS Scores
    # ---------------------------------------------------------
    def fetch_epss(self):
        url = "https://api.first.org/data/v1/epss?pretty=true"
        try:
            return requests.get(url, timeout=10).json().get("data", [])
        except Exception:
            return []

    # ---------------------------------------------------------
    # Enrich single CVE with AI (safe mode)
    # ---------------------------------------------------------
    def enrich_cve_ai(self, cve_id):
        prompt = f"""
You are a cybersecurity analyst AI.

Provide a structured analysis of vulnerability {cve_id}:

1. Executive summary
2. Attack vector
3. MITRE ATT&CK mapping
4. Exploitability considerations (safe, no exploit code)
5. Impact analysis
6. Recommended defenses
7. Whether the CVE is known in KEV or has EPSS > 0.9

Keep it safe and do NOT generate exploit code.
"""

        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.choices[0].message.content

    # ---------------------------------------------------------
    # Insert or update a TI node in Neo4j graph
    # ---------------------------------------------------------
    def inject_ti_vulnerability(self, cve_id, kev=False, epss_score=0.0):
        cypher = """
        MERGE (v:Vulnerability {id:$id})
        SET v.known_exploited=$kev,
            v.epss=$epss,
            v.last_seen=$ts
        RETURN v
        """

        result = self.neo4j.query(
            cypher,
            {
                "id": cve_id,
                "kev": kev,
                "epss": epss_score,
                "ts": datetime.utcnow().isoformat()
            }
        )
        return result[0]["v"] if result else None

    # ---------------------------------------------------------
    # END-TO-END update from all TI sources
    # ---------------------------------------------------------
    def update_all(self):
        kev_list = self.fetch_cisa_kev()
        epss_list = self.fetch_epss()

        kev_set = {item["cveID"] for item in kev_list}
        epss_map = {item["cve"]: float(item["epss"]) for item in epss_list}

        updated = []

        # Merge all unique CVEs
        all_cves = sorted(kev_set.union(epss_map.keys()))

        for cve in all_cves:
            node = self.inject_ti_vulnerability(
                cve_id=cve,
                kev=(cve in kev_set),
                epss_score=epss_map.get(cve, 0.0)
            )
            if node:
                updated.append(node)

        return updated

