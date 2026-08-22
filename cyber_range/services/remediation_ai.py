# remediation_ai.py
"""
Automated Remediation & Hardening AI Engine
-------------------------------------------
Generates:
 - Fix recommendations
 - Patch prioritization
 - Hardening steps
 - Blast radius analysis
 - Dependency impact mapping
 - Graph-aware mitigation strategies
"""

import os
import openai
from datetime import datetime
from cyber_range.services.neo4j_engine import Neo4jEngine

openai.api_key = openai.api_key or os.getenv("OPENAI_API_KEY")


class RemediationAI:

    def __init__(self):
        self.neo4j = Neo4jEngine()

    # ---------------------------------------------------------
    # Graph-aware blast radius analysis
    # ---------------------------------------------------------
    def blast_radius(self, vuln_id):
        cypher = """
        MATCH (v:Vulnerability {id:$id})<-[:HAS_VULN]-(a:Asset)
        OPTIONAL MATCH p = (a)-[:REL*..4]->(x)
        RETURN a, collect(DISTINCT x) AS affected
        """
        result = self.neo4j.query(cypher, {"id": vuln_id})

        if not result:
            return None

        rec = result[0]
        primary_asset = rec["a"]
        secondary = rec["affected"]

        return {
            "primary_asset": primary_asset,
            "affected_assets": secondary,
            "count": len(secondary)
        }

    # ---------------------------------------------------------
    # AI-generated remediation plan for a single CVE
    # ---------------------------------------------------------
    def fix_vulnerability(self, vuln_id):
        blast = self.blast_radius(vuln_id)

        primary = blast["primary_asset"] if blast else "Unknown"
        count = blast["count"] if blast else 0

        prompt = f"""
You are a cybersecurity remediation AI.

Vulnerability: {vuln_id}
Primary Impacted Asset: {primary}
Secondary Impact Scope: {count} related systems

Generate a structured remediation plan including:

1. Summary of the vulnerability (safe, no exploit code)
2. Immediate containment steps
3. Recommended patches or upgrades
4. Hardening steps aligned to CIS/NIST/STIG
5. Dependency risk (services or apps affected)
6. Business impact of delaying remediation
7. Required downtime or maintenance window
8. Testing steps before reactivating service
9. Final verification steps

Return the response in clean, readable markdown.
"""

        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.choices[0].message.content

    # ---------------------------------------------------------
    # Prioritize multiple vulnerabilities
    # ---------------------------------------------------------
    def prioritize_vulns(self, vuln_list):
        text_list = "\n".join(vuln_list)

        prompt = f"""
Rank the following vulnerabilities by priority:

{text_list}

Rank using:
- Exploitability
- KEV status
- EPSS score
- Blast radius (graph impact)
- Business impact
- Fix complexity

Return:
1. A ranked list
2. A short justification for each entry
"""

        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.choices[0].message.content

    # ---------------------------------------------------------
    # Full system hardening checklist
    # ---------------------------------------------------------
    def harden_system(self, asset_id):
        prompt = f"""
You are a cybersecurity hardening AI.

Generate a full hardening checklist for Asset ID: {asset_id}

Checklist must cover:
- OS hardening
- Network segmentation and firewalling
- Identity & access hardening
- Logging & monitoring improvements
- Application security steps
- Cloud IAM improvements if applicable
- Zero-trust alignment
- STIG, CIS, and NIST 800-53 references

Return in clean markdown formatting.
"""

        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.choices[0].message.content
