# ===================================================================
# cyber_range/services/killchain.py — FINAL RECONCILED VERSION
# ===================================================================

import os
import json
import csv
from io import StringIO
from datetime import datetime
from openai import OpenAI

from cyber_range.services.neo4j_engine import Neo4jEngine
from cyber_range.services.ti_feed import ThreatIntelFeed
from cyber_range.services.exploit_ai import ExploitModeler
from cyber_range.services.remediation_ai import RemediationAI


# ===========================================================
# SAFE LAZY CLIENT INITIALIZATION
# ===========================================================
def get_client():
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        # DO NOT CRASH ENTIRE DASHBOARD
        print("[KillChain] WARNING: OPENAI_API_KEY missing — AI narrative disabled.")
        return None

    return OpenAI(api_key=api_key)


# ===========================================================
# MAIN KILL CHAIN CLASS
# ===========================================================
class KillChainGenerator:
    """
    Full Hybrid Kill Chain Engine:
    - Lockheed Martin Kill Chain (7-steps)
    - MITRE ATT&CK mapping
    - Vulnerability + CVSS/EPSS/KEV intelligence
    - Composite chain scoring
    - AI narrative generator
    """

    def __init__(self):
        self.db = Neo4jEngine()
        self.ti = ThreatIntelFeed()
        self.exploit_ai = ExploitModeler()
        self.remediation_ai = RemediationAI()
        self.client = None  # lazy-load OpenAI

    # -----------------------------------------
    def ensure_client(self):
        if self.client is None:
            self.client = get_client()
        return self.client

    # ===================================================================
    # MAIN HYBRID KILL CHAIN GENERATION
    # ===================================================================
    def generate_chain(self, start_node, end_node):
        if not start_node or not end_node:
            return {"error": "Missing start or end node."}

        lm_chain = {
            "Reconnaissance": self._find_recon(start_node),
            "Weaponization": self._find_weaponization(start_node),
            "Delivery": self._find_delivery(start_node),
            "Exploitation": self._find_exploitation(start_node),
            "Installation": self._find_installation(start_node),
            "Command & Control": self._find_c2(start_node),
            "Actions on Objective": self._find_objective(start_node, end_node),
        }

        # Gather CVEs
        vulns = self.db.run_query_simple(
            f"MATCH (n)-[:HAS_VULN]->(v) WHERE id(n)={start_node} RETURN v"
        )

        vuln_ids = []
        for v in vulns or []:
            cve = v.get("cve") or v.get("id") or v.get("name")
            if cve and str(cve).startswith("CVE"):
                vuln_ids.append(cve)

        mitre_chain = self._map_mitre_chain(vuln_ids)
        score = self._calculate_risk_score(vuln_ids)
        narrative = self._generate_narrative(lm_chain, mitre_chain, score)

        return {
            "LM_KillChain": lm_chain,
            "MITRE_Chain": mitre_chain,
            "Risk_Scoring": score,
            "Narrative": narrative,
            "Timestamp": datetime.now().isoformat(),
        }

    # ===================================================================
    # INTERNAL — NEO4J LM QUERIES
    # ===================================================================
    def _find_recon(self, node_id):
        q = f"MATCH (n)-[:SCANNED]->(t) WHERE id(n)={node_id} RETURN t"
        return self.db.run_query_simple(q)

    def _find_weaponization(self, node_id):
        q = f"MATCH (n)-[:HAS_VULN]->(v) WHERE id(n)={node_id} RETURN v"
        return self.db.run_query_simple(q)

    def _find_delivery(self, node_id):
        q = f"MATCH (n)-[:CONNECTED_TO]->(s) WHERE id(n)={node_id} RETURN s"
        return self.db.run_query_simple(q)

    def _find_exploitation(self, node_id):
        q = (
            f"MATCH (n)-[:HAS_VULN]->(v:Vulnerability {{exploitable: true}}) "
            f"WHERE id(n)={node_id} RETURN v"
        )
        return self.db.run_query_simple(q)

    def _find_installation(self, node_id):
        q = f"MATCH (n)-[:INSTALLS]->(m) WHERE id(n)={node_id} RETURN m"
        return self.db.run_query_simple(q)

    def _find_c2(self, node_id):
        q = (
            "MATCH (n)-[:CALLS_OUT]->(c:C2Server) "
            f"WHERE id(n)={node_id} RETURN c"
        )
        return self.db.run_query_simple(q)

    def _find_objective(self, start_id, target_id):
        q = (
            "MATCH p = shortestPath((n)-[*..5]->(t)) "
            f"WHERE id(n)={start_id} AND id(t)={target_id} RETURN p"
        )
        return self.db.run_query_simple(q)

    # ===================================================================
    # MITRE ATT&CK MAPPING
    # ===================================================================
    def _map_mitre_chain(self, cve_list):
        techniques = []
        for cve in cve_list:
            mitre_items = self.ti.get_mitre_for_cve(cve)
            if mitre_items:
                techniques.extend(mitre_items)

        mitre_chain = {}
        for entry in techniques:
            tactic = entry.get("tactic") or entry.get("tactic_id")
            technique = entry.get("technique") or entry.get("technique_id")
            if not tactic:
                continue

            mitre_chain.setdefault(tactic, [])
            if technique not in mitre_chain[tactic]:
                mitre_chain[tactic].append(technique)

        return mitre_chain

    # ===================================================================
    # RISK SCORING (CVSS + EPSS + KEV)
    # ===================================================================
    def _calculate_risk_score(self, cve_list):
        cvss_total = 0
        epss_total = 0
        kev_hits = 0
        count = 0

        for cve in cve_list:
            intel = self.ti.get_vuln_stats(cve)
            if not intel:
                continue

            count += 1
            cvss_total += intel.get("cvss", 0)
            epss_total += intel.get("epss", 0)
            if intel.get("kev", False):
                kev_hits += 1

        if count == 0:
            return {"cvss": 0, "epss": 0, "kev_count": 0, "overall": 0}

        score_val = (
            (cvss_total / count) * 0.5 +
            (epss_total / count) * 0.4 +
            (kev_hits * 1.5)
        )

        return {
            "cvss": round(cvss_total / count, 2),
            "epss": round(epss_total / count, 3),
            "kev_count": kev_hits,
            "overall": round(score_val, 2),
        }

    # ===================================================================
    # AI NARRATIVE GENERATOR (SAFE)
    # ===================================================================
    def _generate_narrative(self, lm_chain, mitre_chain, scores):
        client = self.ensure_client()

        # AI unavailable → safe fallback
        if client is None:
            return (
                "[KillChain AI Disabled — No OPENAI_API_KEY]\n"
                "Attack occurred across multiple LM Kill Chain stages.\n"
                "Apply patches, enable deeper logging, review segmentation."
            )

        prompt = f"""
You are a senior cyber threat intelligence analyst. Using the provided Neo4j kill chain,
MITRE ATT&CK mapping, and vulnerability intelligence, produce a full-spectrum threat report.

LOCKHEED MARTIN KILL CHAIN:
{json.dumps(lm_chain, indent=2)}

MITRE ATT&CK:
{json.dumps(mitre_chain, indent=2)}

RISK SCORING:
{json.dumps(scores, indent=2)}

Write full structured output: Executive Summary, Adversary Persona,
Stage-by-Stage Narrative, MITRE interpretation, Risk interpretation, SOC/IR recommendations.
"""

        try:
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}]
            )
            return resp.choices[0].message.content

        except Exception:
            return (
                "[LOCAL FALLBACK] AI unavailable.\n"
                "Summary: Multi-step intrusion mapped to MITRE ATT&CK. "
                "Remediate vulnerabilities and enhance logging."
            )

    # ===================================================================
    # EXPORT HELPERS
    # ===================================================================
    def export_json(self, chain):
        return json.dumps(chain, indent=2)

    def export_csv(self, chain):
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Stage", "Details"])
        for stage, items in chain.items():
            writer.writerow([stage, json.dumps(items)])
        return output.getvalue()
