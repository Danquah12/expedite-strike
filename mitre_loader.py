#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
STRICT MITRE ATT&CK Enterprise Loader
Runs automatically when app.py launches.

Loads:
• Tactics (TA0001 – TA0011)
• Techniques (T####)
• Sub-techniques (T####.###)
• Technique → Tactic relationships
• Sub-technique → Technique relationships

STRICT CVE Mapping:
Only CVEs present inside Neo4j (from your vulnerability ingestion)
are mapped to MITRE Techniques using MITRE’s official STIX dataset.
"""

import json
import requests
from neo4j import GraphDatabase

# -----------------------------------------------------------
# NEO4J CONFIG
# -----------------------------------------------------------

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


def _driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# -----------------------------------------------------------
# LOCAL MITRE ENTERPRISE BUNDLE
# -----------------------------------------------------------

MITRE_LOCAL = "/opt/vuln_intel/mitre_cache/enterprise.json"


# ===========================================================
# STEP 1 — Load MITRE ATT&CK Enterprise (LOCAL CACHE)
# ===========================================================

def load_enterprise_attack():
    print("[MITRE] Loading Enterprise ATT&CK from local cache…")

    try:
        with open(MITRE_LOCAL, "r") as f:
            data = json.load(f)
        objects = data.get("objects", [])
    except Exception as e:
        print("[MITRE ERROR] Could not load local MITRE bundle:", e)
        return

    print(f"[MITRE] Loaded {len(objects)} STIX objects.")

    driver = _driver()
    session = driver.session()

    try:
        # Clean old MITRE nodes
        session.run("MATCH (x:Tactic) DETACH DELETE x")
        session.run("MATCH (x:Technique) DETACH DELETE x")
        session.run("MATCH (x:SubTechnique) DETACH DELETE x")
        session.run("MATCH (x:IntrusionSet) DETACH DELETE x")
        session.run("MATCH (x:Campaign) DETACH DELETE x")
        session.run("MATCH (x:CourseOfAction) DETACH DELETE x")
        session.run("MATCH (x:Malware) DETACH DELETE x")
        session.run("MATCH (x:Tool) DETACH DELETE x")

        print("[MITRE] Old MITRE data cleared.")

        for obj in objects:
            stix_type = obj.get("type")
            stix_id = obj.get("id")
            name = obj.get("name")

            # -------------------------------
            # TACTICS
            # -------------------------------
            if stix_type == "x-mitre-tactic":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        desc = obj.get("description", "")
                        session.run("""
                            MERGE (t:Tactic {id:$id})
                            SET t.name=$name,
                                t.stix_id=$stix,
                                t.description=$desc
                        """, id=tid, name=name, stix=stix_id, desc=desc)

            # -------------------------------
            # TECHNIQUES + SUBTECHNIQUES
            # -------------------------------
            if stix_type == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        desc = obj.get("description", "")

                        if "." in tid:
                            # SUBTECHNIQUE
                            parent = tid.split(".")[0]

                            session.run("""
                                MERGE (s:SubTechnique {id:$id})
                                SET s.name=$name,
                                    s.stix_id=$stix,
                                    s.description=$desc
                            """, id=tid, name=name, stix=stix_id, desc=desc)

                            session.run("""
                                MATCH (p:Technique {id:$parent})
                                MERGE (p)-[:HAS_SUBTECHNIQUE]->(:SubTechnique {id:$child})
                            """, parent=parent, child=tid)

                        else:
                            # TECHNIQUE
                            session.run("""
                                MERGE (t:Technique {id:$id})
                                SET t.name=$name,
                                    t.stix_id=$stix,
                                    t.description=$desc
                            """, id=tid, name=name, stix=stix_id, desc=desc)

            # -------------------------------
            # INTRUSION SETS (Threat Actors)
            # -------------------------------
            if stix_type == "intrusion-set":
                desc = obj.get("description", "")
                session.run("""
                    MERGE (a:IntrusionSet {id:$stix})
                    SET a.name=$name,
                        a.description=$desc
                """, stix=stix_id, name=name, desc=desc)

            # -------------------------------
            # CAMPAIGNS
            # -------------------------------
            if stix_type == "campaign":
                desc = obj.get("description", "")
                session.run("""
                    MERGE (c:Campaign {id:$stix})
                    SET c.name=$name,
                        c.description=$desc
                """, stix=stix_id, name=name, desc=desc)

            # -------------------------------
            # MITIGATIONS (Course of Action)
            # -------------------------------
            if stix_type == "course-of-action":
                desc = obj.get("description", "")
                mid = stix_id
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        mid = ref.get("external_id")
                        
                session.run("""
                    MERGE (m:CourseOfAction {id:$stix})
                    SET m.name=$name,
                        m.mitre_id=$mid,
                        m.description=$desc
                """, stix=stix_id, name=name, mid=mid, desc=desc)

            # -------------------------------
            # MALWARE & TOOLS
            # -------------------------------
            if stix_type in ["malware", "tool"]:
                desc = obj.get("description", "")
                label = "Malware" if stix_type == "malware" else "Tool"
                session.run(f"""
                    MERGE (m:{label} {{id:$stix}})
                    SET m.name=$name,
                        m.description=$desc
                """, stix=stix_id, name=name, desc=desc)

    except Exception as e:
        print("[MITRE ERROR] Failed loading ATT&CK:", e)

    finally:
        session.close()
        driver.close()

    print("[MITRE] ATT&CK Enterprise loaded successfully.")


# ===========================================================
# STEP 2 — Link Techniques → Tactics
# ===========================================================

def link_techniques_to_tactics():
    print("[MITRE] Linking Techniques → Tactics…")

    try:
        with open(MITRE_LOCAL, "r") as f:
            data = json.load(f)
        objects = data.get("objects", [])
    except Exception as e:
        print("[MITRE ERROR] Could not load STIX for linking:", e)
        return

    driver = _driver()
    session = driver.session()

    try:
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            kill_chain = obj.get("kill_chain_phases", [])
            external_refs = obj.get("external_references", [])

            technique_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")

            if not technique_id:
                continue

            for phase in kill_chain:
                if phase.get("kill_chain_name") != "mitre-attack":
                    continue

                tactic_name = phase.get("phase_name")  # e.g., execution, discovery
                if not tactic_name:
                    continue
                # Replace hyphens so 'initial-access' matches 'Initial Access'
                clean_tactic_name = tactic_name.replace("-", " ")

                match = session.run("""
                    MATCH (t:Tactic)
                    WHERE toLower(t.name) CONTAINS toLower($name)
                    RETURN t.id AS id
                """, name=clean_tactic_name).single()

                if not match:
                    continue

                tactic_id = match["id"]

                session.run("""
                    MATCH (tech:Technique {id:$tech})
                    MATCH (t:Tactic {id:$tact})
                    MERGE (tech)-[:PART_OF]->(t)
                """, tech=technique_id, tact=tactic_id)

    except Exception as e:
        print("[MITRE ERROR] Linking error:", e)

    finally:
        session.close()
        driver.close()

    print("[MITRE] Techniques linked to Tactics.")


# ===========================================================
# STEP 2.5 — Link Entities (USES, MITIGATES, ATTRIBUTED-TO)
# ===========================================================

def link_mitre_relationships():
    print("[MITRE] Linking Actors/Campaigns/Mitigations/Malware…")

    try:
        with open(MITRE_LOCAL, "r") as f:
            data = json.load(f)
        objects = data.get("objects", [])
    except Exception as e:
        print("[MITRE ERROR] Could not load STIX for relationships:", e)
        return

    driver = _driver()
    session = driver.session()

    try:
        for obj in objects:
            if obj.get("type") != "relationship":
                continue

            rel_type = obj.get("relationship_type")
            src = obj.get("source_ref")
            tgt = obj.get("target_ref")

            if not src or not tgt:
                continue

            if rel_type == "uses":
                session.run("""
                    MATCH (s {id: $src})
                    MATCH (t:Technique {stix_id: $tgt})
                    MERGE (s)-[:USES]->(t)
                """, src=src, tgt=tgt)
                session.run("""
                    MATCH (s {id: $src})
                    MATCH (t:SubTechnique {stix_id: $tgt})
                    MERGE (s)-[:USES]->(t)
                """, src=src, tgt=tgt)

            elif rel_type == "mitigates":
                session.run("""
                    MATCH (c:CourseOfAction {id: $src})
                    MATCH (t:Technique {stix_id: $tgt})
                    MERGE (c)-[:MITIGATES]->(t)
                """, src=src, tgt=tgt)
                session.run("""
                    MATCH (c:CourseOfAction {id: $src})
                    MATCH (t:SubTechnique {stix_id: $tgt})
                    MERGE (c)-[:MITIGATES]->(t)
                """, src=src, tgt=tgt)

            elif rel_type == "attributed-to":
                session.run("""
                    MATCH (c:Campaign {id: $src})
                    MATCH (a:IntrusionSet {id: $tgt})
                    MERGE (c)-[:ATTRIBUTED_TO]->(a)
                """, src=src, tgt=tgt)

    except Exception as e:
        print("[MITRE ERROR] Relationship linking error:", e)

    finally:
        session.close()
        driver.close()

    print("[MITRE] Extended relationships linked.")


# ===========================================================
# STEP 3 — STRICT CVE → Technique mapping (FIXED)
# ===========================================================

def strict_map_cves_to_attack():
    print("[MITRE] STRICT CVE mapping started…")

    driver = _driver()
    session = driver.session()

    try:
        # Pull CVEs from scan ingestion
        results = session.run("MATCH (v:Vulnerability) RETURN v.id AS cve")
        your_cves = {r["cve"] for r in results}

        print(f"[MITRE] Your scan contains {len(your_cves)} CVEs.")

        # Load local STIX data
        with open(MITRE_LOCAL, "r") as f:
            data = json.load(f)

        relationships = [
            r for r in data.get("objects", [])
            if r.get("type") == "relationship"
        ]

        for rel in relationships:
            if rel.get("relationship_type") != "exploits":
                continue

            src = rel.get("source_ref")      # cve--xxxx
            tgt = rel.get("target_ref")      # attack-pattern--xxxx

            if not (src.startswith("cve--") and tgt.startswith("attack-pattern--")):
                continue

            cve = src.replace("cve--", "").upper()
            clean_stix = tgt.replace("attack-pattern--", "")

            if cve not in your_cves:
                continue

            # Lookup Technique by CLEANED STIX ID
            tech_row = session.run("""
                MATCH (t:Technique)
                WHERE t.stix_id=$stix
                RETURN t.id AS tid
            """, stix=clean_stix).single()

            if not tech_row:
                continue

            tech_id = tech_row["tid"]

            # Link CVE → Technique
            session.run("""
                MATCH (v:Vulnerability {id:$cve})
                MATCH (t:Technique {id:$tech})
                MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
            """, cve=cve, tech=tech_id)

        print("[MITRE] STRICT CVE mapping completed.")

    except Exception as e:
        print("[MITRE ERROR] Mapping failed:", e)

    finally:
        session.close()
        driver.close()


# ===========================================================
# RUN EVERYTHING
# ===========================================================

def run_full_mitre_loader():
    print("=========================================")
    print("   MITRE ATT&CK LOADER — STRICT MODE")
    print("=========================================")

    load_enterprise_attack()
    link_techniques_to_tactics()
    link_mitre_relationships()
    strict_map_cves_to_attack()
    
    # Run Heuristic Mapping (Fallback) since enterprise.json lacks CVEs natively
    print("[MITRE] Heuristic CVE mapping started...")
    driver = _driver()
    session = driver.session()
    try:
        import sys
        import os
        # Ensure we can import cyber_range
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from cyber_range.services.mitre_mapper import map_vulnerabilities_to_mitre
        map_vulnerabilities_to_mitre(session)
        print("[MITRE] Heuristic CVE mapping completed.")
    except Exception as e:
        print("[MITRE ERROR] Heuristic mapping failed:", e)
    finally:
        session.close()
        driver.close()

    print("=========================================")
    print(" MITRE ATT&CK Load + STRICT Mapping Done ")
    print("=========================================")

