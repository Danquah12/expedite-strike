#!/usr/bin/env python3
import requests
from neo4j import GraphDatabase
from stix2 import MemoryStore

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


# =====================================================
# 1. LOAD MITRE DATA INTO MEMORYSTORE CORRECTLY
# =====================================================
def load_mitre():
    print("[+] Downloading MITRE Enterprise ATT&CK JSON...")

    data = requests.get(MITRE_URL).json()
    print("[+] Loading MemoryStore...")

    ms = MemoryStore(stix_data=data["objects"])

    print("[+] MemoryStore loaded with STIX objects")
    return ms


# =====================================================
# 2. IMPORT INTO NEO4J (CLEAN VERSION)
# =====================================================
def import_into_neo4j(ms):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    with driver.session() as session:
        print("[+] Importing ATT&CK data into Neo4j...")

        # Use ms.query() — this is the OFFICIAL, SUPPORTED API
        for obj in ms.query():

            stix_type = obj.get("type")

            # -----------------------------
            # TACTICS
            # -----------------------------
            if stix_type == "x-mitre-tactic":

                attack_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id")

                if not attack_id:
                    continue

                session.run("""
                    MERGE (t:Tactic {id:$id})
                    SET t.name=$name
                """, id=attack_id, name=obj.get("name"))

            # -----------------------------
            # TECHNIQUES & SUB-TECHNIQUES
            # -----------------------------
            elif stix_type == "attack-pattern":

                attack_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id")

                if not attack_id:
                    continue

                name = obj.get("name")

                if "." in attack_id:
                    # SUB-TECHNIQUE (Txxxx.xx)
                    parent = attack_id.split(".")[0]

                    session.run("""
                        MERGE (s:SubTechnique {id:$id})
                        SET s.name=$name
                    """, id=attack_id, name=name)

                    session.run("""
                        MATCH (p:Technique {id:$parent})
                        MATCH (c:SubTechnique {id:$child})
                        MERGE (p)-[:HAS_SUBTECHNIQUE]->(c)
                    """, parent=parent, child=attack_id)

                else:
                    # MAIN TECHNIQUE
                    session.run("""
                        MERGE (t:Technique {id:$id})
                        SET t.name=$name
                    """, id=attack_id, name=name)

            # -----------------------------
            # RELATIONSHIPS (tech -> tactic)
            # -----------------------------
            elif stix_type == "relationship":

                if obj.get("relationship_type") == "uses":

                    src = obj.get("source_ref")
                    tgt = obj.get("target_ref")

                    if src.startswith("attack-pattern") and tgt.startswith("x-mitre-tactic"):

                        # Lookup objects (safe version)
                        src_obj = ms.get(src)
                        tgt_obj = ms.get(tgt)

                        if not src_obj or not tgt_obj:
                            continue

                        # extract ATT&CK IDs
                        def get_attack_id(o):
                            for ref in o.get("external_references", []):
                                if ref.get("source_name") == "mitre-attack":
                                    return ref.get("external_id")
                            return None

                        src_id = get_attack_id(src_obj)
                        tgt_id = get_attack_id(tgt_obj)

                        if src_id and tgt_id:
                            session.run("""
                                MATCH (tech:Technique {id:$tech})
                                MATCH (tac:Tactic {id:$tactic})
                                MERGE (tech)-[:PART_OF]->(tac)
                            """, tech=src_id, tactic=tgt_id)

        print("[+] Neo4j MITRE import completed.")

    driver.close()


# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    ms = load_mitre()
    import_into_neo4j(ms)
    print("\n==============================================")
    print("  MITRE ATT&CK Import Completed Successfully")
    print("==============================================\n")
