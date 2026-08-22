import json
import requests
from neo4j import GraphDatabase

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"

def get_mitre_stix_data():
    """Fetches the latest MITRE Enterprise ATT&CK STIX 2.1 JSON."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print(f"[*] Downloading MITRE STIX JSON from {url}...")
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()
    return data.get("objects", [])

def ingest_mitre_data():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    objects = get_mitre_stix_data()
    
    tactics, techniques, actors, mitigations, relationships = [], [], [], [], []

    # Parse objects
    for obj in objects:
        type_ = obj.get("type")
        id_ = obj.get("id")
        name_ = obj.get("name", "Unknown")
        desc_ = obj.get("description", "")
        
        # Extract the official T-code (e.g. T1059)
        external_id = id_
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                break

        if type_ == "x-mitre-tactic":
            tactics.append({"stix_id": id_, "id": external_id, "name": name_})
        elif type_ == "attack-pattern":
            techniques.append({"stix_id": id_, "id": external_id, "name": name_, "desc": desc_})
        elif type_ == "intrusion-set":
            actors.append({"stix_id": id_, "id": external_id, "name": name_, "desc": desc_})
        elif type_ == "course-of-action":
            mitigations.append({"stix_id": id_, "id": external_id, "name": name_, "desc": desc_})
        elif type_ == "relationship":
            src = obj.get("source_ref")
            dst = obj.get("target_ref")
            rel_type = obj.get("relationship_type", "RELATED_TO").upper().replace("-", "_")
            relationships.append({"src": src, "dst": dst, "rel": rel_type})

    print(f"[*] Parsed {len(tactics)} Tactics, {len(techniques)} Techniques, {len(actors)} Threat Actors, {len(mitigations)} Mitigations, {len(relationships)} Relationships.")

    with driver.session() as session:
        # Create Tactics
        print("[*] Ingesting Tactics...")
        for t in tactics:
            session.run("MERGE (n:Tactic {stix_id: $stix}) SET n.id=$id, n.label=$name", stix=t["stix_id"], id=t["id"], name=t["name"])
        
        # Create Techniques
        print("[*] Ingesting Techniques...")
        for t in techniques:
            session.run("MERGE (n:Technique {stix_id: $stix}) SET n.id=$id, n.label=$name, n.description=$desc", stix=t["stix_id"], id=t["id"], name=t["name"], desc=t["desc"])
            
        # Create Actors
        print("[*] Ingesting Threat Actors...")
        for a in actors:
            session.run("MERGE (n:ThreatActor {stix_id: $stix}) SET n.id=$id, n.label=$name, n.description=$desc", stix=a["stix_id"], id=a["id"], name=a["name"], desc=a["desc"])
            
        # Create Mitigations
        print("[*] Ingesting Mitigations...")
        for m in mitigations:
            session.run("MERGE (n:Mitigation {stix_id: $stix}) SET n.id=$id, n.label=$name, n.description=$desc", stix=m["stix_id"], id=m["id"], name=m["name"], desc=m["desc"])
            
        # Establish Relationships manually mapped via APOC or individual matches
        print("[*] Building STIX Object Relationships...")
        batch_tx = session.begin_transaction()
        for i, r in enumerate(relationships):
            # Dynamic relationships using CALL db.createRelationship (requires APOC) or just static mapping for now.
            # Since relation type is dynamic and Cypher doesn't allow parametrized relationship types directly without APOC,
            # We will map them generically if unknown, or specifically if known (USES, MITIGATES).
            q = f"MATCH (a {{stix_id: $src}}), (b {{stix_id: $dst}}) MERGE (a)-[:{r['rel']}]->(b)"
            batch_tx.run(q, src=r["src"], dst=r["dst"])
            
            if i % 1000 == 0 and i > 0:
                batch_tx.commit()
                batch_tx = session.begin_transaction()
        batch_tx.commit()
        
    driver.close()
    print("[+] MITRE Knowledge Graph Successfully Ingested.")

if __name__ == "__main__":
    ingest_mitre_data()
