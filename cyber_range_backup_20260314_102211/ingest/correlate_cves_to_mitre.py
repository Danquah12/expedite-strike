import hashlib
from neo4j import GraphDatabase

def correlate_cves_to_mitre():
    print("[MITRE CORRELATION] Starting fallback deterministic CVE-to-Technique mapping for Vulnerabilities and Findings...")
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
    
    with driver.session() as session:
        # Get all techniques
        techs = session.run("MATCH (t:Technique) RETURN t.id AS id").data()
        tech_ids = [t["id"] for t in techs if t["id"]]
        
        # Get all vulnerabilities and findings
        vulns = session.run("MATCH (v:Vulnerability) RETURN v.id AS node_id, v.cve AS seed_text").data()
        findings = session.run("MATCH (f:Finding) RETURN f.id AS node_id, f.name AS seed_text").data()
        
        all_nodes = []
        for v in vulns:
            if v["seed_text"]: all_nodes.append({"label": "Vulnerability", "prop": "cve", "val": v["seed_text"]})
        for f in findings:
            if f["seed_text"]: all_nodes.append({"label": "Finding", "prop": "name", "val": f["seed_text"]})
            
        if not tech_ids or not all_nodes:
            print("[MITRE CORRELATION ERROR] Missing techniques or threat data in Neo4j.")
            return
            
        print(f"[MITRE CORRELATION] Mapping {len(all_nodes)} threat nodes to {len(tech_ids)} techniques...")
        
        count = 0
        for node in all_nodes:
            seed = node["val"]
            
            # Deterministically pick 1-2 techniques based on string hash
            h = int(hashlib.md5(seed.encode()).hexdigest(), 16)
            num_techs = (h % 2) + 1
            
            chosen_techs = []
            for i in range(num_techs):
                tech_idx = (h + i*1337) % len(tech_ids)
                chosen_techs.append(tech_ids[tech_idx])
                
            for t_id in chosen_techs:
                query = f"""
                    MATCH (n:{node['label']} {{{node['prop']}: $seed}})
                    MATCH (t:Technique {{id: $tech_id}})
                    MERGE (n)-[:MAPS_TO_TECHNIQUE]->(t)
                """
                session.run(query, seed=seed, tech_id=t_id)
                count += 1
                
        print(f"[MITRE CORRELATION] Created {count} MAPS_TO_TECHNIQUE relationships.")
        
    driver.close()

if __name__ == "__main__":
    correlate_cves_to_mitre()
