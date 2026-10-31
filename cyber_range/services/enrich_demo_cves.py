from cyber_range.services.neo4j_engine import Neo4jEngine
import random
import re

def enrich_findings():
    db = Neo4jEngine()
    
    # 1. Extract CVEs from Finding titles or names if cve is empty
    res_no_cve = db.run_query('''
        MATCH (f:Finding)
        WHERE (f.cve IS NULL OR f.cve = "") AND f.title CONTAINS "CVE"
        RETURN id(f) as node_id, f.title as title
    ''')
    if res_no_cve:
       for r in res_no_cve:
           match = re.search(r"CVE-\d{4}-\d+", r["title"])
           if match:
               db.run_query('MATCH (f) WHERE id(f)=$nid SET f.cve=$cve', {"nid": r["node_id"], "cve": match.group()})

    res = db.run_query('''
        MATCH (f:Finding)
        WHERE f.cve IS NOT NULL AND f.cve <> ""
        RETURN DISTINCT f.cve AS cve
    ''')
    
    if not res:
        print("No findings with CVEs found.")
        return
        
    cve_list = [r["cve"] for r in res]
    
    techniques = db.run_query('MATCH (t:Technique) RETURN t.id AS id')
    t_ids = [r["id"] for r in techniques] if techniques else ["T1066", "T1047", "T1190"]
    
    print(f"Found {len(cve_list)} distinct CVEs. Enriching...")
    
    # Set seed for reproducible demo data
    random.seed(42)
    
    for cve in cve_list:
        epss = round(random.uniform(0.01, 0.99), 4)
        kev = random.choice([True, False, False, False]) # 25% chance
        
        t_sample = random.sample(t_ids, min(random.randint(1, 4), len(t_ids)))
        
        db.run_query('''
            MERGE (c:CVE {id: $cve})
            SET c.epss = $epss, c.kev = $kev
        ''', {"cve": cve, "epss": epss, "kev": kev})
        
        db.run_query('''
            MATCH (f:Finding {cve: $cve})
            MATCH (c:CVE {id: $cve})
            MERGE (f)-[:HAS_CVE]->(c)
        ''', {"cve": cve})
        
        for tid in t_sample:
            db.run_query('''
                MATCH (c:CVE {id: $cve})
                MATCH (t:Technique {id: $tid})
                MERGE (c)-[:MAPS_TO]->(t)
            ''', {"cve": cve, "tid": tid})
            
    print("Enrichment complete!")

if __name__ == "__main__":
    enrich_findings()
