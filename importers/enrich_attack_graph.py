# ============================================
# enrich_attack_graph.py — Full MITRE Mapping
# ============================================

from neo4j import GraphDatabase

driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "Adomaa12@")
)

def enrich():
    print("[+] Linking CVEs → MITRE Techniques...")

    with driver.session() as session:

        # 1. Link CVEs to Techniques (from MITRE ATT&CK import)
        session.run("""
            MATCH (c:CVE), (t:Technique)
            WHERE t.external_references CONTAINS c.id
            MERGE (c)-[:MAPS_TO]->(t)
        """)

        # 2. Link Techniques to Kill Chain phases
        session.run("""
            MATCH (t:Technique)
            WITH t, t.kill_chain_phases AS phases
            UNWIND phases AS p
            MERGE (k:KillChain {phase:p})
            MERGE (t)-[:PART_OF]->(k)
        """)

        # 3. Connect Vulnerabilities to Techniques
        session.run("""
            MATCH (v:Vulnerability)-[:IS_CVE]->(c:CVE)-[:MAPS_TO]->(t:Technique)
            MERGE (v)-[:EXPLOITABLE_BY]->(t)
        """)

        # Web Vulnerabilities → Techniques
        session.run("""
            MATCH (v:WebVulnerability)-[:IS_CVE]->(c:CVE)-[:MAPS_TO]->(t:Technique)
            MERGE (v)-[:EXPLOITABLE_BY]->(t)
        """)

    print("[+] Enrichment completed.")

if __name__ == "__main__":
    enrich()
