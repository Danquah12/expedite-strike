#==============================================================
# mitre_mapper.py — Heuristic Vulnerability → MITRE mapping
#==============================================================

def map_vulnerabilities_to_mitre(session):
    """
    Heuristically map Vulnerabilities to MITRE Techniques
    using vulnerability names/descriptions.
    """

    mappings = [
        ("sql", "T1190"),        # Exploit Public-Facing App
        ("xss", "T1059"),        # Command & Scripting
        ("command", "T1059"),
        ("upload", "T1105"),     # Ingress Tool Transfer
        ("rce", "T1059"),
        ("remote", "T1021"),     # Remote Services
        ("auth", "T1078"),       # Valid Accounts
        ("credential", "T1003"),
        ("scan", "T1595"),       # Active Scanning
        ("port", "T1046"),       # Network Service Discovery
    ]

    for keyword, tech_id in mappings:
        session.run("""
            MATCH (v:Vulnerability)
            WHERE toLower(v.name) CONTAINS $kw
               OR toLower(v.id) CONTAINS $kw
            MATCH (t:Technique {id: $tech})
            MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
        """, kw=keyword, tech=tech_id)
