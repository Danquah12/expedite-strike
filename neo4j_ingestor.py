from neo4j import GraphDatabase

class Neo4jIngestor:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_zap(self, finding):
        query = """
        MERGE (a:Application {url:$application})
        MERGE (v:Vulnerability {name:$name})
        SET v.severity=$severity,
            v.description=$description,
            v.source=$source
        MERGE (a)-[:HAS_VULN]->(v)
        """
        with self.driver.session() as session:
            session.run(query, {
                "application": finding["host"],
                "name": finding["title"],
                "severity": finding["severity"],
                "description": finding["description"],
                "source": "zap"
            })

    def ingest_nmap(self, finding):
        query = """
        MERGE (h:Host {ip:$host})
        MERGE (s:Service {port:$port, name:$service})
        MERGE (h)-[:EXPOSES]->(s)
        """
        with self.driver.session() as session:
            session.run(query, {
                "host": finding["host"],
                "port": finding["port"],
                "service": finding["title"]
            })
