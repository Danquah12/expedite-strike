# neo4j_loader.py

from neo4j import GraphDatabase

class Neo4jLoader:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", pwd="Adomaa12@"):
        self.driver = GraphDatabase.driver(uri, auth=(user, pwd))

    def load_full_graph(self):
        """
        Load all Assets + all vulnerability types + all relationships.
        Compatible with nmap, zap, burp, openvas.
        """

        query = """
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN n, r, m
        """

        nodes = {}
        edges = []

        with self.driver.session() as session:
            results = session.run(query)

            for record in results:
                n = record["n"]
                m = record["m"]
                r = record["r"]

                # NODES
                if n:
                    nodes[n.id] = {
                        "data": {
                            "id": n.id,
                            "label": list(n.labels)[0],
                            "props": dict(n)
                        }
                    }

                if m:
                    nodes[m.id] = {
                        "data": {
                            "id": m.id,
                            "label": list(m.labels)[0],
                            "props": dict(m)
                        }
                    }

                # EDGES
                if r:
                    edges.append({
                        "data": {
                            "id": str(r.id),
                            "source": n.id,
                            "target": m.id,
                            "label": r.type
                        }
                    })

        return list(nodes.values()) + edges
