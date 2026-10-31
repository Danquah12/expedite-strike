import xml.etree.ElementTree as ET
import subprocess
import tempfile
import os
from neo4j import GraphDatabase


class NmapIngestor:
    """
    Runs Nmap scan and ingests results into Neo4j.
    """

    def __init__(self):
        self.neo4j_password = os.getenv("NEO4J_PASSWORD")
        if not self.neo4j_password:
            raise RuntimeError("NEO4J_PASSWORD not set")

    def scan_and_ingest(self, targets):
        if not targets:
            raise ValueError("Nmap requires at least one target")

        with tempfile.NamedTemporaryFile(
            prefix="nmap_", suffix=".xml", delete=False
        ) as tmp:
            xml_path = tmp.name

        cmd = [
            "nmap",
            "-sS",
            "-sV",
            "-O",
            "-T4",
            "--open",
            "-oX", xml_path,
        ] + targets

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.returncode != 0:
            os.unlink(xml_path)
            raise RuntimeError(f"Nmap scan failed:\n{result.stderr}")

        stats = self._ingest_xml(xml_path)
        os.unlink(xml_path)
        return stats

    def _ingest_xml(self, report_path):
        tree = ET.parse(report_path)
        root = tree.getroot()

        driver = GraphDatabase.driver(
            "bolt://127.0.0.1:7687",
            auth=("neo4j", self.neo4j_password),
        )

        assets = set()
        services = set()

        with driver.session() as session:
            for host in root.findall("host"):
                addr_el = host.find("address")
                if addr_el is None:
                    continue

                ip = addr_el.get("addr")
                if not ip:
                    continue

                assets.add(ip)

                session.run(
                    "MERGE (a:Host {ip:$host}) SET a.host=$host",
                    host=ip,
                )

                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    proto = port.get("protocol")
                    portid = port.get("portid")

                    service_id = f"{ip}:{proto}:{portid}"
                    services.add(service_id)

                    session.run(
                        """
                        MERGE (s:Service {id:$id})
                        SET s.protocol=$proto,
                            s.port=$port,
                            s.source='nmap'
                        WITH s
                        MATCH (a:Host {ip:$host})
                        MERGE (a)-[:RUNS_SERVICE]->(s)
                        """,
                        id=service_id,
                        proto=proto,
                        port=portid,
                        host=ip,
                    )

        driver.close()
        return {
            "assets": len(assets),
            "services": len(services),
        }
