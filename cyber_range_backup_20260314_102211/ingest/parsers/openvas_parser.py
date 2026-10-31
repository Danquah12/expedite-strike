import xml.etree.ElementTree as ET


def ingest_openvas(driver, path):
    tree = ET.parse(path)
    root = tree.getroot()

    with driver.session() as session:
        for result in root.findall(".//result"):
            host = result.findtext("host")
            name = result.findtext("name")
            severity = result.findtext("severity")

            if not host or not name:
                continue

            fid = f"openvas:{host}:{name}"

            session.run(
                """
                MERGE (a:Asset {host:$host})
                MERGE (f:Finding {id:$id})
                SET f.scanner='OpenVAS',
                    f.name=$name,
                    f.severity=$severity
                MERGE (a)-[:HAS_FINDING]->(f)
                """,
                host=host,
                id=fid,
                name=name,
                severity=severity,
            )

