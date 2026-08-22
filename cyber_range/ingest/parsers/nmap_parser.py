import xml.etree.ElementTree as ET


def ingest_nmap(driver, path):
    tree = ET.parse(path)
    root = tree.getroot()

    with driver.session() as session:
        for host in root.findall("host"):
            addr = host.find("address")
            if addr is None:
                continue

            ip = addr.attrib.get("addr")
            session.run("MERGE (a:Asset {host:$host})", host=ip)

            for port in host.findall(".//port"):
                portid = port.attrib.get("portid")
                proto = port.attrib.get("protocol")

                sid = f"{ip}:{proto}:{portid}"
                session.run(
                    """
                    MERGE (s:Service {id:$id})
                    SET s.port=$port,
                        s.protocol=$proto,
                        s.source='nmap'
                    """,
                    id=sid,
                    port=portid,
                    proto=proto,
                )

