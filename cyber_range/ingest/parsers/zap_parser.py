import json


def ingest_zap(driver, path):
    with open(path, "r") as f:
        data = json.load(f)

    with driver.session() as session:
        for site in data.get("site", []):
            host = site.get("@name")
            if not host:
                continue

            session.run("MERGE (a:Asset {host:$host})", host=host)

            for alert in site.get("alerts", []):
                fid = f"zap:{host}:{alert.get('alertRef')}"
                session.run(
                    """
                    MERGE (f:Finding {id:$id})
                    SET f.scanner='ZAP',
                        f.name=$name,
                        f.severity=$severity
                    """,
                    id=fid,
                    name=alert.get("alert"),
                    severity=alert.get("riskdesc"),
                )
