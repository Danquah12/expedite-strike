# cyber_range/services/feed_service_linker.py

import re


def normalize(text):
    if not text:
        return ""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def link_feeds_to_services(session):
    """
    Create POTENTIALLY_APPLIES_TO relationships between
    ImportFeed and Service nodes based on conservative matching.
    """

    # Fetch services
    services = session.run("""
        MATCH (s:Service)
        RETURN id(s) AS sid,
               s.name AS name,
               s.product AS product,
               s.protocol AS protocol
    """)

    services = [
        {
            "sid": r["sid"],
            "name": normalize(r["name"]),
            "product": normalize(r["product"]),
            "protocol": normalize(r["protocol"]),
        }
        for r in services
    ]

    # Fetch feeds
    feeds = session.run("""
        MATCH (f:ImportFeed)
        RETURN id(f) AS fid,
               f.feed_id AS feed_id,
               f.source AS source
    """)

    feeds = [
        {
            "fid": r["fid"],
            "text": normalize(r["feed_id"]),
            "source": r["source"],
        }
        for r in feeds
    ]

    links_created = 0

    for svc in services:
        for feed in feeds:
            # Conservative matching rules
            if (
                svc["product"] and svc["product"] in feed["text"]
                or svc["name"] and svc["name"] in feed["text"]
                or svc["protocol"] and svc["protocol"] in feed["text"]
            ):
                session.run(
                    """
                    MATCH (f) WHERE id(f) = $fid
                    MATCH (s) WHERE id(s) = $sid
                    MERGE (f)-[:POTENTIALLY_APPLIES_TO]->(s)
                    """,
                    fid=feed["fid"],
                    sid=svc["sid"],
                )
                links_created += 1

    return links_created
