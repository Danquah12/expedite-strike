# cyber_range/services/import_feed_queries.py

def fetch_import_feeds(
    session,
    source=None,
    min_confidence=None,
    kev_only=False,
    exploit_only=False,
    limit=500
):
    """
    Fetch ImportFeed nodes with optional filters and
    environment context (affected services count).
    Returns list of dicts for UI consumption.
    """

    query = """
    MATCH (f:ImportFeed)
    OPTIONAL MATCH (f)-[:POTENTIALLY_APPLIES_TO]->(s:Service)
    WHERE 1=1
    """

    params = {}

    if source:
        query += " AND f.source = $source"
        params["source"] = source

    if min_confidence is not None:
        query += " AND f.confidence >= $min_confidence"
        params["min_confidence"] = min_confidence

    if kev_only:
        query += " AND f.in_kev = true"

    if exploit_only:
        query += " AND f.exploit_available = true"

    query += """
    RETURN
        f.source            AS source,
        f.feed_id           AS feed_id,
        f.confidence        AS confidence,
        f.exploit_available AS exploit_available,
        f.cvss              AS cvss,
        f.in_kev            AS in_kev,
        f.kev_due_date      AS kev_due_date,
        f.kev_ransomware    AS kev_ransomware,
        f.last_seen         AS last_seen,
        count(DISTINCT s)   AS affected_services
    ORDER BY affected_services DESC, confidence DESC
    LIMIT $limit
    """

    params["limit"] = limit

    result = session.run(query, params)
    return [dict(record) for record in result]
