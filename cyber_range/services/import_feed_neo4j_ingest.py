# cyber_range/services/import_feed_neo4j_ingest.py

from cyber_range.services.import_feed_confidence import score_import_feed
from cyber_range.services.kev_mapper import enrich_with_kev


class ImportFeedNeo4jIngestor:
    def __init__(self, driver, kev_index):
        self.driver = driver
        self.kev_index = kev_index

    def ingest(self, feeds):
        count = 0

        with self.driver.session() as session:
            for feed in feeds:
                confidence = score_import_feed(feed)
                kev = enrich_with_kev(feed, self.kev_index)

                session.run(
                    """
                    MERGE (f:ImportFeed {key: $key})
                    SET f.feed_id = $feed_id,
                        f.source = $source,
                        f.feed_type = $feed_type,
                        f.cvss = $cvss,
                        f.exploit_available = $exploit_available,
                        f.confidence = $confidence,
                        f.in_kev = $in_kev,
                        f.kev_due_date = $kev_due_date,
                        f.kev_ransomware = $kev_ransomware,
                        f.last_seen = datetime()
                    """,
                    key=f"{feed.source}:{feed.feed_id}".lower(),
                    feed_id=feed.feed_id,
                    source=feed.source,
                    feed_type=feed.feed_type,
                    cvss=feed.cvss,
                    exploit_available=feed.exploit_available,
                    confidence=confidence,
                    in_kev=kev.get("in_kev", False),
                    kev_due_date=kev.get("due_date"),
                    kev_ransomware=kev.get("ransomware", False)
                )
                count += 1

        return count

