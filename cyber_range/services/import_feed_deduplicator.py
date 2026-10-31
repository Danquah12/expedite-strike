# cyber_range/services/import_feed_deduplicator.py

def deduplicate_import_feeds(feeds):
    """
    Deduplicate ImportFeed objects globally.
    Returns a list of unique feeds.
    """
    unique = {}

    for feed in feeds:
        # Stable global identity
        key = f"{feed.source}:{feed.feed_id}".lower()

        # First occurrence wins
        if key not in unique:
            unique[key] = feed
        else:
            # Merge exploit availability (upgrade only)
            if feed.exploit_available:
                unique[key].exploit_available = True

            # Prefer CVSS if missing
            if unique[key].cvss is None and feed.cvss is not None:
                unique[key].cvss = feed.cvss

    return list(unique.values())

