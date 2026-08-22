# cyber_range/services/import_feed_confidence.py

def score_import_feed(feed):
    """
    Returns a confidence score (0–100) for an ImportFeed.
    This does NOT represent risk or exploitability.
    """
    score = 0

    # Strong exploit frameworks
    if feed.source in ("metasploit", "exploitpack"):
        score += 45

    # Known exploit databases
    elif feed.source in ("packetstorm", "seebug", "1337day"):
        score += 30

    # Public PoC repositories
    elif feed.source in ("githubexploit", "gitee"):
        score += 20

    # CVE references only
    elif feed.source == "cve":
        score += 15

    # Explicit exploit flag from NSE
    if feed.exploit_available:
        score += 20

    # CVSS bump
    if feed.cvss is not None:
        if feed.cvss >= 9.0:
            score += 15
        elif feed.cvss >= 7.0:
            score += 10
        elif feed.cvss >= 4.0:
            score += 5

    return min(score, 100)
