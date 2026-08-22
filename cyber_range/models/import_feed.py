# cyber_range/models/import_feed.py

from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ImportFeed:
    # Core identity
    feed_id: str              # e.g. SSV:69341, ZAP:10021
    source: str               # seebug, packetstorm, metasploit, zap
    feed_type: str            # exploit | vulnerability

    # Exploit intelligence
    cvss: Optional[float]
    exploit_available: bool
    exploit_type: Optional[str] = None  # rce, dos, lpe

    # Context / enrichment
    references: List[str] = None
    affected_product: Optional[str] = None
    affected_component: Optional[str] = None
    affected_versions: Optional[str] = None

    # Scan context (IMPORTANT)
    scan_tool: Optional[str] = None     # nmap | zap
    scan_target: Optional[str] = None   # IP, CIDR, hostname
    scan_timestamp: Optional[str] = None
