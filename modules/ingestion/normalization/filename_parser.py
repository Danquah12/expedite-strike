import re
from datetime import datetime


NMAP_PATTERN = re.compile(
    r"^nmap_(?P<target>[^_]+)_(?P<timestamp>\d{8}T\d{6}Z)\.xml$"
)

ZAP_PATTERN = re.compile(
    r"^zap_(?P<target>[^_]+)_(?P<timestamp>\d{8}T\d{6}Z)\.json$"
)


def parse_scan_filename(filename):
    """
    Parses scan filenames and extracts target and timestamp.

    Returns:
        dict with keys: tool, target, timestamp
        or None if filename does not match expected format.
    """

    nmap_match = NMAP_PATTERN.match(filename)
    if nmap_match:
        return {
            "tool": "nmap",
            "target": nmap_match.group("target"),
            "timestamp": _parse_timestamp(nmap_match.group("timestamp"))
        }

    zap_match = ZAP_PATTERN.match(filename)
    if zap_match:
        return {
            "tool": "zap",
            "target": zap_match.group("target"),
            "timestamp": _parse_timestamp(zap_match.group("timestamp"))
        }

    return None


def _parse_timestamp(ts):
    """
    Converts timestamps like 20260124T193101Z → ISO-8601 string.
    """
    return datetime.strptime(ts, "%Y%m%dT%H%M%SZ").isoformat() + "Z"
