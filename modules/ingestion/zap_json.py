import json
from urllib.parse import urlparse


def parse_zap_json(file_path):
    """
    Parses ZAP JSON output.
    Returns:
      web_findings: list[dict]
    """
    findings = []

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = data.get("alerts", [])

    for alert in alerts:
        url = alert.get("url")
        parsed = urlparse(url) if url else None

        if parsed and parsed.port:
            findings.append({
                "port": parsed.port,
                "service": "http",
                "alert": alert.get("alert"),
                "risk": alert.get("risk")
            })

    return findings
