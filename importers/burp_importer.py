#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import os

from shared_utils import (
    merge_asset,
    merge_vulnerability,
    merge_cve,
    extract_cves,
    debug,
)

# -------------------------------------------------
# Burp XML Importer
# -------------------------------------------------
def import_burp(path: str):
    """
    Import a Burp Suite XML report into Neo4j using
    the shared vulnerability model.

    Model:
      (:Asset)-[:HAS_VULNERABILITY]->(:Finding)-[:IS_CVE]->(:CVE)
    """

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Burp XML not found: {path}")

    debug(f"[BURP] Importing Burp XML: {path}")

    tree = ET.parse(path)
    root = tree.getroot()

    count = 0

    for issue in root.findall(".//issue"):
        # ----------------------------
        # Core Burp fields
        # ----------------------------
        host = (
            issue.findtext("host")
            or issue.findtext("location")
            or "unknown-web-host"
        )

        path = issue.findtext("path") or "/"
        name = issue.findtext("name") or "Burp Finding"
        severity = (issue.findtext("severity") or "info").lower()
        confidence = issue.findtext("confidence") or "unknown"

        background = issue.findtext("issueBackground") or ""
        detail = issue.findtext("issueDetail") or ""
        description = f"{background}\n\n{detail}".strip()

        plugin_id = issue.findtext("type") or "BURP-GENERIC"

        # ----------------------------
        # Normalize severity
        # ----------------------------
        severity_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "information": "info",
            "info": "info",
        }
        severity = severity_map.get(severity, "info")

        # ----------------------------
        # Asset
        # ----------------------------
        merge_asset(host)

        # ----------------------------
        # Finding (normalized)
        # ----------------------------
        finding_id = f"burp:{host}:{plugin_id}:{path}"

        merge_vulnerability(
            asset=host,
            port="web",
            plugin_id=finding_id,
            name=name,
            severity=severity,
            description=description,
            scanner="Burp",
            confidence=confidence,
            path=path,
        )

        # ----------------------------
        # CVEs (if referenced)
        # ----------------------------
        for cve in extract_cves(description):
            merge_cve(cve, finding_id)

        count += 1

    debug(f"[BURP] Import complete — {count} findings ingested.")


# -------------------------------------------------
# CLI entrypoint (optional but useful)
# -------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: burp_import.py <burp_report.xml>")
        sys.exit(1)

    import_burp(sys.argv[1])
