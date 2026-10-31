# cyber_range/services/nmap_import_feed_parser.py

import xml.etree.ElementTree as ET
from cyber_range.models.import_feed import ImportFeed


def parse_nmap_import_feeds(scan_artifact):
    """
    Extracts exploit / vuln intelligence feeds from Nmap XML.
    Handles concatenated XML documents safely.
    """
    feeds = []

    with open(scan_artifact.scan_file, "r", errors="ignore") as f:
        content = f.read()

    # Split concatenated XML docs
    xml_docs = content.split("<?xml")
    for doc in xml_docs:
        if "<nmaprun" not in doc:
            continue

        xml_text = "<?xml" + doc if not doc.startswith("<?xml") else doc

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            continue

        for table in root.findall(".//table"):
            source = table.find("elem[@key='type']")
            feed_id = table.find("elem[@key='id']")
            cvss = table.find("elem[@key='cvss']")
            is_exploit = table.find("elem[@key='is_exploit']")

            if source is None or feed_id is None:
                continue

            feeds.append(
                ImportFeed(
                    feed_id=feed_id.text.strip(),
                    source=source.text.strip(),
                    feed_type="exploit",
                    cvss=float(cvss.text) if cvss is not None else None,
                    exploit_available=(is_exploit.text == "true") if is_exploit else False,
                    references=[],
                    affected_product=None,
                    affected_component=None,
                    affected_versions=None,
                    scan_tool="nmap",
                    scan_target=scan_artifact.target,
                    scan_timestamp=scan_artifact.timestamp
                )
            )

    return feeds
