import xml.etree.ElementTree as ET
import datetime

class BurpParser:
    """
    Class-based parser for BurpSuite XML scan exports.
    """

    def parse(self, path):
        findings = []

        try:
            tree = ET.parse(path)
            root = tree.getroot()

            for issue in root.findall(".//issue"):
                name = issue.findtext("name", "").strip()
                host = issue.findtext("host", "").strip()
                severity = issue.findtext("severity", "info").lower()
                desc = issue.findtext("issueBackground", "").strip()

                findings.append({
                    "host": host,
                    "port": "443",
                    "title": name,
                    "severity": severity,
                    "description": desc,
                    "source": "burp",
                    "import_date": datetime.datetime.utcnow().isoformat()
                })

        except Exception as e:
            print(f"[BurpParser] Error parsing Burp XML: {e}")

        return findings
