import os
from cyber_range.parsers.nmap_parser import NmapParser
from cyber_range.parsers.openvas_parser import OpenVASParser
from cyber_range.parsers.zap_parser import ZapParser
from cyber_range.parsers.burp_parser import BurpParser

FEEDS_BASE = "/opt/vuln_intel/feeds"

class FeedLoader:

    def __init__(self):
        self.feed_dirs = {
            "nmap": os.path.join(FEEDS_BASE, "nmap"),
            "openvas": os.path.join(FEEDS_BASE, "openvas"),
            "zap": os.path.join(FEEDS_BASE, "zap"),
            "burp": os.path.join(FEEDS_BASE, "burp")
        }

    def load_all_feeds(self):
        """
        Automatically loads ALL supported feeds and returns a combined list of findings.
        """
        findings = []

        # -------- NMAP --------
        for file in self._list_xml(self.feed_dirs["nmap"]):
            print(f"[+] Loading Nmap feed: {file}")
            findings.extend(NmapParser().parse(file))

        # -------- OPENVAS --------
        for file in self._list_xml(self.feed_dirs["openvas"]):
            print(f"[+] Loading OpenVAS feed: {file}")
            findings.extend(OpenVASParser().parse(file))

        # -------- ZAP --------
        for file in self._list_xml(self.feed_dirs["zap"]):
            print(f"[+] Loading ZAP feed: {file}")
            findings.extend(ZapParser().parse(file))

        # -------- BURP SUITE --------
        for file in self._list_xml(self.feed_dirs["burp"]):
            print(f"[+] Loading BurpSuite feed: {file}")
            findings.extend(BurpParser().parse(file))

        print(f"[✓] Total findings loaded: {len(findings)}")
        return findings

    def _list_xml(self, folder):
        """
        Returns all .xml files in a feed folder.
        """
        if not os.path.exists(folder):
            return []

        return [
            os.path.join(folder, f)
            for f in os.listdir(folder)
            if f.lower().endswith(".xml")
        ]
