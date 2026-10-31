import json
import datetime

class ZapParser:
    def parse(self, path):
        findings = []

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            for site in data.get("site", []):
                host = site.get("@name", "unknown")

                for alert in site.get("alerts", []):
                    findings.append({
                        "host": host,
                        "port": "80",
                        "title": alert.get("alert", "unknown"),
                        "severity": alert.get("riskdesc", "info").split(" ")[0].lower(),
                        "description": alert.get("desc", ""),
                        "source": "zap",
                        "import_date": datetime.datetime.utcnow().isoformat()
                    })

        except Exception as e:
            print(f"[ZapParser] Error parsing ZAP JSON: {e}")

        return findings
