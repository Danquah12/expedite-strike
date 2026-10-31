"""
scan_ingestor.py
================
Universal Neo4j ingestor for ALL scanner output formats.

Supports:
  - nmap XML        (via NmapXmlParser)
  - nuclei JSON     (JSONL — one finding per line)
  - ZAP JSON        (OWASP ZAP report format)
  - Burp XML        (<issues> root)
  - AegisProbe JSON (already has evidence fields)
  - OpenVAS XML     (<report> root, stub-ready)

Call:
    from cyber_range.services.scan_ingestor import ScanIngestor
    ScanIngestor().ingest(report_path, scanner="nuclei", on_output=...)
"""

import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


# ── Shared Neo4j writer ───────────────────────────────────────────────
def _write_findings(findings: list[dict], on_output=None) -> int:
    if not findings:
        return 0

    def _log(m):
        if on_output: on_output(m)
        else: print(m, end="")

    try:
        from neo4j import GraphDatabase
        pw = os.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))

        count = 0
        ts = datetime.now(timezone.utc).isoformat()
        with driver.session() as session:
            for f in findings:
                host     = str(f.get("host", "unknown") or "unknown")
                port     = str(f.get("port", "")  or "")
                protocol = str(f.get("protocol", "tcp") or "tcp")
                svc      = str(f.get("service", "unknown") or "unknown")
                name     = str(f.get("name", "Unknown Finding") or "Unknown Finding")
                severity = str(f.get("severity", "Info") or "Info")
                cve      = str(f.get("cve", "")    or "")
                evidence = str(f.get("evidence", "") or "")
                desc     = str(f.get("description", evidence) or evidence)
                url      = str(f.get("url", "")    or "")
                scanner  = str(f.get("source", "unknown") or "unknown")

                # Derive service ID and finding ID
                sid = f"{host}:{port}:{protocol}" if port else f"{host}:0:{scanner}"
                fid = f"{scanner}:{host}:{port}:{name[:40]}"

                session.run("""
                    MERGE (h:Host {ip: $ip})
                    MERGE (s:Service {id: $sid})
                    SET   s.name = $svc,
                          s.port = $port,
                          s.protocol = $protocol,
                          s.source = $scanner
                    MERGE (h)-[:RUNS_SERVICE]->(s)
                    MERGE (f:Finding {id: $fid})
                    ON CREATE SET f.first_seen = $ts
                    SET   f.name = $name,
                          f.severity = $severity,
                          f.cve = $cve,
                          f.evidence = $evidence,
                          f.description = $desc,
                          f.url = $url,
                          f.source = $scanner,
                          f.scanner = $scanner,
                          f.last_seen = $ts
                    MERGE (s)-[:HAS_FINDING]->(f)
                """,
                    ip=host, sid=sid, svc=svc, port=port, protocol=protocol,
                    scanner=scanner, fid=fid, name=name, severity=severity,
                    cve=cve, evidence=evidence, desc=desc, url=url, ts=ts
                )
                count += 1

        driver.close()
        _log(f"[ScanIngestor] ✓ {count} findings written to Neo4j\n")
        return count
    except Exception as e:
        _log(f"[ScanIngestor] ✗ Neo4j error: {e}\n")
        return 0


# ─────────────────────────────────────────────────────────────────────
# Per-format parsers
# ─────────────────────────────────────────────────────────────────────

def _parse_nmap_xml(path: str) -> list[dict]:
    """Delegate to NmapXmlParser."""
    from cyber_range.services.nmap_xml_parser import parse_nmap_xml
    return parse_nmap_xml(path)


def _parse_nuclei_json(path: str) -> list[dict]:
    """
    Nuclei JSONL output — one JSON object per line.
    Fields: host, matched-at, info.severity, info.name, info.tags, matcher-name
    """
    findings = []
    SEV_MAP = {"info": "Info", "low": "Low", "medium": "Medium",
               "high": "High", "critical": "Critical"}
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                raw_host = obj.get("host", obj.get("ip", "unknown"))
                # Strip scheme
                host = raw_host.split("://")[-1].split("/")[0].split(":")[0]
                port = ""
                if ":" in raw_host.split("://")[-1]:
                    try:
                        port = raw_host.split("://")[-1].split(":")[1].split("/")[0]
                    except Exception:
                        port = ""

                info     = obj.get("info", {})
                sev_raw  = info.get("severity", "info").lower()
                severity = SEV_MAP.get(sev_raw, "Info")
                name     = info.get("name", obj.get("template-id", "Unknown"))
                matched  = obj.get("matched-at", raw_host)
                tags     = ", ".join(info.get("tags", []))
                cve_ids  = [t.upper() for t in info.get("tags", []) if t.upper().startswith("CVE-")]
                evidence = obj.get("extracted-results", [])
                if isinstance(evidence, list):
                    evidence = " | ".join(str(e) for e in evidence[:3])

                findings.append({
                    "host":     host,
                    "port":     port,
                    "protocol": "tcp",
                    "service":  "web",
                    "name":     name,
                    "severity": severity,
                    "cve":      cve_ids[0] if cve_ids else "",
                    "evidence": evidence or f"Template matched: {matched}",
                    "description": info.get("description", ""),
                    "url":      matched,
                    "source":   "nuclei",
                })
    except Exception as e:
        print(f"[ScanIngestor/nuclei] Parse error {path}: {e}")
    return findings


def _parse_zap_json(path: str) -> list[dict]:
    """
    OWASP ZAP JSON report — site[].alerts[].instances[]
    """
    findings = []
    RISK_SEV = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            report = json.load(fh)

        for site in report.get("site", []):
            host = site.get("@host", "unknown")
            port = site.get("@port", "")
            for alert in site.get("alerts", []):
                sev = RISK_SEV.get(str(alert.get("riskcode", "0")), "Info")
                name = alert.get("name", alert.get("alert", "Unknown"))
                desc = alert.get("desc", "")
                # Clean HTML tags from desc
                import re
                desc = re.sub(r"<[^>]+>", "", desc).strip()

                for inst in alert.get("instances", [{"uri": "", "evidence": ""}]):
                    evidence = inst.get("evidence", "") or inst.get("attack", "")
                    url      = inst.get("uri", "")
                    param    = inst.get("param", "")
                    ev_str   = f"{evidence}" + (f" [param: {param}]" if param else "")
                    findings.append({
                        "host":     host,
                        "port":     port,
                        "protocol": "tcp",
                        "service":  "web",
                        "name":     name,
                        "severity": sev,
                        "cve":      "",
                        "evidence": ev_str or f"ZAP alert: {name}",
                        "description": desc,
                        "url":      url,
                        "source":   "zap",
                    })
    except Exception as e:
        print(f"[ScanIngestor/zap] Parse error {path}: {e}")
    return findings


def _parse_burp_xml(path: str) -> list[dict]:
    """
    Burp Suite XML report — <issues><issue>...</issue></issues>
    """
    findings = []
    SEV_MAP  = {"high": "High", "medium": "Medium", "low": "Low",
                "information": "Info", "false positive": "Info"}
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        for issue in root.findall(".//issue"):
            host     = _xt(issue, "host") or "unknown"
            port     = _xt(issue, "port") or ""
            url      = _xt(issue, "path") or ""
            name     = _xt(issue, "name") or "Unknown Burp Issue"
            sev_raw  = (_xt(issue, "severity") or "information").lower()
            severity = SEV_MAP.get(sev_raw, "Info")
            desc     = _clean_html(_xt(issue, "issueBackground") or _xt(issue, "issueDetail") or "")
            evidence = _clean_html(_xt(issue, "issueDetail") or "")
            remediation = _clean_html(_xt(issue, "remediationBackground") or "")

            findings.append({
                "host":     host,
                "port":     port,
                "protocol": "tcp",
                "service":  "web",
                "name":     name,
                "severity": severity,
                "cve":      "",
                "evidence": evidence or f"Burp finding: {name}",
                "description": desc,
                "url":      url,
                "source":   "burp",
            })
    except Exception as e:
        print(f"[ScanIngestor/burp] Parse error {path}: {e}")
    return findings


def _parse_aegisprobe_json(path: str) -> list[dict]:
    """
    AegisProbe JSON report — {findings: [{name, severity, url, evidence, cwe}]}
    """
    findings = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            report = json.load(fh)
        target = report.get("target", "unknown")
        host = target.split("://")[-1].split("/")[0].split(":")[0]

        for f in report.get("findings", []):
            sev_map = {"Critical": "Critical", "High": "High",
                       "Medium": "Medium", "Low": "Low", "Information": "Info"}
            findings.append({
                "host":     host,
                "port":     "443",
                "protocol": "tcp",
                "service":  "web",
                "name":     f.get("name", "Unknown"),
                "severity": sev_map.get(f.get("severity", "Info"), "Info"),
                "cve":      "",
                "evidence": f.get("evidence", ""),
                "description": f.get("description", f.get("evidence", "")),
                "url":      f.get("url", target),
                "source":   "AegisProbe",
            })
    except Exception as e:
        print(f"[ScanIngestor/aegisprobe] Parse error {path}: {e}")
    return findings


def _parse_openvas_xml(path: str) -> list[dict]:
    """
    OpenVAS XML report — <report><results><result>...</result>...</results></report>
    """
    findings = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        for result in root.findall(".//result"):
            host_el  = result.find("host")
            host     = host_el.text.strip() if (host_el is not None and host_el.text) else "unknown"
            port_raw = _xt(result, "port") or ""
            port = port_raw.split("/")[0] if "/" in port_raw else port_raw
            protocol = port_raw.split("/")[1] if "/" in port_raw else "tcp"
            name  = _xt(result, "name") or "Unknown OpenVAS Finding"
            desc  = _xt(result, "description") or ""
            sev_raw = _xt(result, "severity") or "0.0"
            try:
                cvss = float(sev_raw)
            except ValueError:
                cvss = 0.0
            if cvss >= 9.0: sev = "Critical"
            elif cvss >= 7.0: sev = "High"
            elif cvss >= 4.0: sev = "Medium"
            elif cvss > 0:    sev = "Low"
            else:             sev = "Info"
            cve_el = result.find(".//ref[@type='cve']")
            cve    = cve_el.get("id", "") if cve_el is not None else ""
            findings.append({
                "host":     host,
                "port":     port,
                "protocol": protocol,
                "service":  "unknown",
                "name":     name,
                "severity": sev,
                "cve":      cve,
                "evidence": desc[:300],
                "description": desc,
                "url":      "",
                "source":   "openvas",
            })
    except Exception as e:
        print(f"[ScanIngestor/openvas] Parse error {path}: {e}")
    return findings


# ── Small helpers ─────────────────────────────────────────────────────
def _xt(el, tag: str) -> str:
    """Get element text safely."""
    child = el.find(tag)
    return (child.text or "").strip() if child is not None else ""


def _clean_html(s: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", s).strip() if s else ""


# ─────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────
class ScanIngestor:
    """
    Universal scan report → Neo4j ingestor.

    Usage:
        count = ScanIngestor().ingest(report_path, scanner="nuclei", on_output=...)
    """

    PARSERS = {
        "nmap":       _parse_nmap_xml,
        "nuclei":     _parse_nuclei_json,
        "zap":        _parse_zap_json,
        "burp":       _parse_burp_xml,
        "aegisprobe": _parse_aegisprobe_json,
        "openvas":    _parse_openvas_xml,
    }

    def ingest(self, report_path: str, scanner: str, on_output=None) -> int:
        """
        Parse report_path for the given scanner and write to Neo4j.
        Returns number of findings ingested.
        """
        def _log(m):
            if on_output: on_output(m)

        if not os.path.isfile(report_path):
            _log(f"[ScanIngestor] File not found: {report_path}\n")
            return 0

        parser = self.PARSERS.get(scanner.lower())
        if not parser:
            _log(f"[ScanIngestor] Unknown scanner '{scanner}' — supported: {list(self.PARSERS)}\n")
            return 0

        _log(f"[ScanIngestor] Parsing {scanner} report: {report_path}\n")
        try:
            findings = parser(report_path)
        except Exception as e:
            _log(f"[ScanIngestor] ✗ Parse error: {e}\n")
            return 0

        if not findings:
            _log(f"[ScanIngestor] No findings parsed from {report_path}\n")
            return 0

        _log(f"[ScanIngestor] {len(findings)} findings parsed → writing to Neo4j...\n")
        return _write_findings(findings, on_output)

    def auto_detect_and_ingest(self, report_path: str, on_output=None) -> int:
        """
        Auto-detect scanner type from file extension / content and ingest.
        """
        ext = os.path.splitext(report_path)[1].lower()
        name = os.path.basename(report_path).lower()

        if "nmap" in name and ext == ".xml":
            return self.ingest(report_path, "nmap", on_output)
        if "nuclei" in name and ext in (".json", ".jsonl"):
            return self.ingest(report_path, "nuclei", on_output)
        if "zap" in name and ext == ".json":
            return self.ingest(report_path, "zap", on_output)
        if "burp" in name and ext == ".xml":
            return self.ingest(report_path, "burp", on_output)
        if "aegis" in name and ext == ".json":
            return self.ingest(report_path, "aegisprobe", on_output)
        if "openvas" in name and ext == ".xml":
            return self.ingest(report_path, "openvas", on_output)

        # Fallback: sniff file content
        try:
            with open(report_path, encoding="utf-8", errors="ignore") as fh:
                head = fh.read(512)
            if "<nmaprun" in head:
                return self.ingest(report_path, "nmap", on_output)
            if "<issues>" in head or "<issue>" in head:
                return self.ingest(report_path, "burp", on_output)
            if "<report>" in head and "<result>" in head:
                return self.ingest(report_path, "openvas", on_output)
            if '"template-id"' in head or '"matched-at"' in head:
                return self.ingest(report_path, "nuclei", on_output)
            if '"site"' in head and '"alerts"' in head:
                return self.ingest(report_path, "zap", on_output)
        except Exception:
            pass

        if on_output:
            on_output(f"[ScanIngestor] Could not auto-detect format for {report_path}\n")
        return 0


__all__ = ["ScanIngestor"]
