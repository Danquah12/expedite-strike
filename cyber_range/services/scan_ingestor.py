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
  - OpenVAS XML     (<report> root)
  - Nessus XML      (.nessus Tenable format)
  - STIG CKL        (.ckl DISA checklist)
  - SCAP XCCDF      (.xml SCAP/XCCDF benchmark results)

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
                cwe      = str(f.get("cwe", "")    or "")
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
                          f.cwe = $cwe,
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
                    cve=cve, cwe=cwe, evidence=evidence, desc=desc, url=url, ts=ts
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


def _parse_nessus_xml(path: str) -> list[dict]:
    """
    Nessus / Tenable .nessus XML report.
    Structure: <NessusClientData_v2> <Report> <ReportHost> <ReportItem> ...
    Extracts: pluginID, pluginName, CVE, CVSS, severity, host, port, description
    """
    findings = []
    SEV_MAP = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        for host_el in root.findall(".//ReportHost"):
            host = host_el.get("name", "unknown")
            # Try to get IP from HostProperties
            for tag in host_el.findall(".//HostProperties/tag"):
                if tag.get("name") == "host-ip" and tag.text:
                    host = tag.text.strip()
                    break

            for item in host_el.findall("ReportItem"):
                plugin_id   = item.get("pluginID", "")
                plugin_name = item.get("pluginName", "Unknown")
                port        = item.get("port", "0")
                protocol    = item.get("protocol", "tcp")
                svc_name    = item.get("svc_name", "unknown")
                sev_raw     = item.get("severity", "0")
                severity    = SEV_MAP.get(sev_raw, "Info")

                # Skip informational items (severity=0) to reduce noise
                if sev_raw == "0":
                    continue

                # Extract sub-elements
                desc     = _xt(item, "description") or _xt(item, "plugin_output") or ""
                solution = _xt(item, "solution") or ""
                cvss_raw = _xt(item, "cvss3_base_score") or _xt(item, "cvss_base_score") or ""
                cve      = _xt(item, "cve") or ""
                output   = _xt(item, "plugin_output") or ""

                findings.append({
                    "host":        host,
                    "port":        port,
                    "protocol":    protocol,
                    "service":     svc_name,
                    "name":        plugin_name,
                    "severity":    severity,
                    "cve":         cve,
                    "evidence":    output[:500] if output else f"Plugin {plugin_id}: {plugin_name}",
                    "description": desc[:500],
                    "url":         "",
                    "source":      "nessus",
                    "plugin_id":   plugin_id,
                    "cvss":        cvss_raw,
                    "solution":    solution[:300],
                })
    except Exception as e:
        print(f"[ScanIngestor/nessus] Parse error {path}: {e}")
    return findings


def _parse_ckl(path: str) -> list[dict]:
    """
    DISA STIG Checklist (.ckl) parser.
    Structure: <CHECKLIST> <STIGS> <iSTIG> <VULN> <STIG_DATA> ...
    Extracts: Vuln_Num (rule_id), Status, Severity, Finding_Details, Comments
    """
    findings = []
    SEV_MAP = {"high": "High", "medium": "Medium", "low": "Low", "cat i": "High",
               "cat ii": "Medium", "cat iii": "Low"}
    try:
        tree = ET.parse(path)
        root = tree.getroot()

        # Extract host info from ASSET element
        asset = root.find(".//ASSET")
        host = "unknown"
        if asset is not None:
            host = (
                _xt(asset, "HOST_IP") or
                _xt(asset, "HOST_NAME") or
                _xt(asset, "HOST_FQDN") or
                "unknown"
            )

        # Get STIG title
        stig_info = root.find(".//STIG_INFO")
        stig_title = ""
        if stig_info is not None:
            for si_data in stig_info.findall("SI_DATA"):
                name_el = si_data.find("SID_NAME")
                if name_el is not None and name_el.text == "title":
                    val_el = si_data.find("SID_DATA")
                    stig_title = val_el.text.strip() if val_el is not None and val_el.text else ""

        for vuln in root.findall(".//VULN"):
            # Extract STIG_DATA fields into a dict
            stig_data = {}
            for sd in vuln.findall("STIG_DATA"):
                attr_el = sd.find("VULN_ATTRIBUTE")
                data_el = sd.find("ATTRIBUTE_DATA")
                if attr_el is not None and attr_el.text:
                    stig_data[attr_el.text] = (data_el.text or "").strip() if data_el is not None else ""

            rule_id     = stig_data.get("Vuln_Num", stig_data.get("Rule_ID", ""))
            status      = _xt(vuln, "STATUS") or "Not_Reviewed"
            severity    = stig_data.get("Severity", "medium").lower()
            sev_override = _xt(vuln, "SEVERITY_OVERRIDE")
            if sev_override:
                severity = sev_override.lower()
            severity    = SEV_MAP.get(severity, "Medium")
            vuln_title  = stig_data.get("Rule_Title", stig_data.get("Vuln_Num", "Unknown"))
            details     = _xt(vuln, "FINDING_DETAILS") or ""
            comments    = _xt(vuln, "COMMENTS") or ""
            fix_text    = stig_data.get("Fix_Text", "")

            # Only include non-compliant findings
            if status.lower() in ("open", "not_reviewed"):
                findings.append({
                    "host":        host,
                    "port":        "",
                    "protocol":    "",
                    "service":     stig_title[:80] if stig_title else "STIG",
                    "name":        f"{rule_id}: {vuln_title}"[:120],
                    "severity":    severity,
                    "cve":         stig_data.get("CCI_REF", ""),
                    "evidence":    details[:500] if details else f"Status: {status}",
                    "description": f"Rule: {rule_id} | Status: {status} | {vuln_title}",
                    "url":         "",
                    "source":      "stig_ckl",
                    "rule_id":     rule_id,
                    "status":      status,
                    "fix_text":    fix_text[:300],
                    "comments":    comments[:200],
                })
    except Exception as e:
        print(f"[ScanIngestor/ckl] Parse error {path}: {e}")
    return findings


def _parse_xccdf(path: str, target_override: str = "") -> list[dict]:
    """
    SCAP / XCCDF benchmark results parser.
    Handles both XCCDF 1.1 and 1.2 namespace formats.
    Extracts: rule-result idref, result status, severity, description, message

    Args:
        path: Path to the XCCDF XML file
        target_override: If set, replaces the hardcoded <target> from the XML
                         with the user's actual scan target
    """
    findings = []
    # Common XCCDF namespaces
    NAMESPACES = [
        "",                                                          # no namespace
        "{http://checklists.nist.gov/xccdf/1.2}",                    # XCCDF 1.2
        "{http://checklists.nist.gov/xccdf/1.1}",                    # XCCDF 1.1
        "{http://checklists.nist.gov/xccdf}",                        # generic
    ]
    SEV_MAP = {"high": "High", "medium": "Medium", "low": "Low",
               "unknown": "Info", "info": "Info"}
    try:
        tree = ET.parse(path)
        root = tree.getroot()

        # Detect namespace from root tag
        ns = ""
        root_tag = root.tag
        if "{" in root_tag:
            ns = root_tag.split("}")[0] + "}"

        # Find target (host) — use override if provided
        host = "unknown"
        if target_override and target_override.strip():
            host = target_override.strip()
        else:
            target_el = root.find(f".//{ns}target")
            if target_el is not None and target_el.text:
                host = target_el.text.strip()

        # Also check target-address for IP — override takes precedence
        if target_override and target_override.strip():
            host_ip = target_override.strip()
        else:
            target_addr = root.find(f".//{ns}target-address")
            if target_addr is not None and target_addr.text:
                host_ip = target_addr.text.strip()
            else:
                host_ip = host

        # Find benchmark title
        title_el = root.find(f".//{ns}title")
        benchmark_title = title_el.text.strip() if (title_el is not None and title_el.text) else "SCAP Benchmark"

        # Build rule lookup: idref → (title, description, CWE list)
        rule_info = {}
        for rule in root.findall(f".//{ns}Rule"):
            rid = rule.get("id", "")
            if not rid:
                continue
            rtitle_el = rule.find(f"{ns}title")
            rdesc_el  = rule.find(f"{ns}description")
            rtitle = rtitle_el.text.strip() if (rtitle_el is not None and rtitle_el.text) else ""
            rdesc  = ET.tostring(rdesc_el, encoding="unicode", method="text").strip()[:500] if rdesc_el is not None else ""
            rule_info[rid] = {"title": rtitle, "description": rdesc}

        # Iterate rule-results
        for rr in root.findall(f".//{ns}rule-result"):
            idref    = rr.get("idref", "")
            severity = (rr.get("severity", "medium") or "medium").lower()
            severity = SEV_MAP.get(severity, "Medium")

            result_el = rr.find(f"{ns}result")
            status    = result_el.text.strip() if (result_el is not None and result_el.text) else "unknown"

            # Only include failures
            if status.lower() not in ("fail", "error", "unknown", "notchecked"):
                continue

            # Get rule title and description from lookup
            rinfo = rule_info.get(idref, {})
            rule_title = rinfo.get("title", "")
            desc = rinfo.get("description", "")

            # Extract <message> element (AEGIS benchmarks use this for evidence)
            message_el = rr.find(f"{ns}message")
            message = ""
            if message_el is not None and message_el.text:
                message = message_el.text.strip()[:500]

            # Extract check results
            check_el = rr.find(f".//{ns}check-content")
            evidence = ""
            if check_el is not None and check_el.text:
                evidence = check_el.text.strip()[:300]

            # Use message as primary evidence, fallback to check-content
            evidence = message or evidence or f"SCAP result: {status}"

            # Build readable name: prefer rule title over raw idref
            if rule_title:
                finding_name = f"{rule_title} [{status}]"
            else:
                finding_name = f"{idref}: {status}"

            # Extract CWE references from description text
            import re
            cwe_matches = re.findall(r'CWE-\d+', desc)
            cwe_str = ", ".join(cwe_matches[:3]) if cwe_matches else ""

            findings.append({
                "host":        host_ip if host_ip != host else host,
                "port":        "",
                "protocol":    "",
                "service":     benchmark_title[:80],
                "name":        finding_name[:120],
                "severity":    severity,
                "cve":         "",
                "cwe":         cwe_str,
                "evidence":    evidence,
                "description": desc or f"Rule {idref} — {status}",
                "url":         "",
                "source":      "scap_xccdf",
                "rule_id":     idref,
                "status":      status,
            })
    except Exception as e:
        print(f"[ScanIngestor/xccdf] Parse error {path}: {e}")
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
        "nessus":     _parse_nessus_xml,
        "stig_ckl":   _parse_ckl,
        "scap_xccdf": _parse_xccdf,
    }

    def ingest(self, report_path: str, scanner: str, on_output=None,
               target_override: str = "") -> int:
        """
        Parse report_path for the given scanner and write to Neo4j.
        Returns number of findings ingested.

        Args:
            target_override: For SCAP/XCCDF, replace the XML's hardcoded <target>
                             with the user's actual scan target.
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
            # XCCDF parser supports target_override
            if scanner.lower() == "scap_xccdf" and target_override:
                findings = parser(report_path, target_override=target_override)
            else:
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

        # Filename-based detection
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

        # Extension-based detection for new formats
        if ext == ".nessus":
            return self.ingest(report_path, "nessus", on_output)
        if ext == ".ckl":
            return self.ingest(report_path, "stig_ckl", on_output)
        if ("nessus" in name or "tenable" in name) and ext == ".xml":
            return self.ingest(report_path, "nessus", on_output)
        if ("stig" in name or "ckl" in name) and ext == ".xml":
            return self.ingest(report_path, "stig_ckl", on_output)
        if ("xccdf" in name or "scap" in name) and ext == ".xml":
            return self.ingest(report_path, "scap_xccdf", on_output)

        # Fallback: sniff file content
        try:
            with open(report_path, encoding="utf-8", errors="ignore") as fh:
                head = fh.read(1024)
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
            # New format sniffing
            if "NessusClientData" in head or "<Policy>" in head:
                return self.ingest(report_path, "nessus", on_output)
            if "<CHECKLIST>" in head or "<STIG_INFO>" in head:
                return self.ingest(report_path, "stig_ckl", on_output)
            if "<Benchmark" in head or "<TestResult" in head or "rule-result" in head:
                return self.ingest(report_path, "scap_xccdf", on_output)
        except Exception:
            pass

        if on_output:
            on_output(f"[ScanIngestor] Could not auto-detect format for {report_path}\n")
        return 0


__all__ = ["ScanIngestor"]
