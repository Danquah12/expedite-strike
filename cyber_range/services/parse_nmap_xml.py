#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import html
import os
import re

CVSS_RE = re.compile(r"\b(\d+\.\d)\b")
CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def parse_nmap_xml(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    assets = []
    services = []
    vulns = []

    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        mac = host.find("address[@addrtype='mac']")

        if addr is None:
            continue

        ip = addr.attrib["addr"]
        mac_addr = mac.attrib.get("addr") if mac is not None else None
        vendor = mac.attrib.get("vendor") if mac is not None else None

        assets.append({
            "ip": ip,
            "mac": mac_addr,
            "vendor": vendor
        })

        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            portid = int(port.attrib["portid"])
            proto = port.attrib["protocol"]

            svc = port.find("service")
            if svc is None:
                continue

            service_name = svc.attrib.get("name")
            product = svc.attrib.get("product")
            version = svc.attrib.get("version")
            cpes = [c.text for c in svc.findall("cpe")]

            services.append({
                "ip": ip,
                "port": portid,
                "protocol": proto,
                "service": service_name,
                "product": product,
                "version": version,
                "cpe": cpes[0] if cpes else None
            })

            for script in port.findall("script"):
                output = html.unescape(script.attrib.get("output", ""))

                cves = set(CVE_RE.findall(output))
                cvss_scores = CVSS_RE.findall(output)

                max_cvss = max(map(float, cvss_scores)) if cvss_scores else None
                exploitable = "*EXPLOIT*" in output or "Exploitable" in output

                for cve in cves:
                    vulns.append({
                        "ip": ip,
                        "port": portid,
                        "service": service_name,
                        "cve": cve,
                        "cvss": max_cvss,
                        "exploitable": exploitable,
                        "source": script.attrib.get("id")
                    })

    return {
        "assets": assets,
        "services": services,
        "vulnerabilities": vulns
    }
