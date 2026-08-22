"""
NVD / EPSS / CISA-KEV Local Enrichment Knowledge Base
======================================================
Provides offline vulnerability intelligence for pentest report generation.
No external API calls required — all data is embedded.
"""

# ═══════════════════════════════════════════════════════════════════
#  CVE DATABASE — NVD + EPSS + CISA KEV
# ═══════════════════════════════════════════════════════════════════
CVE_DB = {
    "CVE-2011-2523": {
        "description": "vsftpd 2.3.4 downloaded between 2011-06-30 and 2011-07-03 contains a backdoor that opens a shell on port 6200/tcp.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.974, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    "CVE-2004-2687": {
        "description": "DistCC 2.x allows remote code execution via crafted compilation requests when no access control is configured.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.971, "epss_percentile": 99, "cisa_kev": False,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2004-2687"],
    },
    "CVE-2017-0144": {
        "description": "Windows SMB Remote Code Execution (EternalBlue). Allows remote attackers to execute arbitrary code via crafted SMBv1 packets.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.975, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
    "CVE-2016-5195": {
        "description": "Race condition in mm/gup.c (DirtyCow) allows local privilege escalation via a crafted application exploiting COW breakage.",
        "cvss_score": 7.8, "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.976, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 1.8, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-5195"],
    },
    "CVE-2019-0708": {
        "description": "Remote Desktop Services RCE (BlueKeep). Unauthenticated attacker can execute arbitrary code on target via RDP.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.975, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    },
    "CVE-2014-6271": {
        "description": "GNU Bash (Shellshock) allows remote code execution via trailing strings after function definitions in environment variable values.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.976, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
    },
    "CVE-2021-44228": {
        "description": "Apache Log4j2 JNDI RCE (Log4Shell). Remote attacker can execute arbitrary code via crafted log message.",
        "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.976, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 6.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    "CVE-2014-3566": {
        "description": "SSL 3.0 POODLE attack allows MitM to obtain cleartext data via a padding-oracle attack.",
        "cvss_score": 3.4, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "epss_score": 0.968, "epss_percentile": 98, "cisa_kev": False,
        "exploitability_score": 1.6, "impact_score": 1.4,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-3566"],
    },
    "CVE-2007-2447": {
        "description": "Samba 3.0.0-3.0.25rc3 allows remote command execution via shell metacharacters in the username parameter (usermap_script).",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.972, "epss_percentile": 99, "cisa_kev": False,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2007-2447"],
    },
    "CVE-2010-2075": {
        "description": "UnrealIRCd 3.2.8.1 contains an externally introduced backdoor that allows remote attackers to execute arbitrary commands.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.973, "epss_percentile": 99, "cisa_kev": False,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2010-2075"],
    },
    "CVE-2012-2122": {
        "description": "MySQL 5.1.x/5.5.x/5.6.x authentication bypass — casting bug allows login with any password on ~1/256 attempts.",
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss_score": 0.973, "epss_percentile": 99, "cisa_kev": False,
        "exploitability_score": 3.9, "impact_score": 3.6,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2012-2122"],
    },
    "CVE-2012-1823": {
        "description": "PHP before 5.3.12/5.4.2 allows remote code execution when configured as a CGI script via query string parameters.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.975, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2012-1823"],
    },
    "CVE-2015-1635": {
        "description": "HTTP.sys in Windows allows remote code execution via crafted HTTP request (MS15-034).",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.975, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-1635"],
    },
    "CVE-2008-1447": {
        "description": "ISC BIND insufficient randomness of DNS transaction IDs allows DNS cache poisoning (Kaminsky attack).",
        "cvss_score": 6.8, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",
        "epss_score": 0.950, "epss_percentile": 97, "cisa_kev": False,
        "exploitability_score": 2.2, "impact_score": 4.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2008-1447"],
    },
    "CVE-2009-3103": {
        "description": "SMB2 NEGOTIATE PROTOCOL REQUEST handling flaw allows remote DoS/RCE (srv2.sys).",
        "cvss_score": 9.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.968, "epss_percentile": 98, "cisa_kev": False,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2009-3103"],
    },
    "CVE-2010-1428": {
        "description": "JBoss Application Server allows unauthenticated access to JMX Console, enabling remote code execution.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.968, "epss_percentile": 98, "cisa_kev": False,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2010-1428"],
    },
    "CVE-2015-3306": {
        "description": "ProFTPD 1.3.5 mod_copy allows remote command execution via unauthenticated SITE CPFR/CPTO commands.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.974, "epss_percentile": 99, "cisa_kev": False,
        "exploitability_score": 3.9, "impact_score": 5.9,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
    },
    "CVE-2017-5638": {
        "description": "Apache Struts 2 RCE via Content-Type header. Jakarta Multipart parser allows remote command execution.",
        "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.975, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 6.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
    },
    "CVE-2020-1472": {
        "description": "Zerologon — Netlogon Elevation of Privilege. Allows unauthenticated domain admin compromise.",
        "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.976, "epss_percentile": 99, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 6.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-1472"],
    },
    "CVE-2023-44487": {
        "description": "HTTP/2 Rapid Reset Attack (DoS) affecting multiple web servers and proxy products.",
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "epss_score": 0.820, "epss_percentile": 95, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 3.6,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
    },
    "CVE-2024-3094": {
        "description": "XZ Utils backdoor (liblzma) — supply chain compromise allowing remote code execution via SSH.",
        "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.600, "epss_percentile": 88, "cisa_kev": True,
        "exploitability_score": 3.9, "impact_score": 6.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
    },
}

# ═══════════════════════════════════════════════════════════════════
#  COMPLIANCE MAPPING
# ═══════════════════════════════════════════════════════════════════
COMPLIANCE_MAP = {
    "default_creds": {"pci_dss": "2.1, 8.2", "nist_800_53": "IA-5, AC-7", "iso_27001": "A.9.4.3", "cis_controls": "CIS 4.7, 5.2"},
    "missing_patch":  {"pci_dss": "6.2",      "nist_800_53": "SI-2, RA-5", "iso_27001": "A.12.6.1", "cis_controls": "CIS 7.1, 7.4"},
    "weak_encryption":{"pci_dss": "4.1, 2.3", "nist_800_53": "SC-13, SC-8","iso_27001": "A.10.1.1", "cis_controls": "CIS 16.8"},
    "backdoor":       {"pci_dss": "6.2, 11.5","nist_800_53": "SI-3, SI-7", "iso_27001": "A.12.2.1", "cis_controls": "CIS 2.7, 10.1"},
    "sqli":           {"pci_dss": "6.5.1",    "nist_800_53": "SI-10, SA-11","iso_27001": "A.14.2.5", "cis_controls": "CIS 16.4"},
    "xss":            {"pci_dss": "6.5.7",    "nist_800_53": "SI-10",      "iso_27001": "A.14.2.5", "cis_controls": "CIS 16.4"},
    "anonymous_access":{"pci_dss": "7.1, 8.1","nist_800_53": "AC-3, AC-14","iso_27001": "A.9.1.2",  "cis_controls": "CIS 6.1, 6.2"},
    "null_session":   {"pci_dss": "8.1",      "nist_800_53": "AC-3, AC-17","iso_27001": "A.9.1.2",  "cis_controls": "CIS 6.1"},
    "no_auth":        {"pci_dss": "7.1, 8.2", "nist_800_53": "AC-3, IA-2", "iso_27001": "A.9.4.2",  "cis_controls": "CIS 6.2, 5.1"},
    "insecure_protocol":{"pci_dss":"2.3, 4.1","nist_800_53": "SC-8, SC-23","iso_27001": "A.13.1.1", "cis_controls": "CIS 3.10"},
    "rce":            {"pci_dss": "6.2, 6.5", "nist_800_53": "SI-2, SI-3", "iso_27001": "A.12.6.1", "cis_controls": "CIS 7.1, 18.3"},
    "privesc":        {"pci_dss": "7.1, 7.2", "nist_800_53": "AC-6, CM-7", "iso_27001": "A.9.2.3",  "cis_controls": "CIS 5.4, 6.1"},
    "info_disclosure":{"pci_dss": "6.5.6",    "nist_800_53": "AC-4, SI-11","iso_27001": "A.18.1.4", "cis_controls": "CIS 3.1, 13.6"},
    "misconfig":      {"pci_dss": "2.2",      "nist_800_53": "CM-6, CM-7", "iso_27001": "A.12.1.1", "cis_controls": "CIS 4.1, 4.8"},
}

# ═══════════════════════════════════════════════════════════════════
#  ROOT CAUSE CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════
ROOT_CAUSE_MAP = {
    "default_creds":    "Configuration Error",
    "misconfig":        "Configuration Error",
    "no_auth":          "Configuration Error",
    "null_session":     "Configuration Error",
    "anonymous_access": "Configuration Error",
    "missing_patch":    "Missing Patch",
    "rce":              "Missing Patch",
    "weak_encryption":  "Missing Patch",
    "backdoor":         "Design Flaw",
    "insecure_protocol":"Design Flaw",
    "sqli":             "Design Flaw",
    "xss":              "Design Flaw",
    "privesc":          "Policy Gap",
    "info_disclosure":  "Architecture Weakness",
}

_ROOT_KEYWORDS = {
    "Configuration Error": ["default", "misconfigur", "no auth", "null session", "anonymous", "guest", "open access", "unrestricted"],
    "Missing Patch":       ["cve-", "patch", "update", "outdated", "eol", "unpatched", "vulnerable version", "exploit"],
    "Design Flaw":         ["backdoor", "injection", "xss", "deserialization", "insecure", "cleartext", "hardcoded"],
    "Policy Gap":          ["weak password", "brute", "no lockout", "privilege", "suid", "sudo", "world-readable"],
    "Architecture Weakness": ["flat network", "no segmentation", "exposed", "external", "internet-facing", "information disclosure"],
}

# ═══════════════════════════════════════════════════════════════════
#  ASSET CLASSIFICATION BY PORT
# ═══════════════════════════════════════════════════════════════════
ASSET_CLASSIFICATION = {
    3306: {"asset_type": "Database Server",     "criticality": "CROWN_JEWEL", "data_class": "PII / Financial"},
    5432: {"asset_type": "Database Server",     "criticality": "CROWN_JEWEL", "data_class": "PII / Financial"},
    1433: {"asset_type": "Database Server",     "criticality": "CROWN_JEWEL", "data_class": "PII / Financial"},
    1521: {"asset_type": "Database Server",     "criticality": "CROWN_JEWEL", "data_class": "PII / Financial"},
    6379: {"asset_type": "Cache/DB Server",     "criticality": "HIGH",        "data_class": "Credentials / Session"},
    27017:{"asset_type": "NoSQL Database",      "criticality": "CROWN_JEWEL", "data_class": "PII / Financial"},
    88:   {"asset_type": "Domain Controller",   "criticality": "CROWN_JEWEL", "data_class": "Credentials / AD"},
    389:  {"asset_type": "Domain Controller",   "criticality": "CROWN_JEWEL", "data_class": "Credentials / AD"},
    636:  {"asset_type": "Domain Controller",   "criticality": "CROWN_JEWEL", "data_class": "Credentials / AD"},
    80:   {"asset_type": "Web Server",          "criticality": "HIGH",        "data_class": "Internal / App Data"},
    443:  {"asset_type": "Web Server",          "criticality": "HIGH",        "data_class": "Internal / App Data"},
    8080: {"asset_type": "Web App Server",      "criticality": "HIGH",        "data_class": "Internal / App Data"},
    8443: {"asset_type": "Web App Server",      "criticality": "HIGH",        "data_class": "Internal / App Data"},
    21:   {"asset_type": "File Server (FTP)",   "criticality": "MEDIUM",      "data_class": "Internal Files"},
    22:   {"asset_type": "SSH Server",          "criticality": "HIGH",        "data_class": "Credentials / Config"},
    445:  {"asset_type": "File Server (SMB)",   "criticality": "HIGH",        "data_class": "Internal / Credentials"},
    139:  {"asset_type": "File Server (SMB)",   "criticality": "MEDIUM",      "data_class": "Internal Files"},
    25:   {"asset_type": "Mail Server",         "criticality": "HIGH",        "data_class": "PII / Communications"},
    110:  {"asset_type": "Mail Server",         "criticality": "HIGH",        "data_class": "PII / Communications"},
    143:  {"asset_type": "Mail Server",         "criticality": "HIGH",        "data_class": "PII / Communications"},
    53:   {"asset_type": "DNS Server",          "criticality": "HIGH",        "data_class": "Infrastructure"},
    3389: {"asset_type": "Terminal Server",     "criticality": "HIGH",        "data_class": "Credentials / Desktop"},
    5900: {"asset_type": "VNC Remote Desktop",  "criticality": "MEDIUM",      "data_class": "Desktop Access"},
    23:   {"asset_type": "Network Device",      "criticality": "MEDIUM",      "data_class": "Config / Network"},
    161:  {"asset_type": "Network Device",      "criticality": "MEDIUM",      "data_class": "Config / Monitoring"},
    1099: {"asset_type": "Java App Server",     "criticality": "HIGH",        "data_class": "Internal / App Data"},
    8180: {"asset_type": "Java App Server",     "criticality": "HIGH",        "data_class": "Internal / App Data"},
    2049: {"asset_type": "NFS File Server",     "criticality": "HIGH",        "data_class": "Internal Files"},
    3632: {"asset_type": "Build Server",        "criticality": "MEDIUM",      "data_class": "Source Code"},
    6667: {"asset_type": "IRC Server",          "criticality": "LOW",         "data_class": "Communications"},
    8787: {"asset_type": "App Server (Ruby)",   "criticality": "MEDIUM",      "data_class": "Internal / App Data"},
}

# ═══════════════════════════════════════════════════════════════════
#  SLA POLICY
# ═══════════════════════════════════════════════════════════════════
SLA_POLICY = {
    "Critical": {"days": 0,  "label": "IMMEDIATE",  "owner": "Infrastructure / Security Team"},
    "High":     {"days": 7,  "label": "1–7 Days",   "owner": "Infrastructure / Server Team"},
    "Medium":   {"days": 30, "label": "8–30 Days",   "owner": "IT Operations"},
    "Low":      {"days": 90, "label": "31–90 Days",  "owner": "IT Operations / Dev Team"},
    "Info":     {"days": 180,"label": "Next Cycle",   "owner": "Risk & Compliance"},
}

# ═══════════════════════════════════════════════════════════════════
#  ENRICHMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def enrich_finding(f: dict) -> dict:
    """Enrich a finding with NVD/EPSS/CISA data. Returns new dict."""
    out = dict(f)
    cve = (f.get("cve", "") or "").upper().strip()
    if not cve:
        # Try to extract CVE from title/description/evidence
        import re
        for field in ("title", "description", "evidence"):
            m = re.search(r"(CVE-\d{4}-\d{4,7})", str(f.get(field, "")), re.IGNORECASE)
            if m:
                cve = m.group(1).upper()
                break
    if cve and cve in CVE_DB:
        db = CVE_DB[cve]
        out["cve"] = cve
        out["nvd_description"] = db["description"]
        out["cvss_score"] = db["cvss_score"]
        out["cvss_vector"] = db["cvss_vector"]
        out["epss_score"] = db["epss_score"]
        out["epss_percentile"] = db["epss_percentile"]
        out["cisa_kev"] = db["cisa_kev"]
        out["exploitability_score"] = db["exploitability_score"]
        out["impact_score"] = db["impact_score"]
    else:
        # Estimate from severity
        sv = f.get("severity", "Medium")
        est = {"Critical": (0.85, 95), "High": (0.55, 80), "Medium": (0.25, 55), "Low": (0.08, 25), "Info": (0.01, 5)}
        ep, pct = est.get(sv, (0.25, 55))
        out.setdefault("epss_score", ep)
        out.setdefault("epss_percentile", pct)
        out.setdefault("cisa_kev", False)
        out.setdefault("exploitability_score", {"Critical": 3.9, "High": 3.1, "Medium": 2.2, "Low": 1.2, "Info": 0.5}.get(sv, 2.2))
        out.setdefault("impact_score", {"Critical": 5.9, "High": 4.7, "Medium": 3.4, "Low": 1.8, "Info": 0.5}.get(sv, 3.4))
    return out


def get_compliance(f: dict) -> dict:
    """Return compliance mapping for a finding."""
    t = ((f.get("title", "") or "") + " " + (f.get("description", "") or "")).lower()
    for key, mapping in COMPLIANCE_MAP.items():
        kw = key.replace("_", " ")
        if kw in t:
            return mapping
    # Keyword-based fallback
    if any(k in t for k in ["default", "weak password", "brute"]): return COMPLIANCE_MAP["default_creds"]
    if any(k in t for k in ["cve-", "patch", "outdated"]):         return COMPLIANCE_MAP["missing_patch"]
    if any(k in t for k in ["backdoor", "trojan"]):                return COMPLIANCE_MAP["backdoor"]
    if any(k in t for k in ["sqli", "sql injection"]):             return COMPLIANCE_MAP["sqli"]
    if any(k in t for k in ["xss", "cross-site"]):                 return COMPLIANCE_MAP["xss"]
    if any(k in t for k in ["anonym", "guest"]):                   return COMPLIANCE_MAP["anonymous_access"]
    if any(k in t for k in ["null session", "unauthenticated"]):   return COMPLIANCE_MAP["null_session"]
    if any(k in t for k in ["no auth", "without auth"]):           return COMPLIANCE_MAP["no_auth"]
    if any(k in t for k in ["rce", "remote code", "command exec"]): return COMPLIANCE_MAP["rce"]
    if any(k in t for k in ["privilege", "escalat", "suid"]):      return COMPLIANCE_MAP["privesc"]
    if any(k in t for k in ["disclosure", "exposed", "listing"]):  return COMPLIANCE_MAP["info_disclosure"]
    return COMPLIANCE_MAP["misconfig"]


def get_root_cause(f: dict) -> str:
    """Return root cause category for a finding."""
    t = ((f.get("title", "") or "") + " " + (f.get("description", "") or "")).lower()
    for category, keywords in _ROOT_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            return category
    return "Configuration Error"


def get_asset_class(ports: list) -> dict:
    """Return highest-criticality asset classification from port list."""
    crit_order = {"CROWN_JEWEL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best = {"asset_type": "General Server", "criticality": "MEDIUM", "data_class": "Internal"}
    best_score = 0
    for p in (ports or []):
        if p in ASSET_CLASSIFICATION:
            ac = ASSET_CLASSIFICATION[p]
            score = crit_order.get(ac["criticality"], 0)
            if score > best_score:
                best = ac
                best_score = score
    return best


def get_sla(severity: str) -> dict:
    """Return SLA info for severity."""
    return SLA_POLICY.get(severity, SLA_POLICY["Medium"])


def get_confidence_score(f: dict) -> tuple:
    """Return (score 0-100, explanation)."""
    score = 40  # baseline
    reasons = []
    ev = (f.get("evidence", "") or "").lower()
    cls = (f.get("cls", "") or f.get("status", "")).upper()
    if cls == "CONFIRMED":
        score += 40; reasons.append("Exploitation confirmed with proof")
    elif cls == "VALIDATED":
        score += 25; reasons.append("Vulnerability validated")
    if "uid=0" in ev or "root@" in ev or "root shell" in ev:
        score += 15; reasons.append("Root/admin access verified")
    if f.get("cve"):
        score += 5; reasons.append("CVE identifier matched")
    if f.get("cisa_kev"):
        score += 5; reasons.append("CISA KEV listed")
    if "step 1" in ev.lower() and "step 2" in ev.lower():
        score += 5; reasons.append("Multi-step evidence chain")
    score = min(score, 99)
    return (score, "; ".join(reasons) if reasons else "Baseline assessment")


def get_false_positive_likelihood(f: dict) -> tuple:
    """Return (level, explanation)."""
    conf, _ = get_confidence_score(f)
    if conf >= 85: return ("< 1%", "Exploitation verified with direct proof")
    if conf >= 70: return ("< 5%", "Vulnerability validated with strong indicators")
    if conf >= 50: return ("5–15%", "Vulnerability detected by automated scanner, not manually verified")
    if conf >= 30: return ("15–30%", "Potential vulnerability based on version/banner detection")
    return ("30–50%", "Low confidence — information-only finding, manual review recommended")


def get_validation_steps(f: dict) -> list:
    """Return remediation validation commands."""
    t = ((f.get("title", "") or "")).lower()
    d = ((f.get("description", "") or "")).lower()
    td = t + " " + d
    host = f.get("host", "<target>")

    if "vsftpd" in td or ("ftp" in td and "backdoor" in td):
        return [f"1. Verify vsFTPd upgraded: nmap -sV -p 21 {host}  →  expect version ≥ 3.0",
                f"2. Confirm port 6200 closed: nc -zv {host} 6200  →  expect 'refused'",
                f"3. Verify FTP service config: grep -i 'anon' /etc/vsftpd.conf"]
    if "ssh" in t and ("brute" in t or "login" in t or "default" in td):
        return [f"1. Verify password changed: ssh <old_user>@{host}  →  expect 'Permission denied'",
                f"2. Check lockout policy: grep -i 'maxretry' /etc/pam.d/sshd",
                f"3. Verify key-only auth: grep 'PasswordAuthentication' /etc/ssh/sshd_config  →  expect 'no'"]
    if "smb" in td and "null" in td:
        return [f"1. Verify null session blocked: smbclient -L //{host} -N  →  expect 'ACCESS_DENIED'",
                f"2. Check registry: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RestrictAnonymous  →  expect 1 or 2",
                f"3. Verify SMB signing: nmap --script smb2-security-mode -p 445 {host}  →  expect 'required'"]
    if "eternalblue" in td or "ms17-010" in td:
        return [f"1. Verify patch: nmap --script smb-vuln-ms17-010 -p 445 {host}  →  expect 'NOT VULNERABLE'",
                f"2. Verify SMBv1 disabled: Get-SmbServerConfiguration | Select EnableSMB1Protocol  →  expect False",
                f"3. Verify port filtered: nmap -p 445 {host}  →  expect 'filtered' from external"]
    if "tomcat" in td:
        return [f"1. Verify creds changed: curl -u tomcat:tomcat http://{host}:8180/manager/html  →  expect 401",
                f"2. Verify Manager restricted: grep 'allow=' conf/tomcat-users.xml  →  expect localhost only",
                f"3. Verify default apps removed: curl http://{host}:8180/examples/  →  expect 404"]
    if "postgres" in td:
        return [f"1. Verify creds changed: psql -h {host} -U postgres -c 'SELECT 1'  →  expect auth failure",
                f"2. Check pg_hba.conf: grep -v '#' pg_hba.conf  →  expect no 'trust' entries",
                f"3. Verify network binding: ss -tlnp | grep 5432  →  expect 127.0.0.1 only"]
    if "mysql" in td:
        return [f"1. Verify creds changed: mysql -h {host} -u root -p''  →  expect 'Access denied'",
                f"2. Check remote access: SELECT user,host FROM mysql.user  →  expect no '%' hosts",
                f"3. Verify network binding: grep 'bind-address' /etc/mysql/my.cnf  →  expect 127.0.0.1"]
    if "distcc" in td:
        return [f"1. Verify service removed: nmap -p 3632 {host}  →  expect 'closed'",
                f"2. Verify access control: grep 'allow' /etc/distcc/hosts.allow"]
    if "suid" in td:
        return [f"1. Verify SUID removed: find / -perm -4000 2>/dev/null  →  compare against baseline",
                f"2. Verify unnecessary SUID cleared: chmod u-s /path/to/binary"]
    if "nfs" in td:
        return [f"1. Verify exports restricted: showmount -e {host}  →  expect specific IPs, not '*'",
                f"2. Verify NFSv4: mount -t nfs4 {host}:/ /mnt  →  expect Kerberos required"]
    # Generic
    return [f"1. Re-scan target: nmap -sV --script vuln -p- {host}",
            f"2. Verify service patched/hardened per remediation steps",
            f"3. Confirm finding no longer reproducible"]


def get_business_impact(f: dict, asset_class: dict = None) -> dict:
    """Return business impact assessment."""
    sv = f.get("severity", "Medium")
    crit = (asset_class or {}).get("criticality", "MEDIUM")
    data = (asset_class or {}).get("data_class", "Internal")

    # Impact level matrix: severity × criticality
    matrix = {
        ("Critical", "CROWN_JEWEL"): "CATASTROPHIC",
        ("Critical", "HIGH"): "CATASTROPHIC",
        ("Critical", "MEDIUM"): "MAJOR",
        ("High", "CROWN_JEWEL"): "MAJOR",
        ("High", "HIGH"): "MAJOR",
        ("High", "MEDIUM"): "MODERATE",
        ("Medium", "CROWN_JEWEL"): "MODERATE",
        ("Medium", "HIGH"): "MODERATE",
        ("Medium", "MEDIUM"): "MINOR",
    }
    level = matrix.get((sv, crit), "MINOR" if sv in ("Low", "Info") else "MODERATE")

    # Impact categories
    cats = []
    t = ((f.get("title", "") or "") + " " + (f.get("description", "") or "")).lower()
    if any(k in t for k in ["database", "sql", "postgres", "mysql", "data"]):  cats.append("Financial")
    if any(k in t for k in ["credential", "password", "login", "auth"]):       cats.append("Operational")
    if any(k in t for k in ["backdoor", "root", "admin", "rce", "shell"]):     cats.append("Operational")
    if any(k in t for k in ["web", "owasp", "xss", "sqli"]):                  cats.append("Reputational")
    if any(k in t for k in ["pii", "phi", "gdpr", "compliance"]):             cats.append("Legal/Regulatory")
    if not cats: cats = ["Operational"]

    return {"level": level, "categories": cats, "data_at_risk": data}
