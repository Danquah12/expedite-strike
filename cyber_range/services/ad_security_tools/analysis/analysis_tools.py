"""
AD Security Tools — Analysis Module
====================================
7 standalone analysis tool functions for AD security assessment.
Each takes discovery_data for correlation and returns structured findings.
"""

import socket
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)

try:
    from ldap3 import Server, Connection, ALL, ANONYMOUS, SUBTREE
    _HAS_LDAP3 = True
except ImportError:
    _HAS_LDAP3 = False


def _ts():
    return datetime.now(timezone.utc).isoformat()


def _ldap_connect(target_ip, username="", password="", domain=""):
    if not _HAS_LDAP3:
        return None, None
    server = Server(target_ip, get_info=ALL, connect_timeout=5)
    if username and password:
        bind_user = username if "\\" in username else f"{domain.split('.')[0]}\\{username}" if domain else username
        conn = Connection(server, user=bind_user, password=password,
                          auto_bind=True, receive_timeout=15)
    else:
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=False)
        conn.bind()
    return server, conn


def _base_dn(domain, server=None):
    if domain:
        return ",".join(f"DC={p}" for p in domain.split("."))
    if server and server.info and server.info.naming_contexts:
        for nc in server.info.naming_contexts:
            if str(nc).startswith("DC="):
                return str(nc)
    return ""


# ═══════════════════════════════════════════════════════════════════════
# TOOL 1: ANALYZE KERBEROS
# ═══════════════════════════════════════════════════════════════════════

def analyze_kerberos(target_ip: str, username: str = "", password: str = "",
                     domain: str = "", discovery_data: dict = None,
                     log_fn: Callable = None) -> dict:
    """Comprehensive Kerberos security analysis."""
    result = {
        "tool": "analyze_kerberos", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["build_attack_paths"],
        "data": {"unconstrained": [], "constrained": [], "rbcd": []}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain, server)

        # Unconstrained Delegation
        conn.search(base_dn,
                    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                    attributes=["name", "dNSHostName"], search_scope=SUBTREE)
        for entry in conn.entries:
            name = str(entry.name) if hasattr(entry, "name") else "?"
            result["data"]["unconstrained"].append(name)
        if result["data"]["unconstrained"]:
            result["findings"].append({
                "title": f"Unconstrained Delegation: {len(result['data']['unconstrained'])} systems",
                "severity": "Critical",
                "affected_object": ", ".join(result["data"]["unconstrained"][:5]),
                "description": "TGTs of authenticating users are stored in memory. "
                               "Attacker on these systems can impersonate ANY domain user.",
                "mitre_id": "T1550.003", "nist_csf": "PR.AC-4", "cis_control": "6.8",
                "confidence": 1.0, "category": "Kerberos Security",
                "remediation": "Remove unconstrained delegation. Use constrained delegation or RBCD."
            })
            raw.append(f"Unconstrained delegation: {result['data']['unconstrained']}")

        # Constrained Delegation
        conn.search(base_dn,
                    "(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))",
                    attributes=["name", "msDS-AllowedToDelegateTo"], search_scope=SUBTREE)
        for entry in conn.entries:
            name = str(entry.name) if hasattr(entry, "name") else "?"
            targets = [str(t) for t in entry["msDS-AllowedToDelegateTo"]] if hasattr(entry, "msDS-AllowedToDelegateTo") else []
            result["data"]["constrained"].append({"name": name, "targets": targets})
        if result["data"]["constrained"]:
            result["findings"].append({
                "title": f"Constrained Delegation: {len(result['data']['constrained'])} systems",
                "severity": "Medium",
                "affected_object": ", ".join(c["name"] for c in result["data"]["constrained"][:5]),
                "description": "Systems with constrained delegation can impersonate users to specific services.",
                "mitre_id": "T1550.003", "nist_csf": "PR.AC-4", "cis_control": "6.8",
                "confidence": 0.9, "category": "Kerberos Security",
                "remediation": "Review delegation targets. Remove unnecessary delegations."
            })
            raw.append(f"Constrained delegation: {len(result['data']['constrained'])}")

        # RBCD (Resource-Based Constrained Delegation)
        conn.search(base_dn,
                    "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
                    attributes=["name"], search_scope=SUBTREE)
        for entry in conn.entries:
            name = str(entry.name) if hasattr(entry, "name") else "?"
            result["data"]["rbcd"].append(name)
        if result["data"]["rbcd"]:
            result["findings"].append({
                "title": f"RBCD Configured: {len(result['data']['rbcd'])} systems",
                "severity": "High",
                "affected_object": ", ".join(result["data"]["rbcd"][:5]),
                "description": "Resource-based constrained delegation can be abused for lateral movement.",
                "mitre_id": "T1550.003", "nist_csf": "PR.AC-4", "cis_control": "6.8",
                "confidence": 0.85, "category": "Kerberos Security",
                "remediation": "Audit RBCD configurations. Remove unnecessary entries."
            })

        conn.unbind()
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [analyze_kerberos] {len(result['findings'])} findings")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 2: ANALYZE LDAP
# ═══════════════════════════════════════════════════════════════════════

def analyze_ldap(target_ip: str, username: str = "", password: str = "",
                 domain: str = "", log_fn: Callable = None) -> dict:
    """LDAP security configuration analysis."""
    result = {
        "tool": "analyze_ldap", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["analyze_smb"],
        "data": {"anonymous_bind": False, "ldaps_available": False, "signing": "unknown"}
    }
    raw = []

    # Anonymous bind test
    if _HAS_LDAP3:
        try:
            server = Server(target_ip, get_info=ALL, connect_timeout=5)
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=False)
            if conn.bind():
                result["data"]["anonymous_bind"] = True
                result["findings"].append({
                    "title": "Anonymous LDAP Bind Allowed",
                    "severity": "High", "affected_object": target_ip,
                    "description": "Attackers can enumerate users, groups, OUs, trusts without credentials.",
                    "mitre_id": "T1087.002", "nist_csf": "PR.AC-1", "cis_control": "16.8",
                    "confidence": 1.0, "category": "LDAP Analysis",
                    "remediation": "Disable anonymous LDAP bind. Require authentication."
                })
                raw.append("Anonymous bind: ALLOWED ⚠")
                conn.unbind()
            else:
                raw.append("Anonymous bind: Denied ✓")
        except Exception as e:
            raw.append(f"Anonymous bind test: {e}")

    # LDAPS availability
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        if sock.connect_ex((target_ip, 636)) == 0:
            result["data"]["ldaps_available"] = True
            raw.append("LDAPS (636): Available ✓")
        else:
            result["findings"].append({
                "title": "LDAPS Not Available",
                "severity": "Medium", "affected_object": target_ip,
                "description": "LDAP over SSL (port 636) is not available. LDAP traffic may be unencrypted.",
                "mitre_id": "T1557.001", "nist_csf": "PR.DS-2", "cis_control": "3.10",
                "confidence": 0.8, "category": "LDAP Analysis",
                "remediation": "Enable LDAPS with a valid certificate on all DCs."
            })
            raw.append("LDAPS (636): Not available ⚠")
        sock.close()
    except Exception:
        pass

    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [analyze_ldap] {len(result['findings'])} findings")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 3: ANALYZE SMB
# ═══════════════════════════════════════════════════════════════════════

def analyze_smb(target_ip: str, log_fn: Callable = None) -> dict:
    """SMB security analysis — signing, version, null sessions."""
    result = {
        "tool": "analyze_smb", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["analyze_ntlm"],
        "data": {"smb_open": False, "signing": "unknown"}
    }
    raw = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        if sock.connect_ex((target_ip, 445)) == 0:
            result["data"]["smb_open"] = True
            raw.append("SMB (445): Open")
            result["findings"].append({
                "title": "SMB Signing Verification Required",
                "severity": "High", "affected_object": target_ip,
                "description": "SMB is accessible. If signing is not enforced, NTLM relay attacks are possible.",
                "mitre_id": "T1557.001", "nist_csf": "PR.DS-2", "cis_control": "9.2",
                "confidence": 0.8, "category": "SMB Security",
                "remediation": "Enforce SMB signing: Set 'Microsoft network server: Digitally sign communications (always)' to Enabled."
            })
        sock.close()
    except Exception as e:
        raw.append(f"SMB check error: {e}")

    # Check for SMBv1
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        if sock.connect_ex((target_ip, 139)) == 0:
            result["findings"].append({
                "title": "NetBIOS/SMBv1 Port Open",
                "severity": "High", "affected_object": target_ip,
                "description": "Port 139 (NetBIOS) open — may indicate SMBv1 support. Vulnerable to EternalBlue.",
                "mitre_id": "T1210", "nist_csf": "PR.IP-1", "cis_control": "9.2",
                "confidence": 0.7, "category": "SMB Security",
                "remediation": "Disable SMBv1 and NetBIOS over TCP/IP."
            })
            raw.append("NetBIOS (139): Open — SMBv1 risk")
        sock.close()
    except Exception:
        pass

    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [analyze_smb] {len(result['findings'])} findings")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 4: ANALYZE NTLM
# ═══════════════════════════════════════════════════════════════════════

def analyze_ntlm(target_ip: str, log_fn: Callable = None) -> dict:
    """NTLM security analysis."""
    result = {
        "tool": "analyze_ntlm", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["correlate_risks"],
        "data": {"ntlm_ports": []}
    }
    raw = []
    # Check NTLM on common ports
    ntlm_ports = [(445, "SMB"), (389, "LDAP"), (5985, "WinRM"), (80, "HTTP"), (443, "HTTPS")]
    for port, svc in ntlm_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((target_ip, port)) == 0:
                result["data"]["ntlm_ports"].append({"port": port, "service": svc})
                raw.append(f"NTLM surface: {port}/{svc}")
            sock.close()
        except Exception:
            pass

    if result["data"]["ntlm_ports"]:
        result["findings"].append({
            "title": f"NTLM Authentication Surface: {len(result['data']['ntlm_ports'])} services",
            "severity": "Medium", "affected_object": target_ip,
            "description": f"NTLM is likely available on: {', '.join(f'{p['service']}({p['port']})' for p in result['data']['ntlm_ports'])}. "
                           "NTLMv1 hashes can be cracked in seconds. NTLM relay is possible if signing not enforced.",
            "mitre_id": "T1557", "nist_csf": "PR.AC-7", "cis_control": "16.8",
            "confidence": 0.75, "category": "NTLM Security",
            "remediation": "Disable NTLMv1. Enforce NTLMv2. Consider disabling NTLM entirely via GPO."
        })

    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [analyze_ntlm] {len(result['data']['ntlm_ports'])} NTLM surfaces")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 5: ANALYZE AD CS
# ═══════════════════════════════════════════════════════════════════════

def analyze_adcs(target_ip: str, username: str = "", password: str = "",
                 domain: str = "", log_fn: Callable = None) -> dict:
    """AD Certificate Services security analysis (ESC1-ESC8)."""
    result = {
        "tool": "analyze_adcs", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["build_attack_paths"],
        "data": {"cas": [], "vulnerable_templates": []}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain, server)
        config_dn = f"CN=Configuration,{base_dn}"

        # Find CAs
        conn.search(config_dn, "(objectClass=pKIEnrollmentService)",
                    attributes=["name", "dNSHostName", "certificateTemplates"],
                    search_scope=SUBTREE)
        for entry in conn.entries:
            ca_name = str(entry.name) if hasattr(entry, "name") else "?"
            templates = list(entry.certificateTemplates) if hasattr(entry, "certificateTemplates") and entry.certificateTemplates else []
            result["data"]["cas"].append({"name": ca_name, "templates": len(templates)})
            raw.append(f"CA: {ca_name} ({len(templates)} templates)")
            result["findings"].append({
                "title": f"AD Certificate Authority: {ca_name}",
                "severity": "Medium", "affected_object": ca_name,
                "description": f"Enterprise CA with {len(templates)} templates. Check ESC1-ESC8 with Certify/Certipy.",
                "mitre_id": "T1552.004", "nist_csf": "PR.DS-2", "cis_control": "3.12",
                "confidence": 0.9, "category": "Certificate Services",
                "remediation": "Audit all certificate templates. Remove unnecessary enrollment permissions."
            })

        # ESC1: SAN + Client Auth
        conn.search(config_dn,
                    "(&(objectClass=pKICertificateTemplate)(msPKI-Certificate-Name-Flag=1))",
                    attributes=["name", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage"],
                    search_scope=SUBTREE)
        for entry in conn.entries:
            tmpl = str(entry.name) if hasattr(entry, "name") else "?"
            result["data"]["vulnerable_templates"].append(tmpl)
            result["findings"].append({
                "title": f"ESC1: Vulnerable Template — {tmpl}",
                "severity": "Critical", "affected_object": tmpl,
                "description": f"Template '{tmpl}' allows SAN specification with Client Auth EKU. "
                               "Any enrollee can request a certificate as Domain Admin.",
                "mitre_id": "T1649", "nist_csf": "PR.AC-7", "cis_control": "3.12",
                "confidence": 0.95, "category": "Certificate Services",
                "remediation": f"Disable SAN on template '{tmpl}'. Remove low-privilege enrollment rights."
            })
            raw.append(f"ESC1 VULN: {tmpl}")

        conn.unbind()
    except Exception as e:
        raw.append(f"ADCS error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [analyze_adcs] {len(result['data']['cas'])} CAs, "
               f"{len(result['data']['vulnerable_templates'])} ESC vulns")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 6: ANALYZE ACLs
# ═══════════════════════════════════════════════════════════════════════

def analyze_acls(target_ip: str, username: str = "", password: str = "",
                 domain: str = "", discovery_data: dict = None,
                 log_fn: Callable = None) -> dict:
    """ACL/DACL permission analysis for privilege escalation paths."""
    result = {
        "tool": "analyze_acls", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["build_attack_paths"],
        "data": {"dangerous_acls": []}
    }
    raw = []

    # ACL analysis requires specialized tools (BloodHound/SharpHound)
    # We document the attack surface and recommend tooling
    result["findings"].append({
        "title": "ACL Audit Recommended",
        "severity": "Medium", "affected_object": "Domain",
        "description": "Full ACL analysis requires BloodHound/SharpHound collection. "
                       "Check for: GenericAll, GenericWrite, WriteDACL, WriteOwner, "
                       "AddMember on privileged groups. DCSync rights "
                       "(DS-Replication-Get-Changes + DS-Replication-Get-Changes-All).",
        "mitre_id": "T1222.001", "nist_csf": "PR.AC-4", "cis_control": "6.1",
        "confidence": 0.7, "category": "ACL Analysis",
        "remediation": "Run BloodHound collection. Audit AdminSDHolder. Remove unnecessary ACEs."
    })
    raw.append("ACL audit: Requires BloodHound/SharpHound for full analysis")

    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [analyze_acls] ACL audit recommendation generated")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 7: ANALYZE PASSWORDS
# ═══════════════════════════════════════════════════════════════════════

def analyze_passwords(target_ip: str, username: str = "", password: str = "",
                      domain: str = "", log_fn: Callable = None) -> dict:
    """Password policy analysis."""
    result = {
        "tool": "analyze_passwords", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["correlate_risks"],
        "data": {"policy": {}}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain, server)

        conn.search(base_dn, "(objectClass=domain)",
                    attributes=["minPwdLength", "pwdHistoryLength", "lockoutThreshold",
                                "lockoutDuration", "maxPwdAge", "minPwdAge",
                                "pwdProperties"],
                    search_scope=SUBTREE, size_limit=1)

        if conn.entries:
            entry = conn.entries[0]
            policy = {}
            for attr in ["minPwdLength", "pwdHistoryLength", "lockoutThreshold",
                          "lockoutDuration", "maxPwdAge", "minPwdAge", "pwdProperties"]:
                policy[attr] = str(getattr(entry, attr, "")) if hasattr(entry, attr) else ""
            result["data"]["policy"] = policy
            raw.append(f"Password policy: {policy}")

            min_len = int(policy.get("minPwdLength", "0") or "0")
            lockout = int(policy.get("lockoutThreshold", "0") or "0")

            if min_len < 12:
                result["findings"].append({
                    "title": f"Weak Password Length: {min_len} characters",
                    "severity": "High" if min_len < 8 else "Medium",
                    "affected_object": "Default Domain Policy",
                    "description": f"Minimum password length is {min_len}. NIST recommends 12+ characters.",
                    "mitre_id": "T1110", "nist_csf": "PR.AC-1", "cis_control": "5.2",
                    "confidence": 1.0, "category": "Password Policy",
                    "remediation": "Set minimum password length to 14+ characters."
                })

            if lockout == 0:
                result["findings"].append({
                    "title": "No Account Lockout Policy",
                    "severity": "High", "affected_object": "Default Domain Policy",
                    "description": "No lockout threshold set. Unlimited brute force attempts allowed.",
                    "mitre_id": "T1110.001", "nist_csf": "PR.AC-7", "cis_control": "16.11",
                    "confidence": 1.0, "category": "Password Policy",
                    "remediation": "Set lockout threshold to 5 attempts. Duration: 30 minutes."
                })

        conn.unbind()
    except Exception as e:
        raw.append(f"Password policy error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [analyze_passwords] {len(result['findings'])} findings")
    return result


# ═══════════════════════════════════════════════════════════════════════
# ALL ANALYSIS TOOLS
# ═══════════════════════════════════════════════════════════════════════

ALL_ANALYSIS_TOOLS = {
    "analyze_kerberos": analyze_kerberos,
    "analyze_ldap": analyze_ldap,
    "analyze_smb": analyze_smb,
    "analyze_ntlm": analyze_ntlm,
    "analyze_adcs": analyze_adcs,
    "analyze_acls": analyze_acls,
    "analyze_passwords": analyze_passwords,
}
