"""
AD Security Tools — Discovery Module
=====================================
8 standalone discovery tool functions for AD enumeration.
Each returns structured results with evidence tracking.
"""

import socket
import logging
from datetime import datetime, timezone
from typing import Optional, Callable

logger = logging.getLogger(__name__)

try:
    from ldap3 import Server, Connection, ALL, ANONYMOUS, SUBTREE
    _HAS_LDAP3 = True
except ImportError:
    _HAS_LDAP3 = False


def _ts():
    return datetime.now(timezone.utc).isoformat()


def _base_dn(domain: str) -> str:
    if not domain:
        return ""
    return ",".join(f"DC={p}" for p in domain.split("."))


def _ldap_connect(target_ip, username="", password="", domain=""):
    """Open LDAP connection — authenticated or anonymous."""
    if not _HAS_LDAP3:
        return None, None, "ldap3 not installed"
    server = Server(target_ip, get_info=ALL, connect_timeout=5)
    if username and password:
        bind_user = username if "\\" in username else f"{domain.split('.')[0]}\\{username}" if domain else username
        conn = Connection(server, user=bind_user, password=password,
                          auto_bind=True, receive_timeout=15)
    else:
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=False)
        if not conn.bind():
            conn = Connection(server, auto_bind=True, receive_timeout=15)
    return server, conn, None


# ═══════════════════════════════════════════════════════════════════════
# TOOL 1: DISCOVER DOMAIN
# ═══════════════════════════════════════════════════════════════════════

def discover_domain(target_ip: str, username: str = "", password: str = "",
                    domain: str = "", log_fn: Callable = None) -> dict:
    """Discover domain information via LDAP RootDSE and port scanning."""
    result = {
        "tool": "discover_domain", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["enumerate_users", "enumerate_dcs"],
        "data": {"domain_name": "", "forest": "", "functional_level": "",
                 "dns_name": "", "schema": "", "dc_ports": [], "is_dc": False}
    }
    raw = []

    # Port scan for DC identification
    dc_ports = {53: "DNS", 88: "Kerberos", 135: "RPC", 139: "NetBIOS",
                389: "LDAP", 445: "SMB", 464: "kpasswd", 636: "LDAPS",
                3268: "GC", 3269: "GC-SSL", 5985: "WinRM", 9389: "ADWS"}
    open_ports = []
    for port, svc in dc_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            if sock.connect_ex((target_ip, port)) == 0:
                open_ports.append(port)
                raw.append(f"{port}/tcp OPEN ({svc})")
            sock.close()
        except Exception:
            pass

    result["data"]["dc_ports"] = open_ports
    result["data"]["is_dc"] = {88, 389}.issubset(set(open_ports))

    if result["data"]["is_dc"]:
        result["findings"].append({
            "title": f"Domain Controller Identified: {target_ip}",
            "severity": "Medium", "affected_object": target_ip,
            "description": f"Kerberos (88) + LDAP (389) open. DC ports: {open_ports}",
            "mitre_id": "T1018", "nist_csf": "ID.AM-2", "cis_control": "1.1",
            "confidence": 0.95, "category": "Reconnaissance",
            "remediation": "Ensure DC is properly segmented and hardened."
        })

    # LDAP RootDSE
    if _HAS_LDAP3 and (389 in open_ports or 636 in open_ports):
        try:
            server, conn, err = _ldap_connect(target_ip, username, password, domain)
            if server and server.info:
                info = server.info
                ncs = [str(nc) for nc in (info.naming_contexts or [])]
                dn = ncs[0] if ncs else ""
                other = getattr(info, "other", {}) or {}
                result["data"]["domain_name"] = dn
                result["data"]["forest"] = (other.get("rootDomainNamingContext", [""])[0]
                                            if isinstance(other.get("rootDomainNamingContext"), list) else "")
                fl = other.get("domainFunctionality", [""])[0] if isinstance(other.get("domainFunctionality"), list) else ""
                fl_map = {"0": "2000", "1": "2003i", "2": "2003", "3": "2008",
                          "4": "2008R2", "5": "2012", "6": "2012R2", "7": "2016"}
                result["data"]["functional_level"] = fl_map.get(str(fl), str(fl))
                result["data"]["dns_name"] = (other.get("dnsHostName", [""])[0]
                                              if isinstance(other.get("dnsHostName"), list) else "")
                raw.append(f"Domain: {dn}")
                raw.append(f"Forest: {result['data']['forest']}")
                raw.append(f"Functional Level: {result['data']['functional_level']}")

                if str(fl) in ("0", "1", "2", "3"):
                    result["findings"].append({
                        "title": f"Outdated Functional Level: {fl_map.get(str(fl), fl)}",
                        "severity": "High", "affected_object": dn,
                        "description": "Lacks modern security features (Protected Users, Auth Policies, Credential Guard).",
                        "mitre_id": "T1484.001", "nist_csf": "PR.IP-1", "cis_control": "4.1",
                        "confidence": 1.0, "category": "Configuration",
                        "remediation": "Raise domain functional level to 2016 or higher."
                    })
            if conn:
                conn.unbind()
        except Exception as e:
            raw.append(f"LDAP error: {e}")

    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [discover_domain] {target_ip}: {len(result['findings'])} findings, "
               f"{len(open_ports)} ports open")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 2: ENUMERATE USERS
# ═══════════════════════════════════════════════════════════════════════

def enumerate_users(target_ip: str, username: str = "", password: str = "",
                    domain: str = "", log_fn: Callable = None) -> dict:
    """Enumerate and analyze AD user accounts."""
    result = {
        "tool": "enumerate_users", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["analyze_kerberos", "enumerate_spns"],
        "data": {"users": [], "total": 0, "admins": 0, "stale": 0,
                 "no_preauth": 0, "pwd_never_expires": 0, "pwd_in_desc": 0}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn, err = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain) or (
            [str(nc) for nc in (server.info.naming_contexts or []) if str(nc).startswith("DC=")][0]
            if server.info and server.info.naming_contexts else ""
        )
        if not base_dn:
            result["status"] = "error"
            return result

        conn.search(base_dn, "(objectClass=user)",
                    attributes=["sAMAccountName", "userAccountControl", "memberOf",
                                "servicePrincipalName", "pwdLastSet", "lastLogon",
                                "description", "adminCount"],
                    search_scope=SUBTREE, size_limit=2000)

        users = []
        for entry in conn.entries:
            uname = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
            uac = int(str(entry.userAccountControl)) if hasattr(entry, "userAccountControl") and str(entry.userAccountControl).isdigit() else 0
            desc = str(entry.description) if hasattr(entry, "description") else ""
            admin = str(entry.adminCount) == "1" if hasattr(entry, "adminCount") else False
            spns = [str(s) for s in entry.servicePrincipalName] if hasattr(entry, "servicePrincipalName") and entry.servicePrincipalName else []

            user = {"username": uname, "uac": uac, "admin": admin,
                    "description": desc, "spns": spns,
                    "no_preauth": bool(uac & 0x400000),
                    "pwd_never_expires": bool(uac & 0x10000),
                    "disabled": bool(uac & 0x2)}
            users.append(user)

            if not user["disabled"] and any(kw in desc.lower() for kw in ["password", "pwd", "pass:", "p@ss"]):
                result["data"]["pwd_in_desc"] += 1
                result["findings"].append({
                    "title": f"Password in Description: {uname}",
                    "severity": "Critical", "affected_object": uname,
                    "description": f"User description contains credential info: '{desc[:80]}'",
                    "mitre_id": "T1552.001", "nist_csf": "PR.AC-1", "cis_control": "5.2",
                    "confidence": 0.95, "category": "User Security",
                    "remediation": "Remove password information from AD description field."
                })
            if user["no_preauth"]:
                result["data"]["no_preauth"] += 1
            if user["pwd_never_expires"] and not user["disabled"]:
                result["data"]["pwd_never_expires"] += 1
            if admin:
                result["data"]["admins"] += 1

        result["data"]["users"] = users
        result["data"]["total"] = len(users)
        raw.append(f"Total users: {len(users)}")
        raw.append(f"Admins: {result['data']['admins']}")
        raw.append(f"AS-REP Roastable: {result['data']['no_preauth']}")
        raw.append(f"Pwd never expires: {result['data']['pwd_never_expires']}")

        if result["data"]["no_preauth"] > 0:
            asrep_users = [u["username"] for u in users if u["no_preauth"]]
            result["findings"].append({
                "title": f"AS-REP Roastable: {result['data']['no_preauth']} accounts",
                "severity": "High", "affected_object": ", ".join(asrep_users[:10]),
                "description": f"{result['data']['no_preauth']} accounts don't require Kerberos pre-auth. "
                               f"TGTs can be requested and cracked offline.",
                "mitre_id": "T1558.004", "nist_csf": "PR.AC-7", "cis_control": "16.2",
                "confidence": 1.0, "category": "Kerberos Security",
                "remediation": "Enable Kerberos pre-authentication for all accounts."
            })

        if result["data"]["admins"] > 5:
            result["findings"].append({
                "title": f"Admin Sprawl: {result['data']['admins']} admin accounts",
                "severity": "Medium", "affected_object": "Domain",
                "description": f"{result['data']['admins']} accounts with adminCount=1. Excessive privilege.",
                "mitre_id": "T1078.002", "nist_csf": "PR.AC-4", "cis_control": "6.1",
                "confidence": 0.9, "category": "User Security",
                "remediation": "Reduce admin accounts. Use tiered admin model."
            })

        if result["data"]["pwd_never_expires"] > 10:
            result["findings"].append({
                "title": f"Password Never Expires: {result['data']['pwd_never_expires']} accounts",
                "severity": "Medium", "affected_object": "Domain",
                "description": "Stale credentials increase brute force and credential stuffing risk.",
                "mitre_id": "T1110", "nist_csf": "PR.AC-1", "cis_control": "5.2",
                "confidence": 0.85, "category": "User Security",
                "remediation": "Enforce password rotation. Deploy managed service accounts (gMSA)."
            })

        conn.unbind()
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"

    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [enumerate_users] {result['data']['total']} users, "
               f"{len(result['findings'])} findings")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 3: ENUMERATE GROUPS
# ═══════════════════════════════════════════════════════════════════════

def enumerate_groups(target_ip: str, username: str = "", password: str = "",
                     domain: str = "", log_fn: Callable = None) -> dict:
    """Enumerate AD groups and identify privileged group membership."""
    result = {
        "tool": "enumerate_groups", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["analyze_acls"],
        "data": {"groups": [], "privileged_groups": []}
    }
    PRIV_GROUPS = {"Domain Admins", "Enterprise Admins", "Schema Admins",
                   "Backup Operators", "Account Operators", "Server Operators",
                   "Print Operators", "Administrators"}
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn, _ = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain) or (
            [str(nc) for nc in (server.info.naming_contexts or []) if str(nc).startswith("DC=")][0]
            if server.info and server.info.naming_contexts else ""
        )
        conn.search(base_dn, "(objectClass=group)",
                    attributes=["sAMAccountName", "member", "description"],
                    search_scope=SUBTREE, size_limit=1000)
        for entry in conn.entries:
            name = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
            members = len(entry.member) if hasattr(entry, "member") and entry.member else 0
            g = {"name": name, "members": members}
            result["data"]["groups"].append(g)
            if name in PRIV_GROUPS:
                result["data"]["privileged_groups"].append(g)
                raw.append(f"PRIVILEGED: {name} ({members} members)")
                if members > 10:
                    result["findings"].append({
                        "title": f"Excessive Members in {name}: {members}",
                        "severity": "High", "affected_object": name,
                        "description": f"Privileged group '{name}' has {members} members. "
                                       "Principle of least privilege violated.",
                        "mitre_id": "T1069.002", "nist_csf": "PR.AC-4", "cis_control": "6.1",
                        "confidence": 0.9, "category": "User Security",
                        "remediation": f"Reduce membership of '{name}' to essential accounts only."
                    })
        conn.unbind()
        raw.insert(0, f"Total groups: {len(result['data']['groups'])}")
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [enumerate_groups] {len(result['data']['groups'])} groups, "
               f"{len(result['data']['privileged_groups'])} privileged")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 4: ENUMERATE COMPUTERS
# ═══════════════════════════════════════════════════════════════════════

def enumerate_computers(target_ip: str, username: str = "", password: str = "",
                        domain: str = "", log_fn: Callable = None) -> dict:
    """Enumerate AD computer objects and identify outdated OS."""
    result = {
        "tool": "enumerate_computers", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["enumerate_dcs"],
        "data": {"computers": [], "outdated_os": []}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn, _ = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain) or (
            [str(nc) for nc in (server.info.naming_contexts or []) if str(nc).startswith("DC=")][0]
            if server.info and server.info.naming_contexts else ""
        )
        conn.search(base_dn, "(objectClass=computer)",
                    attributes=["sAMAccountName", "operatingSystem", "dNSHostName",
                                "operatingSystemVersion"],
                    search_scope=SUBTREE, size_limit=1000)
        outdated_os = ["2003", "2008", "Windows XP", "Windows 7", "Windows Vista"]
        for entry in conn.entries:
            name = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
            os_str = str(entry.operatingSystem) if hasattr(entry, "operatingSystem") else ""
            comp = {"name": name, "os": os_str}
            result["data"]["computers"].append(comp)
            if any(old in os_str for old in outdated_os):
                result["data"]["outdated_os"].append(comp)
        conn.unbind()
        raw.append(f"Total computers: {len(result['data']['computers'])}")
        if result["data"]["outdated_os"]:
            result["findings"].append({
                "title": f"Outdated OS: {len(result['data']['outdated_os'])} systems",
                "severity": "High", "affected_object": ", ".join(c["name"] for c in result["data"]["outdated_os"][:5]),
                "description": f"Systems running unsupported OS detected. No security patches available.",
                "mitre_id": "T1210", "nist_csf": "ID.AM-2", "cis_control": "2.2",
                "confidence": 0.95, "category": "Configuration",
                "remediation": "Decommission or upgrade systems to supported OS versions."
            })
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [enumerate_computers] {len(result['data']['computers'])} computers")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 5: ENUMERATE DOMAIN CONTROLLERS
# ═══════════════════════════════════════════════════════════════════════

def enumerate_dcs(target_ip: str, username: str = "", password: str = "",
                  domain: str = "", log_fn: Callable = None) -> dict:
    """Identify all domain controllers."""
    result = {
        "tool": "enumerate_dcs", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["analyze_smb", "analyze_ldap"],
        "data": {"dcs": []}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn, _ = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain) or (
            [str(nc) for nc in (server.info.naming_contexts or []) if str(nc).startswith("DC=")][0]
            if server.info and server.info.naming_contexts else ""
        )
        # DCs have SERVER_TRUST_ACCOUNT (0x2000) in UAC
        conn.search(base_dn,
                    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    attributes=["sAMAccountName", "dNSHostName", "operatingSystem"],
                    search_scope=SUBTREE)
        for entry in conn.entries:
            name = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
            dns = str(entry.dNSHostName) if hasattr(entry, "dNSHostName") else ""
            os_str = str(entry.operatingSystem) if hasattr(entry, "operatingSystem") else ""
            dc = {"name": name, "dns": dns, "os": os_str}
            result["data"]["dcs"].append(dc)
            raw.append(f"DC: {name} ({dns}) — {os_str}")
        conn.unbind()
        if len(result["data"]["dcs"]) == 1:
            result["findings"].append({
                "title": "Single Domain Controller — No Redundancy",
                "severity": "Medium", "affected_object": result["data"]["dcs"][0]["name"],
                "description": "Only one DC found. No fault tolerance for authentication services.",
                "mitre_id": "T1018", "nist_csf": "PR.PT-5", "cis_control": "11.1",
                "confidence": 0.9, "category": "Configuration",
                "remediation": "Deploy additional domain controllers for redundancy."
            })
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [enumerate_dcs] {len(result['data']['dcs'])} domain controller(s)")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 6: ENUMERATE GPOs
# ═══════════════════════════════════════════════════════════════════════

def enumerate_gpos(target_ip: str, username: str = "", password: str = "",
                   domain: str = "", log_fn: Callable = None) -> dict:
    """Enumerate Group Policy Objects."""
    result = {
        "tool": "enumerate_gpos", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["analyze_passwords"],
        "data": {"gpos": []}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn, _ = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain) or (
            [str(nc) for nc in (server.info.naming_contexts or []) if str(nc).startswith("DC=")][0]
            if server.info and server.info.naming_contexts else ""
        )
        conn.search(base_dn, "(objectClass=groupPolicyContainer)",
                    attributes=["displayName", "gPCFileSysPath", "flags"],
                    search_scope=SUBTREE, size_limit=500)
        for entry in conn.entries:
            name = str(entry.displayName) if hasattr(entry, "displayName") else ""
            path = str(entry.gPCFileSysPath) if hasattr(entry, "gPCFileSysPath") else ""
            result["data"]["gpos"].append({"name": name, "path": path})
            raw.append(f"GPO: {name}")
        conn.unbind()
        raw.insert(0, f"Total GPOs: {len(result['data']['gpos'])}")
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [enumerate_gpos] {len(result['data']['gpos'])} GPOs")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 7: ENUMERATE TRUSTS
# ═══════════════════════════════════════════════════════════════════════

def enumerate_trusts(target_ip: str, username: str = "", password: str = "",
                     domain: str = "", log_fn: Callable = None) -> dict:
    """Enumerate AD trust relationships."""
    result = {
        "tool": "enumerate_trusts", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["build_attack_paths"],
        "data": {"trusts": []}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn, _ = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain) or (
            [str(nc) for nc in (server.info.naming_contexts or []) if str(nc).startswith("DC=")][0]
            if server.info and server.info.naming_contexts else ""
        )
        conn.search(base_dn, "(objectClass=trustedDomain)",
                    attributes=["name", "trustDirection", "trustType", "trustAttributes", "flatName"],
                    search_scope=SUBTREE)
        dir_map = {"1": "Inbound", "2": "Outbound", "3": "Bidirectional"}
        for entry in conn.entries:
            name = str(entry.name) if hasattr(entry, "name") else ""
            direction = dir_map.get(str(entry.trustDirection) if hasattr(entry, "trustDirection") else "", "?")
            trust = {"name": name, "direction": direction}
            result["data"]["trusts"].append(trust)
            raw.append(f"Trust: {name} ({direction})")
            # External/forest trusts are higher risk
            result["findings"].append({
                "title": f"Trust: {name} ({direction})",
                "severity": "Medium", "affected_object": name,
                "description": f"Trust relationship with {name}. Direction: {direction}. "
                               "Can be exploited for SID History injection, cross-forest golden ticket.",
                "mitre_id": "T1482", "nist_csf": "ID.AM-3", "cis_control": "12.1",
                "confidence": 0.85, "category": "Trust Analysis",
                "remediation": "Review trust necessity. Enable SID filtering on external trusts."
            })
        conn.unbind()
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [enumerate_trusts] {len(result['data']['trusts'])} trust(s)")
    return result


# ═══════════════════════════════════════════════════════════════════════
# TOOL 8: ENUMERATE SPNs
# ═══════════════════════════════════════════════════════════════════════

def enumerate_spns(target_ip: str, username: str = "", password: str = "",
                   domain: str = "", log_fn: Callable = None) -> dict:
    """Enumerate Service Principal Names and identify Kerberoastable accounts."""
    result = {
        "tool": "enumerate_spns", "target": target_ip, "status": "success",
        "evidence_ids": [], "findings": [], "raw_output": "",
        "timestamp": _ts(), "next_recommended": ["analyze_kerberos"],
        "data": {"spns": [], "privileged_spns": []}
    }
    if not _HAS_LDAP3:
        result["status"] = "skipped"
        return result
    raw = []
    try:
        server, conn, _ = _ldap_connect(target_ip, username, password, domain)
        if not conn:
            result["status"] = "error"
            return result
        base_dn = _base_dn(domain) or (
            [str(nc) for nc in (server.info.naming_contexts or []) if str(nc).startswith("DC=")][0]
            if server.info and server.info.naming_contexts else ""
        )
        conn.search(base_dn, "(&(objectClass=user)(servicePrincipalName=*))",
                    attributes=["sAMAccountName", "servicePrincipalName", "adminCount"],
                    search_scope=SUBTREE, size_limit=500)
        for entry in conn.entries:
            name = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
            spn_list = [str(s) for s in entry.servicePrincipalName] if hasattr(entry, "servicePrincipalName") else []
            admin = str(entry.adminCount) == "1" if hasattr(entry, "adminCount") else False
            spn = {"user": name, "spns": spn_list, "admin": admin}
            result["data"]["spns"].append(spn)
            raw.append(f"{'⚠ PRIV ' if admin else ''}{name}: {', '.join(spn_list[:3])}")
            if admin:
                result["data"]["privileged_spns"].append(spn)
                result["findings"].append({
                    "title": f"Privileged Kerberoastable: {name}",
                    "severity": "Critical", "affected_object": name,
                    "description": f"Privileged account '{name}' has SPN ({spn_list[0]}). "
                                   "TGS can be cracked offline for domain compromise.",
                    "mitre_id": "T1558.003", "nist_csf": "PR.AC-7", "cis_control": "16.2",
                    "confidence": 1.0, "category": "Kerberos Security",
                    "remediation": f"Remove SPN from {name} or convert to gMSA. Enforce AES-only."
                })

        if result["data"]["spns"] and not result["data"]["privileged_spns"]:
            result["findings"].append({
                "title": f"Kerberoastable Accounts: {len(result['data']['spns'])}",
                "severity": "High", "affected_object": ", ".join(s["user"] for s in result["data"]["spns"][:10]),
                "description": f"{len(result['data']['spns'])} accounts with SPNs. TGS tickets can be cracked.",
                "mitre_id": "T1558.003", "nist_csf": "PR.AC-7", "cis_control": "16.2",
                "confidence": 0.95, "category": "Kerberos Security",
                "remediation": "Use gMSA for service accounts. Enforce long, complex passwords."
            })
        conn.unbind()
    except Exception as e:
        raw.append(f"Error: {e}")
        result["status"] = "error"
    result["raw_output"] = "\n".join(raw)
    if log_fn:
        log_fn(f"    [enumerate_spns] {len(result['data']['spns'])} SPNs, "
               f"{len(result['data']['privileged_spns'])} privileged")
    return result


# ═══════════════════════════════════════════════════════════════════════
# ALL DISCOVERY TOOLS
# ═══════════════════════════════════════════════════════════════════════

ALL_DISCOVERY_TOOLS = {
    "discover_domain": discover_domain,
    "enumerate_users": enumerate_users,
    "enumerate_groups": enumerate_groups,
    "enumerate_computers": enumerate_computers,
    "enumerate_dcs": enumerate_dcs,
    "enumerate_gpos": enumerate_gpos,
    "enumerate_trusts": enumerate_trusts,
    "enumerate_spns": enumerate_spns,
}
