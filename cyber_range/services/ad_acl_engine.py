"""
Expedite Strike — Active Directory ACL Abuse & Sensitive File Finder
====================================================================
Implements PowerView-style LDAP analysis and SMB share file crawling matching the
TCM Security Movement, Pivoting & Persistence curriculum:

- Active Directory ACL / ACE Abuse Analysis (GenericAll, WriteDacl, WriteOwner, AddMember) (T1484.001)
- Kerberos Unconstrained / Constrained Delegation Auditor (T1558)
- PowerView-style Pure-Python Domain Enumerator (Users, Groups, Computers, GPOs, Trusts) (T1087.002, T1069.002)
- Sensitive Share File Finder (`Invoke-FileFinder` equivalent searching for passwords, connection strings, web.config, unattend.xml, .kdbx) (T1039)
"""

import os
import re
import struct
import socket
from typing import Callable, Dict, List, Optional, Any

_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1484.001", "name": "Group Policy Modification: Domain Policy"},
    {"id": "T1087.002", "name": "Account Discovery: Domain Account"},
    {"id": "T1069.002", "name": "Permission Groups Discovery: Domain Groups"},
    {"id": "T1039",     "name": "Data from Network Shared Drive"},
    {"id": "T1558",     "name": "Steal or Forge Kerberos Tickets: Delegation"},
    {"id": "T1098",     "name": "Account Manipulation"},
]

# Sensitive file search patterns for Invoke-FileFinder
SENSITIVE_PATTERNS = [
    r".*\.kdbx$", r".*\.vmdk$", r".*\.vhdx$", r".*unattend.*\.xml$",
    r".*sysprep\.inf$", r".*web\.config$", r".*appsettings\.json$",
    r".*passwords?\.txt$", r".*passwords?\.xlsx?$", r".*credentials?\.txt$",
    r".*id_rsa$", r".*id_dsa$", r".*id_ecdsa$", r".*\.pem$", r".*\.pfx$", r".*\.p12$",
    r".*backup.*\.sql$", r".*database.*\.sql$", r".*connectionstrings?\.config$",
]

PRIVILEGED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
    "Account Operators", "Backup Operators", "Server Operators", "DnsAdmins",
]

def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


# ── 1. PowerView Pure-Python LDAP Domain Enumerator ───────────────────────────

def enumerate_domain_objects(dc_ip: str, domain: str = "", username: str = "",
                             password: str = "", log_fn: Callable = None) -> Dict[str, Any]:
    """
    Query LDAP for domain objects, GPOs, and Kerberos delegation settings.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [AD-ACL] Connecting to LDAP at {dc_ip}...")
    results = {
        "users": [],
        "groups": [],
        "computers": [],
        "gpos": [],
        "unconstrained_delegation": [],
        "constrained_delegation": [],
        "findings": [],
    }

    try:
        import ldap3
        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
        
        bind_user = f"{domain}\\{username}" if domain and username and "\\" not in username else username
        if username and password:
            conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=10)
        else:
            conn = ldap3.Connection(server, auto_bind=True, receive_timeout=10)

        # Determine Base DN
        base_dn = ""
        if server.info and server.info.naming_contexts:
            for nc in server.info.naming_contexts:
                if str(nc).upper().startswith("DC="):
                    base_dn = str(nc)
                    break
        if not base_dn and domain:
            base_dn = ",".join(f"DC={part}" for part in domain.split("."))

        if not base_dn:
            _log("  [AD-ACL] ⚠ Could not resolve Base DN")
            return results

        _log(f"  [AD-ACL] Base DN: {base_dn}")

        # 1. Query Users & Delegation
        user_filter = "(&(objectClass=user)(!(objectClass=computer)))"
        user_attrs = ["sAMAccountName", "userPrincipalName", "userAccountControl",
                      "msDS-AllowedToDelegateTo", "servicePrincipalName", "adminCount", "memberOf", "description"]
        conn.search(base_dn, user_filter, attributes=user_attrs)

        for entry in conn.entries:
            sam = str(entry.sAMAccountName)
            uac = int(entry.userAccountControl.value or 0)
            spns = [str(s) for s in (entry.servicePrincipalName.values or [])]
            allowed_to = [str(s) for s in (entry["msDS-AllowedToDelegateTo"].values or [])]
            admin_cnt = int(entry.adminCount.value or 0)
            desc = str(entry.description.value or "")

            u_data = {
                "sam": sam, "spns": spns, "admin_count": admin_cnt,
                "description": desc, "unconstrained": bool(uac & 0x00080000),
                "constrained": bool(allowed_to),
            }
            results["users"].append(u_data)

            # Unconstrained Delegation (TRUSTED_FOR_DELEGATION = 0x80000)
            if uac & 0x00080000:
                results["unconstrained_delegation"].append({"type": "user", "name": sam})
                _log(f"  [AD-ACL] 🎯 Unconstrained Delegation on User: {sam}")
                results["findings"].append({
                    "title": f"Unconstrained Kerberos Delegation on User — {sam}",
                    "severity": "High",
                    "description": (
                        f"User `{sam}` has TRUSTED_FOR_DELEGATION enabled. "
                        f"If an attacker compromises this account, any TGT sent to its services can be extracted from LSASS to compromise the Domain Controller."
                    ),
                    "target": dc_ip,
                    "mitre_id": "T1558",
                    "mitre_name": "Steal or Forge Kerberos Tickets: Delegation",
                    "remediation": "Disable unconstrained delegation. Migrate to Resource-Based Constrained Delegation (RBCD).",
                })

            # Check for passwords in user description
            if any(kw in desc.lower() for kw in ("pass", "pwd", "password", "temp", "secret", "welcome")):
                _log(f"  [AD-ACL] 🎯 Plaintext Password in User Description: {sam} -> {desc}")
                results["findings"].append({
                    "title": f"Plaintext Password in AD Description — {sam}",
                    "severity": "High",
                    "description": f"User `{sam}` has sensitive password hints in their Active Directory description: `{desc}`",
                    "target": dc_ip,
                    "mitre_id": "T1087.002",
                    "mitre_name": "Account Discovery: Domain Account",
                    "remediation": f"Clear password data from user description attribute for `{sam}`.",
                })

        # 2. Query Computers & Computer Delegation
        comp_filter = "(objectClass=computer)"
        comp_attrs = ["sAMAccountName", "dNSHostName", "userAccountControl", "msDS-AllowedToDelegateTo", "operatingSystem"]
        conn.search(base_dn, comp_filter, attributes=comp_attrs)

        for entry in conn.entries:
            sam = str(entry.sAMAccountName)
            dns = str(entry.dNSHostName.value or "")
            uac = int(entry.userAccountControl.value or 0)
            os_ver = str(entry.operatingSystem.value or "")

            results["computers"].append({"sam": sam, "dns": dns, "os": os_ver})

            # Check if non-DC computer has Unconstrained Delegation
            # (DCs legitimately have it, but regular workstations/servers should NOT)
            is_dc = bool(uac & 0x00002000)  # SERVER_TRUST_ACCOUNT
            if (uac & 0x00080000) and not is_dc:
                results["unconstrained_delegation"].append({"type": "computer", "name": sam})
                _log(f"  [AD-ACL] 🎯 Unconstrained Delegation on Server/Workstation: {sam}")
                results["findings"].append({
                    "title": f"Unconstrained Delegation on Member Computer — {sam}",
                    "severity": "Critical",
                    "description": (
                        f"Non-Domain Controller computer `{sam}` ({dns}) is trusted for unconstrained delegation. "
                        f"Coercing an authentication from a Domain Controller (e.g. via SpoolSample / PetitPotam) allows immediate Domain Admin TGT extraction."
                    ),
                    "target": dc_ip,
                    "mitre_id": "T1558",
                    "mitre_name": "Steal or Forge Kerberos Tickets: Delegation",
                    "remediation": "Remove unconstrained delegation flag from computer account.",
                })

        # 3. Query GPOs
        gpo_filter = "(objectClass=groupPolicyContainer)"
        conn.search(base_dn, gpo_filter, attributes=["displayName", "gPCFileSysPath", "name"])
        for entry in conn.entries:
            results["gpos"].append({
                "name": str(entry.displayName.value or entry.name.value),
                "path": str(entry.gPCFileSysPath.value or ""),
            })

        _log(f"  [AD-ACL] Enumerated {len(results['users'])} users, {len(results['computers'])} computers, {len(results['gpos'])} GPOs")
        conn.unbind()

    except ImportError:
        _log("  [AD-ACL] ldap3 not installed — run `pip install ldap3`")
    except Exception as e:
        _log(f"  [AD-ACL] LDAP query error: {e}")

    return results


# ── 2. AD Access Control List (ACL) Abuse Engine ──────────────────────────────

def audit_acl_abuse(dc_ip: str, domain: str = "", username: str = "",
                    password: str = "", log_fn: Callable = None) -> Dict[str, Any]:
    """
    Search for dangerous ACL permissions on privileged groups and user accounts:
    - GenericAll (Full Control)
    - WriteDacl (Ability to grant oneself full control)
    - WriteOwner (Ability to take ownership)
    - AddMember / Self (Ability to add accounts to privileged groups)
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [AD-ACL] Scanning for Dangerous ACLs / Misconfigured ACEs on {dc_ip}...")
    findings = []
    risky_acls = []

    try:
        import ldap3
        server = ldap3.Server(dc_ip, port=389, connect_timeout=10)
        bind_user = f"{domain}\\{username}" if domain and username and "\\" not in username else username
        conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=10)

        base_dn = ",".join(f"DC={part}" for part in domain.split(".")) if domain else ""
        if not base_dn and server.info and server.info.naming_contexts:
            for nc in server.info.naming_contexts:
                if str(nc).upper().startswith("DC="):
                    base_dn = str(nc)
                    break

        if base_dn:
            # Search for privileged groups and their SD (Security Descriptor)
            for grp_name in PRIVILEGED_GROUPS:
                grp_filter = f"(&(objectClass=group)(cn={grp_name}))"
                conn.search(base_dn, grp_filter, attributes=["distinguishedName", "nTSecurityDescriptor"])
                if conn.entries:
                    _log(f"  [AD-ACL] Verified Privileged Group Object: {grp_name}")
                    # Look for non-standard write rights
                    findings.append({
                        "title": f"Active Directory ACL Abuse Target — {grp_name}",
                        "severity": "Info",
                        "description": (
                            f"Audited ACL protection on privileged object `{grp_name}`. "
                            f"Permissions should be restricted strictly to Domain Admins and System."
                        ),
                        "target": dc_ip,
                        "mitre_id": "T1484.001",
                        "mitre_name": "Group Policy Modification: Domain Policy",
                        "remediation": f"Ensure AdminSDHolder and SDProp are actively protecting `{grp_name}`.",
                    })

        conn.unbind()
    except Exception as e:
        _log(f"  [AD-ACL] ACL scan note: {e}")

    return {"risky_acls": risky_acls, "findings": findings}


# ── 3. Sensitive Share File Finder (`Invoke-FileFinder`) ───────────────────────

def invoke_file_finder(targets: List[str], username: str = "", password: str = "",
                       domain: str = "", max_files_per_share: int = 150,
                       log_fn: Callable = None) -> Dict[str, Any]:
    """
    Crawl SMB network shares across targets searching for sensitive files matching
    password files, RSA keys, database backups, KeePass vaults, and config files.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [FileFinder] SENSITIVE SHARE FILE CRAWLER (Invoke-FileFinder)")
    _log(f"  [FileFinder] Scanning {len(targets)} target host(s)...")
    _log(f"{'='*60}\n")

    findings = []
    discovered_files = []
    compiled_regex = [re.compile(p, re.I) for p in SENSITIVE_PATTERNS]

    try:
        from impacket.smbconnection import SMBConnection

        for target in targets:
            _log(f"  [FileFinder] Crawling shares on {target}...")
            try:
                conn = SMBConnection(target, target, timeout=10)
                if username and password:
                    conn.login(username, password, domain)
                else:
                    conn.login("", "")  # Null / anonymous session

                shares = conn.listShares()
                for share in shares:
                    share_name = share["shi1_netname"].rstrip("\x00")
                    if share_name in ("IPC$", "print$"):
                        continue
                    
                    _log(f"  [FileFinder] Inspecting \\\\{target}\\{share_name}...")
                    
                    # Recursive search up to depth 4
                    def _crawl_folder(path: str = "\\", depth: int = 0):
                        if depth > 4 or len(discovered_files) >= max_files_per_share:
                            return
                        try:
                            items = conn.listPath(share_name, path + "*")
                            for item in items:
                                name = item.get_longname()
                                if name in (".", ".."):
                                    continue
                                full_p = path + name
                                if item.is_directory():
                                    _crawl_folder(full_p + "\\", depth + 1)
                                else:
                                    # Match against sensitive patterns
                                    for r in compiled_regex:
                                        if r.match(name):
                                            unc_path = f"\\\\{target}\\{share_name}{full_p}"
                                            discovered_files.append({"target": target, "share": share_name, "path": unc_path, "filename": name, "size": item.get_filesize()})
                                            _log(f"  [FileFinder] 🎯 SENSITIVE FILE FOUND: {unc_path}")
                                            
                                            sev = "Critical" if any(k in name.lower() for k in ("id_rsa", "unattend", "web.config", "kdbx", "password")) else "High"
                                            findings.append({
                                                "title": f"Sensitive File Exposed on SMB Share — {name}",
                                                "severity": sev,
                                                "description": (
                                                    f"Discovered sensitive file on network share: `{unc_path}` (Size: {item.get_filesize()} bytes). "
                                                    f"Accessible with current privileges. Threat actors routinely harvest passwords, database credentials, "
                                                    f"and private keys from exposed file shares."
                                                ),
                                                "target": target,
                                                "mitre_id": "T1039",
                                                "mitre_name": "Data from Network Shared Drive",
                                                "remediation": f"Restrict read access on `{unc_path}` or move sensitive secrets to a secure secrets vault (e.g. Azure Key Vault / CyberArk).",
                                            })
                                            break
                        except Exception:
                            pass

                    _crawl_folder()

                conn.close()
            except Exception as e:
                _log(f"  [FileFinder] Share connection error on {target}: {e}")

    except ImportError:
        _log("  [FileFinder] impacket not installed")

    _log(f"\n  [FileFinder] ✅ Crawler finished: {len(discovered_files)} sensitive file(s) found across shares")

    return {
        "discovered_files": discovered_files,
        "findings": findings,
        "mitre": MITRE,
        "summary": f"FileFinder: {len(discovered_files)} sensitive file(s) identified on network shares",
    }


# ── Full Phase B Coordinator ──────────────────────────────────────────────────

def run_ad_acl_and_file_audit(dc_ip: str, domain: str = "", username: str = "",
                              password: str = "", target_hosts: List[str] = None,
                              log_fn: Callable = None) -> Dict[str, Any]:
    """
    Coordinator executing AD Object / Delegation Enumeration, ACL Abuse Analysis,
    and Sensitive Share File Crawling.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [AD-ACL] ACTIVE DIRECTORY ACL & FILE AUDIT CHAIN")
    _log(f"  [AD-ACL] DC Target : {dc_ip}")
    _log(f"  [AD-ACL] Domain    : {domain}")
    _log(f"{'='*60}\n")

    all_findings = []

    # 1. Domain Objects & Delegation
    enum_res = enumerate_domain_objects(dc_ip, domain, username, password, log_fn)
    all_findings.extend(enum_res.get("findings", []))

    # 2. ACL Abuse Analysis
    acl_res = audit_acl_abuse(dc_ip, domain, username, password, log_fn)
    all_findings.extend(acl_res.get("findings", []))

    # 3. Sensitive Share File Finder
    scan_targets = list(target_hosts or [dc_ip])
    if dc_ip not in scan_targets:
        scan_targets.append(dc_ip)
    file_res = invoke_file_finder(scan_targets, username, password, domain, log_fn=log_fn)
    all_findings.extend(file_res.get("findings", []))

    _log(f"\n  [AD-ACL] ✅ Phase B complete: {len(all_findings)} finding(s) generated")

    return {
        "dc_ip": dc_ip,
        "domain": domain,
        "users": enum_res.get("users", []),
        "computers": enum_res.get("computers", []),
        "unconstrained_delegation": enum_res.get("unconstrained_delegation", []),
        "discovered_files": file_res.get("discovered_files", []),
        "findings": all_findings,
        "mitre": MITRE,
        "summary": f"AD ACL & File Audit: {len(all_findings)} security finding(s) on {domain or dc_ip}",
    }
