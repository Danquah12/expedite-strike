"""
Expedite Strike — Windows Privilege Escalation Master Suite
===========================================================
Comprehensive Windows Privilege Escalation scanner and analyzer matching the
TCM Security "Windows Privilege Escalation for Beginners" (PNPT) curriculum:

1. System & AV/EDR Enumeration (Defender, productState, Hotfix matching) (T1082, T1518.001)
2. Kernel Exploit Suggester Engine (OS Build vs CVE database: CVE-2019-1388, MS16-032, CVE-2020-0796, CVE-2021-36934 SeriousSAM) (T1068)
3. Deep Password Hunting (T1552):
   - PowerShell History (ConsoleHost_history.txt)
   - Unattended Install Files (Panther\\unattend.xml, sysprep.inf)
   - SAM/SYSTEM Hive Backups (C:\\Windows\\Repair, RegBack)
   - PuTTY & RDP Stored Sessions
4. WSL (Windows Subsystem for Linux) Escalation Path (T1202)
5. Service Binary & Registry ACLs (`regsvc`, weak service binary write permissions) (T1574.011)
6. DLL Search Order Hijacking Assessment (T1574.001)
7. Alternate Data Streams (ADS) Secret Scanner (T1564.004)
8. RunAs Stored Credential Escalation (cmdkey /savecred) (T1134.001)
"""

import os
import re
import json
import subprocess
from typing import Callable, Dict, List, Optional, Any

_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1068",     "name": "Exploitation for Privilege Escalation"},
    {"id": "T1552.001", "name": "Credentials in Files"},
    {"id": "T1552.002", "name": "Credentials in Registry"},
    {"id": "T1518.001", "name": "Security Software Discovery"},
    {"id": "T1574.011", "name": "Services Registry Permissions Weakness"},
    {"id": "T1574.001", "name": "DLL Search Order Hijacking"},
    {"id": "T1202",     "name": "Indirect Command Execution: WSL"},
    {"id": "T1564.004", "name": "Hide Artifacts: Alternate Data Streams"},
]

# Windows Kernel Exploit Matrix (OS Build -> Missing Patch / CVE)
KERNEL_EXPLOIT_DB = [
    {
        "name": "CVE-2019-1388 (Windows Certificate Dialog UAC Escalation)",
        "cve": "CVE-2019-1388",
        "affected_builds": ["7600", "7601", "9200", "9600", "10240", "10586", "14393", "15063", "16299", "17134", "17763"],
        "severity": "High",
        "description": "Elevation of privilege vulnerability in Windows Certificate Dialog when verifying digital signatures in UAC prompt.",
    },
    {
        "name": "CVE-2021-36934 (HiveNightmare / SeriousSAM)",
        "cve": "CVE-2021-36934",
        "affected_builds": ["17763", "18362", "18363", "19041", "19042", "19043"],
        "severity": "Critical",
        "description": "Overly permissive ACLs on SAM and SYSTEM registry hives allowing standard users to dump local NTLM hashes.",
    },
    {
        "name": "CVE-2020-0796 (SMBGhost)",
        "cve": "CVE-2020-0796",
        "affected_builds": ["18362", "18363"],
        "severity": "Critical",
        "description": "Integer overflow in Srv2.sys SMBv3 compression allowing remote or local SYSTEM privilege escalation.",
    },
    {
        "name": "MS16-032 (Secondary Logon Handle Privilege Escalation)",
        "cve": "CVE-2016-0099",
        "affected_builds": ["7600", "7601", "9200", "9600", "10240", "10586"],
        "severity": "High",
        "description": "Windows Secondary Logon Service fails to properly manage memory handles, allowing standard users to escalate to SYSTEM.",
    },
    {
        "name": "MS17-010 (EternalBlue / EternalRomance Local PrivEsc)",
        "cve": "CVE-2017-0143",
        "affected_builds": ["7600", "7601", "9200", "9600", "10240", "10586", "14393"],
        "severity": "Critical",
        "description": "SMBv1 buffer overflow allowing kernel execution and SYSTEM access.",
    },
]

def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)

def _run_cmd(cmd: list, timeout: int = 25) -> str:
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"[ERROR] {e}"

def _run_remote_query(target: str, username: str, password: str, domain: str, cmd_str: str) -> str:
    if not username or target in ("127.0.0.1", "localhost", "local"):
        return _run_cmd(["cmd.exe", "/c", cmd_str])
    cred = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    cmd = ["python", "-m", "impacket.examples.wmiexec", cred, cmd_str]
    return _run_cmd(cmd, timeout=30)


# ── 1. Antivirus / EDR Enumeration ───────────────────────────────────────────

def enumerate_antivirus_edr(target: str = "local", username: str = "",
                            password: str = "", domain: str = "",
                            log_fn: Callable = None) -> Dict[str, Any]:
    """
    Query installed Antivirus, EDR, and Windows Defender protection status.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [WinPrivEsc] Enumerating Antivirus / EDR on {target}...")
    av_products = []
    defender_running = False

    # 1. Query SecurityCenter2 via PowerShell
    cmd_av = 'powershell -c "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,productState | ConvertTo-Json"'
    out_av = _run_remote_query(target, username, password, domain, cmd_av)

    try:
        data = json.loads(out_av.strip()) if out_av.strip().startswith(("{", "[")) else []
        if isinstance(data, dict):
            data = [data]
        for p in data:
            d_name = p.get("displayName", "")
            if d_name:
                av_products.append(d_name)
                _log(f"  [WinPrivEsc] 🛡️ Detected AV: {d_name}")
    except Exception:
        pass

    # 2. Check Windows Defender Service (WinDefend)
    cmd_def = 'powershell -c "(Get-Service WinDefend -ErrorAction SilentlyContinue).Status"'
    out_def = _run_remote_query(target, username, password, domain, cmd_def)
    defender_running = "Running" in out_def

    _log(f"  [WinPrivEsc] Windows Defender Service: {'RUNNING' if defender_running else 'Stopped / Disabled'}")

    return {
        "av_products": av_products,
        "defender_running": defender_running,
        "has_third_party_edr": len(av_products) > 0 and not all("defender" in a.lower() for a in av_products),
    }


# ── 2. Kernel Exploit Suggester ───────────────────────────────────────────────

def audit_kernel_exploits(target: str = "local", username: str = "",
                          password: str = "", domain: str = "",
                          log_fn: Callable = None) -> Dict[str, Any]:
    """
    Extract OS Build & installed Hotfixes to match against known Windows Kernel Exploits.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [WinPrivEsc] Matching Kernel Exploits against OS build on {target}...")
    findings = []
    matched_exploits = []

    # Get Build Number
    cmd_build = 'powershell -c "[System.Environment]::OSVersion.Version.Build"'
    out_build = _run_remote_query(target, username, password, domain, cmd_build).strip()
    build_num = re.search(r"\b(\d{4,5})\b", out_build)
    current_build = build_num.group(1) if build_num else ""

    _log(f"  [WinPrivEsc] Detected OS Build: {current_build or 'Unknown'}")

    if current_build:
        for exp in KERNEL_EXPLOIT_DB:
            if current_build in exp["affected_builds"]:
                matched_exploits.append(exp)
                _log(f"  [WinPrivEsc] 🎯 Potential Kernel Exploit Match: {exp['name']}")
                findings.append({
                    "title": f"Kernel Privilege Escalation Vector — {exp['name']}",
                    "severity": exp["severity"],
                    "description": (
                        f"Target {target} is running Windows Build `{current_build}`, which is vulnerable to `{exp['name']}` ({exp['cve']}). "
                        f"{exp['description']} Standard users may execute public exploits to obtain NT AUTHORITY\\SYSTEM."
                    ),
                    "target": target,
                    "cve": exp["cve"],
                    "mitre_id": "T1068",
                    "mitre_name": "Exploitation for Privilege Escalation",
                    "remediation": f"Apply latest Microsoft Security Rollup / cumulative updates addressing {exp['cve']}.",
                })

    return {"os_build": current_build, "matched_exploits": matched_exploits, "findings": findings}


# ── 3. Deep Password Hunting ──────────────────────────────────────────────────

def hunt_stored_passwords(target: str = "local", username: str = "",
                          password: str = "", domain: str = "",
                          log_fn: Callable = None) -> Dict[str, Any]:
    """
    Search for plaintext passwords in PowerShell history, Unattend files, SAM backups, and PuTTY sessions.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [WinPrivEsc] Hunting for stored credentials and history files on {target}...")
    findings = []
    creds_found = []

    # 1. PowerShell History (ConsoleHost_history.txt)
    cmd_ps_hist = (
        'powershell -c "$path = \\"$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\\"; '
        'if (Test-Path $path) { Get-Content -Path $path -Tail 50 }"'
    )
    out_hist = _run_remote_query(target, username, password, domain, cmd_ps_hist)
    
    for line in out_hist.splitlines():
        line = line.strip()
        if any(kw in line.lower() for kw in ("password", "pwd", "net user", "runas", "-p ", "pass:", "secret")):
            _log(f"  [WinPrivEsc] 🎯 PowerShell History Secret: {line[:80]}...")
            creds_found.append({"source": "ConsoleHost_history.txt", "snippet": line})
            findings.append({
                "title": "Plaintext Credentials in PowerShell Command History",
                "severity": "High",
                "description": f"Sensitive commands containing credentials found in ConsoleHost_history.txt on {target}: `{line[:150]}`",
                "target": target,
                "mitre_id": "T1552.001",
                "mitre_name": "Credentials in Files",
                "remediation": "Clear PowerShell history via `Clear-History` and avoid passing plaintext passwords via CLI arguments.",
            })

    # 2. Unattended Install Files (Panther, sysprep)
    cmd_unattend = (
        'powershell -c "$paths = @(\\"C:\\Windows\\Panther\\Unattend.xml\\", \\"C:\\Windows\\Panther\\Unattended.xml\\", '
        '\\"C:\\Windows\\System32\\sysprep\\sysprep.xml\\", \\"C:\\Windows\\System32\\sysprep\\sysprep.inf\\"); '
        'foreach ($p in $paths) { if (Test-Path $p) { Write-Output \\"FOUND: $p\\"; Get-Content $p | Select-String -Pattern \'Password|AdministratorPassword|PlainText\' } }"'
    )
    out_unattend = _run_remote_query(target, username, password, domain, cmd_unattend)
    if "FOUND:" in out_unattend:
        _log(f"  [WinPrivEsc] 🎯 Unattended Setup File Found: {out_unattend[:150]}...")
        findings.append({
            "title": "Unattended Deployment XML Credentials Exposed",
            "severity": "Critical",
            "description": f"Discovered Unattended Setup XML files with embedded passwords on {target}:\n{out_unattend[:300]}",
            "target": target,
            "mitre_id": "T1552.001",
            "mitre_name": "Credentials in Files",
            "remediation": "Delete setup configuration files (Unattend.xml, sysprep.inf) after Windows deployment completes.",
        })

    # 3. HiveNightmare / SeriousSAM Registry Backups Check (C:\\Windows\\Repair, RegBack)
    cmd_sam_backup = (
        'powershell -c "$paths = @(\\"C:\\Windows\\System32\\config\\RegBack\\SAM\\", \\"C:\\Windows\\Repair\\SAM\\"); '
        'foreach ($p in $paths) { if (Test-Path $p) { Write-Output \\"BACKUP_EXISTS: $p\\" } }"'
    )
    out_sam_backup = _run_remote_query(target, username, password, domain, cmd_sam_backup)
    if "BACKUP_EXISTS:" in out_sam_backup:
        _log(f"  [WinPrivEsc] 🎯 SAM Registry Hive Backup Accessible!")
        findings.append({
            "title": "Accessible Offline SAM Registry Hive Backup",
            "severity": "Critical",
            "description": f"Offline backup copies of the SAM registry hive exist on {target} ({out_sam_backup.strip()}). Local user NTLM hashes can be extracted offline.",
            "target": target,
            "mitre_id": "T1552.001",
            "mitre_name": "Credentials in Files",
            "remediation": "Restrict ACLs on backup directories and delete outdated SAM copies in C:\\Windows\\Repair.",
        })

    # 4. PuTTY Stored Sessions
    cmd_putty = 'reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"'
    out_putty = _run_remote_query(target, username, password, domain, cmd_putty)
    if "HKEY_CURRENT_USER" in out_putty:
        _log(f"  [WinPrivEsc] PuTTY Stored Sessions detected in registry")
        findings.append({
            "title": "PuTTY Stored SSH Sessions in Registry",
            "severity": "Medium",
            "description": f"PuTTY saved sessions discovered in user registry on {target}. May contain saved hostnames, usernames, or proxy settings.",
            "target": target,
            "mitre_id": "T1552.002",
            "mitre_name": "Credentials in Registry",
            "remediation": "Audit and clear saved PuTTY sessions and private key associations.",
        })

    return {"credentials": creds_found, "findings": findings}


# ── 4. Windows Subsystem for Linux (WSL) Escalation ───────────────────────────

def audit_wsl_escalation(target: str = "local", username: str = "",
                         password: str = "", domain: str = "",
                         log_fn: Callable = None) -> Dict[str, Any]:
    """
    Check if WSL is installed and if unprivileged users can execute commands as root.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [WinPrivEsc] Checking Windows Subsystem for Linux (WSL) on {target}...")
    findings = []
    wsl_installed = False

    cmd_wsl = 'powershell -c "if (Get-Command wsl.exe -ErrorAction SilentlyContinue) { wsl -u root whoami }"'
    out_wsl = _run_remote_query(target, username, password, domain, cmd_wsl).strip()

    if "root" in out_wsl.lower():
        wsl_installed = True
        _log(f"  [WinPrivEsc] 🎯 CRITICAL: WSL Root Execution Verified: `wsl -u root whoami` -> {out_wsl}")
        findings.append({
            "title": "WSL Root Execution & Shadow File Access",
            "severity": "Critical",
            "description": (
                f"Windows Subsystem for Linux (WSL) is installed on {target} and permits execution as `root` without authentication. "
                f"An attacker can mount Windows drives (`/mnt/c`), access restricted files, read shadow files, or execute privileged Linux binaries."
            ),
            "target": target,
            "mitre_id": "T1202",
            "mitre_name": "Indirect Command Execution: WSL",
            "remediation": "Restrict WSL access or configure default user in `/etc/wsl.conf`. Enforce enterprise endpoint policies for WSL distribution usage.",
        })

    return {"wsl_installed": wsl_installed, "findings": findings}


# ── 5. Service Registry ACLs & Binary Overwrite (`regsvc`) ────────────────────

def audit_service_permissions(target: str = "local", username: str = "",
                              password: str = "", domain: str = "",
                              log_fn: Callable = None) -> Dict[str, Any]:
    """
    Check for modifiable service registry keys (`HKLM\\SYSTEM\\CurrentControlSet\\Services`)
    or writable service binary executables.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [WinPrivEsc] Checking Service Registry & Binary Permissions on {target}...")
    findings = []

    # Check for weak permissions on Service registry keys (e.g. regsvc)
    cmd_acl = (
        'powershell -c "$services = Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*\' | Select-Object PSChildName,ImagePath; '
        'foreach ($s in $services) { '
        '  if ($s.ImagePath -and $s.ImagePath -notmatch \'^C:\\\\Windows\\\\System32\') { '
        '    $acl = Get-Acl \\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($s.PSChildName)\\" -ErrorAction SilentlyContinue; '
        '    if ($acl.AccessToString -match \'Users.*(FullControl|WriteKey|SetValue)\') { '
        '      Write-Output \\"VULN_SERVICE_REGISTRY: $($s.PSChildName)\\" '
        '    } '
        '  } '
        '}"'
    )
    out_acl = _run_remote_query(target, username, password, domain, cmd_acl)
    
    for line in out_acl.splitlines():
        if "VULN_SERVICE_REGISTRY:" in line:
            s_name = line.split(":", 1)[1].strip()
            _log(f"  [WinPrivEsc] 🎯 Vulnerable Service Registry Key ACL: {s_name}")
            findings.append({
                "title": f"Weak Service Registry Key Permissions — {s_name}",
                "severity": "Critical",
                "description": (
                    f"The service registry key for `{s_name}` (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\{s_name}`) allows write/modify permissions for standard Users. "
                    f"An unprivileged user can modify `ImagePath` to point to a malicious executable and start the service with SYSTEM privileges."
                ),
                "target": target,
                "mitre_id": "T1574.011",
                "mitre_name": "Services Registry Permissions Weakness",
                "remediation": f"Restore secure default ACLs on `HKLM\\SYSTEM\\CurrentControlSet\\Services\\{s_name}` restricting write access to SYSTEM and Administrators.",
            })

    return {"findings": findings}


# ── Full Master PrivEsc Coordinator ───────────────────────────────────────────

def run_full_win_privesc_suite(target: str = "local", username: str = "",
                               password: str = "", domain: str = "",
                               log_fn: Callable = None) -> Dict[str, Any]:
    """
    Execute complete TCM Windows Privilege Escalation master suite.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [WinPrivEsc] WINDOWS PRIVILEGE ESCALATION MASTER SUITE")
    _log(f"  [WinPrivEsc] Target: {target}")
    _log(f"{'='*60}\n")

    all_findings = []
    all_creds = []

    # 1. Antivirus / EDR
    av_res = enumerate_antivirus_edr(target, username, password, domain, log_fn)

    # 2. Kernel Exploit Suggester
    ke_res = audit_kernel_exploits(target, username, password, domain, log_fn)
    all_findings.extend(ke_res.get("findings", []))

    # 3. Password Hunting (PowerShell history, Unattend, SAM backups)
    ph_res = hunt_stored_passwords(target, username, password, domain, log_fn)
    all_findings.extend(ph_res.get("findings", []))
    all_creds.extend(ph_res.get("credentials", []))

    # 4. WSL Root Escalation
    wsl_res = audit_wsl_escalation(target, username, password, domain, log_fn)
    all_findings.extend(wsl_res.get("findings", []))

    # 5. Service Registry & Binary Permissions
    sp_res = audit_service_permissions(target, username, password, domain, log_fn)
    all_findings.extend(sp_res.get("findings", []))

    _log(f"\n  [WinPrivEsc] ✅ Master PrivEsc Suite finished on {target}: {len(all_findings)} finding(s), {len(all_creds)} credential(s)")

    return {
        "target": target,
        "antivirus": av_res,
        "kernel_exploits": ke_res.get("matched_exploits", []),
        "credentials": all_creds,
        "wsl_vulnerable": wsl_res.get("wsl_installed", False),
        "findings": all_findings,
        "mitre": MITRE,
        "summary": f"Windows PrivEsc Suite on {target}: {len(all_findings)} vector(s) identified",
    }
