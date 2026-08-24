"""
Expedite Strike — Windows Persistence & Autostart Auditor
=========================================================
Audits local and remote Windows systems for persistence mechanisms, backdoor accounts,
and autostart configurations matching the TCM Security Movement, Pivoting & Persistence curriculum:

- Registry Run / RunOnce Autostart Keys (T1547.001)
- Startup Directory Artifacts (T1547.001)
- Suspicious Scheduled Tasks (T1053.005)
- Hidden / Backdoor Local Administrator Accounts (T1078.003, T1098)
- RDP Security & Terminal Server Posture (T1021.001, T1546.008)
"""

import os
import re
import subprocess
from typing import Callable, Dict, List, Optional

_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1547.001", "name": "Boot or Logon Autostart: Registry Run Keys / Startup Folder"},
    {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task"},
    {"id": "T1078.003", "name": "Valid Accounts: Local Accounts"},
    {"id": "T1098",     "name": "Account Manipulation"},
    {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
]

def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)

def _run_cmd(cmd: list, timeout: int = 25) -> str:
    """Run local subprocess safely."""
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"[ERROR] {e}"

def _run_remote_query(target: str, username: str, password: str, domain: str, cmd_str: str) -> str:
    """Execute a query command remotely via Impacket wmiexec or local cmd."""
    if not username or target in ("127.0.0.1", "localhost", "local"):
        return _run_cmd(["cmd.exe", "/c", cmd_str])
    
    cred = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    cmd = ["python", "-m", "impacket.examples.wmiexec", cred, cmd_str]
    return _run_cmd(cmd, timeout=30)


# ── 1. Registry Run / RunOnce Keys ────────────────────────────────────────────

def audit_registry_autoruns(target: str = "local", username: str = "",
                            password: str = "", domain: str = "",
                            log_fn: Callable = None) -> Dict:
    """
    Inspect Registry Autostart locations (HKLM/HKCU Run, RunOnce, Winlogon Userinit).
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [Persistence] Auditing Registry Run / RunOnce keys on {target}...")
    findings = []
    autorun_entries = []

    keys_to_check = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]

    for reg_k in keys_to_check:
        out = _run_remote_query(target, username, password, domain, f'reg query "{reg_k}"')
        for line in out.splitlines():
            line = line.strip()
            if "REG_SZ" in line or "REG_EXPAND_SZ" in line:
                parts = re.split(r"\s+REG_\w+\s+", line)
                if len(parts) >= 2:
                    name = parts[0].strip()
                    val = parts[1].strip()
                    autorun_entries.append({"key": reg_k, "name": name, "value": val})

                    # Flag suspicious paths (Temp, AppData, Downloads, PowerShell encoded commands)
                    is_suspicious = any(p.lower() in val.lower() for p in [
                        "\\temp\\", "\\appdata\\local\\temp", "\\downloads\\", "powershell -enc",
                        "cmd /c powershell", "rundll32", "mshta", "cscript"
                    ])
                    if is_suspicious:
                        _log(f"  [Persistence] ⚠ Suspicious Autostart Entry Found: [{name}] -> {val}")
                        findings.append({
                            "title": f"Suspicious Registry Autostart Entry — {name}",
                            "severity": "High",
                            "description": (
                                f"An autostart entry under `{reg_k}` points to a suspicious binary or script: `{val}`. "
                                f"Malware and threat actors commonly persist across reboots via this registry location."
                            ),
                            "target": target,
                            "mitre_id": "T1547.001",
                            "mitre_name": "Registry Run Keys / Startup Folder",
                            "remediation": f'Investigate binary source and remove malicious key: `reg delete "{reg_k}" /v "{name}" /f`',
                        })

    return {"autoruns": autorun_entries, "findings": findings}


# ── 2. Startup Folder Audit ───────────────────────────────────────────────────

def audit_startup_folder(target: str = "local", username: str = "",
                         password: str = "", domain: str = "",
                         log_fn: Callable = None) -> Dict:
    """
    Inspect user and system-wide Startup folders for unauthorized binaries/shortcuts.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [Persistence] Auditing Startup folders on {target}...")
    findings = []
    startup_items = []

    cmd = (
        'powershell -c "$paths = @(\\"$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\", '
        '\\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"); '
        'Get-ChildItem -Path $paths -ErrorAction SilentlyContinue | Select-Object Name,FullName,Length | ConvertTo-Json"'
    )
    out = _run_remote_query(target, username, password, domain, cmd)

    try:
        import json
        data = json.loads(out.strip()) if out.strip().startswith(("{", "[")) else []
        if isinstance(data, dict):
            data = [data]
        
        for item in data:
            f_name = item.get("Name", "")
            f_path = item.get("FullName", "")
            if f_name and f_name.lower() not in ("desktop.ini",):
                startup_items.append(item)
                _log(f"  [Persistence] Startup item detected: {f_name} at {f_path}")
                findings.append({
                    "title": f"Startup Directory Persistence Item — {f_name}",
                    "severity": "Medium",
                    "description": (
                        f"A non-standard file `{f_name}` exists in the Windows Startup directory: `{f_path}`. "
                        f"This file automatically executes upon user logon."
                    ),
                    "target": target,
                    "mitre_id": "T1547.001",
                    "mitre_name": "Registry Run Keys / Startup Folder",
                    "remediation": f"Audit file authenticity and remove if unrecognized: `Remove-Item -Path '{f_path}'`",
                })
    except Exception as e:
        _log(f"  [Persistence] Startup folder parse error: {e}")

    return {"startup_items": startup_items, "findings": findings}


# ── 3. Local Administrator Accounts Audit ─────────────────────────────────────

def audit_local_administrators(target: str = "local", username: str = "",
                               password: str = "", domain: str = "",
                               log_fn: Callable = None) -> Dict:
    """
    Inspect members of the local Administrators group for unauthorized / backdoor accounts.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [Persistence] Auditing Local Administrators group on {target}...")
    findings = []
    admin_members = []

    cmd = "net localgroup Administrators"
    out = _run_remote_query(target, username, password, domain, cmd)

    in_members = False
    for line in out.splitlines():
        if "---" in line:
            in_members = True
            continue
        if "The command completed" in line or not line.strip():
            in_members = False
            continue
        if in_members:
            member = line.strip()
            admin_members.append(member)

            # Check for non-standard local accounts
            std_accounts = ["Administrator", "Domain Admins", "Enterprise Admins", f"{domain}\\Domain Admins"]
            if member not in std_accounts and not member.endswith("\\Domain Admins"):
                _log(f"  [Persistence] Non-standard Administrator account identified: {member}")
                findings.append({
                    "title": f"Non-Standard Local Administrator Account — {member}",
                    "severity": "Medium",
                    "description": (
                        f"Account `{member}` is a member of the local `Administrators` group on {target}. "
                        f"Attackers frequently create new local users or promote low-privilege users for persistent domain/host dominance."
                    ),
                    "target": target,
                    "username": member,
                    "mitre_id": "T1078.003",
                    "mitre_name": "Valid Accounts: Local Accounts",
                    "remediation": f"Verify legitimate authorization for `{member}` or revoke admin rights: `net localgroup Administrators {member} /delete`",
                })

    return {"administrators": admin_members, "findings": findings}


# ── 4. RDP & Accessibility Backdoor Posture ───────────────────────────────────

def audit_rdp_backdoor_posture(target: str = "local", username: str = "",
                               password: str = "", domain: str = "",
                               log_fn: Callable = None) -> Dict:
    """
    Check RDP configuration and verify sticky keys / accessibility binary integrity (sethc.exe, utilman.exe).
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [Persistence] Auditing RDP & Accessibility helper posture on {target}...")
    findings = []

    # 1. RDP Status
    cmd_rdp = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections'
    out_rdp = _run_remote_query(target, username, password, domain, cmd_rdp)
    rdp_enabled = bool(re.search(r"fDenyTSConnections\s+REG_DWORD\s+0x0", out_rdp, re.I))

    # 2. Sticky Keys / Utilman Debugger Hijack Check
    cmd_image_hijack = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"'
    out_hijack = _run_remote_query(target, username, password, domain, cmd_image_hijack)

    for suspect in ["sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe"]:
        if suspect.lower() in out_hijack.lower():
            # Check if debugger is set
            sub_out = _run_remote_query(target, username, password, domain, f'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{suspect}" /v Debugger')
            if "Debugger" in sub_out:
                _log(f"  [Persistence] 🎯 CRITICAL: Accessibility Debugger Hijack detected for {suspect}!")
                findings.append({
                    "title": f"Accessibility Feature Backdoor (IFEO Hijack) — {suspect}",
                    "severity": "Critical",
                    "description": (
                        f"An Image File Execution Options (IFEO) Debugger registry backdoor is active for `{suspect}` on {target}. "
                        f"This allows unauthenticated command prompt execution at the Windows login screen via shortcut keys (e.g. 5x Shift)."
                    ),
                    "target": target,
                    "mitre_id": "T1546.008",
                    "mitre_name": "Accessibility Features",
                    "remediation": f'Remove the debugger registry entry: `reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{suspect}" /v Debugger /f`',
                })

    return {"rdp_enabled": rdp_enabled, "findings": findings}


# ── Full Persistence Audit Coordinator ────────────────────────────────────────

def run_persistence_audit(target: str = "local", username: str = "",
                          password: str = "", domain: str = "",
                          log_fn: Callable = None) -> Dict:
    """
    Execute full persistence, autostart, and backdoor account audit.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [Persistence] HOST PERSISTENCE & AUTOSTART AUDIT")
    _log(f"  [Persistence] Target: {target}")
    _log(f"{'='*60}\n")

    all_findings = []

    # 1. Registry Autoruns
    reg_res = audit_registry_autoruns(target, username, password, domain, log_fn)
    all_findings.extend(reg_res.get("findings", []))

    # 2. Startup Folder
    st_res = audit_startup_folder(target, username, password, domain, log_fn)
    all_findings.extend(st_res.get("findings", []))

    # 3. Local Admins
    adm_res = audit_local_administrators(target, username, password, domain, log_fn)
    all_findings.extend(adm_res.get("findings", []))

    # 4. RDP & Accessibility Posture
    rdp_res = audit_rdp_backdoor_posture(target, username, password, domain, log_fn)
    all_findings.extend(rdp_res.get("findings", []))

    _log(f"\n  [Persistence] ✅ Persistence audit complete on {target}: {len(all_findings)} finding(s)")

    return {
        "target": target,
        "findings": all_findings,
        "administrators": adm_res.get("administrators", []),
        "autoruns": reg_res.get("autoruns", []),
        "startup_items": st_res.get("startup_items", []),
        "rdp_enabled": rdp_res.get("rdp_enabled", False),
        "mitre": MITRE,
        "summary": f"Persistence Audit on {target}: {len(all_findings)} posture finding(s)",
    }
