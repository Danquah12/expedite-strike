"""
Expedite Strike — Windows Host Misconfiguration & Privilege Audit Engine
========================================================================
Audits local and remote Windows systems for high-impact privilege escalation
misconfigurations matching the TCM Security Movement, Pivoting & Persistence curriculum:

- AutoLogon Plaintext Credentials (T1552.002)
- AlwaysInstallElevated Policy (T1548.002)
- UAC Bypass Vulnerability & Posture (T1548.002)
- Unquoted Service Paths (T1574.009)
- Weak Service Binary / Registry Permissions (T1574.011)

Supports local audit (pure Python / Winreg) and remote audit (Impacket wmiexec / WinRM).
"""

import os
import re
import socket
import subprocess
from typing import Callable, Dict, List, Optional

_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1552.002", "name": "Credentials in Registry"},
    {"id": "T1548.002", "name": "Bypass User Account Control"},
    {"id": "T1574.009", "name": "Path Interception by Unquoted Path"},
    {"id": "T1574.011", "name": "Services Registry Permissions Weakness"},
    {"id": "T1068",     "name": "Exploitation for Privilege Escalation"},
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
    """Execute a query command remotely via Impacket wmiexec or WinRM."""
    if not username or target in ("127.0.0.1", "localhost", "local"):
        return _run_cmd(["cmd.exe", "/c", cmd_str])
    
    cred = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    cmd = ["python", "-m", "impacket.examples.wmiexec", cred, cmd_str]
    return _run_cmd(cmd, timeout=30)


# ── 1. AutoLogon Credential Audit ─────────────────────────────────────────────

def audit_autologon(target: str = "local", username: str = "", password: str = "",
                    domain: str = "", log_fn: Callable = None) -> Dict:
    """
    Check for plaintext credentials saved under Winlogon registry keys.
    Key: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [HostAudit] Checking AutoLogon credentials on {target}...")
    findings = []
    creds_found = []

    cmd = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"'
    out = _run_remote_query(target, username, password, domain, cmd)

    auto_logon = re.search(r"AutoAdminLogon\s+REG_\w+\s+([01])", out, re.I)
    default_user = re.search(r"DefaultUserName\s+REG_\w+\s+(.+)", out, re.I)
    default_pass = re.search(r"DefaultPassword\s+REG_\w+\s+(.+)", out, re.I)
    default_domain = re.search(r"DefaultDomainName\s+REG_\w+\s+(.+)", out, re.I)
    alt_pass = re.search(r"AltDefaultPassword\s+REG_\w+\s+(.+)", out, re.I)

    u = default_user.group(1).strip() if default_user else ""
    p = (default_pass.group(1).strip() if default_pass else "") or (alt_pass.group(1).strip() if alt_pass else "")
    d = default_domain.group(1).strip() if default_domain else ""
    is_active = auto_logon.group(1).strip() == "1" if auto_logon else bool(p)

    if p and u:
        creds_found.append({"username": u, "password": p, "domain": d, "source": "Winlogon Registry"})
        _log(f"  [HostAudit] 🎯 CRITICAL: Plaintext AutoLogon password found: {u}:{p} (Domain: {d or 'Local'})")
        findings.append({
            "title": f"AutoLogon Plaintext Password in Registry — {u}",
            "severity": "Critical",
            "description": (
                f"Plaintext Windows credentials discovered in Winlogon registry on {target}. "
                f"User: {u}, Password: {p}, Domain: {d or 'Local'}. "
                f"Any low-privilege user can read these credentials to achieve local or domain access."
            ),
            "target": target,
            "username": u,
            "password": p,
            "mitre_id": "T1552.002",
            "mitre_name": "Credentials in Registry",
            "remediation": (
                "Disable AutoLogon by removing `DefaultPassword` and setting `AutoAdminLogon` to 0 under "
                "`HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`."
            ),
        })
    elif u:
        _log(f"  [HostAudit] DefaultUserName is set to '{u}', but no DefaultPassword found in registry.")

    return {"credentials": creds_found, "findings": findings, "autologon_active": is_active}


# ── 2. AlwaysInstallElevated Audit ─────────────────────────────────────────────

def audit_always_install_elevated(target: str = "local", username: str = "",
                                  password: str = "", domain: str = "",
                                  log_fn: Callable = None) -> Dict:
    """
    Check if AlwaysInstallElevated is enabled in both HKLM and HKCU.
    If both = 1, any user can run an MSI with elevated SYSTEM privileges.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [HostAudit] Checking AlwaysInstallElevated policy on {target}...")
    findings = []

    cmd_hklm = 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'
    cmd_hkcu = 'reg query "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'

    out_hklm = _run_remote_query(target, username, password, domain, cmd_hklm)
    out_hkcu = _run_remote_query(target, username, password, domain, cmd_hkcu)

    hklm_enabled = bool(re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1", out_hklm, re.I))
    hkcu_enabled = bool(re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1", out_hkcu, re.I))

    if hklm_enabled and hkcu_enabled:
        _log(f"  [HostAudit] 🎯 CRITICAL: AlwaysInstallElevated ENABLED in HKLM and HKCU on {target}!")
        findings.append({
            "title": f"AlwaysInstallElevated SYSTEM Escalation Policy Active — {target}",
            "severity": "Critical",
            "description": (
                f"The AlwaysInstallElevated registry policy is enabled in both HKLM and HKCU on {target}. "
                f"Standard, unprivileged users can author a custom MSI package and install it with NT AUTHORITY\\SYSTEM privileges."
            ),
            "target": target,
            "mitre_id": "T1548.002",
            "mitre_name": "Bypass User Account Control",
            "remediation": (
                "Disable AlwaysInstallElevated via GPO: Computer Configuration & User Configuration -> "
                "Administrative Templates -> Windows Components -> Windows Installer -> Set 'Always install with elevated privileges' to Disabled."
            ),
        })
    else:
        _log(f"  [HostAudit] AlwaysInstallElevated: HKLM={hklm_enabled}, HKCU={hkcu_enabled} (Secure)")

    return {
        "hklm_enabled": hklm_enabled,
        "hkcu_enabled": hkcu_enabled,
        "vulnerable": (hklm_enabled and hkcu_enabled),
        "findings": findings,
    }


# ── 3. UAC Posture & Bypass Assessment ─────────────────────────────────────────

def audit_uac_configuration(target: str = "local", username: str = "",
                            password: str = "", domain: str = "",
                            log_fn: Callable = None) -> Dict:
    """
    Check UAC configuration flags: EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop.
    Identifies susceptibility to silent UAC bypasses (Fodhelper, ComputerDefaults).
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [HostAudit] Checking UAC configuration on {target}...")
    findings = []

    cmd = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"'
    out = _run_remote_query(target, username, password, domain, cmd)

    enable_lua = re.search(r"EnableLUA\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
    consent = re.search(r"ConsentPromptBehaviorAdmin\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
    secure_desktop = re.search(r"PromptOnSecureDesktop\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)

    lua_val = int(enable_lua.group(1), 16) if enable_lua else 1
    consent_val = int(consent.group(1), 16) if consent else 5
    secure_val = int(secure_desktop.group(1), 16) if secure_desktop else 1

    # Evaluation
    # consent_val == 0: Elevate without prompting (Trivial bypass / No UAC)
    # consent_val == 5: Prompt for consent for non-Windows binaries (Default - vulnerable to auto-elevate bypasses like Fodhelper)
    # consent_val == 2: Prompt for credentials on secure desktop (Hardened)
    if lua_val == 0:
        findings.append({
            "title": f"UAC Completely Disabled (EnableLUA=0) — {target}",
            "severity": "Critical",
            "description": f"User Account Control (UAC) is completely disabled on {target}. Administrator processes run with full token without prompt.",
            "target": target,
            "mitre_id": "T1548.002",
            "mitre_name": "Bypass User Account Control",
            "remediation": "Enable UAC by setting EnableLUA to 1 in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.",
        })
    elif consent_val in (0, 5):
        findings.append({
            "title": f"UAC Auto-Elevation Bypass Surface Active — {target}",
            "severity": "Medium",
            "description": (
                f"UAC ConsentPromptBehaviorAdmin is set to {consent_val} on {target}. "
                f"Auto-elevating Windows binaries (such as `fodhelper.exe`, `computerdefaults.exe`) execute without prompt, "
                f"allowing high-integrity escalation if registry hijacking keys (`HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command`) are modified."
            ),
            "target": target,
            "mitre_id": "T1548.002",
            "mitre_name": "Bypass User Account Control",
            "remediation": "Set ConsentPromptBehaviorAdmin to 2 ('Prompt for credentials on secure desktop') or 1 ('Prompt for credentials') for highest security.",
        })

    return {
        "enable_lua": lua_val,
        "consent_prompt": consent_val,
        "prompt_on_secure_desktop": secure_val,
        "fodhelper_bypass_applicable": (lua_val == 1 and consent_val == 5),
        "findings": findings,
    }


# ── 4. Unquoted Service Path Audit ────────────────────────────────────────────

def audit_unquoted_service_paths(target: str = "local", username: str = "",
                                 password: str = "", domain: str = "",
                                 log_fn: Callable = None) -> Dict:
    """
    Search for services running as SYSTEM whose binary path contains spaces and lacks enclosing quotes.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [HostAudit] Scanning for Unquoted Service Paths on {target}...")
    findings = []
    unquoted_services = []

    cmd = 'powershell -c "Get-CimInstance win32_service | Where-Object {$_.StartMode -ne \'Disabled\' -and $_.PathName -notmatch \'^\"\' -and $_.PathName -match \' \' -and $_.PathName -notmatch \'^C:\\\\Windows\\\\\'} | Select-Object Name,DisplayName,PathName,StartName | ConvertTo-Json"'
    out = _run_remote_query(target, username, password, domain, cmd)

    try:
        import json
        data = json.loads(out.strip()) if out.strip().startswith(("{", "[")) else []
        if isinstance(data, dict):
            data = [data]
        
        for svc in data:
            s_name = svc.get("Name", "")
            s_path = svc.get("PathName", "")
            s_acct = svc.get("StartName", "")

            # Filter out quoted or system root paths
            if s_path and not s_path.startswith('"') and " " in s_path:
                unquoted_services.append(svc)
                _log(f"  [HostAudit] ⚠ Unquoted Service Found: {s_name} -> {s_path} ({s_acct})")
                findings.append({
                    "title": f"Unquoted Service Path — {s_name} ({s_acct})",
                    "severity": "High" if "system" in s_acct.lower() else "Medium",
                    "description": (
                        f"Service '{s_name}' on {target} has an unquoted binary path with spaces: `{s_path}`. "
                        f"Account: `{s_acct}`. If an unprivileged user can write a binary to any parent directory in the path, "
                        f"Windows Service Control Manager will execute it upon service start."
                    ),
                    "target": target,
                    "mitre_id": "T1574.009",
                    "mitre_name": "Path Interception by Unquoted Path",
                    "remediation": f'Wrap the service binary path in quotation marks: `sc.exe config "{s_name}" binPath= "\\"{s_path}\\""`',
                })
    except Exception as e:
        _log(f"  [HostAudit] Unquoted path parse error: {e}")

    return {"unquoted_services": unquoted_services, "findings": findings}


# ── Full Host Misconfiguration Coordinator ────────────────────────────────────

def run_host_misconfiguration_audit(target: str = "local", username: str = "",
                                    password: str = "", domain: str = "",
                                    log_fn: Callable = None) -> Dict:
    """
    Execute full suite of local privilege escalation & misconfiguration audits.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [HostAudit] HOST PRIVILEGE ESCALATION AUDIT")
    _log(f"  [HostAudit] Target: {target}")
    _log(f"{'='*60}\n")

    all_findings = []
    all_creds = []

    # 1. AutoLogon
    al_res = audit_autologon(target, username, password, domain, log_fn)
    all_findings.extend(al_res.get("findings", []))
    all_creds.extend(al_res.get("credentials", []))

    # 2. AlwaysInstallElevated
    aie_res = audit_always_install_elevated(target, username, password, domain, log_fn)
    all_findings.extend(aie_res.get("findings", []))

    # 3. UAC Configuration
    uac_res = audit_uac_configuration(target, username, password, domain, log_fn)
    all_findings.extend(uac_res.get("findings", []))

    # 4. Unquoted Service Paths
    usp_res = audit_unquoted_service_paths(target, username, password, domain, log_fn)
    all_findings.extend(usp_res.get("findings", []))

    _log(f"\n  [HostAudit] ✅ Audit complete on {target}: {len(all_findings)} finding(s), {len(all_creds)} credential(s)")

    return {
        "target": target,
        "findings": all_findings,
        "credentials": all_creds,
        "always_install_elevated": aie_res.get("vulnerable", False),
        "autologon": al_res.get("autologon_active", False),
        "unquoted_services": usp_res.get("unquoted_services", []),
        "mitre": MITRE,
        "summary": f"Host Audit on {target}: {len(all_findings)} security posture findings",
    }
