"""
Expedite Strike — Windows Credential Vault & Browser Secret Auditor
===================================================================
Audits local and remote Windows systems for stored secrets, DPAPI-protected credentials,
browser profile databases, and Credential Manager entries matching the
TCM Security Movement, Pivoting & Persistence curriculum:

- Windows Credential Manager / Vault Audit (T1555.004)
- Web Browser Stored Credentials (Chrome, Edge, Firefox SQLite databases) (T1555.003)
- DPAPI Master Keys & Backup Keys (T1555)
- WiFi Profile Stored Plaintext Passwords (T1555)
"""

import os
import re
import sqlite3
import subprocess
from typing import Callable, Dict, List, Optional, Any

_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1555.004", "name": "Credentials from Password Stores: Windows Credential Manager"},
    {"id": "T1555.003", "name": "Credentials from Password Stores: Credentials from Web Browsers"},
    {"id": "T1555",     "name": "Credentials from Password Stores"},
    {"id": "T1003",     "name": "OS Credential Dumping"},
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


# ── 1. Windows Credential Manager / Vault Auditor ─────────────────────────────

def audit_credential_manager(target: str = "local", username: str = "",
                             password: str = "", domain: str = "",
                             log_fn: Callable = None) -> Dict[str, Any]:
    """
    Enumerate stored generic, domain, and web credentials in Windows Credential Manager (`cmdkey /list` and VaultCmd).
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [Vault] Auditing Windows Credential Manager on {target}...")
    findings = []
    stored_targets = []

    cmd = "cmdkey /list"
    out = _run_remote_query(target, username, password, domain, cmd)

    current_target = ""
    current_type = ""
    current_user = ""

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Target:"):
            current_target = line.split("Target:", 1)[1].strip()
        elif line.startswith("Type:"):
            current_type = line.split("Type:", 1)[1].strip()
        elif line.startswith("User:"):
            current_user = line.split("User:", 1)[1].strip()
            if current_target:
                stored_targets.append({"target": current_target, "type": current_type, "user": current_user})
                _log(f"  [Vault] 🎯 Stored Credential Found: Target={current_target}, User={current_user}, Type={current_type}")
                findings.append({
                    "title": f"Windows Credential Manager Stored Secret — {current_target}",
                    "severity": "High",
                    "description": (
                        f"Windows Credential Manager on {target} stores saved credentials for `{current_target}` (User: `{current_user}`). "
                        f"If an attacker executes under this user context, DPAPI-protected tokens allow automatic authentication to remote shares, "
                        f"RDP endpoints, or domain resources without re-entering the password."
                    ),
                    "target": target,
                    "username": current_user,
                    "mitre_id": "T1555.004",
                    "mitre_name": "Credentials from Password Stores: Windows Credential Manager",
                    "remediation": "Audit saved credentials via Control Panel -> Credential Manager and remove unnecessary saved entries.",
                })
                current_target = ""

    return {"stored_credentials": stored_targets, "findings": findings}


# ── 2. Browser Stored Password Posture ─────────────────────────────────────────

def audit_browser_credentials(target: str = "local", username: str = "",
                              password: str = "", domain: str = "",
                              log_fn: Callable = None) -> Dict[str, Any]:
    """
    Check for browser profiles (Chrome, Edge, Firefox, Brave) containing SQLite `Login Data` or `logins.json`.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [Vault] Checking Web Browser credential stores on {target}...")
    findings = []
    browser_profiles = []

    # PowerShell to check existence of Login Data and logins.json across AppData
    cmd = (
        'powershell -c "$paths = @('
        '\\"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\\", '
        '\\"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data\\", '
        '\\"$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*\\logins.json\\", '
        '\\"$env:LOCALAPPDATA\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data\\"'
        '); Get-Item -Path $paths -ErrorAction SilentlyContinue | Select-Object FullName,Length | ConvertTo-Json"'
    )
    out = _run_remote_query(target, username, password, domain, cmd)

    try:
        import json
        data = json.loads(out.strip()) if out.strip().startswith(("{", "[")) else []
        if isinstance(data, dict):
            data = [data]
        
        for item in data:
            f_path = item.get("FullName", "")
            if f_path:
                browser_name = "Chrome" if "Chrome" in f_path else ("Edge" if "Edge" in f_path else ("Firefox" if "Firefox" in f_path else "Browser"))
                browser_profiles.append({"browser": browser_name, "path": f_path, "size": item.get("Length", 0)})
                _log(f"  [Vault] 🎯 {browser_name} Stored Password Database Found: {f_path}")
                findings.append({
                    "title": f"Web Browser Stored Password Database — {browser_name}",
                    "severity": "High",
                    "description": (
                        f"Active {browser_name} credential storage database located at `{f_path}`. "
                        f"Standard user processes can decrypt master keys via DPAPI or dump plaintext saved credentials and web cookies."
                    ),
                    "target": target,
                    "mitre_id": "T1555.003",
                    "mitre_name": "Credentials from Password Stores: Credentials from Web Browsers",
                    "remediation": "Enforce corporate policy disabling in-browser password saving. Mandate enterprise password managers (e.g. 1Password, Bitwarden).",
                })
    except Exception as e:
        _log(f"  [Vault] Browser audit note: {e}")

    return {"browser_profiles": browser_profiles, "findings": findings}


# ── 3. WiFi Plaintext Stored Profiles ─────────────────────────────────────────

def audit_wifi_stored_passwords(target: str = "local", username: str = "",
                                password: str = "", domain: str = "",
                                log_fn: Callable = None) -> Dict[str, Any]:
    """
    Query saved WiFi profiles and extract plaintext pre-shared keys (WPA2-PSK).
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [Vault] Auditing WiFi saved passwords on {target}...")
    findings = []
    wifi_profiles = []

    cmd_list = "netsh wlan show profiles"
    out_list = _run_remote_query(target, username, password, domain, cmd_list)

    profile_names = []
    for line in out_list.splitlines():
        if "All User Profile" in line or ":" in line and "Profile" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                p_name = parts[1].strip()
                if p_name and p_name != "<None>":
                    profile_names.append(p_name)

    for p_name in profile_names[:5]:  # Check top 5 profiles
        cmd_key = f'netsh wlan show profile name="{p_name}" key=clear'
        out_key = _run_remote_query(target, username, password, domain, cmd_key)
        
        key_match = re.search(r"Key Content\s+:\s+(.+)", out_key, re.I)
        if key_match:
            psk = key_match.group(1).strip()
            wifi_profiles.append({"ssid": p_name, "password": psk})
            _log(f"  [Vault] 🎯 WiFi Plaintext Key Recovered: SSID='{p_name}' -> Key='{psk}'")
            findings.append({
                "title": f"WiFi Plaintext Pre-Shared Key Recovered — {p_name}",
                "severity": "High",
                "description": f"Extracted plaintext WPA2-PSK password for wireless network `{p_name}` on {target}: `{psk}`.",
                "target": target,
                "password": psk,
                "mitre_id": "T1555",
                "mitre_name": "Credentials from Password Stores",
                "remediation": "Migrate corporate wireless networks from WPA2-PSK to 802.1X Enterprise (WPA2/WPA3-Enterprise) with RADIUS.",
            })

    return {"wifi_profiles": wifi_profiles, "findings": findings}


# ── Full Vault Audit Coordinator ──────────────────────────────────────────────

def run_credential_vault_audit(target: str = "local", username: str = "",
                               password: str = "", domain: str = "",
                               log_fn: Callable = None) -> Dict[str, Any]:
    """
    Coordinator executing Windows Credential Manager, Browser Credentials, and WiFi Passwords audit.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [Vault] CREDENTIAL VAULT & STORED SECRETS AUDIT")
    _log(f"  [Vault] Target: {target}")
    _log(f"{'='*60}\n")

    all_findings = []

    # 1. Windows Credential Manager
    cm_res = audit_credential_manager(target, username, password, domain, log_fn)
    all_findings.extend(cm_res.get("findings", []))

    # 2. Web Browser Credential Stores
    br_res = audit_browser_credentials(target, username, password, domain, log_fn)
    all_findings.extend(br_res.get("findings", []))

    # 3. WiFi Plaintext Keys
    wf_res = audit_wifi_stored_passwords(target, username, password, domain, log_fn)
    all_findings.extend(wf_res.get("findings", []))

    _log(f"\n  [Vault] ✅ Vault audit finished on {target}: {len(all_findings)} finding(s)")

    return {
        "target": target,
        "findings": all_findings,
        "credential_manager": cm_res.get("stored_credentials", []),
        "browsers": br_res.get("browser_profiles", []),
        "wifi": wf_res.get("wifi_profiles", []),
        "mitre": MITRE,
        "summary": f"Credential Vault Audit on {target}: {len(all_findings)} stored secret findings",
    }
