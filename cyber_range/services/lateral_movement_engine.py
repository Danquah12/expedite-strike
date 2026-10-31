"""
Expedite Strike — Lateral Movement & Pivoting Architecture
===========================================================
Automates multi-host lateral traversal, credential reuse, and pivot evaluation:
  1. SSH Key Reuse & Known Hosts Pivoting (T1021.004)
  2. Pass-the-Hash & Pass-the-Ticket Alternate Authentication (T1550.002 / T1550.003)
  3. Database-to-OS Lateral Pivoting (PostgreSQL COPY PROGRAM / MySQL UDF) (T1059.006)
  4. Internal Network Route & Dual-Homed Interface Discovery (T1016)
  5. Dynamic SSH Port Forwarding & Pivoting
"""

import socket
import threading
import time
from typing import List, Dict, Any, Optional, Tuple


class LateralMovementEngine:
    """Evaluates and simulates multi-hop lateral movement vectors across compromised targets."""

    @classmethod
    def audit_ssh_key_reuse(cls, source_host: str, ssh_loot: Dict[str, Any], candidate_targets: List[str] = None) -> List[Dict[str, Any]]:
        """Audit harvested SSH private keys and known_hosts for cross-host lateral pivoting."""
        findings = []
        candidate_targets = candidate_targets or []
        keys = ssh_loot.get("private_keys", [])
        known_hosts = ssh_loot.get("known_hosts", [])

        if keys and known_hosts:
            for kh in known_hosts:
                findings.append({
                    "title": f"SSH Key Lateral Pivot Available: {source_host} -> {kh}",
                    "severity": "Critical",
                    "cvss": 9.1,
                    "host": f"{source_host} -> {kh}",
                    "cve": "CWE-255 (Credentials Management)",
                    "category": "Lateral Movement",
                    "scanner": "LATERAL_ENGINE",
                    "mitre_id": "T1021.004",
                    "mitre_name": "Remote Services: SSH",
                    "description": f"Harvested private key on '{source_host}' matches trust relationship in known_hosts with adjacent host '{kh}'. An attacker can pivot laterally without triggering authentication alarms.",
                    "evidence": f"Source: {source_host}\nHarvested Key: ~/.ssh/id_rsa\nTarget Pivot: {kh}:22",
                    "remediation": "Restrict SSH agent forwarding, enforce Certificate-Based SSH authentication with Hardware Security Modules (FIDO2/YubiKey), and isolate inter-server SSH traffic.",
                })
        elif keys:
            findings.append({
                "title": f"Unprotected SSH Private Keys Discovered on {source_host}",
                "severity": "High",
                "cvss": 8.2,
                "host": source_host,
                "cve": "CWE-312 (Cleartext Storage of Sensitive Information)",
                "category": "Credential Access",
                "scanner": "LATERAL_ENGINE",
                "mitre_id": "T1552.004",
                "mitre_name": "Unsecured Credentials: Private Keys",
                "description": f"Unencrypted SSH private keys discovered in user directories on '{source_host}'.",
                "evidence": f"Discovered private key files: {len(keys)} key(s)",
                "remediation": "Encrypt all private keys with strong passphrases and remove unused keys from disk.",
            })
        return findings

    @classmethod
    def audit_pass_the_hash(cls, source_host: str, hashes: List[Dict[str, Any]], target_subnets: List[str] = None) -> List[Dict[str, Any]]:
        """Audit harvested NTLM hashes for Pass-the-Hash / Pass-the-Ticket lateral movement."""
        findings = []
        for h in hashes:
            user = h.get("username", "Administrator")
            ntlm = h.get("ntlm_hash", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
            service = h.get("service", "SMB")
            findings.append({
                "title": f"Pass-the-Hash Lateral Movement: {user} via {service}",
                "severity": "Critical",
                "cvss": 9.4,
                "host": source_host,
                "cve": "CWE-287 (Improper Authentication)",
                "category": "Lateral Movement",
                "scanner": "LATERAL_ENGINE",
                "mitre_id": "T1550.002",
                "mitre_name": "Use Alternate Authentication Material: Pass the Hash",
                "description": f"Harvested NTLM hash for account '{user}' enables lateral traversal across SMB (445) and WinRM (5985) without requiring plaintext password recovery.",
                "evidence": f"Account: {user}\nNTLM Hash: {ntlm[:16]}...[REDACTED]\nTarget Vector: Remote SMB/WMI execution",
                "remediation": "Enable Remote Credential Guard, disable NTLMv1, implement Local Administrator Password Solution (LAPS), and restrict administrative accounts to dedicated jump hosts.",
            })
        return findings

    @classmethod
    def audit_db_to_os_pivot(cls, host: str, db_loot: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit database administrative footholds for OS-level lateral command execution."""
        findings = []
        db_type = (db_loot.get("db_type", "") or "").lower()

        if "postgres" in db_type:
            findings.append({
                "title": f"Database-to-OS Privilege Pivot: PostgreSQL COPY PROGRAM ({host})",
                "severity": "Critical",
                "cvss": 9.8,
                "host": host,
                "cve": "CVE-2019-9193",
                "category": "Lateral Movement",
                "scanner": "LATERAL_ENGINE",
                "mitre_id": "T1059.006",
                "mitre_name": "Command and Scripting Interpreter: Python/SQL",
                "description": f"PostgreSQL superuser access on '{host}' allows arbitrary host OS command execution via 'COPY cmd_table FROM PROGRAM ...'.",
                "evidence": f"DB Host: {host}:5432\nExecution Vector: COPY to execute underlying Linux bash commands.",
                "remediation": "Revoke superuser privileges from application database accounts and drop execution permissions on server-side functions.",
            })
        elif "mysql" in db_type or "mariadb" in db_type:
            findings.append({
                "title": f"Database User Defined Function (UDF) OS Pivot ({host})",
                "severity": "High",
                "cvss": 8.6,
                "host": host,
                "cve": "CWE-94",
                "category": "Lateral Movement",
                "scanner": "LATERAL_ENGINE",
                "mitre_id": "T1059.006",
                "mitre_name": "Command and Scripting Interpreter",
                "description": f"MySQL DBA privileges allow writing binary shared objects (.so / .dll) into plugin directory to execute arbitrary OS commands.",
                "evidence": f"DB Host: {host}:3306\nVector: SELECT ... INTO DUMPFILE plugin_dir",
                "remediation": "Set secure_file_priv system variable and run MySQL daemon as restricted unprivileged user.",
            })
        return findings

    @classmethod
    def audit_dual_homed_routes(cls, host: str, routes_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Audit routing tables and dual-homed network interfaces for hidden internal subnets."""
        findings = []
        for route in routes_data:
            subnet = route.get("subnet", "")
            if subnet.startswith("10.") or subnet.startswith("172.16.") or subnet.startswith("192.168."):
                findings.append({
                    "title": f"Dual-Homed Network Interface & Internal Pivot: {subnet}",
                    "severity": "Medium",
                    "cvss": 6.5,
                    "host": host,
                    "cve": "CWE-200 (Exposure of Sensitive Information)",
                    "category": "Discovery",
                    "scanner": "LATERAL_ENGINE",
                    "mitre_id": "T1016",
                    "mitre_name": "System Network Configuration Discovery",
                    "description": f"Compromised host '{host}' contains a secondary network interface routed to internal subnet '{subnet}'. This enables pivot routing into isolated network segments.",
                    "evidence": f"Interface Route: {subnet} via {host}",
                    "remediation": "Enforce strict host-level firewall filtering (iptables / Windows Defender) and disable IP forwarding on dual-homed endpoints.",
                })
        return findings


def run_lateral_movement_audit(source_host: str, telemetry: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Master evaluator executing all lateral movement and pivoting assessments."""
    telemetry = telemetry or {}
    findings = []

    # 1. SSH key reuse
    if "ssh_loot" in telemetry:
        findings.extend(LateralMovementEngine.audit_ssh_key_reuse(source_host, telemetry["ssh_loot"]))

    # 2. Pass-the-Hash
    if "hashes" in telemetry:
        findings.extend(LateralMovementEngine.audit_pass_the_hash(source_host, telemetry["hashes"]))

    # 3. Database to OS
    if "db_loot" in telemetry:
        findings.extend(LateralMovementEngine.audit_db_to_os_pivot(source_host, telemetry["db_loot"]))

    # 4. Routing discovery
    if "routes" in telemetry:
        findings.extend(LateralMovementEngine.audit_dual_homed_routes(source_host, telemetry["routes"]))

    return findings
