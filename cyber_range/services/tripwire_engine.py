"""
Expedite Strike Tripwire & Deception Engine
====================================
Deploy canary credentials, honey files, and canary tokens on compromised hosts.

MITRE ATT&CK: T1036 (Masquerading - for detection)
"""

import os
import uuid
import json
import time
from datetime import datetime
from typing import Callable

_log_fn = None
def _log(msg):
    if _log_fn:
        _log_fn(msg)

CANARY_CREDS = [
    {"username": "svc_backup", "password": "B@ckup2024!Secure"},
    {"username": "admin_prod", "password": "Pr0d-Adm1n-2024"},
    {"username": "sql_service", "password": "SQLsvc_Pass#99"},
    {"username": "domain_admin", "password": "DA-Secret-Key!"},
]

HONEY_FILES = [
    {"name": "passwords.xlsx", "content": "Username,Password\nsvc_backup,B@ckup2024!Secure\nadmin,Canary-Trap-Alert"},
    {"name": "vpn_credentials.txt", "content": "VPN Server: vpn.corp.local\nUsername: vpn_admin\nPassword: VPN-Canary-2024!"},
    {"name": "database_config.ini", "content": "[mysql]\nhost=db01.internal\nuser=root\npassword=Canary-DB-Trap!"},
    {"name": "ssh_keys_backup.txt", "content": "# SSH Key Backup - DO NOT DELETE\n# This is a canary file - any access triggers alert"},
]


def deploy_canary_creds(ip: str, username: str, password: str,
                        log_fn: Callable = None) -> list:
    """Plant fake credentials on compromised hosts."""
    global _log_fn
    _log_fn = log_fn
    deployed = []

    _log(f"  [TRIPWIRE] Deploying canary credentials on {ip}...")

    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password,
                       timeout=10, allow_agent=False, look_for_keys=False)

        for cred in CANARY_CREDS:
            cmd = f'echo "{cred["username"]}:{cred["password"]}" >> /tmp/.cached_credentials 2>/dev/null'
            client.exec_command(cmd)
            deployed.append({
                "type": "credential",
                "host": ip,
                "location": "/tmp/.cached_credentials",
                "username": cred["username"],
                "deployed_at": datetime.now().isoformat(),
            })

        client.close()
        _log(f"  [TRIPWIRE] \ud83e\udea4 Deployed {len(deployed)} canary creds on {ip}")

    except Exception as e:
        _log(f"  [TRIPWIRE] Error: {e}")

    _log_fn = None
    return deployed


def deploy_honey_files(ip: str, username: str, password: str,
                       log_fn: Callable = None) -> list:
    """Place decoy files on compromised hosts."""
    global _log_fn
    _log_fn = log_fn
    deployed = []

    _log(f"  [TRIPWIRE] Deploying honey files on {ip}...")

    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password,
                       timeout=10, allow_agent=False, look_for_keys=False)

        locations = ["/tmp", "/home", "/var/tmp"]
        for loc in locations:
            for hf in HONEY_FILES:
                path = f"{loc}/{hf['name']}"
                cmd = f'echo "{hf["content"]}" > {path} 2>/dev/null'
                client.exec_command(cmd)
                deployed.append({
                    "type": "honey_file",
                    "host": ip,
                    "path": path,
                    "filename": hf["name"],
                    "deployed_at": datetime.now().isoformat(),
                })

        client.close()
        _log(f"  [TRIPWIRE] \ud83c\udf6f Deployed {len(deployed)} honey files on {ip}")

    except Exception as e:
        _log(f"  [TRIPWIRE] Error: {e}")

    _log_fn = None
    return deployed


def deploy_canary_tokens(ip: str, username: str, password: str,
                         token_url: str = "https://canarytokens.com/about",
                         log_fn: Callable = None) -> list:
    """Deploy canary token URLs that trigger alerts when accessed."""
    global _log_fn
    _log_fn = log_fn
    deployed = []

    _log(f"  [TRIPWIRE] Deploying canary tokens on {ip}...")

    token_id = str(uuid.uuid4())[:8]
    canary_content = f"""
# INTERNAL ADMIN PORTAL - CONFIDENTIAL
# Access URL: {token_url}/track/{token_id}
# Last updated: {datetime.now().isoformat()}
# Contact: security@corp.local
"""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password,
                       timeout=10, allow_agent=False, look_for_keys=False)

        cmd = f'echo "{canary_content}" > /tmp/admin_portal.conf 2>/dev/null'
        client.exec_command(cmd)
        deployed.append({
            "type": "canary_token",
            "host": ip,
            "token_id": token_id,
            "url": f"{token_url}/track/{token_id}",
            "deployed_at": datetime.now().isoformat(),
        })

        client.close()
        _log(f"  [TRIPWIRE] \ud83d\udd14 Deployed canary token on {ip} (ID: {token_id})")

    except Exception as e:
        _log(f"  [TRIPWIRE] Error: {e}")

    _log_fn = None
    return deployed


def run_deception_ops(compromised_hosts: list, log_fn: Callable = None) -> dict:
    """Full deception deployment on all compromised hosts."""
    global _log_fn
    _log_fn = log_fn

    result = {"canary_creds": [], "honey_files": [], "canary_tokens": [], "total_deployed": 0}

    for h in compromised_hosts:
        ip = h.get("ip", "")
        user = h.get("username", "")
        pw = h.get("password", "")
        if not ip or not user or not pw:
            continue

        result["canary_creds"].extend(deploy_canary_creds(ip, user, pw, log_fn))
        result["honey_files"].extend(deploy_honey_files(ip, user, pw, log_fn))
        result["canary_tokens"].extend(deploy_canary_tokens(ip, user, pw, log_fn=log_fn))

    result["total_deployed"] = (len(result["canary_creds"]) +
                                 len(result["honey_files"]) +
                                 len(result["canary_tokens"]))

    _log(f"  [TRIPWIRE] \ud83c\udfaf Total deployed: {result['total_deployed']} deception items")
    _log_fn = None
    return result
