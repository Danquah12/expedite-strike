"""
IMAPS Exploit Module — Port 993
Wraps IMAP module with SSL-specific checks.
"""
from cyber_range.modules.port_143_imap import EXPLOITS as _BASE, enumerate as _base_enum

MODULE_INFO = {
    "port": 993, "service": "imaps",
    "name": "IMAPS (Secure IMAP) Module",
    "description": "IMAP over SSL — same brute force attacks plus SSL certificate inspection",
    "author": "Custom", "mitre": ["T1110", "T1114"],
}

EXPLOITS = list(_BASE) + [
    {"name": "SSL Certificate Inspection", "source": "custom", "type": "auxiliary",
     "msf_module": "",
     "description": "Extracts SSL certificate details — reveals hostnames, org names, expiry dates",
     "exec_command": "openssl s_client -connect {target}:993 -servername {target} </dev/null 2>/dev/null | openssl x509 -noout -subject -dates -issuer",
     "risk": "Info — certificate data reveals internal hostnames and organization details"},
]

def enumerate(target_ip, service_info=None):
    return list(EXPLOITS)

def exploit(target_ip, port=993, exploit_info=None):
    ei = exploit_info or EXPLOITS[1]
    return {"command": ei["exec_command"].format(target=target_ip),
            "module": ei.get("msf_module", ""), "status": "ready",
            "target": f"{target_ip}:{port}"}
