"""
POP3S Exploit Module — Port 995
Wraps POP3 module with SSL-specific checks.
"""
from cyber_range.modules.port_110_pop3 import EXPLOITS as _BASE

MODULE_INFO = {
    "port": 995, "service": "pop3s",
    "name": "POP3S (Secure POP3) Module",
    "description": "POP3 over SSL — credential brute force plus SSL certificate analysis",
    "author": "Custom", "mitre": ["T1110", "T1040"],
}

EXPLOITS = list(_BASE) + [
    {"name": "SSL Certificate Inspection", "source": "custom", "type": "auxiliary",
     "msf_module": "",
     "description": "Extracts SSL certificate details for internal hostname discovery",
     "exec_command": "openssl s_client -connect {target}:995 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates",
     "risk": "Info — certificate reveals organization and hostname data"},
]

def enumerate(target_ip, service_info=None):
    return list(EXPLOITS)

def exploit(target_ip, port=995, exploit_info=None):
    ei = exploit_info or EXPLOITS[1]
    return {"command": ei["exec_command"].format(target=target_ip),
            "module": ei.get("msf_module", ""), "status": "ready",
            "target": f"{target_ip}:{port}"}
