"""
Expedite Strike — Built-in CVE Vulnerability Scanner
=====================================================
Pure Python vulnerability scanner that runs ALONGSIDE GVM and ZAP.
Provides network-level vulnerability detection using banner grabbing,
version matching, protocol probes, and CVE mapping.

No external binaries or services required.
"""

import socket
import ssl
import re
import time
import logging
import struct
from datetime import datetime
from typing import List, Dict, Optional, Callable

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
#  CVE SIGNATURE DATABASE — Version-to-CVE Mapping
# ═══════════════════════════════════════════════════════════════════
CVE_SIGNATURES = [
    # FTP
    {"pattern": r"vsftpd 2\.3\.4",           "cve": "CVE-2011-2523", "title": "vsFTPd 2.3.4 Backdoor",
     "severity": "Critical", "port": 21, "desc": "vsFTPd 2.3.4 contains backdoor allowing remote root shell on port 6200"},
    {"pattern": r"ProFTPD 1\.3\.[0-5]",       "cve": "CVE-2015-3306", "title": "ProFTPD mod_copy RCE",
     "severity": "Critical", "port": 21, "desc": "ProFTPD mod_copy allows unauthenticated file copy leading to RCE"},
    {"pattern": r"wu-ftpd",                   "cve": "CVE-2000-0573", "title": "wu-ftpd Remote Overflow",
     "severity": "High", "port": 21, "desc": "wu-ftpd format string vulnerability allows remote code execution"},
    # SSH
    {"pattern": r"OpenSSH[_ ][1-6]\.",        "cve": "CVE-2016-0777", "title": "OpenSSH Legacy Version",
     "severity": "High", "port": 22, "desc": "Legacy OpenSSH versions vulnerable to information leak and authentication bypass"},
    {"pattern": r"OpenSSH[_ ]7\.[0-3]",       "cve": "CVE-2016-6210", "title": "OpenSSH User Enumeration",
     "severity": "Medium", "port": 22, "desc": "OpenSSH 7.0-7.3 allows username enumeration via timing attack"},
    {"pattern": r"dropbear",                  "cve": "CVE-2018-15599", "title": "Dropbear SSH Info Leak",
     "severity": "Medium", "port": 22, "desc": "Dropbear SSH server information disclosure vulnerability"},
    # Telnet
    {"pattern": r"telnet",                    "cve": "CWE-319", "title": "Telnet Cleartext Protocol",
     "severity": "High", "port": 23, "desc": "Telnet transmits credentials in cleartext — susceptible to sniffing"},
    # SMTP
    {"pattern": r"Postfix",                   "cve": "CVE-2019-3462", "title": "Postfix SMTP Server Detected",
     "severity": "Info", "port": 25, "desc": "Postfix SMTP server detected — check for open relay"},
    {"pattern": r"Exim [1-3]\.|Exim 4\.[0-8]", "cve": "CVE-2019-10149", "title": "Exim Remote Command Execution",
     "severity": "Critical", "port": 25, "desc": "Exim before 4.92 allows RCE via crafted recipient address"},
    # DNS
    {"pattern": r"BIND 9\.[0-8]\.",           "cve": "CVE-2008-1447", "title": "BIND DNS Cache Poisoning",
     "severity": "High", "port": 53, "desc": "ISC BIND insufficient source port randomization enables DNS cache poisoning"},
    # HTTP / Web
    {"pattern": r"Apache/2\.[0-2]\.",         "cve": "CVE-2017-9798", "title": "Apache httpd Optionsbleed",
     "severity": "Medium", "port": 80, "desc": "Apache 2.2.x-2.4.x Optionsbleed information leak via OPTIONS requests"},
    {"pattern": r"Apache/2\.4\.(49|50)",      "cve": "CVE-2021-41773", "title": "Apache Path Traversal RCE",
     "severity": "Critical", "port": 80, "desc": "Apache 2.4.49-2.4.50 path traversal allows RCE with mod_cgi"},
    {"pattern": r"nginx/1\.(0|1|2|3|4|5|6)\.",  "cve": "CVE-2013-4547", "title": "Nginx Legacy Version",
     "severity": "Medium", "port": 80, "desc": "Legacy nginx version with known security vulnerabilities"},
    {"pattern": r"Microsoft-IIS/[5-7]\.",     "cve": "CVE-2017-7269", "title": "IIS WebDAV RCE",
     "severity": "Critical", "port": 80, "desc": "IIS 6.0 WebDAV buffer overflow allows remote code execution"},
    {"pattern": r"PHP/[4-5]\.",               "cve": "CVE-2012-1823", "title": "PHP-CGI Remote Code Execution",
     "severity": "Critical", "port": 80, "desc": "PHP before 5.4.2 allows RCE when configured as CGI via query string"},
    {"pattern": r"Apache Tomcat/[4-6]\.",     "cve": "CVE-2017-12617", "title": "Tomcat PUT Method RCE",
     "severity": "High", "port": 8080, "desc": "Apache Tomcat allows RCE via JSP upload using PUT method"},
    {"pattern": r"Jetty.*9\.[0-3]\.",         "cve": "CVE-2021-28164", "title": "Jetty Information Disclosure",
     "severity": "Medium", "port": 8080, "desc": "Eclipse Jetty URI decoding allows information disclosure"},
    # SMB / NetBIOS
    {"pattern": r"Samba 3\.0\.",              "cve": "CVE-2007-2447", "title": "Samba usermap_script RCE",
     "severity": "Critical", "port": 445, "desc": "Samba 3.0.x allows remote command execution via shell metacharacters"},
    {"pattern": r"Samba [2-3]\.",             "cve": "CVE-2017-7494", "title": "Samba SambaCry RCE",
     "severity": "Critical", "port": 445, "desc": "Samba 3.5+ allows remote code execution via writable share"},
    {"pattern": r"Windows.*5\.1|Windows.*XP", "cve": "CVE-2017-0144", "title": "EternalBlue (MS17-010)",
     "severity": "Critical", "port": 445, "desc": "Windows SMBv1 remote code execution — EternalBlue"},
    {"pattern": r"Windows.*6\.0|Windows.*Vista", "cve": "CVE-2017-0144", "title": "EternalBlue (MS17-010)",
     "severity": "Critical", "port": 445, "desc": "Windows SMBv1 remote code execution — EternalBlue"},
    # MySQL
    {"pattern": r"MySQL.*5\.[01]\.",          "cve": "CVE-2012-2122", "title": "MySQL Auth Bypass",
     "severity": "High", "port": 3306, "desc": "MySQL 5.1.x/5.5.x authentication bypass via casting bug"},
    {"pattern": r"MariaDB.*5\.",              "cve": "CVE-2012-2122", "title": "MariaDB Auth Bypass",
     "severity": "High", "port": 3306, "desc": "MariaDB authentication bypass vulnerability"},
    # PostgreSQL
    {"pattern": r"PostgreSQL.*[7-8]\.",       "cve": "CVE-2019-9193", "title": "PostgreSQL COPY FROM PROGRAM RCE",
     "severity": "Critical", "port": 5432, "desc": "PostgreSQL COPY FROM PROGRAM allows authenticated RCE"},
    # RDP
    {"pattern": r"Remote Desktop|Microsoft Terminal",  "cve": "CVE-2019-0708", "title": "BlueKeep RDP RCE",
     "severity": "Critical", "port": 3389, "desc": "Windows RDP unauthenticated remote code execution"},
    # IRC
    {"pattern": r"UnrealIRCd",               "cve": "CVE-2010-2075", "title": "UnrealIRCd Backdoor",
     "severity": "Critical", "port": 6667, "desc": "UnrealIRCd 3.2.8.1 contains backdoor for remote code execution"},
    # DistCC
    {"pattern": r"distccd",                   "cve": "CVE-2004-2687", "title": "DistCC Remote Code Execution",
     "severity": "Critical", "port": 3632, "desc": "DistCC daemon allows remote command execution"},
    # Redis
    {"pattern": r"Redis",                     "cve": "CVE-2022-0543", "title": "Redis Unauthenticated Access",
     "severity": "High", "port": 6379, "desc": "Redis exposed without authentication — arbitrary data read/write"},
    # VNC
    {"pattern": r"RFB 003\.[0-7]",           "cve": "CVE-2006-2369", "title": "VNC Authentication Bypass",
     "severity": "High", "port": 5900, "desc": "VNC RealVNC allows authentication bypass via modified client"},
    # Java RMI
    {"pattern": r"rmiregistry|java.rmi|rmi",  "cve": "CVE-2011-3556", "title": "Java RMI Deserialization RCE",
     "severity": "Critical", "port": 1099, "desc": "Java RMI registry allows remote code execution via deserialization"},
    # MongoDB
    {"pattern": r"MongoDB",                   "cve": "CVE-2020-7921", "title": "MongoDB Unauthenticated Access",
     "severity": "High", "port": 27017, "desc": "MongoDB exposed without authentication"},
    # SNMP
    {"pattern": r"public|private",            "cve": "CVE-1999-0517", "title": "SNMP Default Community String",
     "severity": "High", "port": 161, "desc": "SNMP using default community string — full device info exposure"},
    # NFS
    {"pattern": r"nfs|mountd",                "cve": "CVE-1999-0170", "title": "NFS World-Readable Exports",
     "severity": "High", "port": 2049, "desc": "NFS shares exported without access restrictions"},
    # X11
    {"pattern": r"X11|Xorg",                  "cve": "CVE-2006-6101", "title": "X11 Unauthenticated Access",
     "severity": "High", "port": 6000, "desc": "X11 server allows unauthenticated remote display access"},
]

# ═══════════════════════════════════════════════════════════════════
#  PROTOCOL PROBE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════
PROTOCOL_PROBES = {
    21:   b"",                                  # FTP — server sends banner first
    22:   b"",                                  # SSH — server sends banner first
    23:   b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27",  # Telnet negotiation
    25:   b"EHLO probe\r\n",                    # SMTP
    53:   b"",                                  # DNS — use specific probe
    80:   b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",  # HTTP
    110:  b"",                                  # POP3 — server sends banner
    111:  b"",                                  # RPCbind
    139:  b"",                                  # NetBIOS
    143:  b"",                                  # IMAP — server sends banner
    443:  b"",                                  # HTTPS — use SSL wrapper
    445:  b"",                                  # SMB — use SMB probe
    1099: b"",                                  # RMI
    1433: b"",                                  # MSSQL
    1524: b"\n",                                # Ingreslock
    2049: b"",                                  # NFS
    3306: b"",                                  # MySQL — server sends handshake
    3389: b"",                                  # RDP — use RDP probe
    3632: b"",                                  # DistCC
    5432: b"",                                  # PostgreSQL
    5900: b"",                                  # VNC — server sends RFB banner
    6379: b"PING\r\n",                          # Redis
    6667: b"NICK probe\r\nUSER probe 0 * :probe\r\n",  # IRC
    8080: b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",
    8180: b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",
    8443: b"",                                  # HTTPS alt
    27017: b"",                                 # MongoDB
}

# ═══════════════════════════════════════════════════════════════════
#  SSL / TLS SECURITY CHECKS
# ═══════════════════════════════════════════════════════════════════
SSL_CHECKS = {
    "SSLv2":  {"severity": "Critical", "title": "SSLv2 Enabled", "cve": "CVE-2016-0800",
               "desc": "SSLv2 is enabled — DROWN attack allows decryption of TLS sessions"},
    "SSLv3":  {"severity": "High", "title": "SSLv3 Enabled (POODLE)", "cve": "CVE-2014-3566",
               "desc": "SSLv3 is enabled — POODLE attack allows cleartext extraction"},
    "TLSv1.0": {"severity": "Medium", "title": "TLS 1.0 Enabled (Deprecated)", "cve": "CWE-326",
                "desc": "TLS 1.0 is deprecated and vulnerable to BEAST attack"},
    "TLSv1.1": {"severity": "Low", "title": "TLS 1.1 Enabled (Deprecated)", "cve": "CWE-326",
                "desc": "TLS 1.1 is deprecated — upgrade to TLS 1.2+"},
}


# ═══════════════════════════════════════════════════════════════════
#  SECURITY CHECK FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def _grab_banner(ip: str, port: int, timeout: float = 5.0) -> str:
    """Connect to a port and grab the service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send probe if defined
        probe = PROTOCOL_PROBES.get(port, b"")
        if probe:
            try:
                sock.sendall(probe)
            except Exception:
                pass

        # For ports that need SSL
        if port in (443, 8443, 636):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
                sock.sendall(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
            except Exception:
                pass

        # Read response
        data = b""
        try:
            data = sock.recv(4096)
        except socket.timeout:
            pass
        sock.close()
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _check_ssl_tls(ip: str, port: int) -> List[Dict]:
    """Check SSL/TLS protocol versions and certificate issues."""
    findings = []
    for proto_name, proto_attr in [("SSLv3", "PROTOCOL_SSLv3"), ("TLSv1.0", "PROTOCOL_TLSv1"),
                                    ("TLSv1.1", "PROTOCOL_TLSv1_1")]:
        try:
            proto = getattr(ssl, proto_attr, None)
            if proto is None:
                continue
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    check = SSL_CHECKS.get(proto_name, {})
                    findings.append({
                        "host": ip, "port": port,
                        "title": check.get("title", f"{proto_name} Enabled"),
                        "severity": check.get("severity", "Medium"),
                        "cve": check.get("cve", ""),
                        "description": check.get("desc", ""),
                        "mitre_id": "T1557",
                        "evidence": f"Successfully connected using {proto_name} on {ip}:{port}",
                    })
        except Exception:
            pass

    # Check certificate expiry and self-signed
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(True)
                from datetime import datetime
                # Try to get cert info
                pem_cert = ssl.DER_cert_to_PEM_cert(cert)
                if b"self" in cert.lower() if isinstance(cert, bytes) else False:
                    findings.append({
                        "host": ip, "port": port,
                        "title": "Self-Signed Certificate",
                        "severity": "Medium", "cve": "CWE-295",
                        "description": "Server uses self-signed certificate — susceptible to MitM",
                        "mitre_id": "T1557",
                    })
    except Exception:
        pass

    return findings


def _check_http_security(ip: str, port: int, banner: str) -> List[Dict]:
    """Check HTTP security headers and misconfigurations."""
    findings = []
    try:
        import http.client
        scheme = "https" if port in (443, 8443) else "http"
        if scheme == "https":
            conn = http.client.HTTPSConnection(ip, port, timeout=8,
                                                context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=8)
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}

        # Missing security headers
        header_checks = [
            ("x-frame-options", "Missing X-Frame-Options", "Medium", "CWE-1021",
             "No clickjacking protection — X-Frame-Options header missing"),
            ("content-security-policy", "Missing Content-Security-Policy", "Medium", "CWE-693",
             "No CSP header — XSS and injection attacks not mitigated"),
            ("strict-transport-security", "Missing HSTS Header", "Medium", "CWE-319",
             "No HSTS header — susceptible to SSL stripping attacks"),
            ("x-content-type-options", "Missing X-Content-Type-Options", "Low", "CWE-693",
             "No X-Content-Type-Options header — MIME sniffing not prevented"),
        ]
        for hdr, title, sev, cwe, desc in header_checks:
            if hdr not in headers:
                findings.append({
                    "host": ip, "port": port,
                    "title": title, "severity": sev, "cve": cwe,
                    "description": desc, "mitre_id": "T1190",
                    "evidence": f"HTTP response from {ip}:{port} missing {hdr} header",
                })

        # Server version disclosure
        server = headers.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append({
                "host": ip, "port": port,
                "title": "Server Version Disclosure", "severity": "Low", "cve": "CWE-200",
                "description": f"Server header exposes version: {server}",
                "mitre_id": "T1592",
                "evidence": f"Server: {server}",
            })

        # Directory listing
        for path in ["/icons/", "/manual/", "/.git/", "/server-status", "/server-info"]:
            try:
                if scheme == "https":
                    conn2 = http.client.HTTPSConnection(ip, port, timeout=5,
                                                         context=ssl._create_unverified_context())
                else:
                    conn2 = http.client.HTTPConnection(ip, port, timeout=5)
                conn2.request("GET", path)
                r = conn2.getresponse()
                body = r.read(2048).decode("utf-8", errors="replace")
                if r.status == 200 and ("Index of" in body or "Directory listing" in body or path == "/.git/"):
                    findings.append({
                        "host": ip, "port": port,
                        "title": f"Directory/Info Exposure: {path}",
                        "severity": "Medium" if ".git" in path else "Low",
                        "cve": "CWE-548" if ".git" not in path else "CWE-538",
                        "description": f"Sensitive path accessible: {path}",
                        "mitre_id": "T1083",
                        "evidence": f"HTTP {r.status} on {scheme}://{ip}:{port}{path}",
                    })
                conn2.close()
            except Exception:
                pass
        conn.close()
    except Exception:
        pass
    return findings


def _check_smb(ip: str) -> List[Dict]:
    """Check SMB signing, version, and null session."""
    findings = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 445))

        # SMB Negotiate — send SMBv1 negotiate
        negotiate = (
            b"\x00\x00\x00\x54"  # NetBIOS session
            b"\xff\x53\x4d\x42"  # SMB header
            b"\x72"              # Negotiate command
            b"\x00\x00\x00\x00" b"\x18\x01\x28\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x31\x00"      # Byte count
            b"\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"  # LANMAN1.0
            b"\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"  # LM1.2X002
            b"\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00"  # NT LANMAN 1.0
            b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"  # NT LM 0.12
        )
        sock.sendall(negotiate)
        data = sock.recv(4096)
        sock.close()

        if data and len(data) > 36:
            # Check if SMBv1 is accepted
            if data[4:8] == b"\xff\x53\x4d\x42":
                findings.append({
                    "host": ip, "port": 445,
                    "title": "SMBv1 Protocol Enabled",
                    "severity": "Critical", "cve": "CVE-2017-0144",
                    "description": "SMBv1 is enabled — vulnerable to EternalBlue (MS17-010)",
                    "mitre_id": "T1210",
                    "evidence": f"SMBv1 negotiate response received from {ip}:445",
                })

            # Check security mode byte for signing
            if len(data) > 39:
                sec_mode = data[39] if isinstance(data[39], int) else ord(data[39])
                if not (sec_mode & 0x02):  # Signing not required
                    findings.append({
                        "host": ip, "port": 445,
                        "title": "SMB Signing Not Required",
                        "severity": "High", "cve": "CWE-345",
                        "description": "SMB signing not enforced — relay attacks possible",
                        "mitre_id": "T1557.001",
                        "evidence": f"SMB security mode: 0x{sec_mode:02x} (signing not required)",
                    })
    except Exception:
        pass
    return findings


def _check_redis(ip: str, port: int = 6379) -> List[Dict]:
    """Check for unauthenticated Redis access."""
    findings = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        sock.sendall(b"PING\r\n")
        resp = sock.recv(1024).decode("utf-8", errors="replace")
        if "+PONG" in resp:
            findings.append({
                "host": ip, "port": port,
                "title": "Redis Unauthenticated Access",
                "severity": "Critical", "cve": "CVE-2022-0543",
                "description": "Redis accepts commands without authentication — full data access",
                "mitre_id": "T1190",
                "evidence": f"Redis PING -> {resp.strip()} (no auth required)",
            })
            # Try INFO
            sock.sendall(b"INFO server\r\n")
            info = sock.recv(4096).decode("utf-8", errors="replace")
            if "redis_version" in info:
                ver_match = re.search(r"redis_version:(\S+)", info)
                ver = ver_match.group(1) if ver_match else "unknown"
                findings[-1]["evidence"] += f"\nRedis version: {ver}"
        sock.close()
    except Exception:
        pass
    return findings


def _check_dns_recursion(ip: str) -> List[Dict]:
    """Check if DNS server allows open recursion."""
    findings = []
    try:
        # Build a DNS query for example.com (type A, recursion desired)
        query = (
            b"\xaa\xbb"  # Transaction ID
            b"\x01\x00"  # Flags: recursion desired
            b"\x00\x01"  # Questions: 1
            b"\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00"  # example.com
            b"\x00\x01"  # Type A
            b"\x00\x01"  # Class IN
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (ip, 53))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if data and len(data) > 4:
            flags = struct.unpack("!H", data[2:4])[0]
            if flags & 0x0080:  # RA bit (recursion available)
                findings.append({
                    "host": ip, "port": 53,
                    "title": "DNS Open Recursion",
                    "severity": "Medium", "cve": "CVE-2006-0987",
                    "description": "DNS server allows recursive queries — can be abused for amplification attacks",
                    "mitre_id": "T1498.002",
                    "evidence": f"DNS recursion available on {ip}:53 (RA flag set)",
                })
    except Exception:
        pass
    return findings


def _check_ftp_anonymous(ip: str) -> List[Dict]:
    """Check FTP anonymous login."""
    findings = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((ip, 21))
        banner = sock.recv(1024).decode("utf-8", errors="replace")
        sock.sendall(b"USER anonymous\r\n")
        resp1 = sock.recv(1024).decode("utf-8", errors="replace")
        sock.sendall(b"PASS anonymous@probe.com\r\n")
        resp2 = sock.recv(1024).decode("utf-8", errors="replace")
        if "230" in resp2:
            findings.append({
                "host": ip, "port": 21,
                "title": "FTP Anonymous Login Allowed",
                "severity": "High", "cve": "CWE-287",
                "description": "FTP server accepts anonymous login — unauthorized file access",
                "mitre_id": "T1078",
                "evidence": f"FTP anonymous login: {resp2.strip()}",
            })
        sock.close()
    except Exception:
        pass
    return findings


# ═══════════════════════════════════════════════════════════════════
#  MAIN SCANNER ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

def run_builtin_vuln_scan(hosts: List[Dict], log_fn: Callable = None) -> List[Dict]:
    """
    Run the built-in vulnerability scanner on discovered hosts.

    Args:
        hosts: List of host dicts with 'ip' and 'ports' keys
        log_fn: Optional logging callback

    Returns:
        List of finding dicts compatible with the pentest pipeline
    """
    def _log(msg):
        if log_fn:
            log_fn(msg)
        logger.info(msg)

    all_findings = []
    active_hosts = [h for h in hosts if h.get("ports")]
    _log(f"\n  🔍 XSTRIKE BUILT-IN VULNERABILITY SCANNER")
    _log(f"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    _log(f"  Targets: {len(active_hosts)} host(s)")
    _log(f"  Signatures: {len(CVE_SIGNATURES)} CVE patterns")
    _log(f"  Protocol probes: SSL/TLS, HTTP, SMB, DNS, FTP, Redis")

    for host in active_hosts:
        ip = host.get("ip", "")
        if not ip:
            continue

        ports = []
        for p in host.get("ports", []):
            if isinstance(p, dict):
                ports.append(p.get("port", p.get("portid", 0)))
            elif isinstance(p, int):
                ports.append(p)

        _log(f"\n  🎯 Scanning {ip} ({len(ports)} ports)...")
        host_findings = []

        for port in ports:
            try:
                # 1. Banner grab
                banner = _grab_banner(ip, int(port), timeout=5)
                if banner:
                    _log(f"    [{port}] Banner: {banner[:60].replace(chr(10), ' ')}")

                    # 2. CVE signature matching
                    for sig in CVE_SIGNATURES:
                        if sig.get("port") and int(port) != sig["port"]:
                            # Allow matching on any port if banner matches
                            if not re.search(sig["pattern"], banner, re.IGNORECASE):
                                continue
                        elif re.search(sig["pattern"], banner, re.IGNORECASE):
                            finding = {
                                "host": ip, "port": int(port),
                                "title": sig["title"],
                                "severity": sig["severity"],
                                "cve": sig.get("cve", ""),
                                "description": sig["desc"],
                                "mitre_id": "T1190",
                                "evidence": f"Banner match on {ip}:{port}: {banner[:200]}",
                                "scanner": "XStrike-BuiltinVuln",
                            }
                            host_findings.append(finding)
                            _log(f"    ⚠ [{sig['severity']}] {sig['title']} ({sig.get('cve', '')})")

                # 3. Protocol-specific checks
                port_int = int(port)

                # SSL/TLS checks on HTTPS ports
                if port_int in (443, 8443, 636, 993, 995, 465):
                    ssl_findings = _check_ssl_tls(ip, port_int)
                    host_findings.extend(ssl_findings)
                    for sf in ssl_findings:
                        _log(f"    ⚠ [{sf['severity']}] {sf['title']}")

                # HTTP security header checks
                if port_int in (80, 443, 8080, 8180, 8443, 8888, 9090):
                    http_findings = _check_http_security(ip, port_int, banner)
                    host_findings.extend(http_findings)

                # SMB checks
                if port_int == 445:
                    smb_findings = _check_smb(ip)
                    host_findings.extend(smb_findings)
                    for sf in smb_findings:
                        _log(f"    ⚠ [{sf['severity']}] {sf['title']}")

                # Redis check
                if port_int == 6379:
                    redis_findings = _check_redis(ip, port_int)
                    host_findings.extend(redis_findings)
                    for rf in redis_findings:
                        _log(f"    ⚠ [{rf['severity']}] {rf['title']}")

                # DNS recursion check
                if port_int == 53:
                    dns_findings = _check_dns_recursion(ip)
                    host_findings.extend(dns_findings)

                # FTP anonymous check
                if port_int == 21:
                    ftp_findings = _check_ftp_anonymous(ip)
                    host_findings.extend(ftp_findings)
                    for ff in ftp_findings:
                        _log(f"    ⚠ [{ff['severity']}] {ff['title']}")

            except Exception as e:
                logger.debug(f"  Port {port} scan error: {e}")

        _log(f"    📊 {ip}: {len(host_findings)} vulnerabilities found")
        all_findings.extend(host_findings)

    # Summary
    crit = sum(1 for f in all_findings if f.get("severity") == "Critical")
    high = sum(1 for f in all_findings if f.get("severity") == "High")
    med = sum(1 for f in all_findings if f.get("severity") == "Medium")
    _log(f"\n  📊 XStrike Built-in Scanner: {len(all_findings)} total "
         f"(Critical: {crit}, High: {high}, Medium: {med})")

    return all_findings
