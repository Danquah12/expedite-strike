import os
import json
import subprocess
import glob
import xml.etree.ElementTree as ET
import html
import re
from typing import List, Dict, Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CVSS_RE = re.compile(r"CVSS:[^\s]+", re.IGNORECASE)

DEFAULT_PORT_EXPLOITS = {
    # File Transfer & Management
    21: {"Title": "FTP Anonymous Login & Brute Force", "Path": "auxiliary/scanner/ftp/ftp_login"},
    22: {"Title": "SSH Brute Force & Key Enumeration", "Path": "auxiliary/scanner/ssh/ssh_login"},
    23: {"Title": "Telnet Credential Stuffing", "Path": "auxiliary/scanner/telnet/telnet_login"},
    
    # Email & Directory
    25: {"Title": "SMTP User Enumeration", "Path": "auxiliary/scanner/smtp/smtp_enum"},
    53: {"Title": "DNS Zone Transfer", "Path": "auxiliary/gather/enum_dns"},
    110: {"Title": "POP3 Login Utility", "Path": "auxiliary/scanner/pop3/pop3_login"},
    143: {"Title": "IMAP4 Login Utility", "Path": "auxiliary/scanner/imap/imap_login"},
    389: {"Title": "LDAP Anonymous Bind & Query", "Path": "auxiliary/gather/ldap_hashdump"},
    3268: {"Title": "LDAP Global Catalog Query", "Path": "auxiliary/gather/ldap_hashdump"},
    
    # Web & Application Services
    80: {"Title": "Web App Vulnerability Scanner (LFI/RFI/SQLi)", "Path": "auxiliary/scanner/http/http_version"},
    443: {"Title": "Web App Vulnerability Scanner (SSL)", "Path": "auxiliary/scanner/http/http_version"},
    8080: {"Title": "Apache Tomcat Manager Application", "Path": "exploit/multi/http/tomcat_mgr_upload"},
    8443: {"Title": "Web App Vulnerability Scanner (Alternative SSL)", "Path": "auxiliary/scanner/http/http_version"},
    1099: {"Title": "Java RMI Server Insecure Default Configuration", "Path": "exploit/multi/misc/java_rmi_server"},
    
    # RPC & Windows Networking
    111: {"Title": "RPC Portmapper Enumeration", "Path": "auxiliary/scanner/misc/sunrpc_portmapper"},
    135: {"Title": "MS-RPC Endpoint Mapper Enumeration", "Path": "auxiliary/scanner/dcerpc/endpoint_mapper"},
    139: {"Title": "SMB Relay & Exploit Framework", "Path": "exploit/windows/smb/psexec"},
    445: {"Title": "SMB MS17-010 EternalBlue / Pass-The-Hash", "Path": "exploit/windows/smb/ms17_010_eternalblue"},
    
    # Remote Management
    5985: {"Title": "WinRM Command Execution", "Path": "exploit/windows/local/winrm_vbs"},
    5986: {"Title": "WinRM Command Execution (SSL)", "Path": "exploit/windows/local/winrm_vbs"},
    3389: {"Title": "RDP BlueKeep / Check & Exploit", "Path": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"},
    4899: {"Title": "Radmin Password Brute Force", "Path": "auxiliary/scanner/radmin/radmin_login"},
    5900: {"Title": "VNC Authentication Bypass / Brute Force", "Path": "auxiliary/scanner/vnc/vnc_login"},
    
    # Databases
    1433: {"Title": "MSSQL Authentication Brute Force & Code Execution", "Path": "exploit/windows/mssql/mssql_payload"},
    1521: {"Title": "Oracle TNS Listener Checker / Brute Force", "Path": "auxiliary/scanner/oracle/tnslsnr_version"},
    3306: {"Title": "MySQL Authentication Bypass / Hashdump", "Path": "auxiliary/scanner/mysql/mysql_login"},
    5432: {"Title": "PostgreSQL Payload Execution / Brute Force", "Path": "exploit/linux/postgres/postgres_payload"},
    6379: {"Title": "Redis Unauthenticated Command Execution", "Path": "exploit/linux/redis/redis_replication_cmd_exec"},
    27017: {"Title": "MongoDB Unauthenticated Access / Enum", "Path": "auxiliary/scanner/mongodb/mongodb_login"},
    9200: {"Title": "Elasticsearch Dynamic Script Arbitrary Code Execution", "Path": "exploit/multi/elasticsearch/script_mvel_rce"},
    
    # Infrastructure & IoT
    161: {"Title": "SNMP Community String Brute Force", "Path": "auxiliary/scanner/snmp/snmp_login"},
    500: {"Title": "IKE/IPSec Aggressive Mode Pre-Shared Key Crack", "Path": "auxiliary/scanner/ike/cisco_ike_benign"},
    5060: {"Title": "SIP Username Enumeration", "Path": "auxiliary/scanner/sip/enumerator"}
}

class IntelOrchestrator:
    def __init__(self, scan_dir="/mnt/scans/incoming/nmap"):
        self.scan_dir = scan_dir
        self.parsed_assets = []
        self.parsed_services = []
        self.parsed_vulns = []
        
    def _parse_nmap_xml(self, file_path: str):
        """Extracts IPs, ports, and services from a single NMAP XML file."""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as e:
            return

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.attrib.get("state") != "up":
                continue

            ip = None
            mac_addr = None
            for address in host.findall("address"):
                if address.attrib.get("addrtype") == "ipv4":
                    ip = address.attrib.get("addr")
                elif address.attrib.get("addrtype") == "mac":
                    mac_addr = address.attrib.get("addr")

            if not ip:
                continue

            if ip not in [a["ip"] for a in self.parsed_assets]:
                self.parsed_assets.append({"ip": ip, "mac": mac_addr})

            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue

                portid = int(port.attrib["portid"])
                proto = port.attrib["protocol"]

                svc = port.find("service")
                if svc is None:
                    continue

                service_name = svc.attrib.get("name")
                product = svc.attrib.get("product", "")
                version = svc.attrib.get("version", "")
                
                # Deduplicate service entries per IP/Port
                svc_entry = {
                    "ip": ip,
                    "port": portid,
                    "protocol": proto,
                    "service": service_name,
                    "product": product,
                    "version": version
                }
                if svc_entry not in self.parsed_services:
                    self.parsed_services.append(svc_entry)
                    
    def run_enumeration_scan(self):
        """Scans the configured directory for XML files and extracts standard attributes."""
        self.parsed_assets = []
        self.parsed_services = []
        self.parsed_vulns = []
        
        if not os.path.exists(self.scan_dir):
            return
            
        xml_files = glob.glob(os.path.join(self.scan_dir, "*.xml"))
        for xml_file in xml_files:
            self._parse_nmap_xml(xml_file)

    def query_searchsploit(self, query: str) -> List[Dict[str, str]]:
        """Executes searchsploit and extracts JSON results for a given query."""
        if not query.strip():
            return []
            
        try:
            # -j for JSON output, -w for precise word matching (usually better for specific version strings but we'll stick to broad search for now)
            result = subprocess.run(['searchsploit', query, '--json'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return data.get("RESULTS_EXPLOIT", [])
        except Exception as e:
            pass
            
        return []

    def generate_exploitation_matrix(self) -> List[Dict[str, Any]]:
        """
        Synthesizes the parsed NMAP services against SearchSploit.
        Returns a list of unified dictionary rows intended for the UI DataTable.
        """
        matrix = []
        
        # Ensure we have data loaded from local XMLs
        if not self.parsed_services:
            self.run_enumeration_scan()
            
        # ── ALSO pull live services from Neo4j (Nmap, ZAP, Aegispro) ────────
        try:
            from app import neo4j_driver
            with neo4j_driver.session() as session:
                db_svcs = session.run("""
                    MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
                    RETURN h.ip AS ip, s.port AS port, s.protocol AS protocol, 
                           s.name AS service, s.product AS product, s.version AS version
                """).data()
                for r in db_svcs:
                    svc_entry = {
                        "ip": r.get("ip"),
                        "port": r.get("port"),
                        "protocol": r.get("protocol", "tcp"),
                        "service": r.get("service", ""),
                        "product": r.get("product", ""),
                        "version": r.get("version", "")
                    }
                    if svc_entry not in self.parsed_services:
                        self.parsed_services.append(svc_entry)
        except Exception as e:
            print(f"[IntelOrchestrator] Failed to fetch Neo4j services: {e}")
            
        # Iterate over discovered services and hunt for exploits
        for svc in self.parsed_services:
            # Build an intelligent query string (e.g., "apache 2.4" or "vsftpd 2.3.4")
            query_parts = []
            if svc["product"]:
                query_parts.append(svc["product"])
            elif svc["service"]:
                query_parts.append(svc["service"])
                
            if svc["version"]:
                query_parts.append(svc["version"])
                
            query = " ".join(query_parts).strip()
            
            exploits = []
            if query:
                # To prevent spamming SearchSploit with generic terms like "http" or "ssh", we require at least a product or version
                if len(query) > 3 and query.lower() not in ["http", "ssh", "domain", "tcp", "udp"]:
                    exploits = self.query_searchsploit(query)
            
            # If exploits were found, map the *best* one (or top 3) to the matrix. 
            # For simplicity in the UI, we'll map the first verified Remote exploit, or just the first hit.
            if exploits:
                top_exploit = exploits[0]
                matrix.append({
                    "id": f"{svc['ip']}_{svc['port']}_{top_exploit.get('EDB-ID', 'searchsploit')}",
                    "target_ip": svc["ip"],
                    "port": svc["port"],
                    "service": query or "Unknown",
                    "exploit_name": top_exploit.get("Title", "Unknown Exploit"),
                    "exploit_path": top_exploit.get("Path", "N/A"),
                    "verified": bool(int(top_exploit.get("Verified", 0)))
                })
            else:
                # Fallback: if searchsploit didn't trigger, map a default module based on the port
                port_num = int(svc["port"])
                fallback = DEFAULT_PORT_EXPLOITS.get(port_num)
                
                if fallback:
                    matrix.append({
                        "id": f"{svc['ip']}_{svc['port']}_fallback",
                        "target_ip": svc["ip"],
                        "port": svc["port"],
                        "service": svc.get("service", "Unknown"),
                        "exploit_name": fallback["Title"],
                        "exploit_path": fallback["Path"],
                        "verified": True # Default payloads are considered verified/reliable
                    })
                else:
                    # Generic fallback for completely unknown ports we still want to hit
                    matrix.append({
                        "id": f"{svc['ip']}_{svc['port']}_generic",
                        "target_ip": svc["ip"],
                        "port": svc["port"],
                        "service": svc.get("service", "Unknown"),
                        "exploit_name": "Generic TCP Service Fuzzing & Probing",
                        "exploit_path": "auxiliary/scanner/portscan/tcp",
                        "verified": False
                    })
                
        return matrix
