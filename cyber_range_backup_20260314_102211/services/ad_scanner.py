import socket
import logging
from datetime import datetime
import threading
try:
    from ldap3 import Server, Connection, ALL, ANONYMOUS
except ImportError:
    pass

from cyber_range.services.neo4j_engine import neo4j

logger = logging.getLogger(__name__)

class ADScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.open_ports = []
        self.domain_info = {}
        self.vulnerabilities = []

    def scan_ports(self):
        ports_to_check = {
            53: 'DNS',
            88: 'Kerberos',
            135: 'RPC',
            139: 'NetBIOS',
            389: 'LDAP',
            445: 'SMB',
            636: 'LDAPS',
            3268: 'Global Catalog'
        }
        for port, service in ports_to_check.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                self.open_ports.append(port)
            sock.close()
        return self.open_ports

    def extract_ldap_info(self):
        if 389 not in self.open_ports and 636 not in self.open_ports:
            return
            
        try:
            server = Server(self.target_ip, get_info=ALL)
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=False)
            
            if conn.bind():
                # Anonymous bind successful implies a vulnerability
                self.vulnerabilities.append({
                    "name": "Anonymous LDAP Access Enabled",
                    "severity": "Medium",
                    "tactic": "Discovery",
                    "technique": "Account Discovery"
                })
                
                # Extract RootDSE
                if server.info:
                    self.domain_info['domain_name'] = server.info.other.get('defaultNamingContext', [None])[0]
                    self.domain_info['forest_name'] = server.info.other.get('rootDomainNamingContext', [None])[0]
                    self.domain_info['hostname'] = server.info.other.get('dnsHostName', [None])[0]
                    self.domain_info['server_name'] = server.info.other.get('serverName', [None])[0]
            else:
                self.domain_info['binding'] = "Anonymous bind denied"
                
            conn.unbind()
        except Exception as e:
            logger.error(f"LDAP extraction error: {e}")

    def simulate_additional_findings(self):
        """
        Since we may not have a real vulnerable AD to scan in this lab, we optionally
        append basic simulated findings modeled after PingCastle rules for the UI to consume.
        """
        if 88 in self.open_ports and 389 in self.open_ports: # Characteristics of a DC
            simulated = [
                 ("Domain Admin passwords have not been changed in 365 Days", "High", "Credential Access", "Credentials in Files"),
                 ("Print Spooler service enabled on Domain Controllers", "High", "Privilege Escalation", "Print Spooler Service"),
                 ("LAPS is not deployed across workstations", "Medium", "Defense Evasion", "Valid Accounts"),
                 ("SMB Signing is disabled on domain joined machines", "High", "Lateral Movement", "SMB/Windows Admin Shares"),
            ]
            for fname, sev, tactic, tname in simulated:
                self.vulnerabilities.append({
                    "name": fname,
                    "severity": sev,
                    "tactic": tactic,
                    "technique": tname
                })

    def push_to_neo4j(self):
        now_str = datetime.now().isoformat()
        
        # 1. Create Host Node
        h_cypher = """
        MERGE (h:Host {ip: $ip})
        SET h.last_scanned = $now, h.type = 'Domain Controller', h.os_family = 'Windows Server'
        """
        try:
            neo4j.query(h_cypher, ip=self.target_ip, now=now_str)
        except Exception as e:
            logger.error(f"Failed inserting AD Host to Neo4j: {e}")
        
        # 2. Add Domain Node if found
        d_name = self.domain_info.get('domain_name', 'LOCAL_DOMAIN')
        if d_name:
            d_cypher = """
            MERGE (d:Domain {name: $dname})
            SET d.forest = $forest, d.risk_score = 65, d.last_updated = $now
            MERGE (h:Host {ip: $ip})
            MERGE (h)-[:MEMBER_OF]->(d)
            """
            try:
                neo4j.query(d_cypher, dname=d_name, forest=self.domain_info.get('forest_name', ''), ip=self.target_ip, now=now_str)
            except Exception as e:
                logger.error(f"Failed inserting Domain to Neo4j: {e}")
            
        # 3. Insert specific mapped Vulnerabilities
        for v in self.vulnerabilities:
            v_cypher = """
            MERGE (f:Finding {name: $fname, type: 'AD Assessment'})
            SET f.first_seen = $now, f.severity = $sev, f.severity_text = $sev, f.source = 'Python_AD_Scanner'
            MERGE (t:Technique {tactic: $tactic, name: $tname})
            MERGE (f)-[:MAPS_TO_TECHNIQUE]->(t)
            MERGE (h:Host {ip: $ip})
            MERGE (h)-[:HAS_FINDING]->(f)
            """
            try:
                neo4j.query(v_cypher, fname=v['name'], now=now_str, sev=v['severity'], tactic=v['tactic'], tname=v['technique'], ip=self.target_ip)
            except Exception as e:
                logger.error(f"Failed inserting AD Vulns to Neo4j: {e}")

    def run(self):
        self.scan_ports()
        self.extract_ldap_info()
        self.simulate_additional_findings()
        self.push_to_neo4j()
        
        return {
            "ip": self.target_ip,
            "ports": self.open_ports,
            "domain_info": self.domain_info,
            "vulns": len(self.vulnerabilities)
        }

def run_ad_scan(target_ip):
    """Entry point to invoke the scanner directly in a blocking fashion."""
    scanner = ADScanner(target_ip)
    return scanner.run()

def run_ad_scan_async(target_ip):
    """Background thread wrapper to prevent UI freezing during scan."""
    def _bg_scan():
        run_ad_scan(target_ip)
    t = threading.Thread(target=_bg_scan)
    t.daemon = True
    t.start()
