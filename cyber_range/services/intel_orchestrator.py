import os
import json
import subprocess
import glob
import xml.etree.ElementTree as ET
import html
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import List, Dict, Any

# ── Module-level exploit cache ────────────────────────────────────────────────
# Keyed by (port, service_name[:20], product[:20], version[:10])
_EXPLOIT_CACHE: dict = {}

# ── Background matrix cache ───────────────────────────────────────────────────
_MATRIX_CACHE: list = []
_MATRIX_LOCK  = threading.Lock()
_MATRIX_BUILDING = False

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CVSS_RE = re.compile(r"CVSS:[^\s]+", re.IGNORECASE)

_MSF_PATH = "/usr/share/metasploit-framework/modules"

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
            result = subprocess.run(['searchsploit', query, '--json'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return data.get("RESULTS_EXPLOIT", [])
        except Exception as e:
            pass
            
        return []

    # ── Metasploit filesystem search ───────────────────────────────
    @staticmethod
    def _search_msf_modules(query, search_type="service"):
        """Search Metasploit modules by service directory or CVE grep."""
        results = []
        _TYPE_MAP = {
            "exploits": "exploit", "auxiliary": "auxiliary",
            "post": "post", "encoders": "encoder",
        }
        if search_type == "cve" and query:
            try:
                r = subprocess.run(
                    ["grep", "-rl", "--include=*.rb", query, _MSF_PATH],
                    capture_output=True, text=True, timeout=4,
                )
                if r.stdout:
                    for fpath in r.stdout.strip().split("\n"):
                        if not fpath.strip():
                            continue
                        rel = fpath.strip().replace(_MSF_PATH + "/", "")
                        parts = rel.split("/")
                        mod_dir = parts[0] if parts else ""
                        mod_type = _TYPE_MAP.get(mod_dir, mod_dir)
                        mod_name = rel.replace(mod_dir + "/", "").replace(".rb", "")
                        results.append({
                            "name": os.path.basename(mod_name).replace("_", " ").title(),
                            "source": "metasploit",
                            "type": mod_type,
                            "msf_module": f"{mod_type}/{mod_name}",
                            "description": f"Metasploit {mod_type} module matching {query}",
                            "exec_command": f"msfconsole -q -x 'use {mod_type}/{mod_name}; set RHOSTS {{target}}; run; exit'",
                            "risk": "Varies",
                        })
            except Exception:
                pass
        elif search_type == "service" and query:
            svc_key = query.lower().strip()
            for mod_dir in ["exploits", "auxiliary", "post"]:
                try:
                    r = subprocess.run(
                        ["find", os.path.join(_MSF_PATH, mod_dir),
                         "-type", "f", "-name", "*.rb", "-path", f"*/{svc_key}/*"],
                        capture_output=True, text=True, timeout=3,
                    )
                    if r.stdout:
                        for fpath in r.stdout.strip().split("\n"):
                            if not fpath.strip():
                                continue
                            rel = fpath.strip().replace(_MSF_PATH + "/", "")
                            parts = rel.split("/")
                            mod_d = parts[0] if parts else ""
                            mod_type = _TYPE_MAP.get(mod_d, mod_d)
                            mod_name = rel.replace(mod_d + "/", "").replace(".rb", "")
                            results.append({
                                "name": os.path.basename(mod_name).replace("_", " ").title(),
                                "source": "metasploit",
                                "type": mod_type,
                                "msf_module": f"{mod_type}/{mod_name}",
                                "description": f"Metasploit {mod_type} for {svc_key} service",
                                "exec_command": f"msfconsole -q -x 'use {mod_type}/{mod_name}; set RHOSTS {{target}}; run; exit'",
                                "risk": "Varies",
                            })
                except Exception:
                    pass
        return results[:10]

    # ── Custom module loader ────────────────────────────────────────
    @staticmethod
    def _get_custom_module(port_num):
        """Load custom exploit module for a port from cyber_range/modules/."""
        try:
            from cyber_range.modules import get_module_for_port
            return get_module_for_port(port_num)
        except Exception:
            return None

    # ── Metasploit port-number search ───────────────────────────────
    @staticmethod
    def _search_msf_by_port(port_num):
        """Search Metasploit modules that reference a specific port number."""
        results = []
        _TYPE_MAP = {
            "exploits": "exploit", "auxiliary": "auxiliary",
            "post": "post", "encoders": "encoder",
        }
        try:
            # grep for 'RPORT', 'port', or the port number in module defaults
            r = subprocess.run(
                ["grep", "-rl", "--include=*.rb",
                 f"'RPORT', {port_num}", _MSF_PATH],
                capture_output=True, text=True, timeout=4,
            )
            # Also try the DefaultPort pattern
            r2 = subprocess.run(
                ["grep", "-rl", "--include=*.rb",
                 f"DefaultPort.*{port_num}", _MSF_PATH],
                capture_output=True, text=True, timeout=4,
            )
            all_paths = set()
            for output in [r.stdout, r2.stdout]:
                if output:
                    all_paths.update(p.strip() for p in output.strip().split("\n") if p.strip())

            for fpath in list(all_paths)[:8]:
                rel = fpath.replace(_MSF_PATH + "/", "")
                parts = rel.split("/")
                mod_dir = parts[0] if parts else ""
                mod_type = _TYPE_MAP.get(mod_dir, mod_dir)
                mod_name = rel.replace(mod_dir + "/", "").replace(".rb", "")
                results.append({
                    "name": os.path.basename(mod_name).replace("_", " ").title(),
                    "source": "metasploit",
                    "type": mod_type,
                    "msf_module": f"{mod_type}/{mod_name}",
                    "description": f"Metasploit {mod_type} targeting port {port_num}",
                    "exec_command": f"msfconsole -q -x 'use {mod_type}/{mod_name}; set RHOSTS {{target}}; set RPORT {port_num}; run; exit'",
                    "risk": "Varies",
                })
        except Exception:
            pass
        return results[:6]

    # ── Nmap NSE script search ────────────────────────────────────────
    @staticmethod
    def _search_nse_scripts(service_name):
        """Find nmap NSE scripts matching a service name."""
        results = []
        nse_dir = "/usr/share/nmap/scripts"
        if not os.path.isdir(nse_dir):
            return results
        try:
            svc_key = service_name.lower().strip()
            r = subprocess.run(
                ["find", nse_dir, "-name", f"*{svc_key}*", "-name", "*.nse"],
                capture_output=True, text=True, timeout=3,
            )
            if r.stdout:
                for fpath in r.stdout.strip().split("\n")[:6]:
                    if not fpath.strip():
                        continue
                    script_name = os.path.basename(fpath).replace(".nse", "")
                    results.append({
                        "name": f"Nmap {script_name}",
                        "source": "nmap-nse",
                        "type": "auxiliary",
                        "msf_module": "",
                        "description": f"Nmap NSE script: {script_name}",
                        "exec_command": f"nmap --script {script_name} -p {{port}} {{target}}",
                        "risk": "Medium",
                    })
        except Exception:
            pass
        return results

    def enumerate_service(self, svc, fast_only: bool = False):
        """
        Enumerate exploit sources for a single service.
        fast_only=True  → cache + DEFAULT_PORT_EXPLOITS only (no subprocesses, instant)
        fast_only=False → full scan: searchsploit + MSF grep + NSE find (slow, user-triggered)
        """
        all_exploits = []
        _ip_raw = svc.get("ip")
        target_ip = str(_ip_raw) if _ip_raw is not None else ""
        port_num = int(svc.get("port") or 0)
        service_name = svc.get("service") or ""
        product = svc.get("product") or ""
        version = svc.get("version") or ""

        # ── Fast-path: cache hit (always) ────────────────────────────────────
        _cache_key = (port_num, service_name[:20], product[:20], version[:10])
        if _cache_key in _EXPLOIT_CACHE:
            return _EXPLOIT_CACHE[_cache_key]

        # ── Fast-path: DEFAULT_PORT_EXPLOITS (always) ────────────────────────
        if port_num in DEFAULT_PORT_EXPLOITS:
            fallback = DEFAULT_PORT_EXPLOITS[port_num]
            quick = [{
                "name": fallback["Title"],
                "source": "default",
                "type": "auxiliary",
                "msf_module": fallback["Path"],
                "description": f"Default Metasploit module for port {port_num}",
                "exec_command": f"msfconsole -q -x 'use {fallback['Path']}; set RHOSTS {target_ip or '{target}'}; run; exit'",
                "risk": "Medium",
                "verified": True,
            }]
            _EXPLOIT_CACHE[_cache_key] = quick
            return quick

        # ── fast_only: no subprocesses — auto-probe entry only ───────────────
        if fast_only:
            probe = [{
                "name": f"TCP Probe port {port_num} ({service_name or 'unknown'})",
                "source": "auto-generated",
                "type": "auxiliary",
                "msf_module": "auxiliary/scanner/portscan/tcp",
                "description": f"Generic probe for {service_name or 'unknown'} on port {port_num}",
                "exec_command": f"nmap -sV --script vuln -p {port_num} {target_ip or '{target}'}",
                "risk": "Info",
                "verified": False,
            }]
            _EXPLOIT_CACHE[_cache_key] = probe
            return probe

        # ── Everything below only runs during a FULL (user-triggered) scan ───

        # 1) Custom port module — if it exists, use it
        custom_mod = self._get_custom_module(port_num)
        has_custom = False
        if custom_mod and hasattr(custom_mod, "enumerate"):
            try:
                custom_exploits = custom_mod.enumerate(svc.get("ip", ""), svc)
                for ex in (custom_exploits or []):
                    if "source" not in ex:
                        ex["source"] = "custom"
                    all_exploits.extend(custom_exploits[:6])
                    break
                has_custom = bool(custom_exploits)
            except Exception as e:
                print(f"[IntelOrchestrator] Custom module port {port_num} error: {e}")

        # 2) SearchSploit — multiple query strategies
        queries_tried = set()
        ss_queries = []

        # Build primary query: product + version
        if product and version:
            ss_queries.append(f"{product} {version}")
        if product:
            ss_queries.append(product)
        if service_name and service_name != product:
            if version:
                ss_queries.append(f"{service_name} {version}")
            ss_queries.append(service_name)

        # For uncovered ports, also search by port number
        if not has_custom and port_num not in DEFAULT_PORT_EXPLOITS:
            if service_name:
                ss_queries.append(f"{service_name} port {port_num}")

        for query in ss_queries:
            query = query.strip()
            if not query or len(query) <= 3:
                continue
            if query.lower() in ["http", "ssh", "domain", "tcp", "udp", "unknown"]:
                continue
            if query in queries_tried:
                continue
            queries_tried.add(query)

            try:
                ss_results = self.query_searchsploit(query)
                for ex in ss_results[:3]:
                    title = ex.get("Title", "")
                    # Deduplicate by title
                    if any(e.get("name") == title for e in all_exploits):
                        continue
                    all_exploits.append({
                        "name": title or "Unknown",
                        "source": "searchsploit",
                        "type": "exploit",
                        "msf_module": ex.get("Path", ""),
                        "description": f"ExploitDB: {title}",
                        "exec_command": f"searchsploit -m {ex.get('EDB-ID', '')}",
                        "risk": "Verified" if ex.get("Verified") == "1" else "Unverified",
                        "verified": bool(int(ex.get("Verified", 0))),
                    })
                if ss_results:
                    break  # Good results found, stop querying
            except Exception:
                pass

        # 3) Metasploit filesystem search — by service name
        if service_name:
            msf_mods = self._search_msf_modules(service_name, "service")
            seen = {e.get("msf_module") for e in all_exploits if e.get("msf_module")}
            for m in msf_mods[:4]:
                if m["msf_module"] not in seen:
                    all_exploits.append(m)

        # 4) === AUTO-DISCOVERY for ports WITHOUT custom modules ===
        if not has_custom:
            # 4a) Search Metasploit by port number
            msf_port_mods = self._search_msf_by_port(port_num)
            seen = {e.get("msf_module") for e in all_exploits if e.get("msf_module")}
            for m in msf_port_mods[:4]:
                if m["msf_module"] not in seen:
                    all_exploits.append(m)

            # 4b) Search nmap NSE scripts by service name
            if service_name:
                nse_scripts = self._search_nse_scripts(service_name)
                for nse in nse_scripts[:3]:
                    nse["exec_command"] = nse["exec_command"].replace(
                        "{port}", str(port_num)
                    ).replace("{target}", target_ip or "{target}")
                    all_exploits.append(nse)

            # 4c) Auto-generate a dynamic probe if still nothing found
            if not all_exploits:
                auto_probes = []

                # Nmap version + vuln scan
                auto_probes.append({
                    "name": f"Nmap Deep Scan port {port_num}",
                    "source": "auto-generated",
                    "type": "auxiliary",
                    "msf_module": "",
                    "description": f"Auto-generated: nmap version detection + vuln scripts on port {port_num}",
                    "exec_command": f"nmap -sV -sC --script vuln -p {port_num} {{target}}",
                    "risk": "Medium",
                })

                # Banner grab
                auto_probes.append({
                    "name": f"Banner Grab port {port_num}",
                    "source": "auto-generated",
                    "type": "auxiliary",
                    "msf_module": "",
                    "description": f"Grab service banner to identify software on port {port_num}",
                    "exec_command": f"echo '' | timeout 5 nc -v {{target}} {port_num} 2>&1 | head -20",
                    "risk": "Info",
                })

                # Generic Metasploit TCP scanner
                auto_probes.append({
                    "name": f"Metasploit TCP Probe port {port_num}",
                    "source": "auto-generated",
                    "type": "auxiliary",
                    "msf_module": "auxiliary/scanner/portscan/tcp",
                    "description": f"Auto-generated TCP service probe for port {port_num}",
                    "exec_command": f"msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS {{target}}; set PORTS {port_num}; run; exit'",
                    "risk": "Info",
                })

                all_exploits.extend(auto_probes)

        # 5) Default port fallback (only if still empty)
        if not all_exploits:
            fallback = DEFAULT_PORT_EXPLOITS.get(port_num)
            if fallback:
                all_exploits.append({
                    "name": fallback["Title"],
                    "source": "default",
                    "type": "auxiliary",
                    "msf_module": fallback["Path"],
                    "description": f"Default Metasploit module for port {port_num}",
                    "exec_command": f"msfconsole -q -x 'use {fallback['Path']}; set RHOSTS {{target}}; run; exit'",
                    "risk": "Medium",
                    "verified": True,
                })

        # ── Write to cache ───────────────────────────────────────────────────
        _EXPLOIT_CACHE[_cache_key] = all_exploits
        return all_exploits

    # ── Background matrix builder ─────────────────────────────────────────────
    def _build_matrix_parallel(self) -> List[Dict[str, Any]]:
        """Parallel enumerate_service across all parsed_services with 12 threads."""
        matrix = []
        svcs = list(self.parsed_services[:150])   # cap at 150 services per run

        def _process(svc):
            try:
                return svc, self.enumerate_service(svc, fast_only=True)  # NO subprocesses
            except Exception as ex:
                print(f"[IntelOrchestrator] enumerate_service error: {ex}")
                return svc, []

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:  # 1 worker: fast_only needs no parallelism
                futures = {pool.submit(_process, s): s for s in svcs}
                for fut in as_completed(futures, timeout=40):
                    try:
                        svc, exploits = fut.result(timeout=8)
                        ip  = svc.get("ip", "?")
                        prt = svc.get("port", 0)
                        if exploits:
                            top = exploits[0]
                            matrix.append({
                                "id": f"{ip}_{prt}_{top.get('name','exploit')[:20]}",
                                "target_ip": ip,
                                "port": prt,
                                "service": svc.get("product") or svc.get("service", "Unknown"),
                                "exploit_name": top.get("name", "Unknown Exploit"),
                                "exploit_path": top.get("msf_module", "N/A"),
                                "verified": top.get("verified", False),
                                "source": top.get("source", "unknown"),
                                "all_exploits": exploits,
                            })
                        else:
                            matrix.append({
                                "id": f"{ip}_{prt}_generic",
                                "target_ip": ip,
                                "port": prt,
                                "service": svc.get("service", "Unknown"),
                                "exploit_name": "Generic TCP Service Probe",
                                "exploit_path": "auxiliary/scanner/portscan/tcp",
                                "verified": False,
                                "source": "generic",
                                "all_exploits": [],
                            })
                    except FuturesTimeout:
                        pass
                    except Exception:
                        pass
        except FuturesTimeout:
            pass  # Return partial results
        return matrix

    def _background_build(self):
        """Run _build_matrix_parallel() in background and cache the result."""
        global _MATRIX_CACHE, _MATRIX_BUILDING
        if _MATRIX_BUILDING:
            return
        _MATRIX_BUILDING = True
        # Lower this thread's CPU priority so Dash stays responsive
        try:
            import os as _os
            _os.nice(10)
        except Exception:
            pass
        try:
            # Refresh services first
            if not self.parsed_services:
                self.run_enumeration_scan()
            try:
                from app import neo4j_driver
                with neo4j_driver.session() as session:
                    db_svcs = session.run("""
                        MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
                        RETURN h.ip AS ip, s.port AS port, s.protocol AS protocol,
                               s.name AS service, s.product AS product, s.version AS version
                    """).data()
                    for r in db_svcs:
                        _ip   = r.get("ip")   or None
                        _port = r.get("port") or None
                        if not _ip or not _port:
                            continue
                        entry = {
                            "ip": _ip, "port": _port,
                            "protocol": r.get("protocol") or "tcp",
                            "service":  r.get("service")  or "",
                            "product":  r.get("product")  or "",
                            "version":  r.get("version")  or "",
                        }
                        if entry not in self.parsed_services:
                            self.parsed_services.append(entry)
            except Exception as _ne:
                print(f"[IntelOrchestrator] Neo4j prefetch (background): {_ne}")

            result = self._build_matrix_parallel()
            with _MATRIX_LOCK:
                _MATRIX_CACHE[:] = result
            print(f"[IntelOrchestrator] Background matrix ready: {len(result)} rows")
        except Exception as ex:
            print(f"[IntelOrchestrator] Background build failed: {ex}")
        finally:
            _MATRIX_BUILDING = False

    def get_cached_matrix(self) -> List[Dict[str, Any]]:
        """Return the cached matrix instantly. Kick off background build if empty."""
        with _MATRIX_LOCK:
            cached = list(_MATRIX_CACHE)
        if not cached:
            t = threading.Thread(target=self._background_build, daemon=True)
            t.start()
        return cached

    def generate_exploitation_matrix(self) -> List[Dict[str, Any]]:
        """
        Synthesizes the parsed NMAP services against SearchSploit,
        Metasploit filesystem, and custom port modules.
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
                    _ip   = r.get("ip")   or None
                    _port = r.get("port") or None
                    if not _ip or not _port:
                        continue
                    svc_entry = {
                        "ip": _ip,
                        "port": _port,
                        "protocol": r.get("protocol") or "tcp",
                        "service": r.get("service") or "",
                        "product": r.get("product") or "",
                        "version": r.get("version") or ""
                    }
                    if svc_entry not in self.parsed_services:
                        self.parsed_services.append(svc_entry)
        except Exception as e:
            print(f"[IntelOrchestrator] Failed to fetch Neo4j services: {e}")
            
        # Iterate over discovered services and hunt for exploits
        for svc in self.parsed_services:
            svc_exploits = self.enumerate_service(svc)

            if svc_exploits:
                # Add the best exploit to the matrix (for backward compat)
                top = svc_exploits[0]
                matrix.append({
                    "id": f"{svc['ip']}_{svc['port']}_{top.get('name', 'exploit')[:20]}",
                    "target_ip": svc["ip"],
                    "port": svc["port"],
                    "service": svc.get("product") or svc.get("service", "Unknown"),
                    "exploit_name": top.get("name", "Unknown Exploit"),
                    "exploit_path": top.get("msf_module", "N/A"),
                    "verified": top.get("verified", False),
                    "source": top.get("source", "unknown"),
                    "all_exploits": svc_exploits,  # All found exploits
                })
            else:
                matrix.append({
                    "id": f"{svc['ip']}_{svc['port']}_generic",
                    "target_ip": svc["ip"],
                    "port": svc["port"],
                    "service": svc.get("service", "Unknown"),
                    "exploit_name": "Generic TCP Service Fuzzing & Probing",
                    "exploit_path": "auxiliary/scanner/portscan/tcp",
                    "verified": False,
                    "source": "generic",
                    "all_exploits": [],
                })
                
        return matrix
