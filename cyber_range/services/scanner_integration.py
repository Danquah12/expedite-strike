"""
Expedite Strike Scanner Integration: ZAP + OpenVAS (GVM)
================================================
Integrates OWASP ZAP and OpenVAS/GVM into the auto-pentest pipeline.
Both can run locally on Windows or connect to remote instances.

ZAP:  Runs as daemon on port 8090, API key disabled for lab use.
GVM:  Connects via python-gvm to a GVM instance (local Docker or remote).
"""

import os
import subprocess
import time
import socket
import xml.etree.ElementTree as ET
from typing import Optional, Callable

# ── Configuration ─────────────────────────────────────────────────────
ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("ZAP_PORT", "8090"))
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

GVM_HOST = os.getenv("GVM_HOST", os.getenv("OPENVAS_HOST", "127.0.0.1"))
GVM_PORT = int(os.getenv("GVM_PORT", os.getenv("OPENVAS_PORT", "9390")))
GVM_USER = os.getenv("GVM_USER", os.getenv("OPENVAS_USER", "admin"))
GVM_PASS = os.getenv("GVM_PASS", os.getenv("OPENVAS_PASSWORD", "admin"))

_log_fn: Optional[Callable] = None

def _log(msg):
    if _log_fn:
        _log_fn(msg)


# ══════════════════════════════════════════════════════════════════════
#  ZAP INTEGRATION
# ══════════════════════════════════════════════════════════════════════

def _is_zap_running():
    """Check if ZAP daemon is listening."""
    try:
        s = socket.socket(); s.settimeout(2)
        result = s.connect_ex((ZAP_HOST, ZAP_PORT))
        s.close()
        return result == 0
    except:
        return False


def start_zap_daemon():
    """Attempt to start ZAP in daemon mode."""
    if _is_zap_running():
        _log(f"  [ZAP] Already running on {ZAP_HOST}:{ZAP_PORT}")
        return True

    # Try to find ZAP installation
    zap_paths = [
        r"C:\Program Files\ZAP\zap.bat",
        r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
        r"C:\Program Files (x86)\ZAP\zap.bat",
        r"D:\ZAP\zap.bat",
        r"D:\Tools\ZAP\zap.bat",
    ]
    jar_paths = [
        r"D:\Software Engineering\ZAP\ZAP_2.16.1\zap-2.16.1.jar",
        r"C:\Program Files\ZAP\zap-2.17.0.jar",
        r"D:\ZAP\zap-2.17.0.jar",
    ]

    zap_cmd = None
    for p in zap_paths:
        if os.path.isfile(p):
            zap_cmd = [p, "-daemon", "-port", str(ZAP_PORT),
                      "-config", "api.disablekey=true",
                      "-config", "api.addrs.addr.name=.*",
                      "-config", "api.addrs.addr.regex=true"]
            break

    if not zap_cmd:
        for p in jar_paths:
            if os.path.isfile(p):
                zap_cmd = ["java", "-Xmx512m", "-jar", p,
                          "-daemon", "-port", str(ZAP_PORT),
                          "-config", "api.disablekey=true",
                          "-config", "api.addrs.addr.name=.*",
                          "-config", "api.addrs.addr.regex=true"]
                break

    if not zap_cmd:
        _log("  [ZAP] Not found. Install: https://www.zaproxy.org/download/")
        _log("  [ZAP] Or run manually: java -jar zap-2.17.0.jar -daemon -port 8090 -config api.disablekey=true")
        return False

    try:
        _log(f"  [ZAP] Starting daemon on port {ZAP_PORT}...")
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        subprocess.Popen(zap_cmd, creationflags=flags,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Wait for startup
        for i in range(30):
            time.sleep(2)
            if _is_zap_running():
                _log(f"  [ZAP] Started successfully on port {ZAP_PORT}")
                return True
        _log("  [ZAP] Startup timeout (60s)")
        return False
    except Exception as e:
        _log(f"  [ZAP] Failed to start: {e}")
        return False


def run_zap_scan(targets: list, log_fn: Callable = None) -> list:
    """
    Run ZAP active scan on HTTP targets.
    Returns list of vulnerability findings.
    """
    global _log_fn
    _log_fn = log_fn

    if not _is_zap_running():
        started = start_zap_daemon()
        if not started:
            _log_fn = None
            return []

    try:
        from zapv2 import ZAPv2
    except ImportError:
        _log("  [ZAP] python-owasp-zap-v2.4 not installed")
        _log_fn = None
        return []

    zap = ZAPv2(apikey=ZAP_API_KEY,
                proxies={"http": f"http://{ZAP_HOST}:{ZAP_PORT}",
                         "https": f"http://{ZAP_HOST}:{ZAP_PORT}"})

    findings = []

    for target_ip in targets:
        ports = target_ip.get("ports", [])
        ip = target_ip.get("ip", "")
        services = target_ip.get("services", [])

        # Find HTTP services
        http_ports = []
        for svc in services:
            name = svc.get("name", "").lower()
            port = svc.get("port", 0)
            if "http" in name or port in (80, 443, 8080, 8443, 8000, 8888, 9090):
                http_ports.append(port)

        # Also check raw ports for HTTP
        for p in ports:
            if p in (80, 443, 8080, 8443, 8000, 8888, 9090) and p not in http_ports:
                http_ports.append(p)

        if not http_ports:
            continue

        for port in http_ports:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{ip}:{port}"
            _log(f"  [ZAP] Scanning: {url}")

            try:
                # Spider the site first (hard 90s wall-clock timeout)
                _log(f"  [ZAP] Spidering {url}...")
                scan_id = zap.spider.scan(url, maxchildren=10)
                deadline = time.time() + 90
                while time.time() < deadline:
                    try:
                        status = int(zap.spider.status(scan_id))
                        if status >= 100:
                            break
                    except Exception:
                        break
                    time.sleep(2)
                try:
                    _log(f"  [ZAP] Spider complete: {len(zap.spider.results(scan_id))} URLs found")
                except Exception:
                    _log(f"  [ZAP] Spider complete (results unavailable)")

                # Active scan (hard 180s wall-clock timeout)
                _log(f"  [ZAP] Active scanning {url}...")
                ascan_id = zap.ascan.scan(url)
                deadline = time.time() + 180
                last_progress = -1
                while time.time() < deadline:
                    try:
                        progress = int(zap.ascan.status(ascan_id))
                        if progress >= 100:
                            break
                        if progress != last_progress and progress % 25 == 0:
                            _log(f"  [ZAP] Scan progress: {progress}%")
                            last_progress = progress
                    except Exception:
                        _log(f"  [ZAP] Active scan status check failed, moving on")
                        break
                    time.sleep(3)

                # Collect alerts
                alerts = zap.core.alerts(baseurl=url)
                _log(f"  [ZAP] Scan complete: {len(alerts)} alerts")

                for alert in alerts:
                    risk = alert.get("risk", "Low")
                    severity_map = {"Informational": "Low", "Low": "Low",
                                   "Medium": "Medium", "High": "High"}
                    severity = severity_map.get(risk, "Medium")

                    finding = {
                        "scanner": "ZAP",
                        "host": ip,
                        "port": port,
                        "title": alert.get("alert", ""),
                        "severity": severity,
                        "description": alert.get("description", "")[:200],
                        "url": alert.get("url", ""),
                        "solution": alert.get("solution", "")[:200],
                        "cwe": alert.get("cweid", ""),
                        "evidence": alert.get("evidence", "")[:100],
                        "mitre_id": "T1190",
                    }
                    findings.append(finding)

                    if severity in ("High", "Critical"):
                        _log(f"  [ZAP] {severity}: {finding['title']} at {finding['url']}")

            except Exception as e:
                _log(f"  [ZAP] Error scanning {url}: {e}")

    _log(f"  [ZAP] Total findings: {len(findings)}")
    _log_fn = None
    return findings


# ══════════════════════════════════════════════════════════════════════
#  OPENVAS / GVM INTEGRATION
# ══════════════════════════════════════════════════════════════════════

def _is_gvm_running():
    """Check if GVM/OpenVAS is reachable."""
    try:
        s = socket.socket(); s.settimeout(2)
        result = s.connect_ex((GVM_HOST, GVM_PORT))
        s.close()
        return result == 0
    except:
        return False


def start_gvm_docker():
    """Start GVM/OpenVAS via Docker if available."""
    try:
        # Check if Docker is available
        result = subprocess.run(["docker", "ps"], capture_output=True, text=True, timeout=5,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        if result.returncode != 0:
            _log("  [GVM] Docker not running")
            return False

        # Check if GVM container exists
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=aegis-openvas", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)

        if "Up" in result.stdout:
            _log("  [GVM] Container already running")
            return True

        if result.stdout.strip():
            # Container exists but not running
            _log("  [GVM] Starting existing container...")
            subprocess.run(["docker", "start", "aegis-openvas"],
                          capture_output=True, timeout=10,
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        else:
            # Create new container
            _log("  [GVM] Pulling and starting GVM container (this takes a few minutes)...")
            subprocess.Popen(
                ["docker", "run", "-d", "--name", "aegis-openvas",
                 "-p", f"{GVM_PORT}:9390", "-p", "9392:9392",
                 "-e", f"GVM_ADMIN_PASSWORD={GVM_PASS}",
                 "greenbone/community-edition"],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for GVM to be ready
        _log("  [GVM] Waiting for OpenVAS to initialize...")
        for i in range(60):
            time.sleep(5)
            if _is_gvm_running():
                _log(f"  [GVM] OpenVAS ready on port {GVM_PORT}")
                return True
            if i % 6 == 0:
                _log(f"  [GVM] Still initializing... ({(i+1)*5}s)")

        _log("  [GVM] Startup timeout (300s)")
        return False

    except FileNotFoundError:
        _log("  [GVM] Docker not found. Install Docker Desktop: https://docs.docker.com/desktop/install/windows/")
        return False
    except Exception as e:
        _log(f"  [GVM] Error: {e}")
        return False


def run_gvm_scan(target_ips: list, log_fn: Callable = None) -> list:
    """
    Run OpenVAS/GVM scan via docker exec + Unix socket (GMP XML protocol).
    """
    global _log_fn
    _log_fn = log_fn
    findings = []
    container = "aegis-openvas"

    def _gmp_cmd(xml_cmd: str, timeout_s: int = 30) -> str:
        """Send a GMP XML command via docker exec python3."""
        script = (
            "from gvm.connections import UnixSocketConnection; "
            "from gvm.protocols.gmp import Gmp; "
            "c=UnixSocketConnection(path='/run/gvmd/gvmd.sock'); "
            "gmp=Gmp(connection=c).__enter__(); "
            "gmp.send_command('<authenticate><credentials>"
            f"<username>{GVM_USER}</username><password>{GVM_PASS}</password>"
            "</credentials></authenticate>'); "
            f"r=gmp.send_command('''{xml_cmd}'''); "
            "print(r)"
        )
        try:
            result = subprocess.run(
                ["docker", "exec", container, "python3", "-c", script],
                capture_output=True, text=True, timeout=timeout_s,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception as e:
            return f"ERROR: {e}"

    # Check container
    try:
        check = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )
        if "true" not in check.stdout.lower():
            _log(f"  [GVM] Container '{container}' not running")
            _log_fn = None
            return []
    except Exception:
        _log("  [GVM] Docker not available")
        _log_fn = None
        return []

    _log("  [GVM] Connecting via Unix socket...")
    version_resp = _gmp_cmd("<get_version/>")
    if "status=\"200\"" not in version_resp:
        _log(f"  [GVM] Cannot connect: {version_resp[:100]}")
        _log_fn = None
        return []
    _log(f"  [GVM] Connected (GMP authenticated as {GVM_USER})")

    try:
        ip_list = ",".join(target_ips[:20])
        target_name = f"XStrike-{int(time.time())}"
        _log(f"  [GVM] Creating target: {ip_list}")

        target_resp = _gmp_cmd(
            f'<create_target><name>{target_name}</name>'
            f'<hosts>{ip_list}</hosts>'
            f'<port_range>T:1-10000</port_range></create_target>'
        )
        target_id = ""
        if 'id="' in target_resp:
            target_id = target_resp.split('id="')[1].split('"')[0]
        if not target_id:
            _log(f"  [GVM] Failed to create target: {target_resp[:150]}")
            _log_fn = None
            return []
        _log(f"  [GVM] Target created: {target_id}")

        config_id = "daba56c8-73ec-11df-a475-002264764cea"
        scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"

        task_resp = _gmp_cmd(
            f'<create_task><name>XStrike-Scan-{int(time.time())}</name>'
            f'<config id="{config_id}"/><target id="{target_id}"/>'
            f'<scanner id="{scanner_id}"/></create_task>'
        )
        task_id = ""
        if 'id="' in task_resp:
            task_id = task_resp.split('id="')[1].split('"')[0]
        if not task_id:
            _log(f"  [GVM] Failed to create task: {task_resp[:150]}")
            _log_fn = None
            return []

        _log(f"  [GVM] Starting scan (task: {task_id})...")
        _gmp_cmd(f'<start_task task_id="{task_id}"/>')
        _log("  [GVM] Scan launched!")

        max_wait, poll_interval, elapsed = 1200, 15, 0
        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval
            status_resp = _gmp_cmd(f'<get_tasks task_id="{task_id}"/>', timeout_s=15)
            if '<status>Done</status>' in status_resp:
                _log("  [GVM] Scan complete!")
                break
            elif any(s in status_resp for s in ['<status>Stopped', '<status>Error']):
                _log("  [GVM] Scan stopped/error")
                break
            if elapsed % 30 == 0:
                prog = "?"
                if '<progress>' in status_resp:
                    try: prog = status_resp.split('<progress>')[1].split('<')[0]
                    except: pass
                _log(f"  [GVM] Scanning... {prog}% ({elapsed}s)")

        # Get report
        report_resp = _gmp_cmd(f'<get_tasks task_id="{task_id}"/>', timeout_s=15)
        report_id = ""
        if '<report id="' in report_resp:
            try: report_id = report_resp.split('<report id="')[1].split('"')[0]
            except: pass

        if report_id:
            _log(f"  [GVM] Fetching report...")
            report_xml = _gmp_cmd(
                f'<get_reports report_id="{report_id}" filter="rows=500 min_qod=30" details="1"/>',
                timeout_s=60,
            )
            try:
                root = ET.fromstring(report_xml)
                for result in root.findall('.//result'):
                    host_el = result.find('host')
                    port_el = result.find('port')
                    name_el = result.find('name')
                    desc_el = result.find('description')
                    threat_el = result.find('threat')
                    host = host_el.text if host_el is not None else ""
                    port_str = port_el.text if port_el is not None else ""
                    port_num = 0
                    try: port_num = int(port_str.split("/")[0])
                    except: pass
                    threat = threat_el.text if threat_el is not None else "Low"
                    sev_map = {"Log": "Low", "Low": "Low", "Medium": "Medium",
                              "High": "High", "Critical": "Critical"}
                    finding = {
                        "scanner": "OpenVAS", "host": host, "port": port_num,
                        "title": name_el.text if name_el is not None else "",
                        "severity": sev_map.get(threat, "Medium"),
                        "description": (desc_el.text or "")[:200] if desc_el is not None else "",
                        "cve": "", "mitre_id": "T1190",
                    }
                    refs = result.findall('.//ref[@type="cve"]')
                    if refs:
                        finding["cve"] = refs[0].get("id", "")
                    findings.append(finding)
                    if finding["severity"] in ("High", "Critical"):
                        _log(f"  [GVM] {finding['severity']}: {finding['title']} on {host}:{port_num}")
            except ET.ParseError:
                _log("  [GVM] Could not parse report XML")

        _log(f"  [GVM] Total findings: {len(findings)}")

    except Exception as e:
        _log(f"  [GVM] Error: {e}")

    _log_fn = None
    return findings


# ══════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════

def get_scanner_status():
    """Return status of available scanners."""
    nuclei_path = _find_nuclei()
    return {
        "zap": {
            "installed": True,
            "running": _is_zap_running(),
            "host": ZAP_HOST,
            "port": ZAP_PORT,
        },
        "gvm": {
            "installed": True,
            "running": _is_gvm_running(),
            "host": GVM_HOST,
            "port": GVM_PORT,
        },
        "nuclei": {
            "installed": nuclei_path is not None,
            "running": False,
            "path": nuclei_path or "not found",
        },
    }


# ══════════════════════════════════════════════════════════════════════
#  NUCLEI INTEGRATION
# ══════════════════════════════════════════════════════════════════════

NUCLEI_PATHS = [
    r"D:\Agentic-AI\nuclei.exe",
    r"C:\tools\nuclei.exe",
    os.path.expanduser(r"~\go\bin\nuclei.exe"),
]

def _find_nuclei() -> str:
    """Find nuclei binary."""
    import shutil
    p = shutil.which("nuclei")
    if p:
        return p
    for path in NUCLEI_PATHS:
        if os.path.isfile(path):
            return path
    return None


def run_nuclei_scan(hosts: list, log_fn: Callable = None) -> list:
    """
    Run Nuclei vulnerability scan on web targets.
    Returns list of vulnerability findings.
    """
    global _log_fn
    _log_fn = log_fn
    findings = []

    nuclei_bin = _find_nuclei()
    if not nuclei_bin:
        _log("  [NUCLEI] nuclei not found. Install: https://github.com/projectdiscovery/nuclei")
        _log_fn = None
        return []

    # Build URL list from hosts with HTTP ports
    http_ports = {80, 443, 8080, 8443, 8000, 8081, 8180, 8888, 9000, 9090}
    targets = []
    for h in hosts:
        ip = h.get("ip", "")
        if not ip:
            continue
        for port in h.get("ports", []):
            if port in http_ports:
                scheme = "https" if port in (443, 8443) else "http"
                targets.append(f"{scheme}://{ip}:{port}")

    if not targets:
        _log("  [NUCLEI] No web targets found for scanning")
        _log_fn = None
        return []

    # Write targets to temp file
    import tempfile, json
    target_file = os.path.join(tempfile.gettempdir(), "aegis_nuclei_targets.txt")
    with open(target_file, "w") as f:
        f.write("\n".join(targets))

    _log(f"  [NUCLEI] Scanning {len(targets)} web target(s)...")
    for t in targets[:10]:
        _log(f"    -> {t}")
    if len(targets) > 10:
        _log(f"    ... and {len(targets) - 10} more")

    # Run nuclei with JSON output
    output_file = os.path.join(tempfile.gettempdir(), "aegis_nuclei_output.jsonl")
    try:
        cmd = [
            nuclei_bin,
            "-l", target_file,
            "-json-export", output_file,
            "-severity", "critical,high,medium",
            "-stats", "-si", "10",
            "-timeout", "10",
            "-retries", "1",
            "-c", "25",
            "-silent",
        ]
        _log(f"  [NUCLEI] Running: nuclei -severity critical,high,medium ...")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )

        # Parse JSONL output
        if os.path.isfile(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        info = obj.get("info", {})
                        sev = info.get("severity", "medium").capitalize()
                        sev_map = {"Critical": "Critical", "High": "High",
                                   "Medium": "Medium", "Low": "Low", "Info": "Low"}

                        finding = {
                            "scanner": "Nuclei",
                            "host": obj.get("host", obj.get("ip", "")),
                            "port": obj.get("port", 0) or 0,
                            "title": info.get("name", obj.get("template-id", "")),
                            "severity": sev_map.get(sev, "Medium"),
                            "description": info.get("description", "")[:200],
                            "cve": "",
                            "mitre_id": "T1190",
                            "template_id": obj.get("template-id", ""),
                        }

                        # Extract CVE from references or classification
                        classification = info.get("classification", {})
                        cve_list = classification.get("cve-id", [])
                        if cve_list and isinstance(cve_list, list):
                            finding["cve"] = cve_list[0]

                        findings.append(finding)
                        if finding["severity"] in ("Critical", "High"):
                            _log(f"  [NUCLEI] {finding['severity']}: {finding['title']} at {finding['host']}")

                    except json.JSONDecodeError:
                        continue

            os.remove(output_file)

        os.remove(target_file)

    except subprocess.TimeoutExpired:
        _log("  [NUCLEI] Scan timed out (600s)")
    except Exception as e:
        _log(f"  [NUCLEI] Error: {e}")

    _log(f"  [NUCLEI] Total findings: {len(findings)}")
    _log_fn = None
    return findings


def run_all_scanners(hosts: list, log_fn: Callable = None) -> dict:
    """
    Run all available scanners on discovered hosts.
    Returns dict with scanner results.
    """
    results = {"zap": [], "gvm": [], "nuclei": []}

    # ZAP: scan HTTP services
    if not _is_zap_running():
        if log_fn:
            log_fn("  [SCANNERS] ZAP not running — attempting auto-start...")
        start_zap_daemon()
    if _is_zap_running():
        if log_fn:
            log_fn("  [SCANNERS] Running OWASP ZAP web application scan...")
        results["zap"] = run_zap_scan(hosts, log_fn)
    else:
        if log_fn:
            log_fn("  [SCANNERS] ZAP unavailable — skipping web app scan")

    # Nuclei: scan web targets with CVE templates
    nuclei_bin = _find_nuclei()
    if nuclei_bin:
        if log_fn:
            log_fn("  [SCANNERS] Running Nuclei CVE template scan...")
        results["nuclei"] = run_nuclei_scan(hosts, log_fn)
    else:
        if log_fn:
            log_fn("  [SCANNERS] Nuclei not installed - skipping template scan")

    # GVM: scan all services
    if _is_gvm_running():
        if log_fn:
            log_fn("  [SCANNERS] Running OpenVAS/GVM vulnerability scan...")
        target_ips = [h.get("ip", "") for h in hosts if h.get("ip")]
        results["gvm"] = run_gvm_scan(target_ips, log_fn)
    else:
        if log_fn:
            log_fn("  [SCANNERS] OpenVAS/GVM not running - skipping deep vuln scan")
            log_fn("  [SCANNERS] To enable: docker run -d -p 9390:9390 greenbone/community-edition")

    return results

