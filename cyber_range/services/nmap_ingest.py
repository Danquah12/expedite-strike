import os
import subprocess
import threading
import signal
import json
from datetime import datetime

SCAN_ROOT = "/mnt/scans/incoming/nmap"

# =============================================================================
# Nmap Scan Profiles
# Each profile defines the exact CLI flags and NSE scripts to use.
# =============================================================================
SCAN_PROFILES = {

    "quick": {
        "label": "⚡ Quick Scan (Ping + Top 1000 Ports)",
        "description": "Fast host discovery and top-1000 port scan. No NSE scripts.",
        "flags": [
            "-sV", "-T4", "--open",
            "-F",              # Top 100 ports — even faster option
            "--version-intensity", "0",
        ],
        "script": None,
        "script_args": None,
    },

    "standard": {
        "label": "🔍 Standard Vuln Scan (vuln + vulners)",
        "description": "Service enumeration + CVE cross-reference via vulners DB.",
        "flags": [
            "-Pn", "-n", "-sS", "-sV", "-T4", "--open",
            "--version-intensity", "5",
        ],
        "script": "vuln,vulners",
        "script_args": "mincvss=0.0",
    },

    "full_vuln": {
        "label": "🔥 Full Vuln Scan (All vuln NSE + CVE detection)",
        "description": "Deep NSE vulnerability scan including brute-force checks, ssl, smb, http enum.",
        "flags": [
            "-Pn", "-n", "-sS", "-sV", "-O", "-T4", "--open",
            "--version-intensity", "9",
            "-p-",             # All 65535 ports
        ],
        "script": (
            "vuln,vulners,"
            "auth,brute,default,exploit,"
            "http-auth,http-config-backup,http-csrf,http-dombased-xss,"
            "http-enum,http-fileupload-exploiter,http-git,http-headers,"
            "http-iis-short-name-brute,http-internal-ip-disclosure,"
            "http-methods,http-open-redirect,http-passwd,http-php-version,"
            "http-put,http-robots.txt,http-shellshock,http-sql-injection,"
            "http-stored-xss,http-title,http-trace,http-vuln-cve2006-3392,"
            "http-vuln-cve2010-0738,http-vuln-cve2011-3192,"
            "http-vuln-cve2014-2126,http-vuln-cve2014-2127,"
            "http-vuln-cve2014-2128,http-vuln-cve2014-2129,"
            "http-vuln-cve2014-3704,http-vuln-cve2014-8877,"
            "http-vuln-cve2015-1427,http-vuln-cve2015-1635,"
            "http-vuln-cve2017-5638,http-vuln-cve2017-5689,"
            "http-vuln-cve2017-8917,http-vuln-misfortune-cookie,"
            "http-vuln-wnr1000-creds,"
            "ssl-ccs-injection,ssl-cert,ssl-dh-params,ssl-enum-ciphers,"
            "ssl-heartbleed,ssl-known-key,ssl-poodle,"
            "sslv2,sslv2-drown,"
            "smb-enum-shares,smb-enum-users,smb-os-discovery,"
            "smb-security-mode,smb-vuln-cve-2017-7494,"
            "smb-vuln-cve2009-3103,smb-vuln-ms06-025,"
            "smb-vuln-ms07-029,smb-vuln-ms08-067,"
            "smb-vuln-ms10-054,smb-vuln-ms10-061,"
            "smb-vuln-ms17-010,smb-vuln-regsvc-dos,"
            "ssh-auth-methods,ssh-brute,ssh-hostkey,ssh2-enum-algos,"
            "ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,"
            "ftp-vuln-cve2010-4221,"
            "mysql-databases,mysql-empty-password,mysql-info,"
            "mysql-vuln-cve2012-2122,"
            "rdp-enum-encryption,rdp-vuln-ms12-020,"
            "dns-zone-transfer,"
            "snmp-info,snmp-sysdescr"
        ),
        "script_args": "mincvss=0.0,brute.mode=user,brute.firstonly=true",
    },

    "comprehensive": {
        "label": "🛡️ Comprehensive (All Ports + All Categories)",
        "description": "Maximum coverage: all ports, all vuln scripts, OS detect, traceroute, firewall bypass. Slow — use for internal assessments.",
        "flags": [
            "-Pn", "-n",
            "-sS", "-sU",      # TCP SYN + UDP scan
            "-sV", "-O",
            "-T3",             # Slightly slower to avoid rate-limiting
            "--open",
            "--version-intensity", "9",
            "-p-",             # All 65535 TCP ports
            "--top-ports", "200",  # Top 200 UDP
            "-A",              # Aggressive: OS + version + traceroute + default scripts
            "--script-timeout", "30s",
            "--host-timeout", "20m",
        ],
        "script": (
            "vuln,vulners,auth,brute,default,discovery,exploit,malware,safe,"
            "http-auth,http-config-backup,http-csrf,http-dombased-xss,"
            "http-enum,http-git,http-headers,http-methods,http-open-redirect,"
            "http-passwd,http-php-version,http-put,http-robots.txt,"
            "http-shellshock,http-sql-injection,http-stored-xss,http-title,"
            "http-trace,http-vuln-cve2006-3392,http-vuln-cve2010-0738,"
            "http-vuln-cve2011-3192,http-vuln-cve2014-3704,http-vuln-cve2015-1427,"
            "http-vuln-cve2015-1635,http-vuln-cve2017-5638,http-vuln-cve2017-5689,"
            "http-vuln-cve2017-8917,http-vuln-wnr1000-creds,"
            "ssl-ccs-injection,ssl-cert,ssl-dh-params,ssl-enum-ciphers,"
            "ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,"
            "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,"
            "smb-vuln-cve-2017-7494,smb-vuln-ms17-010,smb-vuln-ms08-067,"
            "smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos,"
            "ssh-auth-methods,ssh-brute,ssh-hostkey,ssh2-enum-algos,"
            "ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,"
            "ftp-vuln-cve2010-4221,"
            "mysql-databases,mysql-empty-password,mysql-info,"
            "mysql-vuln-cve2012-2122,"
            "rdp-enum-encryption,rdp-vuln-ms12-020,"
            "dns-zone-transfer,"
            "snmp-info,snmp-sysdescr,"
            "telnet-ntlm-info,irc-unrealircd-backdoor,"
            "mongodb-info,redis-info,memcached-info,"
            "vnc-info,vnc-brute,rpcinfo"
        ),
        "script_args": "mincvss=0.0,brute.mode=user,brute.firstonly=true,vulners.mincvss=0.0",
    },
}

DEFAULT_PROFILE = "standard"


class NmapIngestor:
    """
    Active Nmap scanner (NSE-enabled) with selectable scan profiles.
    ✔ Live stdout streaming (Dash-safe)
    ✔ HARD cancellation
    ✔ 4 profiles: quick / standard / full_vuln / comprehensive
    ✔ Stores XML + metadata to shared folder for Neo4j ingest
    """

    def __init__(self):
        global SCAN_ROOT
        from cyber_range.services._safe_dirs import safe_makedirs
        SCAN_ROOT = safe_makedirs(SCAN_ROOT)
        self._process = None

    # ----------------------------------------------------------------
    # Build the nmap command from a profile key
    # ----------------------------------------------------------------
    def _build_cmd(self, targets: list, profile_key: str, xml_path: str) -> list:
        profile = SCAN_PROFILES.get(profile_key, SCAN_PROFILES[DEFAULT_PROFILE])
        cmd = ["nmap"] + profile["flags"]

        # Statistics every 2 s for live terminal feed
        cmd += ["--stats-every", "2s", "-vv"]

        if profile["script"]:
            cmd += ["--script", profile["script"]]
        if profile["script_args"]:
            cmd += ["--script-args", profile["script_args"]]

        cmd += ["-oX", xml_path]
        cmd += targets
        return cmd, profile

    # =================================================================
    # ACTIVE SCAN WITH LIVE OUTPUT (USED BY DASH)
    # =================================================================
    def start_scan(self, targets, on_output, on_complete, profile="standard"):
        if not targets:
            raise ValueError("Nmap requires at least one target")

        profile = profile or DEFAULT_PROFILE
        if profile not in SCAN_PROFILES:
            on_output(f"[!] Unknown profile '{profile}', defaulting to 'standard'\n")
            profile = DEFAULT_PROFILE

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        target_label = targets[0].replace("/", "_").replace(":", "_")
        if len(targets) > 1:
            target_label = f"multi_{len(targets)}_targets"
        base_name = f"nmap_{target_label}_{timestamp}"

        xml_path = os.path.join(SCAN_ROOT, f"{base_name}.xml")
        meta_path = os.path.join(SCAN_ROOT, f"{base_name}.meta.json")

        cmd, prof_def = self._build_cmd(targets, profile, xml_path)

        on_output(
            f"[*] Nmap Profile: {prof_def['label']}\n"
            f"[*] Description: {prof_def['description']}\n"
            f"[*] Command: {' '.join(cmd)}\n\n"
        )

        def run():
            cancelled = False
            try:
                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    preexec_fn=os.setsid,
                )

                for line in self._process.stdout:
                    on_output(line)

                self._process.wait()

            except FileNotFoundError:
                on_output(
                    "\n[✖] nmap binary not found. Install with:\n"
                    "    sudo apt-get install -y nmap\n"
                )
                cancelled = True
            except Exception as e:
                on_output(f"\n[!] Nmap exception: {e}\n")
                cancelled = True

            finally:
                if self._process and self._process.poll() is None:
                    try:
                        os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                        cancelled = True
                    except Exception:
                        pass
                self._process = None

                # ── Auto-ingest XML → Neo4j ───────────────────────────
                ingest_count = 0
                ingest_status = "pending"
                if not cancelled and os.path.isfile(xml_path):
                    try:
                        from cyber_range.services.nmap_xml_parser import NmapXmlParser
                        on_output("\n[Nmap] Ingesting results into Neo4j...\n")
                        ingest_count  = NmapXmlParser().parse_and_ingest(xml_path, on_output)
                        ingest_status = "completed"
                    except Exception as ie:
                        on_output(f"[Nmap] ⚠ Auto-ingest failed: {ie}\n")
                        ingest_status = "failed"

                metadata = {
                    "scanner": "nmap",
                    "profile": profile,
                    "profile_label": prof_def["label"],
                    "targets": targets,
                    "scan_time": datetime.utcnow().isoformat(),
                    "format": "nmap-xml",
                    "nse_scripts": prof_def["script"].split(",") if prof_def["script"] else [],
                    "source": "nmap",
                    "ingest": {
                        "status": ingest_status,
                        "destination": "neo4j",
                        "findings": ingest_count,
                    }
                }

                with open(meta_path, "w") as f:
                    json.dump(metadata, f, indent=2)

                on_complete(cancelled, meta_path)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    # =================================================================
    # CANCEL ACTIVE SCAN (HARD KILL)
    # =================================================================
    def cancel_scan(self):
        if self._process and self._process.poll() is None:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                return True
            except Exception:
                return False
        return False

    # =================================================================
    # SYNCHRONOUS SCAN (NO INGEST)
    # =================================================================
    def scan_and_ingest(self, targets, profile="standard"):
        if not targets:
            raise ValueError("Nmap requires at least one target")

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        base_name = f"nmap_{timestamp}"
        xml_path = os.path.join(SCAN_ROOT, f"{base_name}.xml")
        meta_path = os.path.join(SCAN_ROOT, f"{base_name}.meta.json")

        cmd, prof_def = self._build_cmd(targets, profile or DEFAULT_PROFILE, xml_path)

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        metadata = {
            "scanner": "nmap",
            "profile": profile,
            "profile_label": prof_def["label"],
            "targets": targets,
            "scan_time": datetime.utcnow().isoformat(),
            "format": "nmap-xml",
            "nse_scripts": prof_def["script"].split(",") if prof_def["script"] else [],
            "source": "nmap",
            "ingest": {
                "status": "pending",
                "destination": "neo4j"
            }
        }

        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

        return {
            "status": "completed",
            "report": xml_path,
            "metadata": meta_path,
        }

    def ingest_latest(self, targets=None, profile="standard"):
        if not targets:
            raise ValueError("ingest_latest() requires targets")
        return self.scan_and_ingest(targets, profile)


NmapScanner = NmapIngestor
__all__ = ["NmapIngestor", "NmapScanner", "SCAN_PROFILES"]
