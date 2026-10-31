import os
import subprocess
import tempfile
import threading
import signal
import json
from datetime import datetime

SCAN_ROOT = "/mnt/scans/incoming/nuclei"

# =============================================================================
# Nuclei Scan Profiles
# =============================================================================
SCAN_PROFILES = {
    "light": {
        "label": "⚡ Light (SSL & Info checks only)",
        "description": "Passive-only: SSL certs, TLS versions, DNS names, info banners. No network port probing — safe for external targets.",
        "tags": ["ssl", "info"],
        "severity": ["info", "low"],
        "extra_flags": [
            "-rate-limit", "30",
            "-timeout", "5",
            "-retries", "0",
            "-max-host-error", "5",
            "-no-interactsh",
        ],
    },
    "standard": {
        "label": "🔍 Standard (All community templates)",
        "description": "Full default community template run — balanced speed vs coverage. Includes network checks.",
        "tags": None,
        "severity": None,
        "extra_flags": [
            "-rate-limit", "150",
            "-timeout", "5",
            "-retries", "1",
            "-max-host-error", "30",
            "-no-interactsh",
        ],
    },
    "cve_only": {
        "label": "🎯 CVE-Only (CVEs + Exposures)",
        "description": "Focuses on confirmed CVEs and service exposures. Highest signal-to-noise ratio.",
        "tags": ["cve", "exposures", "misconfig"],
        "severity": ["medium", "high", "critical"],
        "extra_flags": [
            "-rate-limit", "150",
            "-timeout", "5",
            "-retries", "1",
            "-max-host-error", "20",
            "-no-interactsh",
        ],
    },
    "full": {
        "label": "🔥 Full (All templates incl. brute & fuzzing)",
        "description": "Everything: CVEs, fuzzing, brute-force, default-credentials, DAST. Use on isolated labs only.",
        "tags": ["cve", "fuzzing", "brute-force", "default-logins",
                 "exposed-panels", "exposures", "misconfiguration",
                 "network", "takeover", "technologies", "token-spray"],
        "severity": None,
        "extra_flags": [
            "-rate-limit", "100",
            "-bulk-size", "10",
            "-timeout", "8",
            "-retries", "1",
            "-max-host-error", "50",
        ],
    },
}

DEFAULT_PROFILE = "standard"


class NucleiIngestor:
    """
    Active Nuclei scanner with selectable profiles.
    ✔ Live stdout streaming (Dash-safe)
    ✔ HARD cancellation via process groups
    ✔ Stores JSON artifacts + meta to shared folder
    """

    def __init__(self):
        os.makedirs(SCAN_ROOT, exist_ok=True)
        self._process = None

    # =================================================
    # BUILD CMD FROM PROFILE
    # =================================================
    def _build_cmd(self, target_path, json_path, profile_key):
        import shutil
        nuclei_bin = (
            shutil.which("nuclei")
            or "/home/kali/.local/bin/nuclei"
            or "/usr/local/bin/nuclei"
        )

        profile = SCAN_PROFILES.get(profile_key, SCAN_PROFILES[DEFAULT_PROFILE])

        cmd = [nuclei_bin, "-l", target_path, "-je", json_path, "-stats", "-si", "2"]

        if profile["tags"]:
            cmd += ["-tags", ",".join(profile["tags"])]
        if profile["severity"]:
            cmd += ["-severity", ",".join(profile["severity"])]

        cmd += profile.get("extra_flags", [])
        return cmd, profile

    # =================================================
    # ACTIVE SCAN WITH LIVE OUTPUT (USED BY DASH)
    # =================================================
    def start_scan(self, targets, on_output, on_complete, profile="standard"):

        if not targets:
            raise ValueError("Nuclei requires at least one target")

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        
        # Safe label creation
        first_target = targets[0].replace("://", "_").replace("/", "_").replace(":", "_")
        target_label = "multi_target" if len(targets) > 1 else first_target
        base_name = f"nuclei_{target_label}_{timestamp}"

        json_path = os.path.join(SCAN_ROOT, f"{base_name}.json")
        meta_path = os.path.join(SCAN_ROOT, f"{base_name}.meta.json")
        target_path = os.path.join(SCAN_ROOT, f"{base_name}_targets.txt")
        
        with open(target_path, "w") as f:
            f.write("\n".join(targets))

        profile_key = profile or DEFAULT_PROFILE
        cmd, prof_def = self._build_cmd(target_path, json_path, profile_key)

        on_output(
            f"[*] Nuclei Profile: {prof_def['label']}\n"
            f"[*] {prof_def['description']}\n"
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
                    preexec_fn=os.setsid,  # Process-group isolation for hard kills
                )

                for line in self._process.stdout:
                    on_output(line)

                self._process.wait()

            except FileNotFoundError:
                on_output(
                    "\n[✖] Nuclei binary not found on this system.\n"
                    "[→] Install it by running in your terminal:\n\n"
                    "    curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.10/nuclei_3.3.10_linux_amd64.zip -o /tmp/nuclei.zip\n"
                    "    unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin\n"
                    "    sudo mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei\n"
                    "    sudo chmod +x /usr/local/bin/nuclei\n\n"
                    "[SYS] Restart the app after installation.\n"
                )
                cancelled = True
            except Exception as e:
                on_output(f"\n[!] Nuclei exception: {e}\n")
                cancelled = True

            finally:
                if self._process and self._process.poll() is None:
                    try:
                        os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                        cancelled = True
                    except Exception:
                        pass

                self._process = None

                # Cleanup targets file
                if os.path.exists(target_path):
                    os.remove(target_path)

                # ── Auto-ingest findings → Neo4j ──────────────────────
                ingest_count  = 0
                ingest_status = "pending"
                if not cancelled and os.path.isfile(json_path):
                    try:
                        from cyber_range.services.scan_ingestor import ScanIngestor
                        on_output("\n[Nuclei] Ingesting results into Neo4j...\n")
                        ingest_count  = ScanIngestor().ingest(json_path, "nuclei", on_output)
                        ingest_status = "completed"
                    except Exception as ie:
                        on_output(f"[Nuclei] ⚠ Auto-ingest failed: {ie}\n")
                        ingest_status = "failed"

                # Write metadata sidecar
                metadata = {
                    "scanner": "nuclei",
                    "profile": profile_key,
                    "profile_label": prof_def.get("label", profile_key),
                    "targets": targets,
                    "scan_time": datetime.utcnow().isoformat(),
                    "format": "nuclei-json",
                    "source": "nuclei",
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

    # =================================================
    # CANCEL ACTIVE SCAN (HARD KILL)
    # =================================================
    def cancel_scan(self):
        if self._process and self._process.poll() is None:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                return True
            except Exception:
                return False
        return False


NucleiScanner = NucleiIngestor
__all__ = ["NucleiIngestor", "NucleiScanner"]
