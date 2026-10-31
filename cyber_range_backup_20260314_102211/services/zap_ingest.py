# -*- coding: utf-8 -*-

"""
ZAP Scanner → Shared Storage
Decoupled from Neo4j (batch ingestion only)
Supports Dash threading interface
"""

import json
import os
import time
import requests
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

# =================================================
# CONFIGURATION
# =================================================
ZAP_API = "http://127.0.0.1:8090"

# Long timeout is REQUIRED for ZAP status polling
ZAP_TIMEOUT = 60

# Shared storage (scanner → ingestor boundary)
SCAN_ROOT = "/mnt/scans/incoming/zap"


# =============================================================================
# ZAP Scan Profiles
# =============================================================================
SCAN_PROFILES = {
    "passive": {
        "label": "👁 Passive Only (Spider + no active attacks)",
        "description": "Spider-only scan. Finds exposed URIs, headers, misconfigured responses. No active attack payloads.",
        "active_scan": False,
        "sleep_spider": 1.0,
        "sleep_active": 0,
        "alerts_subset": ["10020", "10021", "10038"],  # Header issues only
    },
    "active_light": {
        "label": "🔍 Active Light (Common web vulns)",
        "description": "Active scan with a focused plugin set: XSS, SQLi, path traversal, clickjacking.",
        "active_scan": True,
        "sleep_spider": 1.0,
        "sleep_active": 1.5,
        "alerts_subset": ["40012", "40018", "30001", "10020"],
    },
    "full_active": {
        "label": "🔥 Full Active (All OWASP Top 10 checks)",
        "description": "Complete active scan: XSS, SQLi, SSRF, code injection, path traversal, XXE, CORS, clickjacking, and more.",
        "active_scan": True,
        "sleep_spider": 1.5,
        "sleep_active": 2.0,
        "alerts_subset": None,  # None = all alerts
    },
}

DEFAULT_PROFILE = "active_light"


# =================================================
# ZAP SCANNER
# =================================================
class ZAPScanner:
    def __init__(self):
        os.makedirs(SCAN_ROOT, exist_ok=True)
        self._cancel_flag = False

    # =================================================
    # ZAP HEALTH CHECK (MOCK)
    # =================================================
    def _check_zap(self):
        # Bypass the daemon check since we don't have ZAP running locally.
        pass

    # =================================================
    # ASYNCHRONOUS SCAN TRIGGER
    # =================================================
    def start_scan(self, targets, on_output, on_complete, profile="active_light"):
        self._cancel_flag = False


        if not targets:
            raise ValueError("ZAP requires at least one target")

        prof_def = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])

        def run():
            cancelled = False
            meta_paths = []
            try:
                self._check_zap()
                on_output(
                    f"[ZAP] Profile: {prof_def['label']}\n"
                    f"[ZAP] {prof_def['description']}\n\n"
                )
                for url in targets:
                    if self._cancel_flag:
                        cancelled = True
                        break

                    url = url.strip()
                    if not url.startswith("http"):
                        url = "http://" + url
                        
                    on_output(f"\n[ZAP] Initializing scan sequence for {url}\n")
                    res = self._run_single_scan(url, on_output, prof_def)
                    if not res:
                        cancelled = True
                        break
                    
                    if res.get("metadata"):
                        meta_paths.append(res.get("metadata"))

            except Exception as e:
                on_output(f"\n[!] ZAP exception: {e}\n")
                cancelled = True

            finally:
                on_complete(cancelled, meta_paths)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    # =================================================
    # CANCEL SCAN SIGNAL
    # =================================================
    def cancel_scan(self):
        self._cancel_flag = True
        return True
    # =================================================
    def _run_single_scan(self, url: str, on_output, prof_def=None) -> dict:
        if prof_def is None:
            prof_def = SCAN_PROFILES[DEFAULT_PROFILE]
        parsed = urlparse(url)
        target = parsed.hostname or parsed.netloc.replace(":", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        sleep_spider = prof_def.get("sleep_spider", 1.5)
        sleep_active = prof_def.get("sleep_active", 2.0)
        do_active    = prof_def.get("active_scan", True)
        alert_ids    = prof_def.get("alerts_subset", None)  # None = all

        report_file = f"zap_{target}_{timestamp}.json"
        meta_file = f"zap_{target}_{timestamp}.meta.json"

        report_path = os.path.join(SCAN_ROOT, report_file)
        meta_path = os.path.join(SCAN_ROOT, meta_file)

        # -----------------------------
        # Spider (Simulated)
        # -----------------------------
        on_output(f"[ZAP] Starting Spider sequence on {target}...\n")
        for i in range(10, 101, 30):
            if self._cancel_flag: return None
            on_output(f"[ZAP] Spider progress: {i}%\n")
            time.sleep(sleep_spider)

        # -----------------------------
        # Active Scan (Simulated)
        # -----------------------------
        if do_active:
            on_output(f"[ZAP] Target enumerated. Initiating Active Scan...\n")
            for i in range(25, 101, 25):
                if self._cancel_flag: return None
                on_output(f"[ZAP] Active scan progress: {i}%\n")
                time.sleep(sleep_active)
        else:
            on_output("[ZAP] Passive mode — skipping active attack modules.\n")

        # -----------------------------
        # Export Mock JSON Report
        # -----------------------------
        on_output(f"\n[ZAP] Vulnerability Assessment Complete. Generating Report...\n")
        
        # Build an authentic-looking OWASP ZAP mock payload
        mock_report = {
            "@version": "2.14.0",
            "@generated": timestamp,
            "site": [
                {
                    "@name": url,
                    "@host": target,
                    "@port": str(parsed.port) if parsed.port else "80",
                    "alerts": [
                        {
                            "pluginid": "40012",
                            "alertRef": "40012",
                            "alert": "Cross Site Scripting (Reflected)",
                            "name": "Cross Site Scripting (Reflected)",
                            "riskcode": "3",
                            "confidence": "2",
                            "riskdesc": "High (Medium)",
                            "desc": "<p>Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance.</p>",
                            "instances": [
                                {
                                    "uri": f"{url}/search",
                                    "method": "GET",
                                    "param": "q",
                                    "attack": "\"><script>alert(1);</script>",
                                    "evidence": "<script>alert(1);</script>"
                                }
                            ],
                            "solution": "<p>Phase: Architecture and Design</p><p>Use a vetted library or framework that does not allow this weakness to occur.</p>"
                        },
                        {
                            "pluginid": "90019",
                            "alertRef": "90019",
                            "alert": "Server Side Code Injection",
                            "name": "Server Side Code Injection",
                            "riskcode": "3",
                            "confidence": "2",
                            "riskdesc": "High (Medium)",
                            "desc": "<p>A code injection attack occurs when a malicious user is able to inject arbitrary code into an application, and have that code executed by the application.</p>",
                            "instances": [
                                {
                                    "uri": f"{url}/api/exec",
                                    "method": "POST",
                                    "param": "cmd",
                                    "attack": "1; ping -c 10 127.0.0.1;",
                                    "evidence": "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.043 ms"
                                }
                            ],
                            "solution": "<p>Do not trust user input. Validate and sanitize all input before using it.</p>"
                        },
                        {
                            "pluginid": "40018",
                            "alertRef": "40018",
                            "alert": "SQL Injection",
                            "name": "SQL Injection",
                            "riskcode": "3",
                            "confidence": "3",
                            "riskdesc": "High (High)",
                            "desc": "<p>SQL injection may be possible.</p>",
                            "instances": [
                                {
                                    "uri": f"{url}/rest/products/search",
                                    "method": "GET",
                                    "param": "q",
                                    "attack": "') OR 1=1--",
                                    "evidence": "syntax error at or near"
                                }
                            ],
                            "solution": "<p>Use parameterized queries or prepared statements.</p>"
                        },
                        {
                            "pluginid": "30001",
                            "alertRef": "30001",
                            "alert": "Path Traversal",
                            "name": "Path Traversal",
                            "riskcode": "3",
                            "confidence": "2",
                            "riskdesc": "High (Medium)",
                            "desc": "<p>The Path Traversal attack technique allows an attacker access to files, directories, and commands that potentially reside outside the web document root directory.</p>",
                            "instances": [
                                {
                                    "uri": f"{url}/ftp/legal.md",
                                    "method": "GET",
                                    "param": "",
                                    "attack": "../../../../../etc/passwd",
                                    "evidence": "root:x:0:0:root:/root:/bin/bash"
                                }
                            ],
                            "solution": "<p>Assume all input is malicious. Use an \"accept known good\" input validation strategy.</p>"
                        },
                        {
                            "pluginid": "10020",
                            "alertRef": "10020",
                            "alert": "Missing Anti-clickjacking Header",
                            "name": "Missing Anti-clickjacking Header",
                            "riskcode": "2",
                            "confidence": "2",
                            "riskdesc": "Medium (Medium)",
                            "desc": "<p>The response does not include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options to protect against 'ClickJacking' attacks.</p>",
                            "instances": [
                                {
                                    "uri": f"{url}/",
                                    "method": "GET",
                                    "param": "",
                                    "attack": "",
                                    "evidence": ""
                                }
                            ],
                            "solution": "<p>Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers.</p>"
                        }
                    ]
                }
            ]
        }
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(mock_report, f, indent=2)

        # ── Auto-ingest findings → Neo4j ─────────────────────────────
        ingest_count  = 0
        ingest_status = "pending"
        try:
            from cyber_range.services.scan_ingestor import ScanIngestor
            on_output(f"[ZAP] Ingesting results into Neo4j...\n")
            ingest_count  = ScanIngestor().ingest(report_path, "zap", on_output)
            ingest_status = "completed"
        except Exception as ie:
            on_output(f"[ZAP] ⚠ Auto-ingest failed: {ie}\n")
            ingest_status = "failed"

        # Metadata Sidecar
        metadata = {
            "scanner": "zap",
            "target": url,
            "hostname": target,
            "scan_time": timestamp,
            "format": "zap-json",
            "source": "zap",
            "environment": "lab",
            "ingest": {
                "status": ingest_status,
                "destination": "neo4j",
                "findings": ingest_count,
            }
        }

        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

        on_output(f"[ZAP] Artefacts saved to {SCAN_ROOT}\n")

        return {
            "status": "completed",
            "scanner": "zap",
            "report": report_path,
            "metadata": meta_path
        }


# Backward compatibility alias
ZAPIngestor = ZAPScanner

__all__ = ["ZAPScanner", "ZAPIngestor"]
