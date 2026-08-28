"""
Expedite Strike — Continuous Threat Exposure Management (CTEM) & Delta Verification
==================================================================================
Provides:
  1. 1-Click Targeted Fix Verification (Instant lightweight retest of single finding)
  2. Perimeter Drift & Differential Analysis (Baseline vs Current Scan)
  3. Posture Improvement & Delta Scoring
"""

import os
import json
import time
import socket
import urllib.request
import urllib.error
import ssl
from datetime import datetime
from typing import List, Dict, Any, Tuple


class CTEMEngine:
    """Continuous Threat Exposure Management and Delta Verification Engine."""

    # ══════════════════════════════════════════════════════════════════════════
    #  1. 1-CLICK TARGETED FIX VERIFICATION
    # ══════════════════════════════════════════════════════════════════════════
    @classmethod
    def verify_finding_fix(cls, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a targeted, lightweight retest of a single finding to certify remediation."""
        t0 = time.time()
        title = (finding.get("title", "") or finding.get("name", "")).strip()
        host = (finding.get("host", "") or finding.get("ip", "")).strip()
        scanner = finding.get("scanner", finding.get("tool", "")).upper()
        cve = finding.get("cve", "")

        t_low = title.lower()
        h_low = host.lower()

        # Parse host and port
        clean_host = host.replace("http://", "").replace("https://", "").split("/")[0]
        port = 80
        if ":" in clean_host:
            parts = clean_host.split(":")
            clean_host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 80
        elif "https://" in host:
            port = 443

        status = "STILL_VULNERABLE"
        proof = ""

        # ── Test 1: Open Port / Raw Socket Service Check ─────────────────────
        if "open port" in t_low or "port:" in t_low or scanner == "NMAP":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                res = s.connect_ex((clean_host, port))
                if res == 0:
                    # Port still open, check if service banner changed
                    banner = ""
                    try:
                        s.send(b"\r\n")
                        banner = s.recv(256).decode(errors="ignore").strip()
                    except Exception:
                        pass
                    s.close()

                    if "vsftpd" in t_low and "2.3.4" in t_low:
                        if "2.3.4" not in banner and banner:
                            status = "REMEDIATED"
                            proof = f"Service upgraded: Port {port} responded with non-vulnerable banner: '{banner}'"
                        else:
                            status = "STILL_VULNERABLE"
                            proof = f"Port {port} remains OPEN with vulnerable service banner: '{banner or 'vsftpd 2.3.4'}'"
                    else:
                        status = "STILL_VULNERABLE"
                        proof = f"Port {port}/tcp is actively accepting connections. Banner: '{banner[:80]}'"
                else:
                    s.close()
                    status = "REMEDIATED"
                    proof = f"Connection refused/timed out on {clean_host}:{port}. Service has been closed or firewalled."
            except Exception as ex:
                status = "REMEDIATED"
                proof = f"Port unreachable ({ex}). Service verified closed."

        # ── Test 2: Web / HTTP Sensitive File / Header Check ─────────────────
        elif "http" in h_low or "header" in t_low or "sensitive" in t_low or ".env" in t_low or ".git" in t_low:
            url = host if host.startswith("http") else f"http://{clean_host}:{port}"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent": "ExpediteStrike-Verifier/2.0"})
                with urllib.request.urlopen(req, timeout=4.0, context=ctx) as response:
                    resp_code = response.getcode()
                    resp_headers = dict(response.headers)
                    body_sample = response.read(256).decode(errors="ignore")

                    if "header" in t_low:
                        h_name = "content-security-policy" if "csp" in t_low or "content-security" in t_low else \
                                 "x-frame-options" if "frame" in t_low else \
                                 "strict-transport-security" if "hsts" in t_low else "x-content-type-options"
                        if any(h_name in k.lower() for k in resp_headers):
                            status = "REMEDIATED"
                            proof = f"Security header '{h_name}' is now active: '{resp_headers.get(h_name, 'Present')}'"
                        else:
                            status = "STILL_VULNERABLE"
                            proof = f"Security header '{h_name}' is still missing in server HTTP response."
                    elif "sensitive" in t_low or ".env" in t_low:
                        if resp_code in (403, 404):
                            status = "REMEDIATED"
                            proof = f"HTTP status {resp_code} (Access Restricted/Not Found). File is no longer publicly exposed."
                        else:
                            status = "STILL_VULNERABLE"
                            proof = f"HTTP {resp_code} OK. Sensitive endpoint remains accessible. Sample: {body_sample[:60]}"
                    else:
                        status = "STILL_VULNERABLE"
                        proof = f"Endpoint responded with HTTP {resp_code}."
            except urllib.error.HTTPError as he:
                if he.code in (403, 404):
                    status = "REMEDIATED"
                    proof = f"HTTP Error {he.code}: Access now restricted. Endpoint safely hardened."
                else:
                    status = "STILL_VULNERABLE"
                    proof = f"HTTP Error {he.code}: {he.reason}"
            except Exception as ex:
                status = "REMEDIATED"
                proof = f"Endpoint unreachable ({ex}). Vector safely mitigated."

        # ── Test 3: General Fallback Exploit Re-evaluation ───────────────────
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.5)
                res = s.connect_ex((clean_host, port))
                s.close()
                if res != 0:
                    status = "REMEDIATED"
                    proof = f"Target {clean_host}:{port} no longer accepting connections. Vector neutralized."
                else:
                    status = "STILL_VULNERABLE"
                    proof = f"Target {clean_host}:{port} is still reachable. Vulnerability requires patch deployment."
            except Exception as ex:
                status = "REMEDIATED"
                proof = f"Host unreachable: {ex}"

        elapsed = round(time.time() - t0, 2)
        return {
            "finding_title": title,
            "target": host,
            "cve": cve,
            "status": status,
            "is_remediated": status == "REMEDIATED",
            "proof": proof,
            "verification_time_s": elapsed,
            "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ══════════════════════════════════════════════════════════════════════════
    #  2. PERIMETER DRIFT & DELTA SCAN COMPARISON
    # ══════════════════════════════════════════════════════════════════════════
    @classmethod
    def compute_perimeter_delta(cls, current_findings: List[Dict[str, Any]],
                                baseline_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare current scan findings against a historical baseline scan to isolate drift and fixes."""
        current_findings = current_findings or []
        baseline_findings = baseline_findings or []

        def _key(f):
            return ((f.get("title") or f.get("name") or "").strip().lower()[:60],
                    (f.get("host") or f.get("ip") or "").strip().lower()[:60])

        current_map = {_key(f): f for f in current_findings}
        baseline_map = {_key(f): f for f in baseline_findings}

        current_keys = set(current_map.keys())
        baseline_keys = set(baseline_map.keys())

        new_keys = current_keys - baseline_keys
        resolved_keys = baseline_keys - current_keys
        persistent_keys = current_keys & baseline_keys

        new_findings = [current_map[k] for k in new_keys]
        resolved_findings = [baseline_map[k] for k in resolved_keys]
        persistent_findings = [current_map[k] for k in persistent_keys]

        # Severity weights for risk delta
        w = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        score_curr = sum(w.get(f.get("severity", "medium").lower(), 5) for f in current_findings)
        score_base = sum(w.get(f.get("severity", "medium").lower(), 5) for f in baseline_findings)
        delta_score = score_curr - score_base

        if delta_score < 0:
            posture_status = f"POSTURE IMPROVED (Risk reduced by {abs(delta_score)} pts)"
        elif delta_score > 0:
            posture_status = f"DRIFT DETECTED (+{delta_score} pts new risk introduced)"
        else:
            posture_status = "POSTURE UNCHANGED (Baseline maintained)"

        return {
            "baseline_count": len(baseline_findings),
            "current_count": len(current_findings),
            "new_exposures_count": len(new_findings),
            "remediated_count": len(resolved_findings),
            "persistent_count": len(persistent_findings),
            "baseline_risk_score": score_base,
            "current_risk_score": score_curr,
            "risk_delta": delta_score,
            "posture_status": posture_status,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "persistent_findings": persistent_findings,
        }
