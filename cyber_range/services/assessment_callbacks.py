"""
assessment_callbacks.py
=======================
Self-contained module that registers all Assessment Manager callbacks.
Can be imported by both app.py and any standalone Dash app.

Usage:
    from cyber_range.services import assessment_callbacks
    assessment_callbacks.register(app)   # app = Dash instance
"""
from __future__ import annotations

import os
import glob
import threading
import json as _json

import dash
from dash import html, dcc, callback, Input, Output, State, ctx, no_update
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

# ── Shared scan state (process-level singleton) ───────────────────────────────
class ScanStatus:
    READY    = "READY"
    RUNNING  = "RUNNING"
    PARTIAL  = "PARTIAL"
    INVALID  = "INVALID"
    COMPLETE = "COMPLETE"
    ERROR    = "ERROR"


SCAN_STATE: dict = {
    "running":        False,
    "logs":           [],
    "tabs_updated":   [],
    "progress":       0.0,
    "active_scanner": None,
    "status":         ScanStatus.READY,
    "scan_validity":  None,
    "coverage_pct":   None,
    "compliance_pct": None,
    "score_reliable": False,
    "authenticated":  False,
    "benchmark_used": None,
    "scan_target":    None,
    "scan_start":     None,
    "scan_end":       None,
    "poam_path":      None,
    "evidence_path":  None,
}

# ── Scan profile options per engine ──────────────────────────────────────────
SCAN_PROFILES = {
    "nmap": [
        {"label": "Quick (Top 100 ports, no scripts)",       "value": "nmap:quick"},
        {"label": "Standard (vuln + vulners)",               "value": "nmap:standard"},
        {"label": "Full Vuln (All NSE vuln + SSL/SMB/HTTP)", "value": "nmap:full_vuln"},
        {"label": "Comprehensive (All ports + UDP + brute)", "value": "nmap:comprehensive"},
    ],
    "nuclei": [
        {"label": "Light (Info & Network only)",                "value": "nuclei:light"},
        {"label": "Standard (All community templates)",         "value": "nuclei:standard"},
        {"label": "CVE-Only (CVEs + Exposures)",                "value": "nuclei:cve_only"},
        {"label": "Full (All templates + brute + fuzzing)",     "value": "nuclei:full"},
    ],
    "zap": [
        {"label": "Passive (Spider + headers only)",           "value": "zap:passive"},
        {"label": "Active Light (XSS, SQLi, Path Traversal)", "value": "zap:active_light"},
        {"label": "Full Active (All OWASP Top 10)",            "value": "zap:full_active"},
    ],
    "aegisprobe": [
        {"label": "Passive (Passive plugins only)",             "value": "Expedite Strike:passive:low"},
        {"label": "Full (All plugins, medium intensity)",       "value": "Expedite Strike:full:medium"},
        {"label": "Aggressive (All plugins, max workers)",      "value": "Expedite Strike:full:aggressive"},
    ],
    "burp": [
        {"label": "Passive Crawl (Spider + passive issues)",          "value": "burp:passive"},
        {"label": "Active Scan (OWASP Top 10 audit)",                 "value": "burp:active"},
        {"label": "Full Audit (All insertion points + JS analysis)",  "value": "burp:full_audit"},
    ],
    "openvas": [
        {"label": "Discovery (Host discovery only)",             "value": "openvas:discovery"},
        {"label": "Full & Fast (Default NVTs, optimised)",       "value": "openvas:full_fast"},
        {"label": "Deep Scan (All NVTs + brute + DoS-safe)",    "value": "openvas:deep"},
    ],
    "nessus": [
        {"label": "Basic Network (Host discovery + common vulns)",    "value": "nessus:basic"},
        {"label": "Advanced Scan (All plugins, compliance checks)",   "value": "nessus:advanced"},
        {"label": "PCI-DSS / Credentialed (Full audit)",              "value": "nessus:pci_cred"},
    ],
    "stig_ckl": [
        {"label": "Import CKL Checklist",            "value": "stig_ckl:import"},
        {"label": "Evaluate & Score (CAT I/II/III)", "value": "stig_ckl:evaluate"},
    ],
    "scap_xccdf": [
        {"label": "🔍 Full Assessment — All SSG Benchmarks",                "value": "scap_xccdf:all"},
        {"label": "🔍 RHEL 8/9  — DISA STIG + CIS  (1530-1697 rules)",    "value": "scap_xccdf:linux_server"},
        {"label": "🔍 Ubuntu 22.04/24.04 — CIS + DISA STIG",              "value": "scap_xccdf:linux_desktop"},
        {"label": "🔍 Debian 12 / AlmaLinux 9 — CIS Benchmark",           "value": "scap_xccdf:network"},
        {"label": "🔍 Fedora / CentOS 8 — NIST 800-53 + CIS",             "value": "scap_xccdf:applications"},
        {"label": "🔍 Cloud / Container — OCP4, EKS, CS9/10 (1530 rules)","value": "scap_xccdf:cloud"},
        {"label": "🔍 Windows Server — DISA STIG",                        "value": "scap_xccdf:windows_server"},
        {"label": "🔍 Windows Desktop — CIS Win 10/11",                   "value": "scap_xccdf:windows_desktop"},
        {"label": "📂 Import Custom XCCDF / DS File (path in Targets)",   "value": "scap_xccdf:import"},
    ],
}

_SCAN_PROFILES_JSON = _json.dumps(SCAN_PROFILES)

# ── Test type → scanner mapping ───────────────────────────────────────────────
TEST_TYPE_SCANNERS = {
    "web":     ["zap", "nuclei"],
    "api":     ["zap", "aegisprobe", "nuclei"],
    "network": ["nmap", "openvas", "nessus"],
    "sat":     ["stig_ckl", "scap_xccdf"],
}
TEST_TYPE_LABELS = {
    "all":     "🌐 All scanners",
    "web":     "🕸️ Web Testing  (ZAP · Nuclei)",
    "api":     "⚙️ API Testing  (ZAP · aegisprobe · Nuclei)",
    "network": "🖥️ Network / OS-IP  (Nmap · OpenVAS · Nessus)",
    "sat":     "🔒 SAT / Compliance  (STIG · SCAP)",
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — build findings table from Neo4j
# ─────────────────────────────────────────────────────────────────────────────
def _build_scan_summary(scanner_filter=None, scanner_list=None,
                         date_start=None, date_end=None):
    try:
        from cyber_range.services.neo4j_engine import Neo4jEngine
        engine = Neo4jEngine()

        where = "WHERE f.source IS NOT NULL"
        if scanner_list:
            quoted = ", ".join(f"'{s}'" for s in scanner_list)
            where += f" AND f.source IN [{quoted}]"
        elif scanner_filter:
            where += f" AND f.source = '{scanner_filter}'"
        if date_start:
            where += f" AND f.first_seen >= '{date_start}'"
        if date_end:
            where += f" AND f.first_seen <= '{date_end}T23:59:59'"

        with engine.driver.session() as s:
            rows_data = s.run(f"""
                MATCH (srv:Service)-[:HAS_FINDING]->(f:Finding)
                {where}
                RETURN
                    coalesce(f.source, f.scanner, 'Unknown') AS scanner,
                    coalesce(f.name, f.title, 'Unknown Finding') AS name,
                    coalesce(f.severity, f.severity_text,
                        CASE f.riskcode
                            WHEN '3' THEN 'High'
                            WHEN '2' THEN 'Medium'
                            WHEN '1' THEN 'Low'
                            WHEN '0' THEN 'Information'
                            ELSE 'Medium' END
                    ) AS severity,
                    coalesce(f.cwe, f.pluginid, '') AS cwe,
                    coalesce(f.url, f.path, f.host, '') AS url,
                    coalesce(f.description, f.evidence, '') AS evidence,
                    f.cve AS cve
                ORDER BY
                    CASE coalesce(f.severity, '')
                        WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                        WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                    scanner
                LIMIT 500
            """).data()
    except Exception:
        return html.Div()

    if not rows_data:
        return html.Div()

    SEV  = ["Critical", "High", "Medium", "Low", "Information"]
    CLRS = {"Critical": "#ff3333", "High": "#ff9900", "Medium": "#00f0ff",
             "Low": "#aaa", "Information": "#444"}
    BDGE = {"Critical": "danger", "High": "warning", "Medium": "info",
             "Low": "secondary", "Information": "light"}
    SRC_CLR = {
        "nmap": "#00ff99", "zap": "#e67e22", "aegisprobe": "#9b59b6",
        "nuclei": "#e74c3c", "aegisprobe": "#9b59b6",
    }

    counts = {s: 0 for s in SEV}
    for row in rows_data:
        sev = row.get("severity", "Information")
        if sev in counts:
            counts[sev] += 1
    total = len(rows_data)

    pills = dbc.Row([
        dbc.Col(html.Div([
            html.Div(str(counts[s]),
                     style={"fontSize": "26px", "fontWeight": "900", "color": CLRS[s]}),
            html.Div(s, style={"fontSize": "10px", "color": "#8b949e"}),
        ], style={"textAlign": "center", "padding": "10px",
                  "background": "#161b22", "borderRadius": "6px",
                  "border": f"1px solid {CLRS[s]}30"}),
        width="auto") for s in SEV
    ], className="g-2 mb-3")

    bar = [html.Div(str(counts[s]), style={
                "flex": str(max(counts[s] / total * 100, 0.5) if total else 1),
                "background": CLRS[s], "textAlign": "center",
                "fontSize": "11px", "fontWeight": "700", "padding": "3px 0",
                "color": "#000" if s in ("Medium", "Low", "Information") else "#fff",
                "minWidth": "20px"})
           for s in SEV if counts[s]]
    severity_bar = html.Div([
        html.Small("Risk Distribution", style={"color": "#8b949e", "fontSize": "11px"}),
        html.Div(bar, style={"display": "flex", "borderRadius": "4px",
                              "overflow": "hidden", "height": "22px", "marginTop": "4px"}),
    ], style={"marginBottom": "12px"})

    table_rows = []
    for row in rows_data:
        sev   = row.get("severity", "Information")
        src   = row.get("scanner", "Unknown")
        name  = row.get("name", "")
        cwe   = row.get("cwe", "") or ""
        url   = str(row.get("url", "") or "")[:60]
        desc  = str(row.get("evidence", "") or "")[:80]
        cve   = row.get("cve", "") or ""
        src_color = SRC_CLR.get(src, "#8b949e")
        table_rows.append(html.Tr([
            html.Td(dbc.Badge(sev, color=BDGE.get(sev, "secondary"),
                              style={"fontSize": "10px"})),
            html.Td(html.Small(src, style={"color": src_color, "fontWeight": "600"})),
            html.Td([
                html.Span(name, style={"color": "#e6e6e6", "fontWeight": "600", "fontSize": "12px"}),
                html.Span(f" {cve}", style={"color": "#ff6b6b", "fontSize": "10px",
                                             "marginLeft": "4px"}) if cve else "",
            ]),
            html.Td(dbc.Badge(cwe, color="secondary", style={"fontSize": "10px"})),
            html.Td(html.Code(url, style={"fontSize": "10px", "color": "#00f0ff"})),
            html.Td(desc, style={"fontSize": "10px", "color": "#555"}),
        ], style={"borderLeft": f"3px solid {CLRS.get(sev, '#444')}"}))

    table = dbc.Table(
        [html.Thead(html.Tr([
            html.Th("Severity"), html.Th("Scanner"), html.Th("Finding"),
            html.Th("CWE"), html.Th("URL / Host"), html.Th("Evidence"),
         ], style={"fontSize": "11px", "color": "#ffd700", "background": "#111"})),
         html.Tbody(table_rows)],
        bordered=False, hover=True, size="sm"
    )

    scanners_seen: dict = {}
    for row in rows_data:
        src = row.get("scanner", "Unknown")
        scanners_seen[src] = scanners_seen.get(src, 0) + 1
    scanner_pills = html.Div([
        dbc.Badge(f"{src}: {cnt}", color="secondary",
                  style={"marginRight": "6px", "fontSize": "11px",
                         "backgroundColor": SRC_CLR.get(src, "#444"), "color": "#000"})
        for src, cnt in sorted(scanners_seen.items(), key=lambda x: -x[1])
    ], style={"marginBottom": "10px"})

    return dbc.Card([
        dbc.CardHeader(
            f"📊 All Scanner Results — {total} Finding{'s' if total != 1 else ''}",
            style={"background": "#161b22", "color": "#ffd700", "fontWeight": "700",
                   "borderBottom": "1px solid #30363d"}
        ),
        dbc.CardBody([
            scanner_pills, pills, severity_bar,
            html.Div(table, style={"maxHeight": "460px", "overflowY": "auto",
                                    "border": "1px solid #30363d", "borderRadius": "6px"}),
        ], style={"background": "#0d1117"}),
    ], style={"border": "1px solid #30363d", "borderRadius": "8px", "marginTop": "16px"})


# ─────────────────────────────────────────────────────────────────────────────
# REGISTER — call this once after Dash app is created
# ─────────────────────────────────────────────────────────────────────────────
def register(app: dash.Dash) -> None:
    """Register all Assessment Manager callbacks onto `app`."""

    # ── Dynamic scan profile options ─────────────────────────────────────────
    app.clientside_callback(
        """
        function(scanner) {
            var PROFILES = """ + _SCAN_PROFILES_JSON + """;
            if (!scanner) { scanner = 'scap_xccdf'; }
            var opts = PROFILES[scanner] || [];
            var defaultVal = opts.length > 0 ? opts[0].value : null;
            return [opts, defaultVal];
        }
        """,
        Output("nmap-profile-select", "options"),
        Output("nmap-profile-select", "value"),
        Input("scanner-select", "value"),
    )

    # ── Scan interval sync ────────────────────────────────────────────────────
    @app.callback(
        Output("scan-log-interval", "disabled", allow_duplicate=True),
        Input("rt-suite-active-tab", "data"),
        prevent_initial_call=True,
    )
    def sync_scan_interval(active_tab):
        if active_tab == "rt-suite-assessment":
            return not SCAN_STATE.get("running", False)
        raise PreventUpdate

    # ── Scan controller ───────────────────────────────────────────────────────
    @app.callback(
        Output("scan-log-output",   "children",  allow_duplicate=True),
        Output("ingest-btn",        "disabled",  allow_duplicate=True),
        Output("cancel-btn",        "disabled",  allow_duplicate=True),
        Output("scan-log-interval", "disabled",  allow_duplicate=True),
        Input("scan-btn",           "n_clicks"),
        Input("cancel-btn",         "n_clicks"),
        State("scanner-select",     "value"),
        State("target-input",       "value"),
        State("nmap-profile-select","value"),
        State("scap-ssh-user",      "value"),
        State("scap-ssh-key",       "value"),
        State("scap-ssh-password",  "value"),
        prevent_initial_call=True,
    )
    def scan_controller(scan_clicks, cancel_clicks, scanner, targets, nmap_profile,
                        scap_ssh_user, scap_ssh_key, scap_ssh_password):

        trigger = ctx.triggered_id

        def log(msg):
            SCAN_STATE["logs"].append(msg)

        # ── Cancel ────────────────────────────────────────────────────────
        if trigger == "cancel-btn":
            scanner_obj = SCAN_STATE.get("active_scanner")
            if scanner_obj and hasattr(scanner_obj, "cancel_scan"):
                cancelled = scanner_obj.cancel_scan()
                return (
                    "⛔ Scan cancelled by user." if cancelled else "⚠️ Failed to cancel.",
                    True, True, True,
                )
            return "⚠️ No active scan to cancel.", True, True, True

        # ── Run ───────────────────────────────────────────────────────────
        if trigger != "scan-btn":
            raise PreventUpdate

        if not scanner or not targets:
            return "❌ Scanner and target required.", True, True, True

        raw_targets = [t.strip() for t in targets.splitlines() if t.strip()]
        if not raw_targets:
            return "❌ No valid targets.", True, True, True

        # Validate profile/scanner match
        _profile_prefix = (nmap_profile or "").split(":")[0].lower()
        _scanner_lower  = (scanner or "").lower()
        if _profile_prefix and _profile_prefix != _scanner_lower:
            _valid = SCAN_PROFILES.get(_scanner_lower, [])
            nmap_profile = _valid[0]["value"] if _valid else f"{_scanner_lower}:all"

        composite = (nmap_profile or "").strip()
        if ":" in composite:
            parts = composite.split(":")
            profile_scanner = parts[0]
            profile_key     = parts[1]
            xstrike_intensity = parts[2] if len(parts) > 2 else "medium"
        else:
            profile_scanner = _scanner_lower.replace("aegisprobe", "aegis").replace("burp", "aegis")
            profile_key     = composite or "standard"
            xstrike_intensity = "medium"

        effective_scanner = profile_scanner if profile_scanner else _scanner_lower

        # Reset state machine
        SCAN_STATE.update({
            "running": True, "progress": 0.0, "logs": [],
            "tabs_updated": [], "active_scanner": None,
            "status": ScanStatus.RUNNING, "scan_validity": None,
            "coverage_pct": None, "compliance_pct": None,
            "score_reliable": False,
        })
        try:
            from datetime import datetime as _dtnow, timezone as _tznow
            SCAN_STATE["scan_start"] = _dtnow.now(_tznow.utc).isoformat()
        except Exception:
            pass

        from cyber_range.ingest.neo4j_ingestor import Neo4jIngestor
        import pathlib

        def handle_global_completion(cancelled, meta_path):
            if cancelled:
                log("\n⛔ [SYS] Scan aborted by user.")
            else:
                log("\n✅ [SYS] Scan completed.")
                if meta_path:
                    log("[*] Auto Neo4j Ingestion...")
                    try:
                        meta_paths = meta_path if isinstance(meta_path, list) else [meta_path]
                        for p in meta_paths:
                            if p:
                                Neo4jIngestor().process_meta(pathlib.Path(p))
                        log("[+] Graph injection OK.")
                        from cyber_range.services.mitre_mapper import map_vulnerabilities_to_mitre
                        from cyber_range.services.neo4j_engine import Neo4jEngine
                        with Neo4jEngine().driver.session() as s:
                            map_vulnerabilities_to_mitre(s)
                        log("[+] MITRE mapping OK.")
                        from cyber_range.services.vuln_mgmt_sync import sync_findings_to_vuln_mgmt
                        synced = sync_findings_to_vuln_mgmt(on_output=log)
                        log(f"[+] {synced} vulns synced to Vuln Management.")
                        SCAN_STATE["tabs_updated"] = [
                            "Assessment", "Vulnerabilities", "MITRE ATT&CK", "Vulnerability Management"
                        ]
                    except Exception as e:
                        log(f"❌ Auto-ingest: {e}")
            SCAN_STATE["running"] = False
            SCAN_STATE["active_scanner"] = None

        # ── Nmap ──────────────────────────────────────────────────────────
        if effective_scanner == "nmap":
            from cyber_range.services.nmap_ingest import NmapIngestor
            import socket
            clean_targets = []
            for t in raw_targets:
                val = t.lower()
                for prefix in ("https://", "http://"):
                    if val.startswith(prefix): val = val[len(prefix):]
                if "/" in val:
                    parts = val.split("/")
                    if not (len(parts) == 2 and parts[1].isdigit()):
                        val = parts[0]
                if ":" in val: val = val.split(":")[0]
                try:
                    ip = socket.gethostbyname(val)
                    clean_targets.append(ip)
                except Exception:
                    clean_targets.append(val)
            clean_targets = list(dict.fromkeys(clean_targets))
            log(f"[*] Nmap ({len(clean_targets)} targets) — Profile: {nmap_profile}...")
            scanner_obj = NmapIngestor()
            SCAN_STATE["active_scanner"] = scanner_obj
            scanner_obj.start_scan(targets=clean_targets,
                                   on_output=lambda line: log(line.strip()),
                                   on_complete=handle_global_completion,
                                   profile=nmap_profile or "standard")
            return "Initializing Nmap...", True, False, False

        # ── Nuclei ────────────────────────────────────────────────────────
        elif effective_scanner == "nuclei":
            from cyber_range.services.nuclei_ingest import NucleiIngestor
            log(f"[*] Nuclei ({len(raw_targets)} targets) — Profile: {profile_key}...")
            scanner_obj = NucleiIngestor()
            SCAN_STATE["active_scanner"] = scanner_obj
            scanner_obj.start_scan(targets=raw_targets,
                                   on_output=lambda line: log(line.strip()),
                                   on_complete=handle_global_completion,
                                   profile=profile_key)
            return "Initializing Nuclei...", True, False, False

        # ── ZAP ───────────────────────────────────────────────────────────
        elif effective_scanner == "zap":
            from cyber_range.services.zap_ingest import ZAPScanner
            log(f"[*] OWASP ZAP ({len(raw_targets)} targets) — Profile: {profile_key}...")
            scanner_obj = ZAPScanner()
            SCAN_STATE["active_scanner"] = scanner_obj
            scanner_obj.start_scan(targets=raw_targets,
                                   on_output=lambda line: log(line.strip()),
                                   on_complete=handle_global_completion,
                                   profile=profile_key)
            return "Initializing ZAP...", True, False, False

        # ── aegisprobe / Burp ─────────────────────────────────────────────
        elif effective_scanner in ("aegis", "aegisprobe", "burp") or scanner in ("aegisprobe", "burp"):
            from cyber_range.services.aegis_probe import AegisProbeEngine
            _mode = profile_key if profile_key in ("passive", "full") else "full"
            _intensity = xstrike_intensity if xstrike_intensity in ("low", "medium", "aggressive") else "medium"
            log(f"[*] aegisprobe — Mode: {_mode} | Intensity: {_intensity} | Targets: {len(raw_targets)}")
            scanner_obj = AegisProbeEngine(scan_mode=_mode, intensity=_intensity)
            SCAN_STATE["active_scanner"] = scanner_obj
            scanner_obj.start_scan(targets=raw_targets,
                                   on_output=lambda line: log(line.strip()),
                                   on_complete=handle_global_completion)
            return "aegisprobe starting...", True, False, False

        # ── OpenVAS ───────────────────────────────────────────────────────
        elif effective_scanner == "openvas" or scanner == "openvas":
            from cyber_range.services.scan_ingestor import ScanIngestor
            log("[*] OpenVAS Report Import...")
            def _openvas_import():
                try:
                    scan_dir = "/mnt/scans/incoming/openvas"
                    os.makedirs(scan_dir, exist_ok=True)
                    xml_files = glob.glob(os.path.join(scan_dir, "*.xml"))
                    if xml_files:
                        for xf in xml_files:
                            log(f"[*] Ingesting: {xf}")
                            count = ScanIngestor().ingest(xf, "openvas", on_output=log)
                            log(f"[+] {count} findings from {os.path.basename(xf)}")
                    else:
                        target = raw_targets[0] if raw_targets else ""
                        if os.path.isfile(target):
                            count = ScanIngestor().ingest(target, "openvas", on_output=log)
                            log(f"[+] {count} findings from {target}")
                        else:
                            log(f"[!] No OpenVAS XML in {scan_dir}. Place .xml reports there.")
                except Exception as e:
                    log(f"[!] OpenVAS error: {e}")
                SCAN_STATE["running"] = False
                SCAN_STATE["active_scanner"] = None
            SCAN_STATE["running"] = True
            threading.Thread(target=_openvas_import, daemon=True).start()
            return "OpenVAS Import starting...", True, True, False

        # ── Nessus ────────────────────────────────────────────────────────
        elif effective_scanner == "nessus" or scanner == "nessus":
            from cyber_range.services.scan_ingestor import ScanIngestor
            log("[*] Nessus Report Import...")
            def _nessus_import():
                try:
                    scan_dir = "/mnt/scans/incoming/nessus"
                    os.makedirs(scan_dir, exist_ok=True)
                    files = glob.glob(os.path.join(scan_dir, "*.nessus")) + \
                            glob.glob(os.path.join(scan_dir, "*.xml"))
                    if files:
                        for nf in files:
                            log(f"[*] Ingesting: {nf}")
                            count = ScanIngestor().ingest(nf, "nessus", on_output=log)
                            log(f"[+] {count} findings")
                    else:
                        target = raw_targets[0] if raw_targets else ""
                        if os.path.isfile(target):
                            count = ScanIngestor().ingest(target, "nessus", on_output=log)
                            log(f"[+] {count} findings")
                        else:
                            log(f"[!] No Nessus files in {scan_dir}")
                except Exception as e:
                    log(f"[!] Nessus error: {e}")
                SCAN_STATE["running"] = False
                SCAN_STATE["active_scanner"] = None
            SCAN_STATE["running"] = True
            threading.Thread(target=_nessus_import, daemon=True).start()
            return "Nessus Import starting...", True, True, False

        # ── STIG CKL ──────────────────────────────────────────────────────
        elif effective_scanner in ("stig_ckl", "stig") or scanner == "stig_ckl":
            from cyber_range.services.scan_ingestor import ScanIngestor
            log("[*] STIG CKL Checklist Import...")
            def _stig_import():
                try:
                    scan_dir = "/mnt/scans/incoming/stig"
                    os.makedirs(scan_dir, exist_ok=True)
                    files = glob.glob(os.path.join(scan_dir, "*.ckl")) + \
                            glob.glob(os.path.join(scan_dir, "*.xml"))
                    if files:
                        for cf in files:
                            log(f"[*] Ingesting: {cf}")
                            count = ScanIngestor().ingest(cf, "stig_ckl", on_output=log)
                            log(f"[+] {count} findings")
                    else:
                        target = raw_targets[0] if raw_targets else ""
                        if os.path.isfile(target):
                            count = ScanIngestor().ingest(target, "stig_ckl", on_output=log)
                            log(f"[+] {count} findings")
                        else:
                            log(f"[!] No CKL files in {scan_dir}")
                except Exception as e:
                    log(f"[!] STIG error: {e}")
                SCAN_STATE["running"] = False
                SCAN_STATE["active_scanner"] = None
            SCAN_STATE["running"] = True
            threading.Thread(target=_stig_import, daemon=True).start()
            return "STIG CKL Import starting...", True, True, False

        # ── SCAP / XCCDF ─────────────────────────────────────────────────
        elif effective_scanner in ("scap_xccdf", "scap", "xccdf") or scanner == "scap_xccdf":
            from cyber_range.services.scan_ingestor import ScanIngestor
            _profile  = nmap_profile or "scap_xccdf:all"
            _parts    = _profile.split(":")
            _platform = _parts[1] if len(_parts) > 1 else "all"
            _valid_platforms = {
                "all", "linux_server", "linux_desktop", "windows_server",
                "windows_desktop", "network", "applications", "cloud", "import", "evaluate"
            }
            if _platform not in _valid_platforms:
                _platform = "all"
            _platform_labels = {
                "linux_server": "Linux Server", "linux_desktop": "Linux Desktop",
                "windows_server": "Windows Server", "windows_desktop": "Windows Desktop",
                "network": "Network", "applications": "Applications",
                "cloud": "Cloud", "all": "All Platforms",
                "import": "Custom Import", "evaluate": "Benchmark Evaluation",
            }
            _scope_label = _platform_labels.get(_platform, _platform.title())
            _is_import   = (_platform == "import")
            log(f"[SCAP] Assessment: {_scope_label}\n")

            def _scap_full_assessment():
                SCAN_STATE["status"] = ScanStatus.RUNNING
                _scan_target = raw_targets[0].strip() if raw_targets else ""
                try:
                    from cyber_range.services._safe_dirs import safe_makedirs
                    scan_dir = safe_makedirs("/mnt/scans/incoming/scap")

                    log(f"[SCAP] Expedite Strike SCAP Assessment Engine\n")
                    log(f"[SCAP] Target: {_scan_target or '(local)'} | Scope: {_scope_label}\n")

                    # Auth gate
                    try:
                        from cyber_range.services.scap_auth_scanner import AuthEnforcer
                        _auth_result = AuthEnforcer.enforce(
                            target=_scan_target or "localhost",
                            ssh_user=scap_ssh_user or "",
                            ssh_key=scap_ssh_key or "",
                            ssh_password=scap_ssh_password or "",
                            allow_unauthenticated=(_platform in ("import", "evaluate")),
                        )
                        SCAN_STATE["authenticated"] = _auth_result.auth_level != "none"
                        if _auth_result.allowed:
                            log(f"[SCAP] Auth: ✓ {_auth_result.reason}\n")
                        else:
                            log(f"[SCAP] 🚫 AUTH BLOCKED: {_auth_result.reason}\n")
                            log(f"[SCAP] Provide SSH credentials for remote targets.\n")
                            SCAN_STATE.update({"status": ScanStatus.INVALID,
                                               "scan_validity": "INVALID",
                                               "running": False, "active_scanner": None})
                            return
                    except ImportError:
                        pass
                    except Exception as _ce:
                        log(f"[SCAP] Auth check skipped: {_ce}\n")

                    if _is_import:
                        target_raw = raw_targets[0].strip() if raw_targets else ""
                        if os.path.isfile(target_raw):
                            count = ScanIngestor().ingest(target_raw, "scap_xccdf", on_output=log)
                            log(f"[SCAP] ✅ {count} findings imported\n")
                        else:
                            log(f"[SCAP] No file at: {target_raw}\n")
                    else:
                        # Benchmark discovery
                        _app_dir = os.path.dirname(os.path.abspath(__file__))
                        _ssg_dir = os.path.join(os.path.dirname(_app_dir),
                                                 "app", "scap_benchmarks", "ssg")
                        xml_files = []
                        if os.path.isdir(_ssg_dir):
                            xml_files = sorted([
                                f for f in glob.glob(os.path.join(_ssg_dir, "*.xml"))
                                if ("xccdf" in os.path.basename(f).lower()
                                    or os.path.basename(f).startswith("ssg-")
                                    or "-ds.xml" in os.path.basename(f).lower())
                            ])
                        if not xml_files:
                            try:
                                from cyber_range.services.scap_downloader import download_scap_content
                                dl = download_scap_content(
                                    output_dir=scan_dir, platform=_platform,
                                    force=False, on_log=log
                                )
                                if dl["success"]:
                                    xml_files = [
                                        os.path.join(scan_dir, f)
                                        for f in dl["files"]
                                        if os.path.isfile(os.path.join(scan_dir, f))
                                    ]
                            except Exception as dl_err:
                                log(f"[SCAP] Download: {dl_err}\n")

                        if not xml_files:
                            log("[SCAP] No benchmarks found — check SSG directory\n")
                            SCAN_STATE.update({"running": False, "active_scanner": None,
                                               "status": ScanStatus.ERROR})
                            return

                        log(f"[SCAP] Running {len(xml_files)} benchmarks...\n")
                        total_ingested = 0
                        all_parsed = []

                        if _scan_target:
                            from cyber_range.services.scap_assessor import live_assess
                            from cyber_range.services.scan_ingestor import _write_findings
                            for xf in sorted(xml_files):
                                log(f"[SCAP] — {os.path.basename(xf)}\n")
                                findings = live_assess(target=_scan_target,
                                                       benchmark_path=xf, on_log=log)
                                if findings:
                                    all_parsed.extend(findings)
                                    total_ingested += _write_findings(findings, on_output=log)
                        else:
                            for xf in sorted(xml_files):
                                log(f"[SCAP] — {os.path.basename(xf)}\n")
                                total_ingested += ScanIngestor().ingest(
                                    xf, "scap_xccdf", on_output=log)

                        _metrics = [f for f in all_parsed if f.get("_type") == "scap_metrics"]
                        _total_pass  = sum(m.get("pass", 0) for m in _metrics)
                        _total_fail  = sum(m.get("fail", 0) for m in _metrics)
                        _total_na    = sum(m.get("notapplicable", 0) for m in _metrics)
                        _total_eval  = _total_pass + _total_fail
                        _comp_pct    = (_total_pass / _total_eval * 100) if _total_eval else None
                        _reliable    = all(m.get("score_reliable", False) for m in _metrics) if _metrics else False

                        SCAN_STATE.update({
                            "scan_validity":  "VALID" if _reliable else ("PARTIAL" if _total_eval else "INVALID"),
                            "coverage_pct":   (_total_eval / max(1, _total_pass + _total_fail + _total_na)) * 100,
                            "compliance_pct": _comp_pct,
                            "score_reliable": _reliable,
                            "scan_target":    _scan_target,
                            "status":         ScanStatus.COMPLETE if _reliable else ScanStatus.PARTIAL,
                            "tabs_updated":   ["Assessment", "Vulnerabilities", "MITRE ATT&CK"],
                        })
                        log(f"[SCAP] ✅ PASS:{_total_pass} FAIL:{_total_fail} N/A:{_total_na}\n")
                        if _comp_pct is not None:
                            log(f"[SCAP] Compliance: {_comp_pct:.0f}% "
                                f"({'✓ REPORTABLE' if _reliable else '⚠ NOT REPORTABLE'})\n")

                except Exception as e:
                    log(f"[!] SCAP error: {e}\n")
                    SCAN_STATE["status"] = ScanStatus.ERROR
                SCAN_STATE["running"] = False
                SCAN_STATE["active_scanner"] = None

            SCAN_STATE["running"] = True
            threading.Thread(target=_scap_full_assessment, daemon=True).start()
            return f"SCAP Assessment ({_scope_label}) starting...", True, True, False

        raise PreventUpdate

    # ── Live log streaming ────────────────────────────────────────────────────
    @app.callback(
        Output("scan-log-output",         "children",  allow_duplicate=True),
        Output("scan-log-interval",       "disabled"),
        Output("assessment-scan-summary", "children"),
        Output("scan-filtered-summary",   "children",  allow_duplicate=True),
        Input("scan-log-interval", "n_intervals"),
        prevent_initial_call=True,
    )
    def stream_logs(n):
        display_text = "".join(SCAN_STATE["logs"])
        if not SCAN_STATE["running"]:
            summary = _build_scan_summary()
            return display_text or "The Assessment Engine is Ready...", True, summary, summary
        return display_text, False, no_update, no_update

    # ── PTES button visibility ─────────────────────────────────────────────────
    @app.callback(
        Output("assessment-ptes-btn", "style"),
        Input("assessment-scan-summary", "children"),
        prevent_initial_call=True,
    )
    def show_ptes_btn(summary_children):
        if summary_children:
            return {"fontWeight": "800", "color": "#000", "marginTop": "10px",
                    "display": "inline-block"}
        return {"display": "none"}

    # ── Quick date buttons ────────────────────────────────────────────────────
    @app.callback(
        Output("scan-date-range", "start_date"),
        Output("scan-date-range", "end_date"),
        Input("scan-date-today-btn",  "n_clicks"),
        Input("scan-date-week-btn",   "n_clicks"),
        Input("scan-date-month-btn",  "n_clicks"),
        Input("scan-date-all-btn",    "n_clicks"),
        prevent_initial_call=True,
    )
    def set_scan_date_quick(today_n, week_n, month_n, all_n):
        import datetime as _dt_mod
        btn = ctx.triggered_id if ctx.triggered_id else ""
        today = _dt_mod.date.today()
        if btn == "scan-date-today-btn":
            return str(today), str(today)
        elif btn == "scan-date-week-btn":
            start = today - _dt_mod.timedelta(days=today.weekday())
            return str(start), str(today)
        elif btn == "scan-date-month-btn":
            return str(today.replace(day=1)), str(today)
        return None, None

    # ── Findings filter ───────────────────────────────────────────────────────
    @app.callback(
        Output("scan-filtered-summary", "children"),
        Output("scan-date-range-label", "children"),
        Output("scan-test-type-label",  "children"),
        Input("scan-source-filter",     "value"),
        Input("scan-test-type-filter",  "value"),
        Input("scan-date-range",        "start_date"),
        Input("scan-date-range",        "end_date"),
    )
    def filter_scan_findings(source, test_type, date_start, date_end):
        source_list = source if isinstance(source, list) else ([source] if source else [])
        use_all = not source_list or "all" in source_list

        if test_type and test_type != "all":
            scanner_list  = TEST_TYPE_SCANNERS.get(test_type, [])
            scanner_filter = None
        elif not use_all:
            scanner_list  = source_list
            scanner_filter = None
        else:
            scanner_list  = []
            scanner_filter = None

        if date_start and date_end:
            date_label = f"Showing: {date_start}  →  {date_end}"
        elif date_start:
            date_label = f"From: {date_start}"
        elif date_end:
            date_label = f"Up to: {date_end}"
        else:
            date_label = "All dates"

        type_label = TEST_TYPE_LABELS.get(test_type or "all", "")

        return (
            _build_scan_summary(scanner_filter=scanner_filter,
                                scanner_list=scanner_list,
                                date_start=date_start,
                                date_end=date_end),
            date_label,
            type_label,
        )

    # ── Pipeline — send to enumeration ────────────────────────────────────────
    @app.callback(
        Output("pipeline-status-msg",      "children"),
        Output("pipeline-host-options",    "data"),
        Output("pipeline-test-type-badge", "children"),
        Input("pipeline-send-to-enum-btn",     "n_clicks"),
        Input("pipeline-send-latest-scan-btn", "n_clicks"),
        State("scan-test-type-filter",         "value"),
        prevent_initial_call=True,
    )
    def pipeline_send_to_enum(send_n, latest_n, test_type):
        if not ctx.triggered_id:
            raise PreventUpdate
        tid = ctx.triggered_id

        type_label = TEST_TYPE_LABELS.get(test_type or "all", "All")
        badge_text = f"Scope: {type_label}"

        try:
            from cyber_range.services.neo4j_engine import Neo4jEngine
            engine = Neo4jEngine()
            with engine.driver.session() as s:
                if tid == "pipeline-send-latest-scan-btn":
                    result = s.run("""
                        MATCH (h:Host)
                        WHERE h.last_seen IS NOT NULL
                        RETURN h.ip AS ip, h.hostname AS hostname
                        ORDER BY h.last_seen DESC LIMIT 50
                    """).data()
                else:
                    scanners = TEST_TYPE_SCANNERS.get(test_type, []) if test_type != "all" else []
                    if scanners:
                        quoted = ", ".join(f"'{s}'" for s in scanners)
                        result = s.run(f"""
                            MATCH (h:Host)<-[:ON_HOST]-(srv:Service)-[:HAS_FINDING]->(f:Finding)
                            WHERE f.source IN [{quoted}]
                            RETURN DISTINCT h.ip AS ip, h.hostname AS hostname
                            LIMIT 100
                        """).data()
                    else:
                        result = s.run("""
                            MATCH (h:Host)
                            RETURN h.ip AS ip, h.hostname AS hostname LIMIT 100
                        """).data()

            if not result:
                return "⚠️ No hosts found — run a scan first.", [], badge_text

            host_opts = [
                {"label": f"{r.get('ip', '')} {r.get('hostname', '') or ''}".strip(),
                 "value": r.get("ip", "")}
                for r in result if r.get("ip")
            ]
            msg = html.Span([
                html.Span(f"✅ {len(host_opts)} hosts ready for enumeration — ",
                          style={"color": "#27ae60", "fontWeight": "700"}),
                html.Span("switch to ", style={"color": "#8b949e"}),
                html.Span("🔍 Recon / Scan", style={"color": "#00f0ff", "fontWeight": "600"}),
                html.Span(" tab to enumerate.", style={"color": "#8b949e"}),
            ])
            return msg, host_opts, badge_text

        except Exception as e:
            return f"❌ Pipeline error: {e}", [], badge_text

    # ── PTES report download ──────────────────────────────────────────────────
    @app.callback(
        Output("assessment-ptes-download", "data"),
        Output("assessment-ptes-status",   "children"),
        Input("assessment-ptes-btn",       "n_clicks"),
        prevent_initial_call=True,
    )
    def assessment_export_ptes(n):
        if not n:
            raise PreventUpdate
        from cyber_range.services.report_generator import generate_report, get_latest_report_json
        report_path = get_latest_report_json()
        if not report_path:
            return no_update, dbc.Alert(
                "⚠ No scan report found. Run a scan first.",
                color="warning", style={"fontSize": "12px", "padding": "4px 10px",
                                         "display": "inline-block"}
            )
        try:
            out_path, html_content = generate_report(report_path)
            fname = os.path.basename(out_path)
            status = dbc.Alert(
                [html.Span("✅ Report: "), html.Code(fname)],
                color="success",
                style={"fontSize": "12px", "padding": "4px 10px", "display": "inline-block"}
            )
            return dict(content=html_content, filename=fname, type="text/html"), status
        except Exception as e:
            return no_update, dbc.Alert(
                f"❌ {e}", color="danger",
                style={"fontSize": "12px", "padding": "4px 10px", "display": "inline-block"}
            )
