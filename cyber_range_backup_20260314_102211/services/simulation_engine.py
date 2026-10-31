import random
import time
from typing import Dict, List, Any
from cyber_range.services.intel_orchestrator import IntelOrchestrator

# ======================================================================
# CORE SIMULATION ENGINE (SINGLETON)
# ======================================================================
class SimulationEngine:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SimulationEngine, cls).__new__(cls)
            cls._instance.reset()
        return cls._instance

    def reset(self):
        """Reset the entire simulation state to zero."""
        self.nodes = []           # The linear/DAG attack path mapped from Neo4j
        self.current_step = 0     # Index of the currently executing node
        self.status = "IDLE"      # IDLE, RUNNING, PAUSED, COMPLETED, DEFENDED
        self.logs = []            # Master event log
        self.environment = {      # Digital Twin Modifiers (0.0 to 1.0 multipliers)
            "defense_strength": 1.0,
            "visibility": 1.0,
            "segmentation": 1.0
        }
        self.wargame_active = False
        self.honeypots_active = False
        self.attacker_ai_mode = "None"
        self.honeypot_settings = {"probability": 50, "terminate_on_trigger": False}
        self.pentest_state = {
            "status": "IDLE", # IDLE, RUNNING, PAUSED, COMPLETED
            "active_exploits": [],
            "post_exploit_actions": []
        }
        self.intel = IntelOrchestrator()
        self.log_event("SYSTEM", "Simulation Engine reset to IDLE state.")

    def log_event(self, source: str, message: str, level: str = "INFO"):
        """Append a timestamped event to the master log."""
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{source}] [{level}] {message}"
        self.logs.append(entry)
        return entry

    def update_environment(self, defense: float, visibility: float, segmentation: float):
        """Called by the Digital Twin module to alter base probabilities."""
        self.environment["defense_strength"] = defense
        self.environment["visibility"] = visibility
        self.environment["segmentation"] = segmentation
        self.log_event("TWIN", f"Environment updated: DEF={defense}, VIS={visibility}, SEG={segmentation}")

    def load_scenario(self, nodes_data: List[Dict[str, Any]]):
        """
        Takes raw node data from Neo4j (via attack_paths.py) and builds the local state representation.
        Expects nodes with an ID, Label, and basic Tactic metadata.
        """
        self.reset()
        self.status = "READY"
        
        # Build the internal linear sequence representation
        for idx, node in enumerate(nodes_data):
            
            # Default properties assigned if missing in DB
            base_success_prob = int(node.get("base_success_prob", random.randint(40, 95)))
            base_detect_prob = int(node.get("base_detect_prob", random.randint(10, 80)))
            
            sim_node = {
                "id": node.get("id", f"node_{idx}"),
                "label": node.get("label", "Unknown Technique"),
                "tactic": node.get("tactic", "Execution"),
                "base_success": base_success_prob,
                "base_detect": base_detect_prob,
                "state": "PENDING", # PENDING, IN_PROGRESS, SUCCESS, FAILED, DETECTED, BLOCKED
                "result_log": ""
            }
            self.nodes.append(sim_node)
            
        self.log_event("SYSTEM", f"Loaded scenario containing {len(self.nodes)} nodes. Ready.")
        return True

    def calculate_modified_probabilities(self, node: Dict[str, Any]) -> tuple:
        """Apply Digital Twin environment modifiers to the base probabilities."""
        # Success is reduced by defense strength and segmentation
        mod_success = node["base_success"] * (1.0 - (self.environment["defense_strength"] * 0.3)) * (1.0 - (self.environment["segmentation"] * 0.2))
        
        # Detection is increased by visibility
        mod_detect = node["base_detect"] * (1.0 + (self.environment["visibility"] * 0.5))
        
        # Cap logic integer
        final_success = max(1, min(99, int(mod_success)))
        final_detect = max(1, min(99, int(mod_detect)))
        
        return final_success, final_detect

    def step_forward(self):
        """Execute the next pending node in the chain."""
        if self.status in ["COMPLETED", "DEFENDED", "FAILED"]:
            self.log_event("ENGINE", f"Cannot step forward. Status is {self.status}.")
            return False

        if self.current_step >= len(self.nodes):
            self.status = "COMPLETED"
            self.log_event("ENGINE", "Attack chain completed successfully. Crown jewel reached.")
            return False

        current_node = self.nodes[self.current_step]
        self.status = "RUNNING"
        current_node["state"] = "IN_PROGRESS"
        
        label = current_node["label"]
        self.log_event("ATTACK", f"Initiating execution phase for node: {label}")

        # Let the UI breathe, technically immediate but logically models a step
        success_prob, detect_prob = self.calculate_modified_probabilities(current_node)
        self.log_event("PROBABILITY", f"{label} -> Modified Success Req: {success_prob}%, Detect Risk: {detect_prob}%")

        # Roll the Dice (1 to 100)
        attack_roll = random.randint(1, 100)
        detect_roll = random.randint(1, 100)

        # 1. Check Detection First
        if detect_roll <= detect_prob:
            self.log_event("DEFENSE", f"🚨 ALERT: {label} was detected by defensive sensors! (Roll: {detect_roll} <= {detect_prob}%)", "CRITICAL")
            
            # Wargame AI Hook
            if self.wargame_active:
                self.log_event("WARGAME", f"Defender response triggered! Isolating node and blocking progression.")
                current_node["state"] = "BLOCKED"
                self.status = "DEFENDED"
                return False
            else:
                self.log_event("DEFENSE", f"Detect-only mode. Attack continues despite noise.")
                # We do not fail the node, but flag it was loud
                pass

        # 2. Check Success
        if attack_roll <= success_prob:
            current_node["state"] = "SUCCESS"
            self.log_event("ATTACK", f"✅ SUCCESS: {label} executed successfully. (Roll: {attack_roll} <= {success_prob}%)")
            self.current_step += 1
            
            if self.current_step >= len(self.nodes):
                self.status = "COMPLETED"
                self.log_event("ENGINE", "🏆 Attack chain completed successfully. Crown jewel reached.")
                
            return True
        else:
            current_node["state"] = "FAILED"
            self.status = "FAILED"
            self.log_event("ATTACK", f"❌ FAILED: {label} execution failed. Exploit did not fire. (Roll: {attack_roll} > {success_prob}%)", "ERROR")
            self.log_event("ENGINE", f"Chain broken at step {self.current_step}. Halting simulation.")
            return False

    def inject_honeypot(self, position: int, label: str):
        trap_node = {
            "id": f"hp_{int(time.time())}",
            "label": f"🪤 Honeypot: {label}",
            "tactic": "Deception",
            "base_success": 100,
            "base_detect": self.honeypot_settings["probability"],
            "state": "PENDING",
            "result_log": "",
            "is_trap": True
        }
        pos = max(0, min(position, len(self.nodes)))
        self.nodes.insert(pos, trap_node)
        self.log_event("DEFENSE", f"Injected Trap '{label}' at step {pos}.")

    def run_enumeration(self):
        """Simulate an active enumeration cycle across all assets using real NMAP data."""
        if self.pentest_state["status"] == "RUNNING":
            return
        
        import threading, time
        from datetime import datetime
        
        self.pentest_state["status"] = "RUNNING"
        self.pentest_state["enum_start"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        self.pentest_state["enum_end"] = "Active..."
        self.log_event("PENTEST", "Started Automated Enumeration: Parsing /mnt/scans/incoming/nmap...")
        
        def _bg_scan():
            time.sleep(1.5) # Slight delay to let UI show Enumerating state and live feed
            self.intel.run_enumeration_scan()
            assets_found = len(self.intel.parsed_assets)
            services_found = len(self.intel.parsed_services)
            self.log_event("PENTEST", f"Enumeration Complete: Discovered {assets_found} Hosts and {services_found} Services.")
            self.pentest_state["status"] = "COMPLETED"
            self.pentest_state["enum_end"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")

        t = threading.Thread(target=_bg_scan)
        t.daemon = True
        t.start()
        
    def run_pingcastle_ad_test(self):
        """Simulate PingCastle Active Directory Security evaluation."""
        if self.pentest_state["status"] == "RUNNING":
            return
            
        import threading, time
        from datetime import datetime
        
        self.pentest_state["status"] = "RUNNING"
        self.log_event("PENTEST", "Starting PingCastle AD Assessment Simulation...")
        
        def _bg_pc():
            time.sleep(2) # Simulate scan
            try:
                from cyber_range.services.neo4j_engine import neo4j
                now_str = datetime.now().isoformat()
                
                # PingCastle simulated findings mapped to MITRE Tactics
                findings = [
                    ("Domain Admin passwords have not been changed in 365 Days", "High", "Credential Access", "Credentials in Files"),
                    ("Print Spooler service enabled on Domain Controllers", "High", "Privilege Escalation", "Print Spooler Service"),
                    ("LAPS is not deployed across workstations", "Medium", "Defense Evasion", "Valid Accounts"),
                    ("Unconstrained Delegation detected on multiple service accounts", "Critical", "Lateral Movement", "Use Alternate Authentication Material"),
                    ("SMB Signing is disabled on domain joined machines", "High", "Lateral Movement", "SMB/Windows Admin Shares"),
                    ("Orphaned trust relationship with a legacy domain", "Medium", "Discovery", "Domain Trust Discovery")
                ]
                
                for fname, sev, tactic, tname in findings:
                    cypher = """
                    MERGE (f:Finding {name: $fname, type: 'PingCastle AD Assessement'})
                    SET f.first_seen = $now, f.severity = $sev, f.severity_text = $sev,
                        f.source = 'pentest-engine', f.scanner = 'pentest-engine'
                    MERGE (t:Technique {tactic: $tactic, name: $tname})
                    MERGE (f)-[:MAPS_TO_TECHNIQUE]->(t)
                    """
                    neo4j.query(cypher, fname=fname, now=now_str, sev=sev, tactic=tactic, tname=tname)
                    
                self.log_event("PENTEST", f"PingCastle Assessment Complete: Identified {len(findings)} Active Directory misconfigurations.")
            except Exception as e:
                self.log_event("SYSTEM", f"Failed to run PingCastle AD test: {e}")
                
            self.pentest_state["status"] = "COMPLETED"

        t = threading.Thread(target=_bg_pc)
        t.daemon = True
        t.start()
        
    def launch_exploits(self, exploit_info: Dict[str, Any] = None):
        """Launch a specific targeted exploit against a discovered vulnerability."""
        if not exploit_info:
            self.log_event("PENTEST", "No specific exploit provided to launch.")
            return
            
        target = exploit_info.get("target_ip", "Unknown IP")
        port = exploit_info.get("port", "Unknown Port")
        name = exploit_info.get("exploit_name", "Unknown Exploit")
        
        exploit_id = exploit_info.get("id", f"{target}_{port}_{name}")
        self.log_event("PENTEST", f"Launching Exploit: [{name}] against {target}:{port}")
        self.pentest_state["active_exploits"].append(
            {"id": exploit_id, "name": name, "target": f"{target}:{port}", "progress": 10, "status": "RUNNING"}
        )
        
        try:
            from cyber_range.services.neo4j_engine import neo4j
            from datetime import datetime
            now_str = datetime.now().isoformat()
            
            cypher = """
            MERGE (f:Finding {name: $name, type: 'Pentest Exploit'})
            SET f.first_seen = $now, f.severity = 'Critical', f.severity_text = 'Critical',
                f.source = 'pentest-engine', f.scanner = 'pentest-engine'
            MERGE (t:Technique {tactic: 'Initial Access', name: 'Exploitation for Client Execution'})
            MERGE (f)-[:MAPS_TO_TECHNIQUE]->(t)
            MERGE (h:Host {ip: $target_ip})
            MERGE (s:Service {port: $port})
            MERGE (h)-[:RUNS_SERVICE]->(s)
            MERGE (s)-[:HAS_FINDING]->(f)
            """
            neo4j.query(cypher, name=f"Automated Exploit: {name}", now=now_str, target_ip=target, port=int(port) if str(port).isdigit() else port)
            self.log_event("PENTEST", f"Injected Finding to Neo4j Graph for Timeline tracking.")
        except Exception as e:
            self.log_event("SYSTEM", f"Failed to push exploit to Neo4j: {e}")
        
    def stop_exploit(self, exploit_id: str):
        """Stops an active exploit by ID."""
        for ex in self.pentest_state["active_exploits"]:
            if ex.get("id") == exploit_id:
                ex["status"] = "STOPPED"
                self.log_event("PENTEST", f"Exploit Stopped: {ex['name']} against {ex['target']}")
                break
        
    def execute_post_exploitation(self):
        """Simulate post-exploitation, moving laterally and exfiltrating data targets (like share drives)."""
        self.log_event("PENTEST", "Executing post-exploitation: Lateral movement and Data Exfiltration.")
        self.pentest_state["post_exploit_actions"] = [
            {"type": "Lateral Movement", "target": "DC01", "method": "Pass-the-Hash"},
            {"type": "Data Exfiltration", "target": "HR Share Drive", "status": "Compromised - 4.7GB accessible"}
        ]
        
        try:
            from cyber_range.services.neo4j_engine import neo4j
            from datetime import datetime
            now_str = datetime.now().isoformat()
            
            queries = [
                ("Pass-the-Hash to DC01", "Critical", "Lateral Movement", "Use Alternate Authentication Material"),
                ("Data Exfiltration: HR Share Drive", "Critical", "Exfiltration", "Exfiltration Over Alternative Protocol"),
                ("Scheduled Task Persistence", "High", "Persistence", "Scheduled Task/Job"),
                ("Golden Ticket Creation", "Critical", "Privilege Escalation", "Valid Accounts: Domain Accounts"),
                ("C2 Beacon Established", "High", "Command & Control", "Web Protocols"),
                ("Event Log Clearing", "Medium", "Defense Evasion", "Indicator Removal on Host"),
                ("SOC Alert Firing Timestamp", "Low", "Discovery", "Network Service Discovery"),
                ("Network Isolation Timelines", "Low", "Collection", "Data from Local System"),
                ("Malware Purging Metrics", "Low", "Credential Access", "OS Credential Dumping")
            ]
            
            for fname, sev, tactic, tname in queries:
                cypher = """
                MERGE (f:Finding {name: $fname, type: 'Pentest Post-Exploitation'})
                SET f.first_seen = $now, f.severity = $sev, f.severity_text = $sev
                MERGE (t:Technique {tactic: $tactic, name: $tname})
                MERGE (f)-[:MAPS_TO_TECHNIQUE]->(t)
                """
                neo4j.query(cypher, fname=f"Automated PT: {fname}", now=now_str, sev=sev, tactic=tactic, tname=tname)
                
            self.log_event("PENTEST", "Injected Post-Exploitation Findings into Neo4j Graph.")
        except Exception as e:
            self.log_event("SYSTEM", f"Failed to push post-exploitation traces to Neo4j: {e}")

        
    def generate_pt_report(self):
        """Generates a penetration testing report driven by live Neo4j data."""
        from datetime import datetime
        report_date = datetime.now().strftime("%Y-%m-%d")
        report_time = datetime.now().strftime("%H:%M:%S")

        # ── Pull all data from Neo4j ──────────────────────────────────────
        hosts_data, services_data, findings_data, scanner_stats = [], [], [], {}
        crit_count = high_count = med_count = low_count = info_count = 0
        try:
            from cyber_range.services.neo4j_engine import Neo4jEngine
            ng = Neo4jEngine()
            with ng.driver.session() as s:
                hosts_data = s.run("""
                    MATCH (h:Host) RETURN h.ip AS ip, coalesce(h.os, h.os_family, 'Unknown') AS os
                    ORDER BY h.ip
                """).data()

                services_data = s.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE]->(srv:Service)
                    RETURN h.ip AS host, srv.port AS port,
                           coalesce(srv.name,'unknown') AS name,
                           coalesce(srv.product,'') AS product,
                           coalesce(srv.version,'') AS version
                    ORDER BY h.ip, toInteger(srv.port)
                    LIMIT 200
                """).data()

                findings_data = s.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE]->(srv:Service)-[:HAS_FINDING]->(f:Finding)
                    RETURN h.ip AS host,
                           coalesce(srv.name,'unknown') AS service,
                           srv.port AS port,
                           coalesce(f.name, f.title, 'Unnamed') AS name,
                           coalesce(f.severity,
                               CASE f.riskcode
                                   WHEN '3' THEN 'High' WHEN '2' THEN 'Medium'
                                   WHEN '1' THEN 'Low'  WHEN '0' THEN 'Info'
                                   ELSE 'Medium' END) AS severity,
                           coalesce(f.source, f.scanner, 'Unknown') AS scanner,
                           coalesce(f.cve, '') AS cve,
                           coalesce(f.description, '') AS desc
                    ORDER BY h.ip,
                        CASE coalesce(f.severity,'')
                            WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                            WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END
                """).data()

                # Severity counts
                sev_counts = s.run("""
                    MATCH (f:Finding)
                    RETURN coalesce(f.severity,
                        CASE f.riskcode
                            WHEN '3' THEN 'High' WHEN '2' THEN 'Medium'
                            WHEN '1' THEN 'Low'  WHEN '0' THEN 'Info'
                            ELSE 'Medium' END) AS sev,
                        count(f) AS n
                """).data()
                for r in sev_counts:
                    sev = r['sev']
                    n   = r['n']
                    if sev == 'Critical': crit_count = n
                    elif sev == 'High':   high_count = n
                    elif sev == 'Medium': med_count  = n
                    elif sev == 'Low':    low_count  = n
                    else:                 info_count += n

                # Scanner stats
                for r in s.run("""
                    MATCH (f:Finding)
                    RETURN coalesce(f.source, f.scanner, 'Unknown') AS src, count(f) AS n
                    ORDER BY n DESC
                """).data():
                    scanner_stats[r['src']] = r['n']
        except Exception as e:
            pass

        total_findings = crit_count + high_count + med_count + low_count + info_count
        risk_rating = ("CRITICAL" if crit_count > 0 else
                       "HIGH"     if high_count > 0 else
                       "MEDIUM"   if med_count  > 0 else
                       "LOW"      if low_count  > 0 else "INFORMATIONAL")

        # Group findings by host
        from collections import defaultdict
        by_host = defaultdict(list)
        for f in findings_data:
            by_host[f['host']].append(f)

        L = []
        def section(title): L.extend(["", title, "=" * 65])
        def sub(title):     L.extend(["", title, "-" * 50])

        # ── Cover Page ────────────────────────────────────────────────────
        L.append("📘 PENETRATION TESTING REPORT")
        L.append("NIST SP 800-115 & PTES Aligned")
        section("1. COVER PAGE")
        L += [
            f"Report Title    : Full-Scope Penetration Test Report",
            f"Client          : Internal Assessment",
            f"Scope           : Internal Network + Web Applications + Active Directory",
            f"Assessment Type : Black-Box / Hybrid Automated",
            f"Report Date     : {report_date}  {report_time}",
            f"Version         : 1.0",
            f"Classification  : CONFIDENTIAL / INTERNAL USE ONLY",
            f"Prepared By     : VulnIntel Agentic AI Platform",
            f"Framework       : NIST SP 800-115 | PTES | OWASP",
        ]

        # ── Executive Summary ─────────────────────────────────────────────
        section("2. EXECUTIVE SUMMARY")
        L += [
            f"Overall Risk Rating  : ⚠️  {risk_rating}",
            f"Total Hosts Scanned  : {len(hosts_data)}",
            f"Total Services Found : {len(services_data)}",
            f"Total Findings       : {total_findings:,}",
            "",
            "Severity Breakdown:",
            f"  🔴 Critical   : {crit_count:>6,}",
            f"  🟠 High       : {high_count:>6,}",
            f"  🟡 Medium     : {med_count:>6,}",
            f"  🟢 Low        : {low_count:>6,}",
            f"  🔵 Info       : {info_count:>6,}",
            "",
            "Scanner Coverage:",
        ]
        for src, cnt in scanner_stats.items():
            L.append(f"  • {str(src or 'Unknown'):<20} {cnt:>6,} findings")

        # ── Scope & Methodology ───────────────────────────────────────────
        section("3. SCOPE & METHODOLOGY")
        L += [
            "Assessment phases followed NIST SP 800-115 and PTES:",
            "  Phase 1: Reconnaissance & OSINT",
            "  Phase 2: Enumeration (Nmap, Nuclei, ZAP, AegisProbe)",
            "  Phase 3: Vulnerability Analysis",
            "  Phase 4: Exploitation (Automated Exploit Engine)",
            "  Phase 5: Post-Exploitation & Lateral Movement",
            "  Phase 6: Reporting (this document)",
        ]

        # ── Discovered Assets ─────────────────────────────────────────────
        section("4. ENUMERATION — DISCOVERED ASSETS")
        sub(f"4.1 Hosts ({len(hosts_data)} total)")
        for h in hosts_data:
            L.append(f"  🖥️  {str(h['ip'] or 'N/A'):<20} OS: {h['os'] or 'Unknown'}")

        sub(f"4.2 Services ({len(services_data)} total)")
        for svc in services_data[:50]:
            ver = f" ({svc['product']} {svc['version']})".strip(" ()")
            ver = f" [{ver}]" if ver else ""
            L.append(f"  🔌 {str(svc['host'] or 'N/A'):<18} :{str(svc['port'] or '?'):<6} {svc['name'] or 'unknown'}{ver}")
        if len(services_data) > 50:
            L.append(f"  ... and {len(services_data)-50} more services (see full Neo4j export)")

        # ── Detailed Findings per Host ────────────────────────────────────
        section("5. DETAILED FINDINGS BY HOST")
        for host_ip in sorted((k for k in by_host.keys() if k), key=lambda x: str(x)):
            findings = by_host[host_ip]
            worst = findings[0]['severity'] if findings else 'Info'
            sub(f"Host: {host_ip}  [{worst}]  —  {len(findings)} findings")
            for i, f in enumerate(findings[:30], 1):
                cve_str = f" CVE: {f['cve']}" if f['cve'] else ""
                L.append(f"  [{i:03d}] [{str(f['severity'] or 'Unknown'):<8}] [{str(f['scanner'] or 'Unknown'):<16}] {f['name'] or 'Unnamed'}{cve_str}")
                L.append(f"         Port: {f['service']}:{f['port']}")
                if f['desc']:
                    L.append(f"         {f['desc'][:120]}")
            if len(findings) > 30:
                L.append(f"         ... and {len(findings)-30} more findings for this host")

        # ── Risk Summary Table ───────────────────────────────────────────
        section("6. RISK SUMMARY TABLE")
        L += [
            f"{'Host':<20} {'Critical':>8} {'High':>6} {'Medium':>8} {'Low':>6} {'Info':>6} {'Total':>7}",
            "-" * 65,
        ]
        for host_ip, flist in sorted(((k,v) for k,v in by_host.items() if k), key=lambda x: str(x[0])):
            sc = sc_h = sc_m = sc_l = sc_i = 0
            for f in flist:
                sev = f['severity']
                if sev == 'Critical': sc  += 1
                elif sev == 'High':   sc_h += 1
                elif sev == 'Medium': sc_m += 1
                elif sev == 'Low':    sc_l += 1
                else:                 sc_i += 1
            L.append(f"{str(host_ip or 'N/A'):<20} {sc:>8} {sc_h:>6} {sc_m:>8} {sc_l:>6} {sc_i:>6} {len(flist):>7}")
        L.append("-" * 65)
        L.append(f"{'TOTAL':<20} {crit_count:>8} {high_count:>6} {med_count:>8} {low_count:>6} {info_count:>6} {total_findings:>7}")

        # ── Remediation Priorities ────────────────────────────────────────
        section("7. REMEDIATION PRIORITIES")
        L += [
            "Priority 1 — Critical (Immediate action required):",
        ]
        shown = 0
        for f in findings_data:
            if f['severity'] == 'Critical' and shown < 10:
                L.append(f"  • [{f['host']}:{f['port']}] {f['name']}" +
                          (f" ({f['cve']})" if f['cve'] else ""))
                shown += 1
        if shown == 0: L.append("  None identified.")
        L += [
            "",
            "Priority 2 — High:",
        ]
        shown = 0
        for f in findings_data:
            if f['severity'] == 'High' and shown < 10:
                L.append(f"  • [{f['host']}:{f['port']}] {f['name']}" +
                          (f" ({f['cve']})" if f['cve'] else ""))
                shown += 1
        if shown == 0: L.append("  None identified.")

        # ── Conclusion ────────────────────────────────────────────────────
        section("8. CONCLUSION")
        L += [
            f"This penetration test identified {total_findings:,} findings across {len(hosts_data)} hosts.",
            f"Risk rating: {risk_rating}.",
            "",
            "Key recommendations:",
            "  1. Patch all Critical and High findings within 30 days.",
            "  2. Implement network segmentation between discovered subnets.",
            "  3. Enforce strong authentication (MFA) on all exposed services.",
            "  4. Disable legacy protocols (Telnet, FTP, NTLMv1) identified during scanning.",
            "  5. Conduct a follow-up scan after remediation to verify closure.",
            "",
            f"Report generated: {report_date} {report_time} by VulnIntel Agentic AI",
        ]

        # ── Logs Appendix ─────────────────────────────────────────────────
        section("APPENDIX A — EXECUTION LOGS")
        for log in self.logs[-20:]:
            L.append(log)

        self.log_event("REPORT", f"PT Report generated: {total_findings} findings, {len(hosts_data)} hosts.")
        return "\n".join(L)

        

# Create a global instance for the application to import
engine = SimulationEngine()
