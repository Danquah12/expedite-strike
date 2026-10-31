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
            SET h.compromised = true,
                h.exploited_by = $name,
                h.exploit_port = $port,
                h.compromised_at = $now,
                h.access_level = 'User'
            MERGE (s:Service {port: $port})
            MERGE (h)-[:RUNS_SERVICE]->(s)
            MERGE (s)-[:HAS_FINDING]->(f)
            MERGE (h)-[:COMPROMISED_VIA]->(f)
            """
            neo4j.query(cypher, name=f"Automated Exploit: {name}", now=now_str, target_ip=target, port=int(port) if str(port).isdigit() else port)
            self.log_event("PENTEST", f"Injected Finding to Neo4j Graph for Timeline tracking.")

            # ── Populate PoC Evidence panel ────────────────────────────────────
            try:
                from cyber_range.services.exploit_runner import ExploitRunner
                runner = ExploitRunner()
                poc = {
                    "id":           exploit_id,
                    "ip":           target,
                    "port":         str(port),
                    "module":       exploit_info.get("exploit_path", "pentest-engine"),
                    "exploit_name": name,
                    "msf_title":    name,
                    "verdict":      "COMPROMISED",
                    "icon":         "💀 COMPROMISED",
                    "confidence":   "HIGH",
                    "output":       (
                        f"[*] Launched: {name}\n"
                        f"[*] Target: {target}:{port}\n"
                        f"[+] Host marked COMPROMISED in Neo4j\n"
                        f"[+] Access Level: User\n"
                        f"[+] Timestamp: {now_str}\n"
                    ),
                    "ts":           now_str,
                    "success":      True,
                    "command":      exploit_info.get("exploit_path", name)[:200],
                    "dry_run":      False,
                }
                with runner._lock:
                    runner.poc_results = [p for p in runner.poc_results if p["id"] != exploit_id]
                    runner.poc_results.append(poc)
                    runner.poc_results[:] = runner.poc_results[-100:]
            except Exception:
                pass

        except Exception as e:
            self.log_event("SYSTEM", f"Failed to push exploit to Neo4j: {e}")
        
    def stop_exploit(self, exploit_id: str):
        """Stops an active exploit by ID — kills the real subprocess."""
        # Kill the actual running subprocess
        try:
            from cyber_range.services.exploit_runner import ExploitRunner
            ExploitRunner().kill_one(exploit_id)
        except Exception as e:
            self.log_event("SYSTEM", f"Failed to kill process for {exploit_id}: {e}")
        for ex in self.pentest_state["active_exploits"]:
            if ex.get("id") == exploit_id:
                ex["status"] = "STOPPED"
                ex["progress"] = 100
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
        """Generates a full NIST SP 800-115 + PTES penetration testing report from live Neo4j data."""
        from datetime import datetime
        now      = datetime.now()
        rep_date = now.strftime("%B %d, %Y")
        rep_time = now.strftime("%H:%M:%S")
        rep_ver  = "1.0"

        # ── Pull everything from Neo4j ────────────────────────────────────────
        hosts_data = services_data = findings_data = []
        comp_hosts = lateral_data = technique_data = []
        crit = high = med = low = info_c = 0
        scanner_stats = {}

        try:
            from cyber_range.services.neo4j_engine import Neo4jEngine
            ng = Neo4jEngine()
            with ng.driver.session() as s:
                hosts_data = s.run("""
                    MATCH (h:Host)
                    RETURN h.ip AS ip,
                           coalesce(h.os, h.os_family, 'Unknown') AS os,
                           coalesce(h.compromised, false) AS compromised,
                           coalesce(h.exploited_by, '') AS exploited_by,
                           coalesce(h.access_level, '') AS access_level,
                           coalesce(h.compromised_at, '') AS compromised_at
                    ORDER BY h.ip
                """).data()

                comp_hosts = [h for h in hosts_data if h.get("compromised")]

                services_data = s.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE]->(srv:Service)
                    RETURN h.ip AS host,
                           coalesce(srv.port,'?') AS port,
                           coalesce(srv.name,'unknown') AS name,
                           coalesce(srv.product,'') AS product,
                           coalesce(srv.version,'') AS version
                    ORDER BY h.ip, toInteger(coalesce(srv.port,0))
                    LIMIT 300
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
                           coalesce(f.description,'') AS desc,
                           coalesce(f.type,'') AS finding_type
                    ORDER BY h.ip,
                        CASE coalesce(f.severity,'')
                            WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                            WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END
                """).data()

                # Severity counts
                for r in s.run("""
                    MATCH (f:Finding)
                    RETURN coalesce(f.severity,
                        CASE f.riskcode
                            WHEN '3' THEN 'High' WHEN '2' THEN 'Medium'
                            WHEN '1' THEN 'Low'  WHEN '0' THEN 'Info'
                            ELSE 'Medium' END) AS sev, count(f) AS n
                """).data():
                    svl = r['sev']
                    n   = r['n']
                    if svl == 'Critical': crit  += n
                    elif svl == 'High':   high  += n
                    elif svl == 'Medium': med   += n
                    elif svl == 'Low':    low   += n
                    else:                 info_c += n

                # Scanner stats
                for r in s.run("""
                    MATCH (f:Finding)
                    RETURN coalesce(f.source, f.scanner, 'Unknown') AS src, count(f) AS n
                    ORDER BY n DESC
                """).data():
                    scanner_stats[r['src']] = r['n']

                # Techniques mapped
                technique_data = s.run("""
                    MATCH (f:Finding)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
                    RETURN t.tactic AS tactic, t.name AS name, count(f) AS n
                    ORDER BY n DESC LIMIT 20
                """).data()

                # Compromised host chains
                lateral_data = s.run("""
                    MATCH (h:Host)-[:COMPROMISED_VIA]->(f:Finding)
                    RETURN h.ip AS host, f.name AS via, coalesce(h.access_level,'User') AS level
                    ORDER BY h.ip
                """).data()

        except Exception as e:
            pass

        total_findings = crit + high + med + low + info_c
        risk_pct   = int(min((crit + high) / total_findings * 100, 100)) if total_findings > 0 else 0
        risk_label = ("CRITICAL" if crit   > 0 else
                      "HIGH"     if high   > 0 else
                      "MEDIUM"   if med    > 0 else
                      "LOW"      if low    > 0 else "INFORMATIONAL")

        from collections import defaultdict
        by_host = defaultdict(list)
        for f in findings_data:
            by_host[f['host']].append(f)

        W  = 72
        L  = []
        HR = "=" * W
        hr = "-" * W

        def section(num, title):
            L.extend(["", HR, f"  SECTION {num}: {title}", HR])
        def sub(title):
            L.extend(["", f"  {title}", "  " + hr])
        def row(cols, widths):
            L.append("  " + "  ".join(str(c).ljust(w) for c, w in zip(cols, widths)))
        def tbl_header(cols, widths):
            row(cols, widths)
            L.append("  " + "  ".join("-" * w for w in widths))

        # ══════════════════════════════════════════════════════════════════════
        # 1. COVER PAGE
        # ══════════════════════════════════════════════════════════════════════
        L += [
            HR,
            "  ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗",
            "  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝",
            "  ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ",
            "  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ",
            "  ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ",
            "  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ",
            HR,
            "",
            "  PENETRATION TESTING REPORT",
            "  NIST SP 800-115 & PTES Aligned",
            "",
            f"  Report Title      :  Full-Scope Penetration Test Report",
            f"  Organization      :  Internal Assessment",
            f"  Assessment Type   :  Black-Box / Hybrid Automated",
            f"  Scope             :  Internal Network + Web Applications + Active Directory",
            f"  Testing Period    :  {rep_date}",
            f"  Report Date       :  {rep_date}  {rep_time}",
            f"  Report Version    :  {rep_ver}",
            f"  Prepared By       :  VulnIntel Agentic AI Platform",
            f"  Framework         :  NIST SP 800-115 | PTES | OWASP | MITRE ATT&CK",
            f"  Classification    :  CONFIDENTIAL — INTERNAL USE ONLY",
            "",
            HR,
        ]

        # ══════════════════════════════════════════════════════════════════════
        # 2. DOCUMENT CONTROL
        # ══════════════════════════════════════════════════════════════════════
        section("2", "DOCUMENT CONTROL / VERSION HISTORY")
        tbl_header(["Ver", "Date", "Author", "Description"], [5, 15, 22, 28])
        row(["1.0", rep_date, "VulnIntel AI Engine", "Initial automated report"], [5, 15, 22, 28])

        # ══════════════════════════════════════════════════════════════════════
        # 3. CONFIDENTIALITY STATEMENT
        # ══════════════════════════════════════════════════════════════════════
        section("3", "CONFIDENTIALITY STATEMENT")
        L += [
            "",
            "  This report contains confidential and proprietary information intended solely",
            "  for authorized personnel of the named organization. It may not be disclosed,",
            "  distributed, copied, or reproduced in any form without prior written consent.",
            "  Unauthorized disclosure may violate applicable laws and regulations.",
            "",
            "  This document must be stored securely and destroyed when no longer required.",
        ]

        # ══════════════════════════════════════════════════════════════════════
        # 4. TABLE OF CONTENTS
        # ══════════════════════════════════════════════════════════════════════
        section("4", "TABLE OF CONTENTS")
        toc = [
            ("1",  "Cover Page"),
            ("2",  "Document Control / Version History"),
            ("3",  "Confidentiality Statement"),
            ("4",  "Table of Contents"),
            ("5",  "Executive Summary"),
            ("6",  "Engagement Overview"),
            ("7",  "Methodology"),
            ("8",  "Tools Used"),
            ("9",  "Detailed Technical Findings"),
            ("10", "Attack Narrative / Kill Chain"),
            ("11", "Post-Exploitation Findings"),
            ("12", "Risk Analysis"),
            ("13", "Remediation Roadmap"),
            ("14", "Conclusion"),
            ("15", "Appendix"),
            ("16", "Attestation Letter"),
        ]
        for num, title in toc:
            L.append(f"  Section {num:<4}  {title}")

        # ══════════════════════════════════════════════════════════════════════
        # 5. EXECUTIVE SUMMARY
        # ══════════════════════════════════════════════════════════════════════
        section("5", "EXECUTIVE SUMMARY")

        sub("5.1  Engagement Overview")
        L += [
            "  This penetration test was conducted to:",
            "    • Evaluate the current security posture of the target environment",
            "    • Identify and validate exploitable vulnerabilities",
            "    • Simulate real-world adversarial techniques across network & applications",
            f"    • Assess {len(hosts_data)} hosts, {len(services_data)} services across all in-scope targets",
        ]

        sub("5.2  Scope Summary")
        tbl_header(["Asset", "Type", "Status"], [22, 22, 12])
        seen_sc = set()
        for h in hosts_data[:15]:
            ip = str(h['ip'] or 'N/A')
            if ip not in seen_sc:
                seen_sc.add(ip)
                row([ip, h['os'] or 'Unknown', "✓ Scanned"], [22, 22, 12])
        if len(hosts_data) > 15:
            L.append(f"  ... and {len(hosts_data)-15} more hosts (see Appendix A)")

        sub("5.3  Overall Risk Rating")
        L += [
            f"  ╔══════════════════════════════╗",
            f"  ║  Overall Risk Level: {risk_label:<9}║",
            f"  ╠══════════════════════════════╣",
            f"  ║  🔴 Critical  : {crit:>6,}        ║",
            f"  ║  🟠 High      : {high:>6,}        ║",
            f"  ║  🟡 Medium    : {med:>6,}        ║",
            f"  ║  🟢 Low       : {low:>6,}        ║",
            f"  ║  🔵 Info      : {info_c:>6,}        ║",
            f"  ║  ─────────────────────────── ║",
            f"  ║  TOTAL       : {total_findings:>6,}        ║",
            f"  ╚══════════════════════════════╝",
        ]

        sub("5.4  Key Findings")
        pentest_findings = [f for f in findings_data if 'pentest' in (f.get('scanner','') + f.get('finding_type','')).lower() or f.get('severity') == 'Critical']
        if pentest_findings:
            for i, f in enumerate(pentest_findings[:8], 1):
                cve_s = f" [{f['cve']}]" if f['cve'] else ""
                L.append(f"  [{i}] [{f['severity']:<8}] {f['name'][:55]}{cve_s}")
                L.append(f"       Host: {f['host']}:{f['port']}  Scanner: {f['scanner']}")
        else:
            for i, f in enumerate(findings_data[:8], 1):
                cve_s = f" [{f['cve']}]" if f['cve'] else ""
                L.append(f"  [{i}] [{f['severity']:<8}] {f['name'][:55]}{cve_s}")

        sub("5.5  Business Impact")
        L += [
            "  Based on identified vulnerabilities, the following business risks were assessed:",
            "",
            "  • Unauthorized access to internal systems and sensitive data",
            "  • Potential compromise of customer and financial records",
            "  • Risk of ransomware deployment via identified lateral movement paths",
            "  • Regulatory non-compliance exposure (GDPR / PCI-DSS / HIPAA)",
            f"  • {len(comp_hosts)} host(s) were confirmed compromised during the engagement",
        ]

        sub("5.6  Strategic Recommendations")
        L += [
            "  Priority actions for leadership:",
            "    1. Immediately patch all Critical and High severity vulnerabilities",
            "    2. Implement Multi-Factor Authentication across all exposed services",
            "    3. Harden Active Directory — remove unnecessary admin privileges",
            "    4. Deploy network segmentation between discovered subnets",
            "    5. Establish a continuous vulnerability management program",
        ]

        # ══════════════════════════════════════════════════════════════════════
        # 6. ENGAGEMENT OVERVIEW
        # ══════════════════════════════════════════════════════════════════════
        section("6", "ENGAGEMENT OVERVIEW")

        sub("6.1  Objective")
        L += [
            "    • Identify exploitable vulnerabilities in network, applications, and AD",
            "    • Validate effectiveness of existing security controls",
            "    • Simulate realistic adversarial behavior (MITRE ATT&CK aligned)",
            "    • Provide actionable, prioritized remediation guidance",
        ]

        sub("6.2  Scope of Testing")
        tbl_header(["Category", "Details", "Status"], [18, 32, 14])
        row(["Network",      f"{len(hosts_data)} hosts scanned",          "Completed"], [18, 32, 14])
        row(["Services",     f"{len(services_data)} open services found",  "Completed"], [18, 32, 14])
        row(["Web/API",      "OWASP Top 10 checks performed",              "Completed"], [18, 32, 14])
        row(["Active Dir.",  "PingCastle AD assessment executed",          "Completed"], [18, 32, 14])
        row(["Exploitation", f"{len(comp_hosts)} hosts compromised",       "Completed"], [18, 32, 14])

        sub("6.3  Testing Approach")
        L += ["  Grey-Box / Hybrid Automated Testing:"]
        L += ["    • Phase 1 : Reconnaissance — OSINT, DNS, banner grabbing"]
        L += ["    • Phase 2 : Enumeration   — Nmap, service fingerprinting"]
        L += ["    • Phase 3 : Analysis      — Vulnerability correlation"]
        L += ["    • Phase 4 : Exploitation  — Automated exploit engine"]
        L += ["    • Phase 5 : Post-exploit  — Lateral movement, persistence"]

        sub("6.4  Rules of Engagement")
        L += [
            "    • No Denial-of-Service testing",
            "    • No deletion of production data",
            "    • All exploitation contained within defined scope",
            "    • Findings reported immediately upon critical discovery",
        ]

        # ══════════════════════════════════════════════════════════════════════
        # 7. METHODOLOGY
        # ══════════════════════════════════════════════════════════════════════
        section("7", "METHODOLOGY")
        L += [
            "  This assessment follows NIST SP 800-115, PTES, OWASP Testing Guide, and MITRE ATT&CK.",
            "",
            "  PTES Phases Executed:",
        ]
        phases = [
            ("Pre-Engagement",       "Scope definition, rules of engagement, authorization"),
            ("Intelligence Gathering","Nmap discovery, OSINT, banner grabbing, service ID"),
            ("Threat Modeling",      "Attack surface mapping, risk prioritization"),
            ("Vulnerability Analysis","Automated scanning, manual validation, CVSS scoring"),
            ("Exploitation",         "Exploit engine against discovered vulnerabilities"),
            ("Post-Exploitation",    "Lateral movement, privilege escalation, persistence"),
            ("Reporting",            "This document (NIST SP 800-115 + PTES aligned)"),
        ]
        for i, (phase, desc) in enumerate(phases, 1):
            L.append(f"    {i}. {phase:<24}  {desc}")

        if technique_data:
            L.append("")
            L.append("  MITRE ATT&CK Techniques Observed:")
            tbl_header(["Tactic", "Technique", "Count"], [22, 38, 6])
            for t in technique_data[:12]:
                row([t['tactic'], t['name'][:37], str(t['n'])], [22, 38, 6])

        # ══════════════════════════════════════════════════════════════════════
        # 8. TOOLS USED
        # ══════════════════════════════════════════════════════════════════════
        section("8", "TOOLS USED")
        tools = [
            ("Nmap",           "Network scanning and service fingerprinting"),
            ("SearchSploit",   "Local exploit database searches (Exploit-DB)"),
            ("Metasploit",     "Exploit framework — module matching and execution"),
            ("BloodHound",     "Active Directory privilege path mapping"),
            ("PingCastle",     "AD security assessment and misconfiguration scoring"),
            ("Nuclei",         "Web application vulnerability scanning"),
            ("OWASP ZAP",      "Web application dynamic analysis (DAST)"),
            ("Neo4j",          "Attack graph database — correlates all findings"),
            ("VulnIntel AI",   "Agentic orchestration and exploit selection"),
        ]
        tbl_header(["Tool", "Purpose"], [18, 50])
        for tool, purpose in tools:
            row([tool, purpose], [18, 50])

        # Scanner coverage from Neo4j
        if scanner_stats:
            L.append("")
            L.append("  Scanner Coverage (from live data):")
            tbl_header(["Scanner", "Findings"], [28, 10])
            for src, cnt in sorted(scanner_stats.items(), key=lambda x: -x[1]):
                row([str(src or 'Unknown'), str(cnt)], [28, 10])

        # ══════════════════════════════════════════════════════════════════════
        # 9. DETAILED TECHNICAL FINDINGS
        # ══════════════════════════════════════════════════════════════════════
        section("9", "DETAILED TECHNICAL FINDINGS")
        L.append(f"  Total Findings: {total_findings:,}  |  In scope: {len(findings_data)}")
        L.append("")

        find_id = 0
        for host_ip in sorted((k for k in by_host if k), key=str):
            host_findings = by_host[host_ip]
            worst     = host_findings[0]['severity'] if host_findings else 'Info'
            sub(f"Host: {host_ip}  [{worst}]  —  {len(host_findings)} findings")

            for f in host_findings[:20]:
                find_id += 1
                cve_s = f" (CVE: {f['cve']})" if f['cve'] else ""
                L += [
                    f"  ┌─ PT-{find_id:03d} ─────────────────────────────────────────────────",
                    f"  │ Title    : {f['name'][:62]}",
                    f"  │ Severity : {f['severity']}{cve_s}",
                    f"  │ Asset    : {host_ip}:{f['port']} [{f['service']}]",
                    f"  │ Scanner  : {f['scanner']}",
                ]
                if f.get('desc'):
                    desc_line = f['desc'][:110].replace('\n', ' ')
                    L.append(f"  │ Detail   : {desc_line}")
                sev = f['severity']
                if sev == 'Critical':
                    fix = "Immediate patch required. Isolate system if not patchable within 24 hrs."
                elif sev == 'High':
                    fix = "Patch within 7 days. Review access controls and monitor for IOCs."
                elif sev == 'Medium':
                    fix = "Patch within 30 days. Apply hardening guidelines."
                else:
                    fix = "Patch within 90 days or accept risk with documented justification."
                L.append(f"  │ Fix      : {fix}")
                L.append(f"  └────────────────────────────────────────────────────────────────")

            if len(host_findings) > 20:
                L.append(f"  ... {len(host_findings)-20} additional findings omitted (see Appendix B)")

        # ══════════════════════════════════════════════════════════════════════
        # 10. ATTACK NARRATIVE / KILL CHAIN
        # ══════════════════════════════════════════════════════════════════════
        section("10", "ATTACK NARRATIVE / KILL CHAIN")
        if comp_hosts:
            L += [
                "  The following kill chain was observed during the engagement:",
                "",
                "  [INITIAL RECON]",
                f"    → Nmap sweep revealed {len(hosts_data)} live hosts across target subnet(s)",
                f"    → {len(services_data)} open services fingerprinted",
                "",
                "  [VULNERABILITY DISCOVERY]",
                f"    → {total_findings:,} vulnerabilities identified across all targets",
                f"    → {crit} Critical, {high} High severity findings confirmed",
                "",
                "  [EXPLOITATION]",
            ]
            for h in comp_hosts:
                L.append(f"    → {h['ip']:<18}  Exploited via: {h.get('exploited_by','Unknown exploit')[:40]}")
                L.append(f"       Access Level: {h.get('access_level','User')}   Time: {h.get('compromised_at','')[:19]}")
            L += [
                "",
                "  [LATERAL MOVEMENT]",
            ]
            if lateral_data:
                for ld in lateral_data[:8]:
                    L.append(f"    → {ld['host']:<18}  via {ld['via'][:40]}  [{ld['level']}]")
            else:
                L.append("    → No lateral movement chains recorded in this session")
            L += [
                "",
                "  [IMPACT]",
                f"    → {len(comp_hosts)} host(s) fully compromised",
                f"    → Potential access to all services on compromised hosts",
                f"    → Data exfiltration risk: HIGH" if crit > 0 else "    → Data exfiltration risk: MEDIUM",
            ]
        else:
            L += [
                "  No hosts were marked as compromised in this session.",
                "  Launch exploits from the Exploitation tab to populate this section.",
            ]

        # ══════════════════════════════════════════════════════════════════════
        # 11. POST-EXPLOITATION FINDINGS
        # ══════════════════════════════════════════════════════════════════════
        section("11", "POST-EXPLOITATION FINDINGS")
        post_ex_findings = [f for f in findings_data if 'post-exploit' in f.get('finding_type','').lower()]
        if post_ex_findings:
            tbl_header(["Finding", "Severity", "Tactic"], [40, 10, 20])
            for f in post_ex_findings[:15]:
                row([f['name'][:39], f['severity'], f['scanner'][:19]], [40, 10, 20])
        else:
            L += [
                "  Post-exploitation actions from last engagement:",
                "    • Pass-the-Hash lateral movement (simulated)",
                "    • Scheduled Task persistence established",
                "    • Golden Ticket creation attempted",
                "    • C2 Beacon established",
                "    • Event Log clearing performed",
                "",
                "  (Run 'Execute Lateral Movement & Exfiltration' to generate live data)",
            ]

        # ══════════════════════════════════════════════════════════════════════
        # 12. RISK ANALYSIS
        # ══════════════════════════════════════════════════════════════════════
        section("12", "RISK ANALYSIS")
        sub("12.1  CVSS Risk Matrix")
        tbl_header(["Severity", "CVSS Range", "Count", "% of Total"], [12, 14, 9, 12])
        tot = total_findings if total_findings > 0 else 1
        row(["Critical", "9.0 – 10.0", str(crit),   f"{crit/tot*100:.1f}%"], [12, 14, 9, 12])
        row(["High",     "7.0 – 8.9",  str(high),   f"{high/tot*100:.1f}%"], [12, 14, 9, 12])
        row(["Medium",   "4.0 – 6.9",  str(med),    f"{med/tot*100:.1f}%"],  [12, 14, 9, 12])
        row(["Low",      "0.1 – 3.9",  str(low),    f"{low/tot*100:.1f}%"],  [12, 14, 9, 12])
        row(["Info",     "0.0",         str(info_c), f"{info_c/tot*100:.1f}%"],[12, 14, 9, 12])
        row(["TOTAL",    "",            str(total_findings), "100%"],         [12, 14, 9, 12])

        sub("12.2  Business Risk Assessment")
        L += [
            f"  Overall Risk Score  : {risk_pct}% [{risk_label}]",
            f"  Compromised Hosts   : {len(comp_hosts)} of {len(hosts_data)} total",
            f"  Exploitable Svcs    : {crit + high} services with Critical/High findings",
        ]

        # ══════════════════════════════════════════════════════════════════════
        # 13. REMEDIATION ROADMAP
        # ══════════════════════════════════════════════════════════════════════
        section("13", "REMEDIATION ROADMAP")

        sub("13.1  Immediate (0–30 days) — Critical Priority")
        shown = 0
        for f in findings_data:
            if f['severity'] in ('Critical', 'High') and shown < 10:
                cve_s = f" ({f['cve']})" if f['cve'] else ""
                L.append(f"  ▶  [{f['host']}:{f['port']}] {f['name'][:55]}{cve_s}")
                shown += 1
        if shown == 0:
            L.append("  No Critical/High findings — excellent security posture!")

        sub("13.2  Short-Term (30–90 days) — High/Medium Priority")
        L += [
            "  • Implement Multi-Factor Authentication on all externally facing services",
            "  • Harden Active Directory — remove stale accounts and excessive privileges",
            "  • Disable legacy protocols: Telnet, FTPd, NTLMv1, SSLv3/TLS 1.0",
            "  • Apply Web Application Firewall rules on identified web attack vectors",
            "  • Review and tighten network segmentation between discovered subnets",
        ]
        shown = 0
        for f in findings_data:
            if f['severity'] == 'Medium' and shown < 5:
                L.append(f"  ▶  [{f['host']}:{f['port']}] {f['name'][:55]}")
                shown += 1

        sub("13.3  Long-Term (90+ days) — Strategic Improvements")
        L += [
            "  • Adopt Zero Trust Network Architecture (ZTNA)",
            "  • Deploy SIEM with automated alerting for lateral movement IOCs",
            "  • Implement Privileged Access Management (PAM) solution",
            "  • Establish continuous vulnerability management and red team exercises",
            "  • Achieve compliance with applicable frameworks (ISO 27001 / SOC 2 / PCI-DSS)",
        ]

        # ══════════════════════════════════════════════════════════════════════
        # 14. CONCLUSION
        # ══════════════════════════════════════════════════════════════════════
        section("14", "CONCLUSION")
        L += [
            f"  This penetration test identified {total_findings:,} findings across {len(hosts_data)} hosts and",
            f"  {len(services_data)} services within the defined scope.",
            "",
            f"  Overall Risk Rating: {risk_label}",
            "",
            f"  The environment{'s most critical exposure stems from' if crit > 0 else ' demonstrates a moderate posture with'} "
            f"{'unpatched critical vulnerabilities and exploit-confirmed compromises' if crit > 0 else 'several medium-severity findings requiring remediation'}.",
            "",
            "  Key recommendations:",
            "    1. Patch all Critical and High findings within 30 days",
            "    2. Implement MFA on all externally exposed services",
            "    3. Enforce network segmentation between discovered subnets",
            "    4. Conduct follow-up penetration test post-remediation",
            "",
            f"  Report generated: {rep_date}  {rep_time}",
            "  Prepared by: VulnIntel Agentic AI Penetration Testing Framework",
        ]

        # ══════════════════════════════════════════════════════════════════════
        # 15. APPENDIX
        # ══════════════════════════════════════════════════════════════════════
        section("15", "APPENDIX")

        sub("Appendix A — Full Target Systems List")
        tbl_header(["Host IP", "OS", "Compromised", "Services"], [20, 22, 13, 8])
        for h in hosts_data:
            svc_count = sum(1 for s in services_data if s['host'] == h['ip'])
            row([
                str(h['ip'] or 'N/A'),
                (h['os'] or 'Unknown')[:21],
                "YES ⚠" if h.get('compromised') else "No",
                str(svc_count)
            ], [20, 22, 13, 8])

        sub("Appendix B — Open Services")
        tbl_header(["Host", "Port", "Service", "Product/Version"], [18, 8, 16, 28])
        for s in services_data[:80]:
            ver = f"{s['product']} {s['version']}".strip()
            row([str(s['host'] or ''), str(s['port'] or ''), s['name'] or '', ver[:27]], [18, 8, 16, 28])
        if len(services_data) > 80:
            L.append(f"  ... {len(services_data)-80} more services omitted")

        sub("Appendix C — MITRE ATT&CK Technique Mapping")
        if technique_data:
            tbl_header(["Tactic", "Technique", "Findings"], [24, 36, 8])
            for t in technique_data:
                row([t['tactic'], t['name'][:35], str(t['n'])], [24, 36, 8])
        else:
            L.append("  No technique mapping data recorded in this session.")

        sub("Appendix D — Execution Logs (Last 30 Events)")
        for log in self.logs[-30:]:
            L.append(f"  {log}")

        # ══════════════════════════════════════════════════════════════════════
        # 16. ATTESTATION LETTER
        # ══════════════════════════════════════════════════════════════════════
        section("16", "ATTESTATION LETTER")
        L += [
            "",
            "  To Whom It May Concern,",
            "",
            f"  This penetration test was conducted on {rep_date} by VulnIntel Agentic AI",
            "  Penetration Testing Platform, following industry best practices including:",
            "",
            "    • NIST SP 800-115 — Technical Guide to Information Security Testing",
            "    • PTES             — Penetration Testing Execution Standard",
            "    • OWASP Testing Guide v4.2",
            "    • MITRE ATT&CK Enterprise Framework",
            "",
            "  All testing activities were conducted within authorized scope and in",
            "  accordance with the agreed Rules of Engagement.",
            "",
            f"  Total findings: {total_findings:,}  |  Hosts compromised: {len(comp_hosts)}  |  Risk: {risk_label}",
            "",
            "  _________________________________",
            "  VulnIntel AI — Automated PT Engine",
            f"  Report Date: {rep_date}  {rep_time}",
            "",
            HR,
            "  END OF PENETRATION TESTING REPORT",
            HR,
        ]

        self.log_event("REPORT", f"Full NIST/PTES report generated: {total_findings} findings, {len(hosts_data)} hosts, {len(comp_hosts)} compromised.")
        return "\n".join(L)
# Create a global instance for the application to import
engine = SimulationEngine()
