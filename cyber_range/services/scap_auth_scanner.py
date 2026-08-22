"""
scap_auth_scanner.py
====================
Authenticated SCAP scanning engine supporting:
  - SSH + sudo execution (Linux/Unix)
  - oscap-ssh integration (DISA-approved method)
  - Local agent mode (direct oscap execution)
  - Evidence collection (command output, file states, package versions)

Federal alignment:
  - ACAS/Nessus credentialed scan model
  - DISA STIG Viewer workflow
  - OpenSCAP enterprise scanning patterns
"""

import os
import re
import json
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Optional, Callable


class AuthMethod:
    """Authentication method constants."""
    SSH_KEY = "ssh_key"
    SSH_PASSWORD = "ssh_password"
    LOCAL = "local"
    OSCAP_SSH = "oscap_ssh"


class ScanResult:
    """SCAP result states per NIST SP 800-126."""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    UNKNOWN = "unknown"
    NOTAPPLICABLE = "notapplicable"   # System not relevant to this control
    NOTCHECKED = "notchecked"         # Scan could not evaluate
    NOTSELECTED = "notselected"       # Rule excluded from profile
    INFORMATIONAL = "informational"   # Advisory only


# ── NIST 800-53 Control Family Mapping ──────────────────────────────────
RULE_TO_CONTROL_FAMILY = {
    # Access Control (AC)
    "access_control": "AC", "account": "AC", "auth": "AC", "login": "AC",
    "password": "AC", "pam": "AC", "sudo": "AC", "privilege": "AC",
    "session": "AC", "lockout": "AC", "su_command": "AC",
    # Audit and Accountability (AU)
    "audit": "AU", "auditd": "AU", "log": "AU", "syslog": "AU",
    "journal": "AU", "rsyslog": "AU", "recording": "AU",
    # Configuration Management (CM)
    "install": "CM", "package": "CM", "software": "CM", "service": "CM",
    "daemon": "CM", "kernel": "CM", "sysctl": "CM", "grub": "CM",
    "boot": "CM", "module": "CM", "gpg": "CM", "repo": "CM",
    # Identification and Authentication (IA)
    "crypto": "IA", "fips": "IA", "certificate": "IA", "tls": "IA",
    "ssl": "IA", "ssh": "IA", "kerberos": "IA", "pki": "IA",
    "smartcard": "IA", "openssh": "IA",
    # System and Communications Protection (SC)
    "firewall": "SC", "iptables": "SC", "nftables": "SC", "selinux": "SC",
    "apparmor": "SC", "encrypt": "SC", "partition": "SC", "mount": "SC",
    "network": "SC", "tcp": "SC", "icmp": "SC", "ipv4": "SC", "ipv6": "SC",
    # System and Information Integrity (SI)
    "rpm": "SI", "aide": "SI", "tripwire": "SI", "integrity": "SI",
    "antivirus": "SI", "malware": "SI", "virus": "SI", "hashes": "SI",
    # Risk Assessment (RA)
    "vulnerability": "RA", "scan": "RA", "assess": "RA",
    # Maintenance (MA)
    "cron": "MA", "at": "MA", "timer": "MA", "maintenance": "MA",
    # Media Protection (MP)
    "usb": "MP", "removable": "MP", "cdrom": "MP", "media": "MP",
    # Physical and Environmental Protection (PE)
    "physical": "PE", "screen": "PE", "lock": "PE", "idle": "PE",
    "screensaver": "PE", "gnome": "PE", "dconf": "PE",
    # Personnel Security (PS)
    "user": "PS", "group": "PS", "home": "PS", "shell": "PS",
    # Contingency Planning (CP)
    "backup": "CP", "recovery": "CP", "restore": "CP",
}

# DISA STIG severity mapping
STIG_CAT = {
    "High": "CAT I",
    "Medium": "CAT II",
    "Low": "CAT III",
    "Info": "CAT III",
}


def map_rule_to_nist(rule_id: str, title: str, description: str = "") -> dict:
    """Map a SCAP rule to NIST 800-53 control family and STIG category."""
    combined = f"{rule_id} {title} {description}".lower()
    
    matched_family = "CM"  # Default: Configuration Management
    for keyword, family in RULE_TO_CONTROL_FAMILY.items():
        if keyword in combined:
            matched_family = family
            break
    
    # NIST 800-53 control family full names
    family_names = {
        "AC": "Access Control",
        "AU": "Audit and Accountability",
        "CM": "Configuration Management",
        "IA": "Identification and Authentication",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "RA": "Risk Assessment",
        "MA": "Maintenance",
        "MP": "Media Protection",
        "PE": "Physical and Environmental Protection",
        "PS": "Personnel Security",
        "CP": "Contingency Planning",
    }
    
    return {
        "nist_family": matched_family,
        "nist_family_name": family_names.get(matched_family, "Unknown"),
        "nist_control": f"{matched_family}-1",  # Base control
    }


def classify_applicability(rule_id: str, title: str, target_os: dict) -> str:
    """
    Determine if a rule is applicable to the target system.
    
    Returns: 'applicable', 'notapplicable', or 'notassessed'
    """
    rid = rule_id.lower()
    rtitle = title.lower()
    combined = f"{rid} {rtitle}"
    os_family = target_os.get("os_family", "unknown").lower()
    
    # Windows-only rules on Linux target → NOTAPPLICABLE
    windows_indicators = ["windows", "win32", "win64", "registry", "gpo",
                         "active_directory", "group_policy", "powershell",
                         "iis", "bitlocker", "defender"]
    if os_family not in ("windows",) and any(w in combined for w in windows_indicators):
        return "notapplicable"
    
    # Linux-only rules on Windows target → NOTAPPLICABLE
    linux_indicators = ["selinux", "apparmor", "systemd", "journald", "auditd",
                       "pam_", "sysctl", "grub", "yum", "dnf", "apt",
                       "rpm", "dpkg", "firewalld", "nftables"]
    if os_family == "windows" and any(l in combined for l in linux_indicators):
        return "notapplicable"
    
    # RHEL-specific rules on Ubuntu → NOTAPPLICABLE
    rhel_only = ["rhel", "red_hat", "centos", "almalinux", "oracle_linux",
                "subscription-manager", "yum", "rpm"]
    if os_family in ("ubuntu", "debian") and any(r in combined for r in rhel_only):
        if "rpm" not in combined[:20]:  # Don't exclude if rule_id starts with rpm
            return "notapplicable"
    
    # Ubuntu/Debian-specific rules on RHEL → NOTAPPLICABLE
    deb_only = ["ubuntu", "debian", "apt", "dpkg", "ufw"]
    if os_family in ("rhel", "centos", "almalinux", "fedora") and any(d in combined for d in deb_only):
        return "notapplicable"
    
    # GUI/GNOME rules on headless server → NOTAPPLICABLE (heuristic)
    gui_indicators = ["gnome", "gdm", "xdmcp", "dconf", "screensaver", "x11",
                     "wayland", "display_manager"]
    # We assume server unless we know otherwise
    if any(g in combined for g in gui_indicators):
        return "notapplicable"  # Safe default for servers
    
    # Container-specific rules on bare metal → NOTAPPLICABLE
    container_indicators = ["openshift", "ocp4", "kubernetes", "kubelet",
                          "container", "podman", "docker"]
    if os_family not in ("ocp", "kubernetes") and any(c in combined for c in container_indicators):
        return "notapplicable"
    
    return "applicable"


class AuthenticatedScanner:
    """
    Authenticated SCAP scanner using SSH + sudo.
    
    Supports:
      - SSH key-based authentication
      - oscap-ssh wrapper (DISA-approved)
      - Local execution (when running on target)
      - Evidence collection for each control
    """
    
    def __init__(self, target: str, auth_method: str = AuthMethod.SSH_KEY,
                 ssh_user: str = "root", ssh_key: str = "",
                 ssh_password: str = "", sudo: bool = True,
                 on_log: Optional[Callable] = None):
        self.target = target
        self.auth_method = auth_method
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.ssh_password = ssh_password
        self.sudo = sudo
        self.log = on_log or (lambda m: None)
        self._connected = False
    
    def test_connection(self) -> bool:
        """Test SSH connectivity to target."""
        if self.auth_method == AuthMethod.LOCAL:
            self._connected = True
            return True
        
        try:
            _ssh_cfg = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".ssh_config")
            cmd = ["ssh", "-F", _ssh_cfg,
                   "-o", "BatchMode=yes"]
            if self.ssh_key:
                cmd.extend(["-i", self.ssh_key])
            cmd.extend([f"{self.ssh_user}@{self.target}", "echo", "XSTRIKE_AUTH_OK"])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self._connected = "XSTRIKE_AUTH_OK" in result.stdout
            return self._connected
        except Exception as e:
            self.log(f"[AUTH]   Connection failed: {e}\n")
            return False
    
    def exec_remote(self, command: str, timeout: int = 15) -> dict:
        """Execute a command on the remote target and collect evidence."""
        evidence = {
            "command": command,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "success": False,
        }
        
        try:
            if self.auth_method == AuthMethod.LOCAL:
                # Local execution
                full_cmd = f"sudo {command}" if self.sudo else command
                result = subprocess.run(
                    full_cmd, shell=True, capture_output=True,
                    text=True, timeout=timeout
                )
            else:
                # SSH execution
                _ssh_cfg = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".ssh_config")
                ssh_cmd = ["ssh", "-F", _ssh_cfg,
                          "-o", "BatchMode=yes"]
                if self.ssh_key:
                    ssh_cmd.extend(["-i", self.ssh_key])
                
                remote_cmd = f"sudo {command}" if self.sudo else command
                ssh_cmd.extend([f"{self.ssh_user}@{self.target}", remote_cmd])
                
                result = subprocess.run(
                    ssh_cmd, capture_output=True, text=True, timeout=timeout
                )
            
            evidence["stdout"] = result.stdout[:2000]
            evidence["stderr"] = result.stderr[:500]
            evidence["exit_code"] = result.returncode
            evidence["success"] = result.returncode == 0
            
        except subprocess.TimeoutExpired:
            evidence["stderr"] = "Command timed out"
        except Exception as e:
            evidence["stderr"] = str(e)
        
        return evidence
    
    def check_file_exists(self, path: str) -> dict:
        """Check if a file exists and get its metadata."""
        return self.exec_remote(f"stat -c '%a %U %G %s %Y' {path} 2>/dev/null || echo 'NOT_FOUND'")
    
    def check_file_content(self, path: str, pattern: str) -> dict:
        """Check if file contains a pattern."""
        return self.exec_remote(f"grep -c '{pattern}' {path} 2>/dev/null || echo '0'")
    
    def check_service_status(self, service: str) -> dict:
        """Check systemd service status."""
        return self.exec_remote(f"systemctl is-active {service} 2>/dev/null")
    
    def check_package_installed(self, package: str) -> dict:
        """Check if a package is installed."""
        return self.exec_remote(
            f"rpm -q {package} 2>/dev/null || dpkg -l {package} 2>/dev/null || echo 'NOT_INSTALLED'"
        )
    
    def check_sysctl(self, param: str) -> dict:
        """Check kernel parameter value."""
        return self.exec_remote(f"sysctl -n {param} 2>/dev/null")
    
    def get_os_release(self) -> dict:
        """Get /etc/os-release for definitive OS identification (99%+ confidence)."""
        result = self.exec_remote("cat /etc/os-release 2>/dev/null")
        if result["success"]:
            info = {}
            for line in result["stdout"].splitlines():
                if "=" in line:
                    key, val = line.split("=", 1)
                    info[key.strip()] = val.strip().strip('"')
            
            os_id = info.get("ID", "").lower()
            version = info.get("VERSION_ID", "")
            
            return {
                "os_family": os_id,
                "os_version": version,
                "os_name": info.get("PRETTY_NAME", ""),
                "confidence": 0.99,
                "method": "os-release",
                "raw": result["stdout"][:500],
            }
        return {}
    
    def run_oscap_ssh(self, benchmark_path: str, profile: str = "",
                      results_dir: str = "/tmp") -> dict:
        """
        Run oscap-ssh for DISA-approved authenticated scanning.
        
        This is the gold standard for federal SCAP assessment.
        """
        self.log(f"[AUTH] Running oscap-ssh authenticated scan...\n")
        
        results_xml = os.path.join(results_dir, f"aegis_scap_results_{int(datetime.now().timestamp())}.xml")
        report_html = results_xml.replace(".xml", ".html")
        
        cmd = [
            "oscap-ssh", f"{self.ssh_user}@{self.target}", "22",
            "xccdf", "eval",
            "--results", results_xml,
            "--report", report_html,
        ]
        
        if profile:
            cmd.extend(["--profile", profile])
        
        cmd.append(benchmark_path)
        
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            
            return {
                "success": result.returncode in (0, 2),  # 2 = some failures (normal)
                "results_xml": results_xml if os.path.exists(results_xml) else None,
                "report_html": report_html if os.path.exists(report_html) else None,
                "stdout": result.stdout[:5000],
                "stderr": result.stderr[:2000],
                "exit_code": result.returncode,
            }
        except FileNotFoundError:
            self.log(f"[AUTH]   oscap-ssh not installed. Install: sudo apt install openscap-utils\n")
            return {"success": False, "error": "oscap-ssh not found"}
        except subprocess.TimeoutExpired:
            self.log(f"[AUTH]   oscap-ssh timed out after 5 minutes\n")
            return {"success": False, "error": "timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}


# ── Compliance Scoring Engine ─────────────────────────────────────────

class ComplianceScorer:
    """
    Federal-grade compliance scoring engine.
    
    Model: Score = PASS / (PASS + FAIL) × Coverage Factor
    
    Coverage Factor = evaluated_controls / total_applicable_controls
    
    States tracked:
      - PASS: Control verified as compliant
      - FAIL: Control verified as non-compliant
      - NOTAPPLICABLE: Control not relevant to this system
      - NOTCHECKED: Could not evaluate (scan limitation)
      - NOTASSESSED: Explicitly out of scope
      - ERROR: Scan error occurred
    """
    
    def __init__(self):
        self.results = {
            ScanResult.PASS: 0,
            ScanResult.FAIL: 0,
            ScanResult.ERROR: 0,
            ScanResult.NOTAPPLICABLE: 0,
            ScanResult.NOTCHECKED: 0,
            ScanResult.NOTSELECTED: 0,
            ScanResult.INFORMATIONAL: 0,
        }
        self.control_families = {}  # family → {pass, fail, total}
        self.stig_cats = {"CAT I": 0, "CAT II": 0, "CAT III": 0}
        self.evidence = []
    
    def record(self, status: str, severity: str = "Medium",
               nist_family: str = "CM", evidence: dict = None):
        """Record a control evaluation result."""
        if status in self.results:
            self.results[status] += 1
        
        # Track by control family
        if nist_family not in self.control_families:
            self.control_families[nist_family] = {"pass": 0, "fail": 0, "na": 0, "unverified": 0, "total": 0}
        self.control_families[nist_family]["total"] += 1
        if status == ScanResult.PASS:
            self.control_families[nist_family]["pass"] += 1
        elif status == ScanResult.FAIL:
            self.control_families[nist_family]["fail"] += 1
        elif status == ScanResult.NOTAPPLICABLE:
            self.control_families[nist_family]["na"] += 1
        else:
            self.control_families[nist_family]["unverified"] += 1
        
        # Track STIG severity
        cat = STIG_CAT.get(severity, "CAT III")
        if status == ScanResult.FAIL:
            self.stig_cats[cat] += 1
        
        if evidence:
            self.evidence.append(evidence)
    
    @property
    def total_controls(self) -> int:
        return sum(self.results.values())
    
    @property
    def total_applicable(self) -> int:
        """Controls that ARE applicable to this system."""
        return self.total_controls - self.results[ScanResult.NOTAPPLICABLE] - self.results[ScanResult.NOTSELECTED]
    
    @property
    def total_evaluated(self) -> int:
        """Controls actually tested (PASS + FAIL + ERROR)."""
        return self.results[ScanResult.PASS] + self.results[ScanResult.FAIL] + self.results[ScanResult.ERROR]
    
    @property
    def coverage_pct(self) -> Optional[float]:
        """What percentage of applicable controls were evaluated."""
        if self.total_applicable == 0:
            return None
        return (self.total_evaluated / self.total_applicable) * 100
    
    @property
    def compliance_pct(self) -> Optional[float]:
        """
        Compliance score: PASS / (PASS + FAIL).
        
        Returns None if no controls were evaluated (coverage = 0%).
        This prevents false "100% compliant" on unauthenticated scans.
        """
        if self.total_evaluated == 0:
            return None  # CRITICAL: NULL, not 0% or 100%
        return (self.results[ScanResult.PASS] / self.total_evaluated) * 100
    
    @property
    def weighted_score(self) -> Optional[float]:
        """
        Compliance Score × Coverage Factor.
        
        This is the actual reportable score for dashboards.
        A system with 80% compliance but only 30% coverage = 24% weighted.
        """
        comp = self.compliance_pct
        cov = self.coverage_pct
        if comp is None or cov is None:
            return None
        return (comp * cov) / 100
    
    def to_dict(self) -> dict:
        """Export scoring data for persistence."""
        return {
            "total_controls": self.total_controls,
            "total_applicable": self.total_applicable,
            "total_evaluated": self.total_evaluated,
            "pass": self.results[ScanResult.PASS],
            "fail": self.results[ScanResult.FAIL],
            "error": self.results[ScanResult.ERROR],
            "notapplicable": self.results[ScanResult.NOTAPPLICABLE],
            "notchecked": self.results[ScanResult.NOTCHECKED],
            "notselected": self.results[ScanResult.NOTSELECTED],
            "coverage_pct": round(self.coverage_pct, 1) if self.coverage_pct is not None else None,
            "compliance_pct": round(self.compliance_pct, 1) if self.compliance_pct is not None else None,
            "weighted_score": round(self.weighted_score, 1) if self.weighted_score is not None else None,
            "stig_cats": dict(self.stig_cats),
            "control_families": dict(self.control_families),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def render_scorecard(self, log: Callable, benchmark: str = "", target: str = ""):
        """Render the compliance scorecard to log output."""
        log(f"[SCAP]   ╔══════════════════════════════════════════════╗\n")
        log(f"[SCAP]   ║      COMPLIANCE ASSESSMENT SCORECARD        ║\n")
        log(f"[SCAP]   ╠══════════════════════════════════════════════╣\n")
        if target:
            log(f"[SCAP]   ║  Target     : {target:<30} ║\n")
        if benchmark:
            log(f"[SCAP]   ║  Benchmark  : {benchmark:<30} ║\n")
        log(f"[SCAP]   ╠══════════════════════════════════════════════╣\n")
        log(f"[SCAP]   ║  ✓ PASS          : {self.results[ScanResult.PASS]:<25} ║\n")
        log(f"[SCAP]   ║  ✗ FAIL          : {self.results[ScanResult.FAIL]:<25} ║\n")
        log(f"[SCAP]   ║  ○ NOT CHECKED   : {self.results[ScanResult.NOTCHECKED]:<25} ║\n")
        log(f"[SCAP]   ║  - NOT APPLICABLE: {self.results[ScanResult.NOTAPPLICABLE]:<25} ║\n")
        if self.results[ScanResult.ERROR]:
            log(f"[SCAP]   ║  ⚠ ERROR         : {self.results[ScanResult.ERROR]:<25} ║\n")
        log(f"[SCAP]   ╠══════════════════════════════════════════════╣\n")
        
        cov = self.coverage_pct
        comp = self.compliance_pct
        weighted = self.weighted_score
        
        if cov is not None:
            log(f"[SCAP]   ║  Coverage        : {cov:>5.0f}% ({self.total_evaluated}/{self.total_applicable}){' ' * 7}║\n")
        else:
            log(f"[SCAP]   ║  Coverage        : N/A                       ║\n")
        
        if comp is not None:
            log(f"[SCAP]   ║  Compliance      : {comp:>5.0f}% ({self.results[ScanResult.PASS]}/{self.total_evaluated}){' ' * 9}║\n")
            if weighted is not None:
                log(f"[SCAP]   ║  Weighted Score  : {weighted:>5.0f}%{' ' * 23}║\n")
        else:
            log(f"[SCAP]   ║  Compliance      : NULL (insufficient data)  ║\n")
            log(f"[SCAP]   ║  ⚠ POSTURE: UNKNOWN — NOT a clean system    ║\n")
        
        # STIG severity breakdown
        if any(v > 0 for v in self.stig_cats.values()):
            log(f"[SCAP]   ╠══════════════════════════════════════════════╣\n")
            log(f"[SCAP]   ║  STIG Severity (failures only):              ║\n")
            for cat, count in self.stig_cats.items():
                if count > 0:
                    log(f"[SCAP]   ║    {cat}: {count} findings{' ' * (30 - len(cat) - len(str(count)))}║\n")
        
        log(f"[SCAP]   ╚══════════════════════════════════════════════╝\n")


# ── POA&M Generator ──────────────────────────────────────────────────

class POAMGenerator:
    """
    Plan of Action & Milestones (POA&M) auto-generator.
    
    Federal requirement per OMB A-130 / NIST SP 800-53.
    Every FAIL finding must have a corresponding POA&M entry.
    """
    
    def __init__(self, system_name: str = "Aegis Platform",
                 issm: str = "System Admin", isso: str = "Security Officer"):
        self.system_name = system_name
        self.issm = issm
        self.isso = isso
        self.entries = []
    
    def add_finding(self, rule_id: str, title: str, severity: str,
                    nist_family: str, evidence: str = "",
                    recommendation: str = "", milestone_days: int = 30):
        """Add a FAIL finding to the POA&M."""
        cat = STIG_CAT.get(severity, "CAT III")
        
        # Set milestone based on STIG category
        if cat == "CAT I":
            milestone_days = 30   # 30 days for Critical
        elif cat == "CAT II":
            milestone_days = 90   # 90 days for High
        else:
            milestone_days = 180  # 180 days for Medium/Low
        
        self.entries.append({
            "poam_id": f"POAM-{len(self.entries) + 1:04d}",
            "weakness": title[:200],
            "rule_id": rule_id,
            "stig_cat": cat,
            "severity": severity,
            "nist_control": f"{nist_family}-1",
            "nist_family": nist_family,
            "status": "Open",
            "scheduled_completion": f"{milestone_days} days",
            "milestone_date": (datetime.now(timezone.utc).replace(
                day=1) + timedelta(days=milestone_days)).isoformat()[:10],
            "evidence": evidence[:500],
            "recommendation": recommendation or f"Remediate {title[:100]} per STIG guidance",
            "responsible": self.isso,
            "system": self.system_name,
            "created": datetime.now(timezone.utc).isoformat()[:10],
        })
    
    def to_json(self) -> str:
        """Export POA&M as JSON."""
        return json.dumps({
            "poam_report": {
                "system": self.system_name,
                "issm": self.issm,
                "isso": self.isso,
                "generated": datetime.now(timezone.utc).isoformat(),
                "total_items": len(self.entries),
                "cat_i_count": len([e for e in self.entries if e["stig_cat"] == "CAT I"]),
                "cat_ii_count": len([e for e in self.entries if e["stig_cat"] == "CAT II"]),
                "cat_iii_count": len([e for e in self.entries if e["stig_cat"] == "CAT III"]),
                "entries": self.entries,
            }
        }, indent=2)
    
    def render_summary(self, log: Callable):
        """Render POA&M summary to log output."""
        if not self.entries:
            log(f"[POAM]   No POA&M entries — no failures found\n")
            return
        
        cat_i = len([e for e in self.entries if e["stig_cat"] == "CAT I"])
        cat_ii = len([e for e in self.entries if e["stig_cat"] == "CAT II"])
        cat_iii = len([e for e in self.entries if e["stig_cat"] == "CAT III"])
        
        log(f"[POAM] ═══════════════════════════════════════\n")
        log(f"[POAM] Plan of Action & Milestones (POA&M)\n")
        log(f"[POAM] System: {self.system_name}\n")
        log(f"[POAM] ───────────────────────────────────────\n")
        log(f"[POAM]   Total items: {len(self.entries)}\n")
        if cat_i:
            log(f"[POAM]   CAT I  (30-day):  {cat_i} — CRITICAL\n")
        if cat_ii:
            log(f"[POAM]   CAT II (90-day):  {cat_ii}\n")
        if cat_iii:
            log(f"[POAM]   CAT III (180-day): {cat_iii}\n")
        log(f"[POAM] ═══════════════════════════════════════\n")


# ── Auth Enforcement Gate ────────────────────────────────────────────

class AuthEnforcementResult:
    """Result of an authentication enforcement check."""
    def __init__(self, allowed: bool, reason: str, auth_level: str):
        self.allowed = allowed
        self.reason = reason
        self.auth_level = auth_level  # "local" | "ssh_key" | "ssh_password" | "none"

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "auth_level": self.auth_level,
        }


class AuthEnforcer:
    """
    Authentication enforcement gate for SCAP compliance scans.

    Policy:
      - LOCAL targets (localhost, 127.0.0.1, ::1) → ALWAYS allowed
      - REMOTE targets → REQUIRE SSH key or password
      - If auth fails → scan is BLOCKED with clear reason
      - No "proceed anyway" — unauthenticated remote scans produce
        garbage data and must not be allowed to complete as VALID

    Federal justification:
      - NIST SP 800-53 IA-2: Identification and Authentication
      - DISA STIG: Credentialed scans mandatory for compliance claims
      - ACAS policy: Unauthenticated scans are informational only
    """

    LOCAL_TARGETS = {"localhost", "127.0.0.1", "::1", ""}

    @classmethod
    def enforce(cls, target: str, ssh_user: str = "",
                ssh_key: str = "", ssh_password: str = "",
                allow_unauthenticated: bool = False) -> AuthEnforcementResult:
        """
        Check if scan is allowed to proceed.

        Args:
            target: Scan target IP/hostname
            ssh_user: SSH username
            ssh_key: Path to SSH key
            ssh_password: SSH password
            allow_unauthenticated: If True, allow unauthenticated scans
                                    but mark result as advisory-only

        Returns:
            AuthEnforcementResult with allowed/reason/auth_level
        """
        target = (target or "").strip().lower()

        # ── Local targets: always allowed ──
        if target in cls.LOCAL_TARGETS:
            return AuthEnforcementResult(
                allowed=True,
                reason="Local target — oscap runs directly (no SSH needed)",
                auth_level="local",
            )

        # ── Remote targets: require credentials ──
        if ssh_key:
            return AuthEnforcementResult(
                allowed=True,
                reason=f"SSH key authentication → {ssh_user or 'root'}@{target}",
                auth_level="ssh_key",
            )

        if ssh_password:
            return AuthEnforcementResult(
                allowed=True,
                reason=f"SSH password authentication → {ssh_user or 'root'}@{target}",
                auth_level="ssh_password",
            )

        # ── Try environment / Vault fallback ──
        env_key = os.environ.get("SCAP_SSH_KEY", "")
        env_pass = os.environ.get("SCAP_SSH_PASSWORD", "")
        if env_key or env_pass:
            return AuthEnforcementResult(
                allowed=True,
                reason="Credentials from environment/Vault",
                auth_level="ssh_key" if env_key else "ssh_password",
            )

        # ── Explicit opt-in for unauthenticated (advisory scan) ──
        if allow_unauthenticated:
            return AuthEnforcementResult(
                allowed=True,
                reason=(
                    "UNAUTHENTICATED scan — advisory only. "
                    "Results will be marked PARTIAL/INVALID and NOT "
                    "written to production compliance databases."
                ),
                auth_level="none",
            )

        # ── BLOCKED: no credentials for remote target ──
        return AuthEnforcementResult(
            allowed=False,
            reason=(
                f"BLOCKED: Remote target '{target}' requires SSH credentials. "
                f"Provide SSH key or password for authenticated scanning. "
                f"Unauthenticated scans against remote targets produce unreliable "
                f"data and cannot be used for compliance reporting."
            ),
            auth_level="none",
        )


__all__ = [
    "AuthMethod", "ScanResult", "AuthenticatedScanner",
    "ComplianceScorer", "POAMGenerator",
    "map_rule_to_nist", "classify_applicability",
    "STIG_CAT", "RULE_TO_CONTROL_FAMILY",
    "AuthEnforcer", "AuthEnforcementResult",
]
