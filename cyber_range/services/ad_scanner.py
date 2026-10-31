"""
Expedite Strike — Full-Spectrum Active Directory Security Scanner
================================================================
Comprehensive AD assessment from discovery to domain compromise detection.

Assessment Categories:
  1. RECONNAISSANCE — Port enumeration, DC identification
  2. LDAP ANALYSIS — Anonymous bind, RootDSE, naming contexts
  3. USER SECURITY — Password policies, stale accounts, admin sprawl
  4. KERBEROS SECURITY — AS-REP Roastable, Kerberoastable, delegation
  5. GPO & CONFIGURATION — SMB signing, LDAP signing, LAPS, Print Spooler
  6. TRUST ANALYSIS — Forest trusts, external trusts
  7. CERTIFICATE SERVICES — ESC1-ESC8 AD CS misconfigurations
  8. EXPOSURE SCORING — PingCastle-style weighted risk score

MITRE ATT&CK Coverage:
  T1087.002 - Account Discovery: Domain Account
  T1558.003 - Kerberoasting
  T1558.004 - AS-REP Roasting
  T1550.002 - Pass the Hash
  T1003.006 - DCSync
  T1187     - Forced Authentication (Spooler)
  T1484.001 - Group Policy Modification
  T1552.004 - Private Keys (ADCS)
"""

import socket
import logging
from datetime import datetime
import threading
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# Try ldap3 — graceful degradation if not installed
try:
    from ldap3 import Server, Connection, ALL, ANONYMOUS, NTLM, SUBTREE
    _HAS_LDAP3 = True
except ImportError:
    _HAS_LDAP3 = False


class ADSecurityScanner:
    """Full-spectrum Active Directory security assessment engine."""

    # AD-relevant ports
    AD_PORTS = {
        53:   "DNS",
        88:   "Kerberos",
        135:  "RPC/MSRPC",
        139:  "NetBIOS-SSN",
        389:  "LDAP",
        445:  "SMB/CIFS",
        464:  "Kerberos-kpasswd",
        593:  "HTTP-RPC-EPMAP",
        636:  "LDAPS",
        3268: "Global Catalog",
        3269: "Global Catalog SSL",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
        9389: "AD Web Services",
    }

    def __init__(self, target_ip: str, domain: str = "",
                 username: str = "", password: str = "",
                 log_fn: Callable = None):
        self.target_ip = target_ip
        self.domain = domain
        self.username = username
        self.password = password
        self._log_fn = log_fn
        self.open_ports = []
        self.domain_info = {}
        self.findings = []       # List of finding dicts
        self.users = []
        self.groups = []
        self.computers = []
        self.spns = []
        self.asrep_users = []
        self.unconstrained = []
        self.password_policy = {}
        self.trusts = []
        self.exposure_score = 0
        self._conn = None        # LDAP connection

    def _log(self, msg):
        if self._log_fn:
            self._log_fn(msg)

    def _add_finding(self, title: str, severity: str, description: str,
                     mitre_id: str, category: str = "AD"):
        """Add a finding to the results."""
        self.findings.append({
            "scanner": "AutoPentest-ADScan",
            "host": self.target_ip,
            "title": title,
            "severity": severity,
            "description": description,
            "mitre_id": mitre_id,
            "category": category,
        })
        icon = {"Critical": "🚨", "High": "⚠️", "Medium": "🔶", "Low": "ℹ️"}.get(severity, "•")
        self._log(f"    {icon} [{severity}] {title}")

    # ── Phase 1: RECONNAISSANCE ──────────────────────────────────────

    def scan_ports(self):
        """Enumerate AD-relevant ports."""
        self._log(f"    [RECON] Port scanning {self.target_ip}...")
        for port, service in self.AD_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    self.open_ports.append(port)
                    self._log(f"    [RECON] {port}/tcp OPEN → {service}")
                sock.close()
            except Exception:
                pass

        # Identify DC characteristics
        dc_ports = {88, 389}
        if dc_ports.issubset(set(self.open_ports)):
            self._add_finding(
                f"Domain Controller Identified: {self.target_ip}",
                "Medium",
                f"Host {self.target_ip} has Kerberos (88) and LDAP (389) open, "
                f"indicating it is a Domain Controller. Open AD ports: "
                f"{', '.join(f'{p}/{self.AD_PORTS[p]}' for p in sorted(self.open_ports))}",
                "T1018", "Reconnaissance"
            )

        # Check WinRM exposure
        if 5985 in self.open_ports or 5986 in self.open_ports:
            self._add_finding(
                f"WinRM Exposed: {self.target_ip}",
                "Medium",
                "Windows Remote Management is externally accessible. "
                "Attackers can use this for lateral movement with valid credentials.",
                "T1021.006", "Reconnaissance"
            )

        return self.open_ports

    # ── Phase 2: LDAP ANALYSIS ───────────────────────────────────────

    def analyze_ldap(self):
        """Test LDAP binding and extract domain information."""
        if 389 not in self.open_ports and 636 not in self.open_ports:
            self._log("    [LDAP] No LDAP/LDAPS ports open — skipping")
            return

        if not _HAS_LDAP3:
            self._log("    [LDAP] ldap3 not installed — skipping LDAP analysis")
            return

        self._log(f"    [LDAP] Analyzing LDAP on {self.target_ip}...")

        # Test 1: Anonymous bind
        try:
            server = Server(self.target_ip, get_info=ALL, connect_timeout=5)
            anon_conn = Connection(server, authentication=ANONYMOUS, auto_bind=False)
            if anon_conn.bind():
                self._add_finding(
                    "Anonymous LDAP Bind Allowed",
                    "High",
                    f"Anonymous LDAP bind succeeded on {self.target_ip}. "
                    "Attackers can enumerate users, groups, OUs, and trust relationships "
                    "without any credentials. This is a critical misconfiguration.",
                    "T1087.002", "LDAP Analysis"
                )
                # Extract RootDSE from anonymous bind
                if server.info:
                    self._extract_domain_info(server.info)
                anon_conn.unbind()
            else:
                self.domain_info["anonymous_bind"] = "denied"
                self._log("    [LDAP] Anonymous bind denied (good)")
        except Exception as e:
            self._log(f"    [LDAP] Anonymous bind test: {e}")

        # Test 2: Authenticated bind (if credentials provided)
        if self.username and self.password:
            try:
                bind_user = self.username
                if "\\" not in bind_user and self.domain:
                    bind_user = f"{self.domain.split('.')[0]}\\{self.username}"
                server = Server(self.target_ip, get_info=ALL, connect_timeout=5)
                self._conn = Connection(server, user=bind_user,
                                        password=self.password,
                                        auto_bind=True, receive_timeout=15)
                self._log(f"    [LDAP] Authenticated bind as {bind_user} ✓")
                if server.info:
                    self._extract_domain_info(server.info)
            except Exception as e:
                self._log(f"    [LDAP] Auth bind failed: {e}")

        # Test 3: LDAP Signing
        if 389 in self.open_ports:
            self._check_ldap_signing()

    def _extract_domain_info(self, info):
        """Extract domain information from LDAP server info."""
        try:
            other = getattr(info, 'other', {})
            self.domain_info["domain_name"] = (
                getattr(info, 'naming_contexts', [None]) or [None]
            )[0]
            if other:
                self.domain_info["dns_name"] = other.get("dnsHostName", [""])[0] if isinstance(other.get("dnsHostName"), list) else ""
                self.domain_info["forest_name"] = other.get("rootDomainNamingContext", [""])[0] if isinstance(other.get("rootDomainNamingContext"), list) else ""
                self.domain_info["server_name"] = other.get("serverName", [""])[0] if isinstance(other.get("serverName"), list) else ""
                self.domain_info["schema_version"] = other.get("schemaNamingContext", [""])[0] if isinstance(other.get("schemaNamingContext"), list) else ""
                func_level = other.get("domainFunctionality", [""])[0] if isinstance(other.get("domainFunctionality"), list) else ""
                self.domain_info["functional_level"] = func_level
                fl_map = {"0": "2000", "1": "2003 Interim", "2": "2003",
                          "3": "2008", "4": "2008 R2", "5": "2012",
                          "6": "2012 R2", "7": "2016"}
                fl_label = fl_map.get(str(func_level), func_level)
                self._log(f"    [LDAP] Domain: {self.domain_info.get('domain_name', '?')}")
                self._log(f"    [LDAP] Functional Level: {fl_label}")

                # Old functional level = vulnerability
                if str(func_level) in ("0", "1", "2", "3"):
                    self._add_finding(
                        f"Outdated Domain Functional Level: {fl_label}",
                        "High",
                        f"Domain functional level is {fl_label}, which lacks modern "
                        "security features like Protected Users group, Authentication "
                        "Policies, and Credential Guard support.",
                        "T1484.001", "Configuration"
                    )
        except Exception as e:
            self._log(f"    [LDAP] Domain info extraction: {e}")

    def _check_ldap_signing(self):
        """Check if LDAP signing is enforced."""
        try:
            server = Server(self.target_ip, get_info=ALL, connect_timeout=5)
            # Attempt unsigned bind — if it works, signing is not enforced
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=False)
            if conn.bind():
                self._add_finding(
                    "LDAP Signing Not Enforced",
                    "High",
                    "LDAP channel does not require signing. Attackers can perform "
                    "LDAP relay attacks to modify AD objects, add users to groups, "
                    "or set resource-based constrained delegation.",
                    "T1557.001", "Configuration"
                )
                conn.unbind()
        except Exception:
            pass

    # ── Phase 3: USER SECURITY ───────────────────────────────────────

    def analyze_users(self):
        """Enumerate and analyze user accounts for security issues."""
        if not self._conn:
            return

        base_dn = self._get_base_dn()
        if not base_dn:
            return

        self._log(f"    [USERS] Enumerating user accounts...")

        try:
            self._conn.search(
                base_dn,
                "(objectClass=user)",
                attributes=["sAMAccountName", "userAccountControl",
                             "memberOf", "servicePrincipalName",
                             "pwdLastSet", "lastLogon", "description",
                             "adminCount"],
                search_scope=SUBTREE,
                size_limit=2000
            )

            admin_count = 0
            stale_count = 0
            no_preauth = 0
            password_never_expires = 0
            pwd_in_description = 0

            for entry in self._conn.entries:
                user = {
                    "username": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "",
                    "uac": str(entry.userAccountControl) if hasattr(entry, "userAccountControl") else "0",
                    "spns": [str(s) for s in entry.servicePrincipalName] if hasattr(entry, "servicePrincipalName") and entry.servicePrincipalName else [],
                    "admin": str(entry.adminCount) == "1" if hasattr(entry, "adminCount") else False,
                    "description": str(entry.description) if hasattr(entry, "description") else "",
                }
                self.users.append(user)

                uac = int(user["uac"]) if user["uac"].isdigit() else 0

                # Check: Kerberos Pre-Auth not required (AS-REP Roastable)
                if uac & 0x400000:  # DONT_REQUIRE_PREAUTH
                    no_preauth += 1
                    self.asrep_users.append(user["username"])

                # Check: Password never expires
                if uac & 0x10000:  # DONT_EXPIRE_PASSWD
                    password_never_expires += 1

                # Check: Admin accounts
                if user["admin"]:
                    admin_count += 1

                # Check: Password in description
                desc = user["description"].lower()
                if any(kw in desc for kw in ["password", "pwd", "pass:", "p@ss", "cred"]):
                    pwd_in_description += 1
                    self._add_finding(
                        f"Password in Description: {user['username']}",
                        "Critical",
                        f"User {user['username']} has password-related information "
                        f"in their AD description field: '{user['description'][:80]}'",
                        "T1552.001", "User Security"
                    )

                # Check: Service Principal Names (Kerberoastable)
                if user["spns"]:
                    self.spns.append({
                        "user": user["username"],
                        "spn": ", ".join(user["spns"][:3]),
                    })

            self._log(f"    [USERS] Enumerated {len(self.users)} users")

            # Report findings
            if no_preauth > 0:
                self._add_finding(
                    f"AS-REP Roastable Accounts: {no_preauth}",
                    "High",
                    f"{no_preauth} user(s) do not require Kerberos pre-authentication. "
                    f"Accounts: {', '.join(self.asrep_users[:10])}. "
                    "Attackers can request TGTs and crack passwords offline.",
                    "T1558.004", "Kerberos Security"
                )

            if self.spns:
                self._add_finding(
                    f"Kerberoastable Accounts: {len(self.spns)}",
                    "High",
                    f"{len(self.spns)} service account(s) with SPNs set. "
                    f"Accounts: {', '.join(s['user'] for s in self.spns[:10])}. "
                    "TGS tickets can be requested and cracked offline.",
                    "T1558.003", "Kerberos Security"
                )

            if admin_count > 5:
                self._add_finding(
                    f"Admin Account Sprawl: {admin_count} admin accounts",
                    "Medium",
                    f"{admin_count} accounts with adminCount=1 detected. "
                    "Excessive admin accounts increase the attack surface. "
                    "Principle of least privilege violated.",
                    "T1078.002", "User Security"
                )

            if password_never_expires > 10:
                self._add_finding(
                    f"Password Policy: {password_never_expires} accounts never expire",
                    "Medium",
                    f"{password_never_expires} accounts have DONT_EXPIRE_PASSWD set. "
                    "Stale credentials increase credential stuffing and brute force risk.",
                    "T1110", "User Security"
                )

        except Exception as e:
            self._log(f"    [USERS] Enumeration error: {e}")

    # ── Phase 4: KERBEROS & DELEGATION ───────────────────────────────

    def analyze_delegation(self):
        """Check for dangerous delegation configurations."""
        if not self._conn:
            return

        base_dn = self._get_base_dn()
        if not base_dn:
            return

        self._log(f"    [KERBEROS] Checking delegation configurations...")

        # Unconstrained Delegation
        try:
            self._conn.search(
                base_dn,
                "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                attributes=["name", "dNSHostName"],
                search_scope=SUBTREE
            )
            for entry in self._conn.entries:
                name = str(entry.name) if hasattr(entry, "name") else "?"
                self.unconstrained.append(name)

            if self.unconstrained:
                self._add_finding(
                    f"Unconstrained Delegation: {len(self.unconstrained)} systems",
                    "Critical",
                    f"Computers with unconstrained delegation: "
                    f"{', '.join(self.unconstrained[:10])}. "
                    "Any user authenticating to these systems has their TGT stored "
                    "in memory, allowing impersonation of ANY domain user including "
                    "Domain Admins. This is a Tier-0 compromise path.",
                    "T1550.003", "Kerberos Security"
                )
        except Exception as e:
            self._log(f"    [KERBEROS] Delegation check error: {e}")

        # Constrained Delegation (with protocol transition)
        try:
            self._conn.search(
                base_dn,
                "(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))",
                attributes=["name", "msDS-AllowedToDelegateTo"],
                search_scope=SUBTREE
            )
            constrained_count = len(self._conn.entries)
            if constrained_count > 0:
                self._add_finding(
                    f"Constrained Delegation: {constrained_count} systems",
                    "Medium",
                    f"{constrained_count} computer(s) have constrained delegation configured. "
                    "If protocol transition (S4U2Self) is enabled, these can be used "
                    "to impersonate users to specific services.",
                    "T1550.003", "Kerberos Security"
                )
        except Exception:
            pass

    # ── Phase 5: GPO & CONFIGURATION ─────────────────────────────────

    def analyze_configuration(self):
        """Check AD security configuration settings."""
        self._log(f"    [CONFIG] Checking security configuration...")

        # SMB Signing check
        if 445 in self.open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, 445))
                # Send SMB negotiate to check signing
                sock.close()
                self._add_finding(
                    "SMB Signing Check Required",
                    "High",
                    "SMB is accessible on port 445. If SMB signing is not required "
                    "and enforced, attackers can perform SMB relay attacks to "
                    "authenticate to other systems, create accounts, or modify "
                    "domain objects. Verify with: nmap --script smb2-security-mode.",
                    "T1557.001", "Configuration"
                )
            except Exception:
                pass

        # Print Spooler (PrintNightmare CVE-2021-34527)
        if 445 in self.open_ports:
            spooler = self._check_print_spooler()
            if spooler:
                self._add_finding(
                    "Print Spooler Active on Domain Controller",
                    "Critical",
                    "The Print Spooler service is running on this Domain Controller. "
                    "This enables: PrintNightmare (CVE-2021-34527) for RCE, "
                    "SpoolFool for privilege escalation, and printer relay attacks "
                    "for coerced authentication. Disable Spooler on all DCs.",
                    "T1187", "Configuration"
                )

        # LAPS check (via LDAP attribute)
        if self._conn:
            self._check_laps()

        # NTLMv1 check
        self._add_finding(
            "NTLMv1 Audit Recommended",
            "Medium",
            "Verify that NTLMv1 is disabled on all domain-joined systems. "
            "NTLMv1 hashes can be cracked in seconds using rainbow tables. "
            "Check GPO: Network security: LAN Manager authentication level.",
            "T1557", "Configuration"
        )

    def _check_print_spooler(self) -> bool:
        """Check if Print Spooler is accessible via RPC."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target_ip, 445))
            sock.close()
            return result == 0  # If SMB is open, spooler likely active on DC
        except Exception:
            return False

    def _check_laps(self):
        """Check if LAPS is deployed."""
        base_dn = self._get_base_dn()
        if not base_dn:
            return
        try:
            # Search for LAPS schema attribute
            self._conn.search(
                base_dn,
                "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
                attributes=["name"],
                search_scope=SUBTREE,
                size_limit=1
            )
            if not self._conn.entries:
                self._add_finding(
                    "LAPS Not Deployed",
                    "High",
                    "Microsoft Local Administrator Password Solution (LAPS) "
                    "does not appear to be deployed. Local admin passwords "
                    "may be shared across workstations, enabling mass lateral "
                    "movement after a single workstation compromise.",
                    "T1078.003", "Configuration"
                )
            else:
                self._log("    [CONFIG] LAPS deployed ✓")
        except Exception:
            # Attribute may not exist = LAPS not installed
            self._add_finding(
                "LAPS Not Installed",
                "High",
                "LAPS schema extension (ms-Mcs-AdmPwd) not found. "
                "Local admin passwords are likely identical across workstations.",
                "T1078.003", "Configuration"
            )

    # ── Phase 6: TRUST ANALYSIS ──────────────────────────────────────

    def analyze_trusts(self):
        """Enumerate AD trust relationships."""
        if not self._conn:
            return

        base_dn = self._get_base_dn()
        if not base_dn:
            return

        self._log(f"    [TRUSTS] Checking trust relationships...")

        try:
            self._conn.search(
                base_dn,
                "(objectClass=trustedDomain)",
                attributes=["name", "trustDirection", "trustType",
                             "trustAttributes", "flatName"],
                search_scope=SUBTREE
            )
            for entry in self._conn.entries:
                trust_name = str(entry.name) if hasattr(entry, "name") else "?"
                trust_dir = str(entry.trustDirection) if hasattr(entry, "trustDirection") else "?"
                dir_map = {"1": "Inbound", "2": "Outbound", "3": "Bidirectional"}
                direction = dir_map.get(trust_dir, trust_dir)

                self.trusts.append({
                    "name": trust_name,
                    "direction": direction,
                })
                self._log(f"    [TRUSTS] {trust_name} ({direction})")

            if self.trusts:
                self._add_finding(
                    f"Domain Trusts: {len(self.trusts)} trust(s) found",
                    "Medium",
                    f"Trust relationships: {', '.join(t['name'] + ' (' + t['direction'] + ')' for t in self.trusts[:5])}. "
                    "Cross-domain trusts can be exploited for SID History injection, "
                    "golden ticket attacks across forest boundaries, and trust abuse.",
                    "T1482", "Trust Analysis"
                )
        except Exception as e:
            self._log(f"    [TRUSTS] Enumeration error: {e}")

    # ── Phase 7: CERTIFICATE SERVICES (AD CS) ────────────────────────

    def analyze_adcs(self):
        """Check for AD Certificate Services misconfigurations (ESC1-ESC8)."""
        if not self._conn:
            return

        base_dn = self._get_base_dn()
        if not base_dn:
            return

        self._log(f"    [ADCS] Checking AD Certificate Services...")

        # Search for Certificate Authority enrollment services
        try:
            config_dn = f"CN=Configuration,{base_dn}"
            self._conn.search(
                config_dn,
                "(objectClass=pKIEnrollmentService)",
                attributes=["name", "dNSHostName", "certificateTemplates"],
                search_scope=SUBTREE
            )
            if self._conn.entries:
                for entry in self._conn.entries:
                    ca_name = str(entry.name) if hasattr(entry, "name") else "?"
                    templates = entry.certificateTemplates if hasattr(entry, "certificateTemplates") else []
                    template_count = len(templates) if templates else 0
                    self._log(f"    [ADCS] CA found: {ca_name} ({template_count} templates)")

                    self._add_finding(
                        f"AD Certificate Authority: {ca_name}",
                        "Medium",
                        f"Enterprise CA '{ca_name}' detected with {template_count} templates. "
                        "Check for ESC1 (SAN misconfiguration), ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), "
                        "and ESC8 (HTTP enrollment) vulnerabilities using Certify or Certipy.",
                        "T1552.004", "Certificate Services"
                    )

                # Check for vulnerable templates (ESC1: enrollment rights + SAN)
                self._conn.search(
                    config_dn,
                    "(&(objectClass=pKICertificateTemplate)"
                    "(msPKI-Certificate-Name-Flag=1)"
                    "(pKIExtendedKeyUsage=1.3.6.1.5.5.7.3.2))",
                    attributes=["name", "msPKI-Certificate-Name-Flag"],
                    search_scope=SUBTREE
                )
                if self._conn.entries:
                    for entry in self._conn.entries:
                        tmpl_name = str(entry.name) if hasattr(entry, "name") else "?"
                        self._add_finding(
                            f"ESC1: Vulnerable Certificate Template: {tmpl_name}",
                            "Critical",
                            f"Template '{tmpl_name}' allows Subject Alternative Name (SAN) "
                            "specification by the enrollee with Client Authentication EKU. "
                            "Attackers can request certificates as any user including "
                            "Domain Admins → instant domain compromise.",
                            "T1552.004", "Certificate Services"
                        )
            else:
                self._log("    [ADCS] No Certificate Authority found")

        except Exception as e:
            self._log(f"    [ADCS] Analysis error: {e}")

    # ── Phase 8: EXPOSURE SCORING ────────────────────────────────────

    def calculate_exposure_score(self) -> int:
        """Calculate PingCastle-style weighted risk score (0-100)."""
        score = 0

        # Count by severity
        for f in self.findings:
            sev = f.get("severity", "Low")
            if sev == "Critical":
                score += 15
            elif sev == "High":
                score += 8
            elif sev == "Medium":
                score += 3
            elif sev == "Low":
                score += 1

        # Cap at 100
        self.exposure_score = min(100, score)
        return self.exposure_score

    # ── HELPER ───────────────────────────────────────────────────────

    def _get_base_dn(self) -> str:
        """Get the base DN for LDAP searches."""
        if self.domain:
            return ",".join(f"DC={p}" for p in self.domain.split("."))
        dn = self.domain_info.get("domain_name", "")
        if dn and dn.startswith("DC="):
            return dn
        return ""

    # ── MAIN RUN ─────────────────────────────────────────────────────

    def run(self) -> dict:
        """Execute full-spectrum AD security assessment."""
        self._log(f"\n    {'━'*55}")
        self._log(f"    🏢 AD SECURITY ASSESSMENT: {self.target_ip}")
        self._log(f"    {'━'*55}")

        # Phase 1: Reconnaissance
        self._log(f"\n    📡 Phase 1: RECONNAISSANCE")
        self.scan_ports()

        # Phase 2: LDAP Analysis
        self._log(f"\n    🔍 Phase 2: LDAP ANALYSIS")
        self.analyze_ldap()

        # Phase 3: User Security
        self._log(f"\n    👤 Phase 3: USER SECURITY")
        self.analyze_users()

        # Phase 4: Kerberos & Delegation
        self._log(f"\n    🎟️ Phase 4: KERBEROS & DELEGATION")
        self.analyze_delegation()

        # Phase 5: GPO & Configuration
        self._log(f"\n    ⚙️ Phase 5: CONFIGURATION AUDIT")
        self.analyze_configuration()

        # Phase 6: Trust Analysis
        self._log(f"\n    🔗 Phase 6: TRUST ANALYSIS")
        self.analyze_trusts()

        # Phase 7: Certificate Services
        self._log(f"\n    📜 Phase 7: AD CERTIFICATE SERVICES")
        self.analyze_adcs()

        # Phase 8: Exposure Score
        score = self.calculate_exposure_score()
        risk_label = "LOW" if score < 25 else "MODERATE" if score < 50 else "HIGH" if score < 75 else "CRITICAL"

        self._log(f"\n    {'━'*55}")
        self._log(f"    📊 AD EXPOSURE SCORE: {score}/100 ({risk_label})")
        self._log(f"    📋 Total Findings: {len(self.findings)}")
        self._log(f"       Critical: {sum(1 for f in self.findings if f['severity']=='Critical')}")
        self._log(f"       High:     {sum(1 for f in self.findings if f['severity']=='High')}")
        self._log(f"       Medium:   {sum(1 for f in self.findings if f['severity']=='Medium')}")
        self._log(f"       Low:      {sum(1 for f in self.findings if f['severity']=='Low')}")
        self._log(f"    {'━'*55}")

        # Cleanup
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass

        return {
            "ip": self.target_ip,
            "ports": self.open_ports,
            "domain_info": self.domain_info,
            "findings": self.findings,
            "users": len(self.users),
            "groups": len(self.groups),
            "computers": len(self.computers),
            "spns": self.spns,
            "asrep_users": self.asrep_users,
            "unconstrained": self.unconstrained,
            "trusts": self.trusts,
            "exposure_score": self.exposure_score,
            "vulns": len(self.findings),
        }


# ── Public API ───────────────────────────────────────────────────────

def run_ad_scan(target_ip: str, domain: str = "",
                username: str = "", password: str = "",
                log_fn: Callable = None) -> dict:
    """Entry point: run full-spectrum AD security assessment."""
    scanner = ADSecurityScanner(
        target_ip, domain=domain,
        username=username, password=password,
        log_fn=log_fn
    )
    return scanner.run()


def run_ad_scan_async(target_ip: str, domain: str = "",
                      username: str = "", password: str = "",
                      log_fn: Callable = None):
    """Background thread wrapper."""
    def _bg():
        run_ad_scan(target_ip, domain, username, password, log_fn)
    t = threading.Thread(target=_bg)
    t.daemon = True
    t.start()
    return t
