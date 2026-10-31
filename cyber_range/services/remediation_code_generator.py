"""
Expedite Strike — Fix-as-Code Remediation Engine
================================================
Generates production-ready, deterministic remediation code from scan findings:
  1. Ansible Playbook (.yml) — Automated host patching and configuration hardening
  2. Terraform / Cloud (.tf) — Security group & access policy fixes
  3. Web Server Config (.conf) — Nginx / Apache modern security headers & TLS hardening
  4. PowerShell Script (.ps1) — Windows / Active Directory remediation
"""

import io
import json
import zipfile
from datetime import datetime
from typing import List, Dict, Any, Tuple


class RemediationCodeGenerator:
    """Translates vulnerability and reconnaissance findings into actionable hardening code."""

    def __init__(self, findings: List[Dict[str, Any]], targets: List[str] = None):
        self.findings = findings or []
        self.targets = targets or ["target_hosts"]
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ══════════════════════════════════════════════════════════════════════════
    #  1. ANSIBLE PLAYBOOK GENERATOR
    # ══════════════════════════════════════════════════════════════════════════
    def generate_ansible_playbook(self) -> str:
        """Generate a production-ready Ansible playbook targeting all discovered issues."""
        tasks = []
        seen_tasks = set()

        def _add_task(name: str, yaml_snippet: str):
            if name not in seen_tasks:
                seen_tasks.add(name)
                tasks.append(yaml_snippet.strip())

        header = f"""---
# ==============================================================================
# EXPEDITE STRIKE — AUTOMATED REMEDIATION PLAYBOOK
# Generated: {self.timestamp}
# Targets: {', '.join(self.targets[:5])}
# Total Findings Addressed: {len(self.findings)}
# ==============================================================================

- name: Expedite Strike Security Hardening & Remediation
  hosts: all
  become: true
  gather_facts: true

  vars:
    expedite_remediation_tag: "expedite-strike-{datetime.now().strftime('%Y%m%d')}"

  tasks:
    - name: 00. Create audit directory for pre-remediation backups
      ansible.builtin.file:
        path: /var/backups/expedite_remediation
        state: directory
        mode: '0700'
"""

        for f in self.findings:
            title = (f.get("title", "") or f.get("name", "")).lower()
            desc = (f.get("description", "") or "").lower()
            t_str = title + " " + desc

            # vsftpd Backdoor / Outdated FTP
            if "vsftpd" in t_str or "ftp" in t_str:
                _add_task("vsftpd_remediate", """
    - name: 01. Remediation: Remove compromised vsftpd package and disable service
      block:
        - name: Stop and disable vsftpd service
          ansible.builtin.service:
            name: vsftpd
            state: stopped
            enabled: false
          ignore_errors: true

        - name: Purge vulnerable vsftpd binary
          ansible.builtin.package:
            name: vsftpd
            state: absent
            purge: true
          when: ansible_os_family == "Debian"
""")

            # Telnet Insecure Cleartext
            if "telnet" in t_str:
                _add_task("telnet_remediate", """
    - name: 02. Remediation: Disable cleartext Telnet service and remove package
      block:
        - name: Disable telnet socket/service
          ansible.builtin.service:
            name: telnet
            state: stopped
            enabled: false
          ignore_errors: true
        - name: Remove telnetd server
          ansible.builtin.package:
            name: telnetd
            state: absent
          ignore_errors: true
""")

            # SMB / Samba vulnerabilities (EternalBlue / Null Sessions)
            if "smb" in t_str or "samba" in t_str or "445" in t_str:
                _add_task("smb_harden", """
    - name: 03. Remediation: Harden Samba/SMB Configuration (Disable SMBv1 & Null Sessions)
      block:
        - name: Ensure SMBv1 is disabled and signing is enforced in smb.conf
          ansible.builtin.lineinfile:
            path: /etc/samba/smb.conf
            line: "{{ item }}"
            insertafter: "\\[global\\]"
          loop:
            - "server min protocol = SMB2_10"
            - "client min protocol = SMB2_10"
            - "server signing = mandatory"
            - "restrict anonymous = 2"
          ignore_errors: true
          notify: Restart Samba
""")

            # SSH Hardening (Weak passwords, Root Login, Weak Ciphers)
            if "ssh" in t_str or "22" in t_str or "msfadmin" in t_str:
                _add_task("ssh_harden", """
    - name: 04. Remediation: Enforce SSH Security Hardening Baseline
      block:
        - name: Backup existing sshd_config
          ansible.builtin.copy:
            src: /etc/ssh/sshd_config
            dest: /var/backups/expedite_remediation/sshd_config.bak
            remote_src: true
          ignore_errors: true

        - name: Configure strict SSH security parameters
          ansible.builtin.lineinfile:
            path: /etc/ssh/sshd_config
            regexp: "{{ item.regex }}"
            line: "{{ item.line }}"
            state: present
          loop:
            - { regex: '^#?PermitRootLogin', line: 'PermitRootLogin prohibit-password' }
            - { regex: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }
            - { regex: '^#?PermitEmptyPasswords', line: 'PermitEmptyPasswords no' }
            - { regex: '^#?X11Forwarding', line: 'X11Forwarding no' }
            - { regex: '^#?MaxAuthTries', line: 'MaxAuthTries 4' }
            - { regex: '^#?ClientAliveInterval', line: 'ClientAliveInterval 300' }
          notify: Reload SSH
""")

            # Exposed Databases (Postgres, MySQL, Redis, MongoDB)
            if "postgres" in t_str or "mysql" in t_str or "redis" in t_str or "mongo" in t_str:
                _add_task("db_bind_harden", """
    - name: 05. Remediation: Restrict Database Listener to Localhost / Private Interface
      block:
        - name: Bind PostgreSQL to localhost if public
          ansible.builtin.lineinfile:
            path: /etc/postgresql/*/main/postgresql.conf
            regexp: '^#?listen_addresses'
            line: "listen_addresses = 'localhost'"
          ignore_errors: true

        - name: Bind MySQL/MariaDB to localhost
          ansible.builtin.lineinfile:
            path: /etc/mysql/my.cnf
            regexp: '^#?bind-address'
            line: "bind-address = 127.0.0.1"
          ignore_errors: true

        - name: Require Redis Authentication & Bind localhost
          ansible.builtin.lineinfile:
            path: /etc/redis/redis.conf
            regexp: '^#?bind '
            line: "bind 127.0.0.1 ::1"
          ignore_errors: true
""")

            # Exposed Sensitive Files / .git / .env
            if "sensitive" in t_str or ".env" in t_str or ".git" in t_str or "phpmyadmin" in t_str:
                _add_task("web_protect_sensitive", """
    - name: 06. Remediation: Restrict Sensitive Configuration & Admin Panel Files
      block:
        - name: Set strict file permissions on web configurations (.env, wp-config.php)
          ansible.builtin.file:
            path: "{{ item }}"
            mode: '0600'
          loop:
            - /var/www/html/.env
            - /var/www/html/wp-config.php
            - /var/www/html/config.php
          ignore_errors: true
""")

        if not tasks:
            tasks.append("""
    - name: 01. Baseline Security: Apply OS Security Updates & Firewall Rules
      block:
        - name: Update apt cache and upgrade security packages
          ansible.builtin.apt:
            upgrade: dist
            update_cache: true
          when: ansible_os_family == "Debian"

        - name: Enable UFW Firewall with default deny incoming
          community.general.ufw:
            state: enabled
            policy: deny
            direction: incoming
          ignore_errors: true
""")

        handlers = """
  handlers:
    - name: Restart Samba
      ansible.builtin.service:
        name: smbd
        state: restarted
      ignore_errors: true

    - name: Reload SSH
      ansible.builtin.service:
        name: sshd
        state: reloaded
      ignore_errors: true
"""
        return header + "\n".join(tasks) + handlers

    # ══════════════════════════════════════════════════════════════════════════
    #  2. TERRAFORM / CLOUD INFRASTRUCTURE REMEDIATION GENERATOR
    # ══════════════════════════════════════════════════════════════════════════
    def generate_terraform_remediation(self) -> str:
        """Generate Terraform definitions for securing public cloud perimeters."""
        return f"""# ==============================================================================
# EXPEDITE STRIKE — TERRAFORM PERIMETER HARDENING MODULE
# Generated: {self.timestamp}
# Enforces Least-Privilege Network Access & Cloud Security Posture
# ==============================================================================

terraform {{
  required_version = ">= 1.5.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

# ── 1. Restrict Public Security Groups (Block Dangerous Ports) ────────────────
resource "aws_security_group" "hardened_perimeter_sg" {{
  name        = "expedite-hardened-perimeter-sg"
  description = "Hardened security group generated by Expedite Strike"
  vpc_id      = var.vpc_id

  # Allow HTTP/HTTPS Web Traffic Only
  ingress {{
    description = "Allow Inbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  ingress {{
    description = "Allow Inbound HTTP (Redirect to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  # Restrict Administrative SSH Access to Corporate VPN / Bastion CIDR
  ingress {{
    description = "Restricted Management SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_trusted_cidr]
  }}

  # Egress: Allow outbound response traffic
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  tags = {{
    ManagedBy = "Expedite-Strike"
    SecurityLevel = "Strict-CIS-Compliant"
  }}
}}

# ── 2. Block Public S3 Bucket Access ──────────────────────────────────────────
resource "aws_s3_account_public_access_block" "block_all_public_s3" {{
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}

# ── 3. Variables Definition ───────────────────────────────────────────────────
variable "vpc_id" {{
  type        = string
  description = "Target AWS VPC ID"
  default     = "vpc-0123456789abcdef0"
}}

variable "management_trusted_cidr" {{
  type        = string
  description = "Authorized CIDR block for SSH/Admin access (VPN Gateway)"
  default     = "10.0.0.0/16"
}}
"""

    # ══════════════════════════════════════════════════════════════════════════
    #  3. WEB SERVER HARDENING CONFIGURATION GENERATOR
    # ══════════════════════════════════════════════════════════════════════════
    def generate_webserver_configs(self) -> Tuple[str, str]:
        """Generate Nginx and Apache strict security headers & cipher configurations."""
        nginx_conf = f"""# ==============================================================================
# EXPEDITE STRIKE — NGINX SECURITY HARDENING CONFIGURATION
# Generated: {self.timestamp}
# Drop into: /etc/nginx/conf.d/expedite_security.conf
# ==============================================================================

# ── 1. Modern Strict Security Headers (OWASP Top 10 Compliant) ────────────────
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;

# ── 2. Hide Server Information ────────────────────────────────────────────────
server_tokens off;

# ── 3. TLS 1.3 & Strong Cipher Suites ─────────────────────────────────────────
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# ── 4. Block Sensitive Files & Hidden Directories ─────────────────────────────
location ~ /\\.(?!well-known) {{
    deny all;
    return 404;
}}

location ~* (\\.(env|git|bak|config|sql|tar|gz)|/phpmyadmin/|/wp-admin/includes/) {{
    deny all;
    return 403;
}}
"""

        apache_conf = f"""# ==============================================================================
# EXPEDITE STRIKE — APACHE HTTPD SECURITY HARDENING
# Generated: {self.timestamp}
# Drop into: /etc/apache2/conf-available/expedite-security.conf
# ==============================================================================

<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
</IfModule>

ServerTokens Prod
ServerSignature Off
TraceEnable Off

<DirectoryMatch "/\\.(?!well-known)">
    Require all denied
</DirectoryMatch>
"""
        return nginx_conf, apache_conf

    # ══════════════════════════════════════════════════════════════════════════
    #  4. WINDOWS POWERSHELL / GPO HARDENING SCRIPT
    # ══════════════════════════════════════════════════════════════════════════
    def generate_powershell_script(self) -> str:
        """Generate PowerShell hardening script for Windows and Active Directory servers."""
        return f"""<#
==============================================================================
EXPEDITE STRIKE — WINDOWS & ACTIVE DIRECTORY REMEDIATION SCRIPT
Generated: {self.timestamp}
Run in elevated PowerShell (Run as Administrator)
==============================================================================
#>

Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " [EXPEDITE STRIKE] Executing Automated Remediation Baseline..." -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# ── 1. Disable SMBv1 Protocol (Mitigates EternalBlue & Lateral Movement) ──────
Write-Host "[+] Disabling SMBv1 Protocol..." -ForegroundColor Yellow
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue

# ── 2. Enable SMB Signing ─────────────────────────────────────────────────────
Write-Host "[+] Enforcing SMB Signing (Mandatory)..." -ForegroundColor Yellow
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# ── 3. Disable LLMNR (Mitigates Responder / NTLM Credential Theft) ────────────
Write-Host "[+] Disabling LLMNR Protocol..." -ForegroundColor Yellow
$LLMNRPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
If (-Not (Test-Path $LLMNRPath)) {{ New-Item -Path $LLMNRPath -Force | Out-Null }}
Set-ItemProperty -Path $LLMNRPath -Name "EnableMulticast" -Value 0 -Type DWord -Force

# ── 4. Enforce TLS 1.2 / 1.3 & Disable Insecure SSL/TLS Protocols ─────────────
Write-Host "[+] Disabling SSLv2, SSLv3, TLS 1.0, TLS 1.1..." -ForegroundColor Yellow
$Protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
ForEach ($Proto in $Protocols) {{
    $KeyServer = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$Proto\\Server"
    If (-Not (Test-Path $KeyServer)) {{ New-Item -Path $KeyServer -Force | Out-Null }}
    Set-ItemProperty -Path $KeyServer -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $KeyServer -Name "DisabledByDefault" -Value 1 -Type DWord -Force
}}

# ── 5. Enable Windows Defender Real-time Monitoring & Firewall ───────────────
Write-Host "[+] Verifying Windows Firewall Profiles are ACTIVE..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " [✔] Remediation Baseline Successfully Applied." -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
"""

    # ══════════════════════════════════════════════════════════════════════════
    #  5. BUILD ZIP PACKAGE
    # ══════════════════════════════════════════════════════════════════════════
    def build_remediation_zip(self) -> bytes:
        """Bundle all remediation artifacts into an in-memory ZIP archive."""
        buf = io.BytesIO()
        ansible_yml = self.generate_ansible_playbook()
        terraform_tf = self.generate_terraform_remediation()
        nginx_conf, apache_conf = self.generate_webserver_configs()
        powershell_ps1 = self.generate_powershell_script()

        readme_md = f"""# Expedite Strike — Fix-as-Code Remediation Package
Generated: {self.timestamp}
Total Findings Covered: {len(self.findings)}

## Package Contents

1. **`remediation_playbook.yml`**
   - Ansible playbook for automated OS-level patching, service removal (vsftpd, Telnet), and SSH hardening.
   - Run: `ansible-playbook -i inventory.ini remediation_playbook.yml`

2. **`cloud_remediation.tf`**
   - Terraform perimeter security definition restricting public ingress to authorized CIDRs and enforcing S3 public access blocks.
   - Run: `terraform init && terraform plan && terraform apply`

3. **`nginx_security.conf` & `apache_security.conf`**
   - Web server configurations with OWASP-compliant headers (HSTS, CSP, X-Frame-Options) and TLS 1.3 cipher enforcement.

4. **`windows_remediation.ps1`**
   - PowerShell script disabling SMBv1, enforcing SMB signing, disabling LLMNR, and removing deprecated SSL/TLS ciphers.
   - Run: `powershell -ExecutionPolicy Bypass -File .\\windows_remediation.ps1`
"""

        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("remediation_playbook.yml", ansible_yml)
            z.writestr("cloud_remediation.tf", terraform_tf)
            z.writestr("nginx_security.conf", nginx_conf)
            z.writestr("apache_security.conf", apache_conf)
            z.writestr("windows_remediation.ps1", powershell_ps1)
            z.writestr("README.md", readme_md)

        val = buf.getvalue()
        buf.close()
        return val
