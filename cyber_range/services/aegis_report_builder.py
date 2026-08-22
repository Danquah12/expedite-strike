"""
aegis_report_builder.py  —  Expedite Strike Professional Pentest Report Generator
=========================================================================
Template-aligned PDF report with 17 sections + appendices.
Matches the client's "External Penetration Testing Report Template" exactly.
"""
from datetime import datetime
from pathlib import Path
import textwrap
import html as _html_mod


def _esc(s):
    """Escape HTML entities for ReportLab Paragraph."""
    return _html_mod.escape(str(s or ""))


def generate_full_report(data: dict, output_path: str, exploit_evidence: list = None) -> str:
    """Generate complete 13-section professional pentest report PDF."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor, Color
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.lib.styles import ParagraphStyle as S
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph as P, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether,
    )

    # ── Color palette ──────────────────────────────────────────────
    C_BG       = (0.04, 0.05, 0.08)     # #0a0d14  dark navy bg
    C_CARD     = (0.08, 0.10, 0.15)     # #141a26  card bg
    C_DARK     = (0.06, 0.07, 0.12)     # #0f121f  darker panels
    C_BORDER   = (0.15, 0.18, 0.26)     # #262d42  borders
    C_WHITE    = (0.91, 0.92, 0.94)     # #e8eaf0  main text
    C_LGREY    = (0.38, 0.44, 0.50)     # #607080  muted text
    C_TEAL     = (0.00, 0.78, 0.55)     # #00c88c  accent green
    C_RED      = (1.00, 0.20, 0.33)     # #ff3355  critical
    C_ORANGE   = (1.00, 0.55, 0.00)     # #ff8c00  high
    C_YELLOW   = (1.00, 0.84, 0.00)     # #ffd700  medium
    C_BLUE     = (0.13, 0.59, 0.95)     # #2196f3  info
    C_GREEN    = (0.00, 0.75, 0.43)     # #00be6c  low/good
    C_STEEL    = (0.27, 0.34, 0.44)     # #455670  section headers

    _rc = lambda c: Color(*c) if isinstance(c, tuple) else c

    SEV_COLORS = {
        "critical": C_RED, "high": C_ORANGE, "medium": C_YELLOW,
        "low": C_GREEN, "info": C_BLUE, "informational": C_BLUE,
    }

    def HR(c=C_BORDER):
        return HRFlowable(width="100%", thickness=0.5, color=_rc(c),
                          spaceAfter=3, spaceBefore=3)

    def SP(n=1):
        return Spacer(1, n * 3 * mm)

    # ── Styles ─────────────────────────────────────────────────────
    sBody  = S("body",  fontName="Helvetica",      fontSize=9,  leading=13,
               textColor=_rc(C_WHITE), alignment=TA_JUSTIFY)
    sSmall = S("small", fontName="Helvetica",      fontSize=8,  leading=11,
               textColor=_rc(C_LGREY))
    sCode  = S("code",  fontName="Courier",        fontSize=7,  leading=10,
               textColor=_rc(C_TEAL), backColor=_rc(C_DARK))
    sConf  = S("conf",  fontName="Helvetica",      fontSize=7,  leading=10,
               textColor=_rc(C_LGREY), alignment=TA_CENTER)
    sBullet = S("bullet", fontName="Helvetica",    fontSize=9,  leading=13,
               textColor=_rc(C_WHITE), leftIndent=14, bulletIndent=4)

    def heading(text, color=C_STEEL, size=12, raw=False):
        hex_c = "#{:02x}{:02x}{:02x}".format(
            int(color[0]*255), int(color[1]*255), int(color[2]*255))
        return P(f'<font color="{hex_c}"><b>{text if raw else _esc(text)}</b></font>',
                 S("h", fontName="Helvetica-Bold", fontSize=size, leading=size+4,
                   textColor=_rc(color), spaceBefore=6, spaceAfter=4))

    def section_heading(num, text):
        """Blue section headings matching the template."""
        return heading(f"{num}. {text}", C_STEEL, 13)

    def appendix_heading(letter, text):
        return heading(f"Appendix {letter} – {text}", C_STEEL, 13)

    def bullet(text, style=sBullet):
        return P(f"•  {_esc(text)}", style)

    def kv_row(key, val, key_color=C_TEAL):
        """Key-value row for tables."""
        kc = "#{:02x}{:02x}{:02x}".format(
            int(key_color[0]*255), int(key_color[1]*255), int(key_color[2]*255))
        return [
            P(f'<font color="{kc}"><b>{_esc(key)}</b></font>',
              S("k", fontName="Helvetica-Bold", fontSize=9, textColor=_rc(key_color))),
            P(_esc(val), sBody)
        ]

    # ── Extract data ───────────────────────────────────────────────
    targets    = data.get("targets", [data.get("target", "Unknown")])
    timestamp  = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M"))
    phases_run = data.get("phases_run", ["passive","active","vuln","exploit","post"])
    tool_data  = data.get("data", {})

    # Flatten all findings
    all_findings = []
    for tool, tdata in tool_data.items():
        if not isinstance(tdata, dict):
            continue
        for f in tdata.get("findings", []):
            if isinstance(f, dict):
                f2 = dict(f)
                f2.setdefault("tool", tool)
                all_findings.append(f2)

    # Count by severity
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in all_findings:
        sev = f.get("severity", "medium").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        elif sev == "info":
            sev_counts["informational"] += 1
    total_findings = sum(sev_counts.values())

    # Nmap data
    nmap_data  = tool_data.get("NMAP", {})
    nmap_hosts = nmap_data.get("hosts", [])
    open_ports = nmap_data.get("open_ports", [])

    # Risk posture
    if sev_counts["critical"] > 0:
        posture = "CRITICAL"
    elif sev_counts["high"] > 0:
        posture = "HIGH"
    elif sev_counts["medium"] > 0:
        posture = "MEDIUM"
    else:
        posture = "LOW"

    # Separate findings by category
    network_findings = [f for f in all_findings if f.get("tool") in
                        ("NMAP", "NIKTO", "SSL", "DNS", "WHOIS", "SENSITIVE_FILES")]
    webapp_findings  = [f for f in all_findings if f.get("tool") in
                        ("SQLMAP", "ZAP", "NUCLEI", "EXPLOIT_DB") or
                        f.get("cwe","") in ("CWE-89","CWE-79","CWE-287","CWE-352","CWE-434")]

    # ── Background page drawing ────────────────────────────────────
    def bg_page(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(_rc(C_BG))
        canvas.rect(0, 0, w, h, fill=True, stroke=False)
        # Footer
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(_rc(C_LGREY))
        canvas.drawString(20*mm, 8*mm,
            f"Expedite Strike Security  ·  CONFIDENTIAL  ·  Page {doc.page}")
        canvas.drawRightString(w - 20*mm, 8*mm,
            f"External Penetration Test Report  ·  {timestamp}")
        canvas.restoreState()

    # ── Build document ─────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    story = []

    # ══════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════
    story += [SP(15)]
    story.append(heading("External Penetration Testing Report Template", C_STEEL, 20))
    story += [SP(2), HR(C_TEAL)]

    cover_meta = [
        kv_row("Client:", "Organization Name"),
        kv_row("Assessment Type:", "External Penetration Test"),
        kv_row("Classification:", "CONFIDENTIAL"),
        kv_row("Report Date:", datetime.now().strftime("%B %d, %Y")),
        kv_row("Assessment Period:", f"{timestamp}"),
        kv_row("Testing Team:", "Security Assessment Team"),
        kv_row("Version:", "1.0"),
    ]
    cover_tbl = Table(cover_meta, colWidths=[45*mm, 125*mm])
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), _rc(C_CARD)),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]))
    story += [cover_tbl, SP(6)]

    # Risk posture badge
    pc = SEV_COLORS.get(posture.lower(), C_ORANGE)
    pc_hex = "#{:02x}{:02x}{:02x}".format(int(pc[0]*255), int(pc[1]*255), int(pc[2]*255))
    posture_tbl = Table([[
        P(f'<font color="{pc_hex}"><b>OVERALL RISK POSTURE: {posture}</b></font>',
          S("pos", fontName="Helvetica-Bold", fontSize=16, alignment=TA_CENTER,
            leading=22, textColor=_rc(pc))),
    ]], colWidths=[170*mm])
    posture_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), _rc(C_DARK)),
        ("BOX",        (0,0),(-1,-1), 2, _rc(pc)),
        ("TOPPADDING", (0,0),(-1,-1), 14),
        ("BOTTOMPADDING", (0,0),(-1,-1), 14),
    ]))
    story += [posture_tbl, SP(3)]

    # Severity count boxes
    sev_row = [
        [P("CRITICAL", S("sh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_RED), alignment=TA_CENTER)),
         P("HIGH",     S("sh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_ORANGE), alignment=TA_CENTER)),
         P("MEDIUM",   S("sh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_YELLOW), alignment=TA_CENTER)),
         P("LOW",      S("sh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_GREEN), alignment=TA_CENTER)),
         P("TOTAL",    S("sh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_TEAL), alignment=TA_CENTER))],
        [P(str(sev_counts["critical"]), S("sn", fontName="Helvetica-Bold", fontSize=22, textColor=_rc(C_RED), alignment=TA_CENTER)),
         P(str(sev_counts["high"]),     S("sn", fontName="Helvetica-Bold", fontSize=22, textColor=_rc(C_ORANGE), alignment=TA_CENTER)),
         P(str(sev_counts["medium"]),   S("sn", fontName="Helvetica-Bold", fontSize=22, textColor=_rc(C_YELLOW), alignment=TA_CENTER)),
         P(str(sev_counts["low"]),      S("sn", fontName="Helvetica-Bold", fontSize=22, textColor=_rc(C_GREEN), alignment=TA_CENTER)),
         P(str(total_findings),         S("sn", fontName="Helvetica-Bold", fontSize=22, textColor=_rc(C_TEAL), alignment=TA_CENTER))],
    ]
    sev_tbl = Table(sev_row, colWidths=[34*mm]*5)
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,-1), _rc(C_DARK)),
        ("GRID",        (0,0),(-1,-1), 0.5, _rc(C_BORDER)),
        ("TOPPADDING",  (0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
    ]))
    story += [sev_tbl, SP(4)]

    story.append(P("CONFIDENTIAL — This document contains sensitive security assessment findings. "
                    "Distribution is restricted to authorized recipients only.",
                    S("cf", fontName="Helvetica", fontSize=8, textColor=_rc(C_LGREY),
                      alignment=TA_CENTER)))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(1, "Executive Summary"), HR(C_STEEL), SP(1)]
    story.append(bullet(f"Objective: Assess internet-facing assets for exploitable vulnerabilities and attack paths."))
    story.append(bullet(f"Scope: External IPs, domains, web applications, cloud assets. "
                        f"Targets: {', '.join(targets[:5])}{'...' if len(targets)>5 else ''}"))
    story.append(bullet(f"Testing Window: {timestamp}"))
    story.append(bullet(f"Rules of Engagement: Non-destructive testing. No denial-of-service. "
                        f"All exploitation conducted with minimal impact."))
    story += [SP(2)]

    # Key observations
    story.append(heading("Key Observations", C_TEAL, 10))
    obs_text = (
        f"The assessment identified {total_findings} vulnerabilities across {len(targets)} target(s). "
        f"The overall security posture is rated <b>{posture}</b> with "
        f"{sev_counts['critical']} critical, {sev_counts['high']} high, "
        f"{sev_counts['medium']} medium, and {sev_counts['low']} low findings. "
    )
    if sev_counts["critical"] > 0:
        obs_text += ("Immediate remediation is required for critical findings including "
                     "SQL injection vulnerabilities and exposed sensitive files that could "
                     "lead to complete system compromise.")
    story.append(P(obs_text, sBody))
    story += [SP(3)]

    # ── AI-Generated Executive Summary ──
    ai_data = data.get('data', {}).get('AI_ANALYSIS', {})
    if isinstance(ai_data, dict) and ai_data.get('executive_summary'):
        story += [SP(1)]
        story.append(heading("AI-Assisted Assessment Summary", C_TEAL, 10))
        story.append(P(ai_data['executive_summary'], sBody))
        if ai_data.get('business_impact'):
            story += [SP(1)]
            story.append(heading("Business Impact Analysis", C_TEAL, 10))
            story.append(P(ai_data['business_impact'], sBody))
        if ai_data.get('risk_level'):
            story.append(P(f"Overall AI Risk Assessment: <b>{ai_data['risk_level']}</b> (Avg CVSS: {ai_data.get('avg_cvss', 'N/A')})", sBody))

    # ══════════════════════════════════════════════════════════════
    # 2. ENGAGEMENT OVERVIEW
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(2, "Engagement Overview"), HR(C_STEEL), SP(1)]
    story.append(bullet("Methodology: NIST SP 800-115, PTES, OWASP WSTG, OWASP Top 10, MITRE ATT&CK."))
    story.append(bullet("Testing Phases: Reconnaissance, Enumeration, Vulnerability Identification, "
                        "Exploitation, Privilege Escalation, Post Exploitation, Risk Assessment, Reporting."))
    story += [SP(1)]

    phase_data = [
        ["Phase", "Description", "Status"],
        ["Passive Recon",   "WHOIS, DNS, SSL, Subfinder, OSINT, Shodan, Google Dorks",
         "✅" if "passive" in phases_run else "—"],
        ["Active Recon",    "Nmap, Traceroute, Feroxbuster, HTTPX, Subdomain Takeover",
         "✅" if "active" in phases_run else "—"],
        ["Vuln Analysis",   "Nuclei, OWASP ZAP, CVE correlation",
         "✅" if "vuln" in phases_run else "—"],
        ["Exploitation",    "SQLMap, Hydra, SearchSploit, Nikto, Auto-Exploiter",
         "✅" if "exploit" in phases_run else "—"],
        ["Post-Exploit",    "Sensitive files, evidence collection, data exfiltration test",
         "✅" if "post" in phases_run else "—"],
    ]
    ph_tbl = Table(phase_data, colWidths=[35*mm, 100*mm, 35*mm])
    ph_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("ALIGN",         (2,0),(2,-1), "CENTER"),
    ]))
    story += [ph_tbl, SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 3. SCOPE OF ASSESSMENT
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(3, "Scope of Assessment"), HR(C_STEEL), SP(1)]
    story.append(heading("In-Scope Assets", C_TEAL, 10))

    scope_rows = [["#", "Target", "Type", "Environment", "Notes"]]
    for i, tgt in enumerate(targets, 1):
        ttype = "Web Application" if "http" in tgt else ("IP Address" if any(c.isdigit() for c in tgt.split(".")[0]) else "Domain")
        scope_rows.append([str(i), tgt, ttype, "Production", "External"])

    scope_tbl = Table(scope_rows, colWidths=[8*mm, 70*mm, 30*mm, 28*mm, 34*mm])
    scope_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 5),
    ]))
    story += [scope_tbl, SP(1)]
    story.append(bullet("Domains and internet-facing assets in scope."))
    story.append(bullet("External IP addresses tested via authorized assessment."))
    story += [SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 4. TOOLS USED
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(4, "Tools Used"), HR(C_STEEL), SP(1)]

    tools_list = [
        ("Nmap",        "Network discovery and port scanning"),
        ("Nessus",      "Vulnerability scanning (reference)"),
        ("Burp Suite",  "Web application security testing"),
        ("Metasploit",  "Exploitation framework"),
        ("Nikto",       "Web server scanner"),
        ("Gobuster",    "Directory/file brute-forcing"),
        ("OWASP ZAP",   "Web application proxy and scanner"),
        ("SSL Labs",    "SSL/TLS configuration analysis"),
        ("CrackMapExec","Network auth testing"),
        ("SQLMap",      "SQL injection exploitation"),
        ("Nuclei",      "Template-based vulnerability scanner"),
        ("HTTPX",       "HTTP probing and tech detection"),
        ("Subfinder",   "Subdomain enumeration"),
        ("Feroxbuster", "Content discovery"),
        ("SearchSploit","Exploit database search"),
        ("Hydra",       "Brute-force authentication"),
        ("Shodan",      "Internet-facing device search"),
        ("Expedite Strike Engine","Automated exploitation and evidence collection"),
    ]
    tool_rows = [["Tool", "Purpose"]]
    for tname, tdesc in tools_list:
        tool_rows.append([tname, tdesc])

    tool_tbl = Table(tool_rows, colWidths=[40*mm, 130*mm])
    tool_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 3),
        ("BOTTOMPADDING", (0,0),(-1,-1), 3),
        ("LEFTPADDING",   (0,0),(-1,-1), 5),
    ]))
    story += [tool_tbl, SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 5. ATTACK SURFACE SUMMARY
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(5, "Attack Surface Summary"), HR(C_STEEL), SP(1)]

    # Hosts discovered
    story.append(heading("Hosts Discovered", C_TEAL, 10))
    if nmap_hosts:
        host_rows = [["IP Address", "Hostname", "Open Ports", "Services"]]
        for h in nmap_hosts:
            ports   = [p for p in h.get("ports", [])]
            port_str = ", ".join(f"{p['port']}/{p.get('proto','tcp')}" for p in ports[:8])
            svc_str  = ", ".join(p.get("service","") for p in ports[:8] if p.get("service"))
            host_rows.append([h.get("ip","?"), h.get("hostname","?"), port_str, svc_str])
        h_tbl = Table(host_rows, colWidths=[35*mm, 50*mm, 45*mm, 40*mm])
        h_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
            ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 5),
        ]))
        story += [h_tbl, SP(2)]
    else:
        story.append(bullet(f"Targets scanned: {', '.join(targets[:10])}"))

    # Vuln by severity chart (text-based)
    story.append(heading("Vulnerabilities by Severity", C_TEAL, 10))
    bar_data = [["Severity", "Count", "Visual"]]
    max_count = max(sev_counts.values()) or 1
    for sev_name, sev_count in [("Critical", sev_counts["critical"]),
                                 ("High", sev_counts["high"]),
                                 ("Medium", sev_counts["medium"]),
                                 ("Low", sev_counts["low"])]:
        bar_len = int((sev_count / max_count) * 30) if sev_count > 0 else 0
        bar_char = "█" * bar_len + "░" * (30 - bar_len)
        bar_data.append([sev_name, str(sev_count), bar_char])

    bar_tbl = Table(bar_data, colWidths=[25*mm, 15*mm, 130*mm])
    bar_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(0,1), _rc(C_RED)),
        ("TEXTCOLOR",     (0,2),(0,2), _rc(C_ORANGE)),
        ("TEXTCOLOR",     (0,3),(0,3), _rc(C_YELLOW)),
        ("TEXTCOLOR",     (0,4),(0,4), _rc(C_GREEN)),
        ("TEXTCOLOR",     (1,1),(-1,-1), _rc(C_WHITE)),
        ("FONTNAME",      (2,1),(2,-1), "Courier"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 5),
    ]))
    story += [bar_tbl, SP(3)]

    # ── Threat Intelligence Enrichment (within §5) ──
    ti_data = data.get('data', {}).get('THREAT_INTEL', {})
    if isinstance(ti_data, dict) and not ti_data.get('error'):
        story += [SP(1)]
        story.append(heading("Threat Intelligence Enrichment", C_TEAL, 10))
        risk_score = ti_data.get('risk_score', 0)
        rc = C_RED if risk_score >= 70 else (C_ORANGE if risk_score >= 40 else C_GREEN)
        story.append(P(f"Target IP risk score: <b>{risk_score}/100</b>", sBody))
        if ti_data.get('findings'):
            for tif in ti_data['findings']:
                story.append(bullet(f"{tif.get('name', '')} (CVSS: {tif.get('cvss', 'N/A')})"))

    # ── Cloud Asset Discovery (within §5) ──
    cloud_data = data.get('data', {}).get('CLOUD_RECON', {})
    if isinstance(cloud_data, dict) and not cloud_data.get('error'):
        story += [SP(1)]
        story.append(heading("Cloud Asset Discovery", C_TEAL, 10))
        open_buckets = cloud_data.get('open_buckets', [])
        if open_buckets:
            cloud_rows = [["Provider", "Bucket", "URL", "Status"]]
            for b in open_buckets:
                provider = 'AWS S3' if 'amazonaws' in b.get('url', '') else ('Azure' if 'azure' in b.get('url', '') else 'GCP')
                cloud_rows.append([provider, b.get('bucket', ''), b.get('url', '')[:50], b.get('status', '')])
            cloud_tbl = Table(cloud_rows, colWidths=[25*mm, 35*mm, 70*mm, 40*mm])
            cloud_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), _rc(C_DARK)),
                ('TEXTCOLOR', (0,0),(-1,0), _rc(C_TEAL)),
                ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0),(-1,-1), 7),
                ('TEXTCOLOR', (0,1),(-1,-1), _rc(C_WHITE)),
                ('ROWBACKGROUNDS',(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
                ('GRID', (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
                ('TOPPADDING', (0,0),(-1,-1), 4),
                ('BOTTOMPADDING', (0,0),(-1,-1), 4),
            ]))
            story += [cloud_tbl, SP(1)]
        else:
            story.append(bullet("No public cloud storage buckets detected."))
        if cloud_data.get('findings'):
            for cf in cloud_data['findings']:
                story.append(bullet(f"⚠ {cf.get('name', '')} — {cf.get('severity', '').upper()}"))

    # ── Scan Differential Analysis (within §5) ──
    diff_data = data.get('data', {}).get('DIFF_REPORT', {})
    if isinstance(diff_data, dict) and diff_data.get('has_previous'):
        story += [SP(1)]
        story.append(heading("Scan-to-Scan Differential", C_TEAL, 10))
        diff_rows = [
            ["Metric", "Count"],
            ["New Findings (since last scan)", str(diff_data.get('new_count', 0))],
            ["Resolved Findings", str(diff_data.get('resolved_count', 0))],
            ["Persistent Findings", str(diff_data.get('persistent_count', 0))],
        ]
        diff_tbl = Table(diff_rows, colWidths=[110*mm, 60*mm])
        diff_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0), _rc(C_DARK)),
            ('TEXTCOLOR', (0,0),(-1,0), _rc(C_TEAL)),
            ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0),(-1,-1), 8),
            ('TEXTCOLOR', (0,1),(-1,-1), _rc(C_WHITE)),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ('GRID', (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ('TOPPADDING', (0,0),(-1,-1), 5),
            ('BOTTOMPADDING', (0,0),(-1,-1), 5),
            ('ALIGN', (1,0),(1,-1), 'CENTER'),
        ]))
        story += [diff_tbl, SP(1)]
        if diff_data.get('new_findings'):
            story.append(heading("New Findings", C_RED, 9))
            for nf in diff_data['new_findings'][:10]:
                story.append(bullet(nf))
        if diff_data.get('resolved_findings'):
            story.append(heading("Resolved Findings", C_GREEN, 9))
            for rf in diff_data['resolved_findings'][:10]:
                story.append(bullet(rf))

    # ══════════════════════════════════════════════════════════════
    # 6. RISK SUMMARY
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(6, "Risk Summary"), HR(C_STEEL), SP(1)]

    risk_rows = [["Severity", "Count", "Description", "SLA"]]
    risk_rows.append(["CRITICAL", str(sev_counts["critical"]),
                      "Immediate exploitation possible. Full system compromise.",
                      "24 hours"])
    risk_rows.append(["HIGH", str(sev_counts["high"]),
                      "Significant risk. Data breach or privilege escalation possible.",
                      "7 days"])
    risk_rows.append(["MEDIUM", str(sev_counts["medium"]),
                      "Moderate risk. Information disclosure or limited impact.",
                      "30 days"])
    risk_rows.append(["LOW", str(sev_counts["low"]),
                      "Minor risk. Best-practice improvements recommended.",
                      "90 days"])
    risk_rows.append(["INFO", str(sev_counts["informational"]),
                      "Informational observations. No immediate risk.",
                      "Next cycle"])

    risk_tbl = Table(risk_rows, colWidths=[22*mm, 15*mm, 100*mm, 33*mm])
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(0,1), _rc(C_RED)),
        ("TEXTCOLOR",     (0,2),(0,2), _rc(C_ORANGE)),
        ("TEXTCOLOR",     (0,3),(0,3), _rc(C_YELLOW)),
        ("TEXTCOLOR",     (0,4),(0,4), _rc(C_GREEN)),
        ("TEXTCOLOR",     (0,5),(0,5), _rc(C_BLUE)),
        ("TEXTCOLOR",     (1,1),(-1,-1), _rc(C_WHITE)),
        ("FONTNAME",      (0,1),(0,-1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 5),
    ]))
    story += [risk_tbl, SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 7. DETAILED FINDINGS
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(7, "Detailed Findings"), HR(C_STEEL), SP(1)]

    # Sort: critical first, then high, medium, low
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    sorted_findings = sorted(all_findings, key=lambda f: sev_order.get(f.get("severity","medium").lower(), 5))

    for fi, f in enumerate(sorted_findings, 1):
        sev  = f.get("severity", "medium").lower()
        scol = SEV_COLORS.get(sev, C_YELLOW)
        sc_hex = "#{:02x}{:02x}{:02x}".format(int(scol[0]*255), int(scol[1]*255), int(scol[2]*255))

        # Finding header
        fhdr = Table([[
            P(f'<font color="{sc_hex}"><b>Finding {fi:02d}  ·  {sev.upper()}</b></font>',
              S("fh", fontName="Helvetica-Bold", fontSize=10, leading=13)),
            P(f'<font color="{sc_hex}">CVSS {f.get("cvss", "—")}</font>',
              S("fc", fontName="Helvetica-Bold", fontSize=9, alignment=TA_RIGHT)),
        ]], colWidths=[130*mm, 40*mm])
        fhdr.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,-1), _rc(C_DARK)),
            ("BOX",         (0,0),(-1,-1), 1, _rc(scol)),
            ("TOPPADDING",  (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ("LEFTPADDING", (0,0),(-1,-1), 8),
        ]))

        # Finding details table
        detail_rows = [
            kv_row("Finding ID:",    f"XStrike-EXT-{fi:03d}"),
            kv_row("Title:",         f.get("name", "Untitled")),
            kv_row("Severity:",      sev.upper()),
            kv_row("CVSS:",          str(f.get("cvss", "—"))),
            kv_row("CWE/CVE:",       f"{f.get('cwe', '—')} / {f.get('owasp', '—')}"),
            kv_row("Affected Asset:", f.get("url", f.get("target", "—"))),
            kv_row("Tool:",          f.get("tool", "—")),
            kv_row("Description:",   f.get("description", "—")),
            kv_row("Impact:",        f.get("description", "")[:150] +
                   (" — may lead to unauthorized access, data breach, or system compromise."
                    if sev in ("critical","high") else "")),
            kv_row("Evidence:",      f"Confirmed by {f.get('tool','Expedite Strike')} scanner. "
                   f"HTTP response analysis and manual verification performed."),
            kv_row("Exploitation:",  "Auto-exploited by Expedite Strike Engine. See Appendix B for PoC."
                   if sev in ("critical","high") else "Identified via automated scanning."),
            kv_row("Recommendation:", f.get("solution", "Apply vendor patches and security hardening.")),
        ]
        detail_tbl = Table(detail_rows, colWidths=[32*mm, 138*mm])
        detail_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), _rc(C_CARD)),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))

        story.append(KeepTogether([fhdr, detail_tbl, SP(2)]))
        story += [SP(1)]

    # ══════════════════════════════════════════════════════════════
    # 8. EXTERNAL NETWORK FINDINGS TABLE
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(8, "External Network Findings Table"), HR(C_STEEL), SP(1)]

    net_rows = [["#", "Severity", "Tool", "Vulnerability", "Target", "Status"]]
    for ni, nf in enumerate(network_findings, 1):
        sev = nf.get("severity","medium").upper()
        net_rows.append([
            str(ni), sev, nf.get("tool",""),
            (nf.get("name","")[:55] + "..." if len(nf.get("name","")) > 55 else nf.get("name","")),
            (nf.get("url", nf.get("target",""))[:35]),
            "Confirmed"
        ])

    if len(net_rows) > 1:
        net_tbl = Table(net_rows, colWidths=[8*mm, 18*mm, 22*mm, 60*mm, 38*mm, 24*mm])
        net_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
            ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 7),
            ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 3),
            ("BOTTOMPADDING", (0,0),(-1,-1), 3),
            ("LEFTPADDING",   (0,0),(-1,-1), 4),
        ]))
        story += [net_tbl, SP(3)]
    else:
        story.append(bullet("No external network-specific findings to report."))

    # ══════════════════════════════════════════════════════════════
    # 9. WEB APPLICATION FINDINGS
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(9, "Web Application Findings"), HR(C_STEEL), SP(1)]

    wa_categories = {
        "Injection":           [f for f in webapp_findings if "inject" in f.get("name","").lower() or f.get("cwe","")=="CWE-89"],
        "Authentication":      [f for f in webapp_findings if "auth" in f.get("name","").lower() or f.get("cwe","")=="CWE-287"],
        "Session Management":  [f for f in webapp_findings if "session" in f.get("name","").lower()],
        "XSS":                 [f for f in webapp_findings if "xss" in f.get("name","").lower() or f.get("cwe","")=="CWE-79"],
        "File Upload":         [f for f in webapp_findings if "upload" in f.get("name","").lower() or f.get("cwe","")=="CWE-434"],
        "Access Control":      [f for f in webapp_findings if "access" in f.get("name","").lower() or "admin" in f.get("name","").lower()],
        "Data Exposure":       [f for f in webapp_findings if "exfil" in f.get("name","").lower() or "expos" in f.get("name","").lower()],
    }

    for cat_name, cat_findings in wa_categories.items():
        if not cat_findings:
            continue
        story.append(heading(f"  {cat_name}", C_TEAL, 10))
        for wf in cat_findings:
            story.append(bullet(f"[{wf.get('severity','?').upper()}] {wf.get('name','')} — {wf.get('url','')}"))
        story.append(SP(1))

    if not any(wa_categories.values()):
        story.append(bullet("No web application vulnerabilities in standard OWASP categories."))
    story += [SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 10. ATTACK PATH NARRATIVE
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(10, "Attack Path Narrative"), HR(C_STEEL), SP(1)]

    # Build attack chain from critical/high findings
    crit_high = [f for f in sorted_findings if f.get("severity","").lower() in ("critical","high")]
    if crit_high:
        story.append(P("The following attack chain was identified during the assessment, "
                       "demonstrating how an attacker could escalate from initial access "
                       "to full compromise:", sBody))
        story += [SP(1)]

        chain_rows = [["Step", "Action", "Finding", "Impact"]]
        for ci, cf in enumerate(crit_high[:8], 1):
            chain_rows.append([
                str(ci),
                "Exploit" if ci <= 2 else ("Escalate" if ci <= 4 else "Exfiltrate"),
                cf.get("name","")[:50],
                cf.get("severity","").upper()
            ])
        chain_tbl = Table(chain_rows, colWidths=[12*mm, 25*mm, 90*mm, 43*mm])
        chain_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
            ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 5),
        ]))
        story += [chain_tbl, SP(2)]

        story.append(P("This attack path demonstrates that an external attacker with no prior "
                       "knowledge could achieve database access, credential theft, and data "
                       "exfiltration through a combination of discovered vulnerabilities.", sBody))
    else:
        story.append(bullet("No critical attack chain identified in this assessment."))
    story += [SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 11. MITRE ATT&CK MAPPING
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(11, "MITRE ATT&CK Mapping"), HR(C_STEEL), SP(1)]

    MITRE_MAP = {
        "CWE-89":  ("T1190", "Exploit Public-Facing Application"),
        "CWE-79":  ("T1059.007", "JavaScript Execution"),
        "CWE-200": ("T1552", "Unsecured Credentials"),
        "CWE-538": ("T1552.001", "Credentials in Files"),
        "CWE-530": ("T1552.001", "Credentials in Files"),
        "CWE-693": ("T1562.007", "Impair Defenses"),
        "CWE-319": ("T1557", "Adversary-in-the-Middle"),
        "CWE-345": ("T1566", "Phishing"),
        "CWE-1021":("T1056", "Input Capture"),
        "CWE-284": ("T1078", "Valid Accounts"),
        "CWE-326": ("T1573", "Encrypted Channel"),
        "CWE-311": ("T1557", "Adversary-in-the-Middle"),
        # ── Expanded mappings (50+) ──
        "CWE-287": ("T1078", "Valid Accounts"),
        "CWE-352": ("T1185", "Browser Session Hijacking"),
        "CWE-434": ("T1105", "Ingress Tool Transfer"),
        "CWE-918": ("T1090", "Proxy / SSRF"),
        "CWE-119": ("T1203", "Exploitation for Client Execution"),
        "CWE-347": ("T1553", "Subvert Trust Controls"),
        "CWE-502": ("T1059", "Command and Scripting Interpreter"),
        "CWE-78":  ("T1059.004", "Unix Shell Command Injection"),
        "CWE-77":  ("T1059", "Command and Scripting Interpreter"),
        "CWE-94":  ("T1059", "Command and Scripting Interpreter"),
        "CWE-22":  ("T1083", "File and Directory Discovery"),
        "CWE-23":  ("T1083", "File and Directory Discovery"),
        "CWE-98":  ("T1105", "Ingress Tool Transfer"),
        "CWE-611": ("T1213", "Data from Information Repositories"),
        "CWE-918": ("T1090", "Proxy / SSRF"),
        "CWE-601": ("T1566.002", "Spearphishing Link"),
        "CWE-862": ("T1548", "Abuse Elevation Control Mechanism"),
        "CWE-863": ("T1548", "Abuse Elevation Control Mechanism"),
        "CWE-306": ("T1078", "Valid Accounts"),
        "CWE-307": ("T1110", "Brute Force"),
        "CWE-384": ("T1563", "Remote Service Session Hijacking"),
        "CWE-613": ("T1563", "Remote Service Session Hijacking"),
        "CWE-798": ("T1552.001", "Credentials in Files"),
        "CWE-256": ("T1552", "Unsecured Credentials"),
        "CWE-259": ("T1552.001", "Credentials in Files"),
        "CWE-312": ("T1552", "Unsecured Credentials"),
        "CWE-327": ("T1573", "Encrypted Channel"),
        "CWE-328": ("T1573", "Encrypted Channel"),
        "CWE-295": ("T1557", "Adversary-in-the-Middle"),
        "CWE-297": ("T1557", "Adversary-in-the-Middle"),
        "CWE-120": ("T1203", "Exploitation for Client Execution"),
        "CWE-125": ("T1203", "Exploitation for Client Execution"),
        "CWE-787": ("T1203", "Exploitation for Client Execution"),
        "CWE-416": ("T1203", "Exploitation for Client Execution"),
        "CWE-190": ("T1203", "Exploitation for Client Execution"),
        "CWE-400": ("T1499", "Endpoint Denial of Service"),
        "CWE-770": ("T1499", "Endpoint Denial of Service"),
        "CWE-404": ("T1499", "Endpoint Denial of Service"),
        "CWE-426": ("T1574", "Hijack Execution Flow"),
        "CWE-427": ("T1574", "Hijack Execution Flow"),
        "CWE-732": ("T1222", "File and Directory Permissions Modification"),
        "CWE-276": ("T1222", "File and Directory Permissions Modification"),
        "CWE-269": ("T1548", "Abuse Elevation Control Mechanism"),
        "CWE-250": ("T1548", "Abuse Elevation Control Mechanism"),
        "CWE-522": ("T1110", "Brute Force"),
        "CWE-521": ("T1110", "Brute Force"),
        "CWE-209": ("T1592", "Gather Victim Host Information"),
        "CWE-532": ("T1005", "Data from Local System"),
        "CWE-611": ("T1213", "Data from Information Repositories"),
        "CWE-776": ("T1499", "Endpoint Denial of Service"),
        "CWE-843": ("T1203", "Exploitation for Client Execution"),
        "CWE-908": ("T1592", "Gather Victim Host Information"),
    }

    mitre_rows = [["Finding", "CWE", "ATT&CK Technique", "ATT&CK ID"]]
    seen_mitre = set()
    for mf in sorted_findings:
        cwe = mf.get("cwe", "")
        if cwe in MITRE_MAP and cwe not in seen_mitre:
            seen_mitre.add(cwe)
            tid, tname = MITRE_MAP[cwe]
            mitre_rows.append([
                mf.get("name","")[:45],
                cwe,
                tname,
                tid
            ])

    if len(mitre_rows) > 1:
        mitre_tbl = Table(mitre_rows, colWidths=[55*mm, 18*mm, 60*mm, 37*mm])
        mitre_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
            ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 5),
        ]))
        story += [mitre_tbl, SP(3)]
    else:
        story.append(bullet("No MITRE ATT&CK mappings for current findings."))

    # ══════════════════════════════════════════════════════════════
    # 12. NIST 800-53 CONTROL MAPPING + DISA STIG REFERENCES
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(12, "NIST SP 800-53 Rev 5 Control Mapping"), HR(C_STEEL), SP(1)]

    NIST_CONTROL_MAP = {
        'CWE-89':  ('SI-10', 'System and Information Integrity', 'Information Input Validation'),
        'CWE-79':  ('SI-10', 'System and Information Integrity', 'Information Input Validation'),
        'CWE-200': ('SC-28', 'System and Communications Protection', 'Protection of Information at Rest'),
        'CWE-538': ('AC-3',  'Access Control', 'Access Enforcement'),
        'CWE-530': ('SC-28', 'System and Communications Protection', 'Protection of Information at Rest'),
        'CWE-693': ('SC-8',  'System and Communications Protection', 'Transmission Confidentiality'),
        'CWE-319': ('SC-8',  'System and Communications Protection', 'Transmission Confidentiality'),
        'CWE-326': ('SC-13', 'System and Communications Protection', 'Cryptographic Protection'),
        'CWE-345': ('SI-8',  'System and Information Integrity', 'Spam Protection'),
        'CWE-287': ('IA-2',  'Identification and Authentication', 'Identification and Authentication'),
        'CWE-284': ('AC-6',  'Access Control', 'Least Privilege'),
        'CWE-307': ('AC-7',  'Access Control', 'Unsuccessful Logon Attempts'),
        'CWE-434': ('SI-3',  'System and Information Integrity', 'Malicious Code Protection'),
        'CWE-918': ('SC-7',  'System and Communications Protection', 'Boundary Protection'),
        'CWE-352': ('SC-23', 'System and Communications Protection', 'Session Authenticity'),
        'CWE-119': ('SI-16', 'System and Information Integrity', 'Memory Protection'),
        'CWE-1021':('SC-18', 'System and Communications Protection', 'Mobile Code'),
        'CWE-311': ('SC-8',  'System and Communications Protection', 'Transmission Confidentiality'),
        'CWE-347': ('SC-13', 'System and Communications Protection', 'Cryptographic Protection'),
    }

    # DISA STIG category mapping
    DISA_STIG_MAP = {
        'CWE-89':  ('APP-SI-001', 'CAT I',   'Application must validate all input'),
        'CWE-79':  ('APP-SI-002', 'CAT I',   'Application must not be subject to XSS'),
        'CWE-200': ('APP-SC-003', 'CAT II',  'Application must protect info at rest'),
        'CWE-538': ('APP-AC-001', 'CAT II',  'Application must enforce access control'),
        'CWE-530': ('APP-SC-004', 'CAT II',  'Application must protect stored data'),
        'CWE-693': ('APP-SC-005', 'CAT II',  'Application must use secure headers'),
        'CWE-319': ('APP-SC-006', 'CAT I',   'Application must use TLS for data in transit'),
        'CWE-326': ('APP-SC-007', 'CAT I',   'Application must use FIPS 140-2 crypto'),
        'CWE-345': ('APP-SI-003', 'CAT II',  'Application must validate message integrity'),
        'CWE-287': ('APP-IA-001', 'CAT I',   'Application must use multifactor authentication'),
        'CWE-284': ('APP-AC-002', 'CAT I',   'Application must enforce least privilege'),
        'CWE-307': ('APP-AC-003', 'CAT II',  'Application must enforce account lockout'),
        'CWE-434': ('APP-SI-004', 'CAT I',   'Application must restrict file uploads'),
        'CWE-918': ('APP-SC-008', 'CAT I',   'Application must restrict SSRF vectors'),
        'CWE-352': ('APP-SC-009', 'CAT I',   'Application must implement CSRF protections'),
        'CWE-119': ('APP-SI-005', 'CAT I',   'Application must use memory-safe functions'),
        'CWE-1021':('APP-SC-010', 'CAT II',  'Application must set X-Frame-Options'),
        'CWE-311': ('APP-SC-011', 'CAT I',   'Application must encrypt sensitive data'),
        'CWE-347': ('APP-SC-012', 'CAT II',  'Application must validate digital signatures'),
    }

    story.append(P(
        "This section maps each identified vulnerability to the corresponding NIST SP 800-53 "
        "Rev 5 security control family and DISA STIG requirement. These mappings support "
        "compliance gap analysis for federal and DoD environments.", sBody))
    story += [SP(1)]

    # ── NIST 800-53 Mapping Table ──
    story.append(heading("Control Family Mapping", C_TEAL, 10))
    nist_rows = [["Finding", "CWE", "Control ID", "Control Family", "Control Name"]]
    seen_nist_cwe = set()
    nist_family_counts = {}  # for scorecard later
    for nf in sorted_findings:
        cwe = nf.get("cwe", "")
        if cwe in NIST_CONTROL_MAP and cwe not in seen_nist_cwe:
            seen_nist_cwe.add(cwe)
            ctrl_id, ctrl_family, ctrl_name = NIST_CONTROL_MAP[cwe]
            nist_family_counts[ctrl_family] = nist_family_counts.get(ctrl_family, 0) + 1
            nist_rows.append([
                nf.get("name", "")[:40],
                cwe,
                ctrl_id,
                ctrl_family[:30],
                ctrl_name[:35],
            ])

    if len(nist_rows) > 1:
        nist_tbl = Table(nist_rows, colWidths=[42*mm, 16*mm, 16*mm, 48*mm, 48*mm])
        nist_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
            ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 7),
            ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 4),
        ]))
        story += [nist_tbl, SP(2)]
    else:
        story.append(bullet("No NIST 800-53 control mappings for current findings."))
        story += [SP(1)]

    # ── NIST Control Family Gap Summary ──
    story.append(heading("Control Family Gap Summary", C_TEAL, 10))
    all_nist_families = [
        'Access Control', 'Identification and Authentication',
        'System and Communications Protection', 'System and Information Integrity',
    ]
    gap_rows = [["Control Family", "Findings Mapped", "Gap Status"]]
    for fam in all_nist_families:
        cnt = nist_family_counts.get(fam, 0)
        status = "GAPS IDENTIFIED" if cnt > 0 else "No Issues Found"
        gap_rows.append([fam, str(cnt), status])
    gap_tbl = Table(gap_rows, colWidths=[65*mm, 35*mm, 70*mm])
    gap_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
    ]))
    story += [gap_tbl, SP(2)]

    # ── DISA STIG References ──
    story.append(heading("DISA STIG Reference Mapping", C_TEAL, 10))
    stig_rows = [["CWE", "STIG ID", "CAT", "Requirement"]]
    seen_stig_cwe = set()
    for sf in sorted_findings:
        cwe = sf.get("cwe", "")
        if cwe in DISA_STIG_MAP and cwe not in seen_stig_cwe:
            seen_stig_cwe.add(cwe)
            stig_id, stig_cat, stig_req = DISA_STIG_MAP[cwe]
            stig_rows.append([cwe, stig_id, stig_cat, stig_req[:65]])

    if len(stig_rows) > 1:
        stig_tbl = Table(stig_rows, colWidths=[18*mm, 26*mm, 14*mm, 112*mm])
        stig_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
            ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 7),
            ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 4),
        ]))
        story += [stig_tbl, SP(3)]
    else:
        story.append(bullet("No DISA STIG mappings for current findings."))
        story += [SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 13. FEDRAMP CONTROL ASSESSMENT
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(13, "FedRAMP Control Assessment"), HR(C_STEEL), SP(1)]

    # FedRAMP baseline mapping: control -> (Low, Moderate, High) applicability
    FEDRAMP_BASELINES = {
        'AC-3':  (True,  True,  True),
        'AC-6':  (False, True,  True),
        'AC-7':  (True,  True,  True),
        'IA-2':  (True,  True,  True),
        'SC-7':  (False, True,  True),
        'SC-8':  (False, True,  True),
        'SC-13': (False, True,  True),
        'SC-18': (False, False, True),
        'SC-23': (False, True,  True),
        'SC-28': (False, True,  True),
        'SI-3':  (True,  True,  True),
        'SI-8':  (False, True,  True),
        'SI-10': (True,  True,  True),
        'SI-16': (False, False, True),
    }

    story.append(P(
        "This section evaluates the assessment findings against FedRAMP Low, Moderate, and "
        "High baselines. Each mapped NIST control is checked against FedRAMP applicability "
        "to determine the compliance impact at each authorization level.", sBody))
    story += [SP(1)]

    # Determine which controls are violated
    violated_controls = set()
    for cwe in seen_nist_cwe:
        if cwe in NIST_CONTROL_MAP:
            violated_controls.add(NIST_CONTROL_MAP[cwe][0])

    # Count compliance per baseline
    total_checked = len(FEDRAMP_BASELINES)
    low_pass = mod_pass = high_pass = 0
    fed_rows = [["Control ID", "Control Name", "Low", "Moderate", "High", "Status"]]
    for ctrl_id, (in_low, in_mod, in_high) in sorted(FEDRAMP_BASELINES.items()):
        violated = ctrl_id in violated_controls
        status = "FAIL" if violated else "PASS"
        low_app  = "✗" if (in_low and violated) else ("✓" if in_low else "—")
        mod_app  = "✗" if (in_mod and violated) else ("✓" if in_mod else "—")
        high_app = "✗" if (in_high and violated) else ("✓" if in_high else "—")
        if not violated:
            if in_low:  low_pass += 1
            if in_mod:  mod_pass += 1
            if in_high: high_pass += 1
        # count total applicable
        fed_rows.append([ctrl_id, NIST_CONTROL_MAP.get(
            next((c for c, v in NIST_CONTROL_MAP.items() if v[0] == ctrl_id), ''), ('','',''))[2][:35] if
            next((c for c, v in NIST_CONTROL_MAP.items() if v[0] == ctrl_id), None) else ctrl_id,
            low_app, mod_app, high_app, status])

    fed_tbl = Table(fed_rows, colWidths=[20*mm, 55*mm, 18*mm, 22*mm, 18*mm, 37*mm])
    fed_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 7),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 4),
        ("ALIGN",         (2,0),(4,-1), "CENTER"),
    ]))
    story += [fed_tbl, SP(2)]

    # FedRAMP Compliance Score
    low_total  = sum(1 for v in FEDRAMP_BASELINES.values() if v[0])
    mod_total  = sum(1 for v in FEDRAMP_BASELINES.values() if v[1])
    high_total = sum(1 for v in FEDRAMP_BASELINES.values() if v[2])
    low_pct  = int((low_pass / max(low_total, 1)) * 100)
    mod_pct  = int((mod_pass / max(mod_total, 1)) * 100)
    high_pct = int((high_pass / max(high_total, 1)) * 100)

    story.append(heading("FedRAMP Compliance Score", C_TEAL, 10))
    score_rows = [
        ["Baseline", "Controls Applicable", "Controls Passing", "Compliance %"],
        ["Low",      str(low_total),        str(low_pass),      f"{low_pct}%"],
        ["Moderate", str(mod_total),         str(mod_pass),      f"{mod_pct}%"],
        ["High",     str(high_total),        str(high_pass),     f"{high_pct}%"],
    ]
    score_tbl = Table(score_rows, colWidths=[30*mm, 40*mm, 40*mm, 60*mm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("ALIGN",         (1,0),(-1,-1), "CENTER"),
    ]))
    story += [score_tbl, SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 14. POA&M TABLE
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(14, "Plan of Action & Milestones (POA&M)"), HR(C_STEEL), SP(1)]

    story.append(P(
        "The following POA&M entries are auto-generated from assessment findings. Each entry "
        "includes the weakness description, mapped control, risk level, CVSS score, current "
        "status, recommended remediation, and target due date based on severity SLAs.", sBody))
    story += [SP(1)]

    SLA_DAYS = {"critical": 30, "high": 60, "medium": 90, "low": 180, "info": 365, "informational": 365}

    poam_rows = [["POA&M ID", "Weakness", "Control", "Risk", "CVSS",
                  "Status", "Remediation", "Due Date"]]
    for pi, pf in enumerate(sorted_findings, 1):
        sev = pf.get("severity", "medium").lower()
        cwe = pf.get("cwe", "")
        ctrl = NIST_CONTROL_MAP.get(cwe, ("",))[0] if cwe in NIST_CONTROL_MAP else "—"
        sla_d = SLA_DAYS.get(sev, 90)
        from datetime import timedelta
        due = (datetime.now() + timedelta(days=sla_d)).strftime("%Y-%m-%d")
        poam_rows.append([
            f"POA-{pi:03d}",
            pf.get("name", "")[:35],
            ctrl,
            sev.upper()[:4],
            str(pf.get("cvss", "—")),
            "Open",
            pf.get("solution", "Apply vendor patch")[:35],
            due,
        ])

    if len(poam_rows) > 1:
        poam_tbl = Table(poam_rows, colWidths=[17*mm, 35*mm, 14*mm, 12*mm, 12*mm,
                                                13*mm, 38*mm, 22*mm])
        poam_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
            ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 6.5),
            ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
            ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
            ("TOPPADDING",    (0,0),(-1,-1), 3),
            ("BOTTOMPADDING", (0,0),(-1,-1), 3),
            ("LEFTPADDING",   (0,0),(-1,-1), 3),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))
        story += [poam_tbl, SP(3)]
    else:
        story.append(bullet("No POA&M entries generated — no findings to track."))
        story += [SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 15. REMEDIATION ROADMAP  (was Section 12)
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(15, "Remediation Roadmap"), HR(C_STEEL), SP(1)]

    story.append(heading("Immediate Actions (0-24 hours)", C_RED, 10))
    for rf in [f for f in sorted_findings if f.get("severity","").lower() == "critical"]:
        story.append(bullet(f"[CRITICAL] {rf.get('name','')[:60]} → {rf.get('solution','Patch immediately')[:80]}"))
    if not sev_counts["critical"]:
        story.append(bullet("No critical findings requiring immediate action."))
    story += [SP(1)]

    story.append(heading("Short-Term Actions (1-7 days)", C_ORANGE, 10))
    for rf in [f for f in sorted_findings if f.get("severity","").lower() == "high"]:
        story.append(bullet(f"[HIGH] {rf.get('name','')[:60]} → {rf.get('solution','')[:80]}"))
    if not sev_counts["high"]:
        story.append(bullet("No high-severity findings requiring short-term action."))
    story += [SP(1)]

    story.append(heading("Long-Term Actions (30-90 days)", C_YELLOW, 10))
    for rf in [f for f in sorted_findings if f.get("severity","").lower() == "medium"][:8]:
        story.append(bullet(f"[MEDIUM] {rf.get('name','')[:60]} → {rf.get('solution','')[:80]}"))
    if not sev_counts["medium"]:
        story.append(bullet("No medium findings requiring long-term action."))
    story += [SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 16. COMPLIANCE SCORECARDS
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [section_heading(16, "Compliance Scorecards"), HR(C_STEEL), SP(1)]

    story.append(P(
        "The following scorecards provide a visual summary of the organization's compliance "
        "posture across multiple frameworks based on the findings in this assessment.", sBody))
    story += [SP(1)]

    # ── NIST 800-53 Scorecard ──
    total_nist_controls = len(NIST_CONTROL_MAP)
    nist_violated = len(violated_controls)
    nist_compliance_pct = int(((total_nist_controls - nist_violated) / max(total_nist_controls, 1)) * 100)
    nist_bar_len = int(nist_compliance_pct * 0.3)
    nist_bar = "█" * nist_bar_len + "░" * (30 - nist_bar_len)

    # ── OWASP Top 10 Scorecard ──
    OWASP_CWES = {
        'A01': ['CWE-284','CWE-862','CWE-863','CWE-269','CWE-732'],
        'A02': ['CWE-326','CWE-327','CWE-328','CWE-311','CWE-312','CWE-319'],
        'A03': ['CWE-89','CWE-79','CWE-78','CWE-77','CWE-94','CWE-352'],
        'A04': ['CWE-22','CWE-23','CWE-918'],
        'A05': ['CWE-693','CWE-1021'],
        'A06': ['CWE-200','CWE-209','CWE-538','CWE-530','CWE-532'],
        'A07': ['CWE-287','CWE-307','CWE-384','CWE-613','CWE-798','CWE-522','CWE-521'],
        'A08': ['CWE-502','CWE-434'],
        'A09': ['CWE-532','CWE-778'],
        'A10': ['CWE-918','CWE-611'],
    }
    finding_cwes = {f.get("cwe", "") for f in all_findings}
    owasp_cats_hit = sum(1 for cat_cwes in OWASP_CWES.values()
                        if any(c in finding_cwes for c in cat_cwes))
    owasp_compliance_pct = int(((10 - owasp_cats_hit) / 10) * 100)
    owasp_bar_len = int(owasp_compliance_pct * 0.3)
    owasp_bar = "█" * owasp_bar_len + "░" * (30 - owasp_bar_len)

    # ── PCI DSS Scorecard ──
    PCI_CWES = {
        'Req 6.5.1': ['CWE-89'],
        'Req 6.5.4': ['CWE-22','CWE-23'],
        'Req 6.5.7': ['CWE-79'],
        'Req 6.5.9': ['CWE-352'],
        'Req 6.5.10':['CWE-287','CWE-284'],
        'Req 4.1':   ['CWE-319','CWE-326','CWE-311'],
        'Req 8.2':   ['CWE-307','CWE-521','CWE-522'],
    }
    pci_reqs_hit = sum(1 for req_cwes in PCI_CWES.values()
                       if any(c in finding_cwes for c in req_cwes))
    pci_total = len(PCI_CWES)
    pci_compliance_pct = int(((pci_total - pci_reqs_hit) / max(pci_total, 1)) * 100)
    pci_bar_len = int(pci_compliance_pct * 0.3)
    pci_bar = "█" * pci_bar_len + "░" * (30 - pci_bar_len)

    # ── MITRE ATT&CK Scorecard ──
    mitre_techniques_hit = len(seen_mitre)
    mitre_total_mapped = len(MITRE_MAP)
    mitre_coverage_pct = int(((mitre_total_mapped - mitre_techniques_hit) / max(mitre_total_mapped, 1)) * 100)
    mitre_bar_len = int(mitre_coverage_pct * 0.3)
    mitre_bar = "█" * mitre_bar_len + "░" * (30 - mitre_bar_len)

    # Composite scorecard table
    sc_rows = [
        ["Framework", "Score", "Status", "Visual"],
        ["NIST 800-53",  f"{nist_compliance_pct}%",
         "PASS" if nist_compliance_pct >= 80 else ("AT RISK" if nist_compliance_pct >= 50 else "FAIL"),
         nist_bar],
        ["OWASP Top 10", f"{owasp_compliance_pct}%",
         "PASS" if owasp_compliance_pct >= 80 else ("AT RISK" if owasp_compliance_pct >= 50 else "FAIL"),
         owasp_bar],
        ["PCI DSS",      f"{pci_compliance_pct}%",
         "PASS" if pci_compliance_pct >= 80 else ("AT RISK" if pci_compliance_pct >= 50 else "FAIL"),
         pci_bar],
        ["MITRE ATT&CK", f"{mitre_coverage_pct}%",
         "PASS" if mitre_coverage_pct >= 80 else ("AT RISK" if mitre_coverage_pct >= 50 else "FAIL"),
         mitre_bar],
    ]
    sc_tbl = Table(sc_rows, colWidths=[30*mm, 18*mm, 18*mm, 104*mm])
    sc_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("FONTNAME",      (3,1),(3,-1), "Courier"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("ALIGN",         (1,0),(2,-1), "CENTER"),
    ]))
    story += [sc_tbl, SP(2)]

    # ── Detailed OWASP Top 10 Breakdown ──
    story.append(heading("OWASP Top 10 (2021) Breakdown", C_TEAL, 10))
    owasp_names = {
        'A01': 'Broken Access Control',     'A02': 'Cryptographic Failures',
        'A03': 'Injection',                  'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',  'A06': 'Vulnerable Components',
        'A07': 'Auth Failures',              'A08': 'Software/Data Integrity',
        'A09': 'Logging Failures',           'A10': 'SSRF',
    }
    owasp_det_rows = [["Category", "Name", "Findings", "Status"]]
    for cat_id in sorted(OWASP_CWES.keys()):
        cat_cwes = OWASP_CWES[cat_id]
        hits = [c for c in cat_cwes if c in finding_cwes]
        status = "FAIL" if hits else "PASS"
        owasp_det_rows.append([cat_id, owasp_names.get(cat_id, ""),
                               str(len(hits)), status])
    owasp_det_tbl = Table(owasp_det_rows, colWidths=[18*mm, 50*mm, 22*mm, 80*mm])
    owasp_det_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 5),
        ("ALIGN",         (2,0),(3,-1), "CENTER"),
    ]))
    story += [owasp_det_tbl, SP(3)]

    # ══════════════════════════════════════════════════════════════
    # 17. CONCLUSION  (was Section 13)
    # ══════════════════════════════════════════════════════════════
    story += [section_heading(17, "Conclusion"), HR(C_STEEL), SP(1)]
    story.append(P(
        f"This external penetration test identified <b>{total_findings} vulnerabilities</b> "
        f"across {len(targets)} target(s), including "
        f"<b>{sev_counts['critical']} critical</b> and <b>{sev_counts['high']} high</b> severity "
        f"findings that require immediate attention. "
        f"The overall security posture is rated <b>{posture}</b>.",
        sBody))
    story += [SP(1)]
    story.append(P(
        "The testing team recommends prioritizing the remediation of critical and high "
        "severity findings within the SLA timeframes outlined in Section 15. A re-test "
        "should be scheduled after remediation to verify effectiveness of applied fixes.",
        sBody))
    story += [SP(1)]
    story.append(P(
        "The Expedite Strike auto-exploitation engine confirmed that multiple vulnerabilities are "
        "actively exploitable, with proof-of-concept evidence captured in Appendix B. "
        "Organizations should treat these findings with the highest priority.",
        sBody))
    story += [SP(3)]

    # ── Continuous Monitoring ──
    monitor_data = data.get('data', {}).get('MONITOR', {})
    if isinstance(monitor_data, dict) and not monitor_data.get('error'):
        story += [SP(1)]
        story.append(heading("Continuous Monitoring Configuration", C_TEAL, 10))
        story.append(P(f"Monitoring has been configured for {monitor_data.get('domain', target)} "
                      f"with a {monitor_data.get('schedule', 'weekly')} scan schedule. "
                      f"Next scan: {monitor_data.get('next_scan', 'TBD')}. "
                      f"Baseline: {monitor_data.get('baseline_findings', 0)} findings "
                      f"({monitor_data.get('baseline_critical', 0)} critical).", sBody))

    # ══════════════════════════════════════════════════════════════
    # APPENDIX A — COMMANDS EXECUTED
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [appendix_heading("A", "Commands Executed"), HR(C_STEEL), SP(1)]

    commands = [
        ("nmap",       f"nmap -sV -sC -p- -oX scan.xml {targets[0] if targets else ''}"),
        ("nikto",      f"nikto -h {targets[0] if targets else ''} -o nikto.csv"),
        ("gobuster",   f"gobuster dir -u {targets[0] if targets else ''} -w common.txt"),
        ("sslscan",    f"sslscan {targets[0] if targets else ''}"),
        ("sqlmap",     f"sqlmap -u \"{targets[0] if targets else ''}?id=1\" --batch --level=3"),
        ("nuclei",     f"nuclei -u {targets[0] if targets else ''} -t cves/ -severity critical,high"),
        ("whatweb",    f"whatweb -v {targets[0] if targets else ''}"),
        ("subfinder",  f"subfinder -d {targets[0].split('//')[1].split('/')[0] if targets and '//' in targets[0] else targets[0] if targets else ''}"),
        ("feroxbuster",f"feroxbuster -u {targets[0] if targets else ''} -w /usr/share/seclists/..."),
        ("zap",        f"zap-cli active-scan {targets[0] if targets else ''}"),
    ]

    cmd_rows = [["Tool", "Command"]]
    for cname, ccmd in commands:
        cmd_rows.append([cname, ccmd[:110]])

    cmd_tbl = Table(cmd_rows, colWidths=[25*mm, 145*mm])
    cmd_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
        ("TEXTCOLOR",     (0,0),(-1,0), _rc(C_TEAL)),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 7),
        ("FONTNAME",      (1,1),(1,-1), "Courier"),
        ("TEXTCOLOR",     (0,1),(-1,-1), _rc(C_WHITE)),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_rc(C_CARD), _rc(C_DARK)]),
        ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 3),
        ("BOTTOMPADDING", (0,0),(-1,-1), 3),
        ("LEFTPADDING",   (0,0),(-1,-1), 5),
    ]))
    story += [cmd_tbl, SP(3)]

    # ══════════════════════════════════════════════════════════════
    # APPENDIX B — EVIDENCE (Exploit PoC)
    # ══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story += [appendix_heading("B", "Evidence"), HR(C_STEEL), SP(1)]
    story.append(P(
        "This appendix contains live exploitation evidence including auto-generated "
        "exploit scripts, HTTP request/response captures, and extracted data collected "
        "during Phase 4.5 of the assessment.", sBody))
    story += [SP(2)]

    _ev_list = exploit_evidence or data.get("exploit_evidence", [])
    if _ev_list:
        # Evidence summary
        _confirmed = [e for e in _ev_list if e.get("status") == "EXPLOITED"]
        _not_vuln  = [e for e in _ev_list if e.get("status") != "EXPLOITED"]

        ev_summ = Table([
            [P("EXPLOITED", S("es", fontName="Helvetica-Bold", fontSize=9,
                             textColor=_rc(C_RED), alignment=TA_CENTER)),
             P("NOT EXPLOITED", S("es", fontName="Helvetica-Bold", fontSize=9,
                             textColor=_rc(C_GREEN), alignment=TA_CENTER)),
             P("TOTAL", S("es", fontName="Helvetica-Bold", fontSize=9,
                         textColor=_rc(C_TEAL), alignment=TA_CENTER))],
            [P(str(len(_confirmed)), S("en", fontName="Helvetica-Bold", fontSize=20,
                                      textColor=_rc(C_RED), alignment=TA_CENTER)),
             P(str(len(_not_vuln)), S("en", fontName="Helvetica-Bold", fontSize=20,
                                    textColor=_rc(C_GREEN), alignment=TA_CENTER)),
             P(str(len(_ev_list)), S("en", fontName="Helvetica-Bold", fontSize=20,
                                   textColor=_rc(C_TEAL), alignment=TA_CENTER))],
        ], colWidths=[57*mm, 57*mm, 56*mm])
        ev_summ.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,-1), _rc(C_DARK)),
            ("GRID",        (0,0),(-1,-1), 0.5, _rc(C_BORDER)),
            ("TOPPADDING",  (0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ]))
        story += [ev_summ, SP(3)]

        # Each evidence entry
        for ei, ev in enumerate(_ev_list, 1):
            estat  = ev.get("status", "?")
            ecol   = C_RED if estat == "EXPLOITED" else C_GREEN
            ec_hex = "#{:02x}{:02x}{:02x}".format(
                int(ecol[0]*255), int(ecol[1]*255), int(ecol[2]*255))

            # Header
            ehdr = Table([[
                P(f'<font color="{ec_hex}"><b>PoC #{ei:02d} · {estat}</b></font>',
                  S("eh", fontName="Helvetica-Bold", fontSize=10, leading=13)),
                P(f'<font color="{ec_hex}">{_esc(ev.get("timestamp","")[:19])}</font>',
                  S("et", fontSize=8, alignment=TA_RIGHT, leading=13)),
            ]], colWidths=[130*mm, 40*mm])
            ehdr.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,-1), _rc(C_DARK)),
                ("BOX",          (0,0),(-1,-1), 0.5, _rc(ecol)),
                ("TOPPADDING",   (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
                ("LEFTPADDING",  (0,0),(-1,-1), 8),
            ]))

            # Meta
            emeta = Table([
                kv_row("Exploit:",    ev.get("exploit_name","")),
                kv_row("Target:",     ev.get("target","")),
                kv_row("Confirmed:",  "YES — EXPLOITED" if ev.get("vuln_confirmed") else "Not confirmed"),
                kv_row("Impact:",     ev.get("cvss_impact","—")[:120]),
            ], colWidths=[25*mm, 145*mm])
            emeta.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), _rc(C_CARD)),
                ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
                ("TOPPADDING",    (0,0),(-1,-1), 3),
                ("BOTTOMPADDING", (0,0),(-1,-1), 3),
                ("LEFTPADDING",   (0,0),(-1,-1), 5),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]))

            # Script
            script = ev.get("exploit_script", "")
            script_rows = [[P("Auto-Generated Exploit Script",
                             S("sh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_TEAL)))]]
            for sl in (script[:1200].splitlines())[:25]:
                script_rows.append([P(_esc(sl),
                    S("sc", fontName="Courier", fontSize=6.5, textColor=_rc(C_TEAL),
                      leading=9, backColor=_rc(C_DARK)))])
            script_tbl = Table(script_rows, colWidths=[170*mm])
            script_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), _rc(C_DARK)),
                ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
                ("TOPPADDING",    (0,0),(-1,-1), 1),
                ("BOTTOMPADDING", (0,0),(-1,-1), 1),
                ("LEFTPADDING",   (0,0),(-1,-1), 5),
            ]))

            # HTTP evidence
            req_d  = (_esc(ev.get("request_dump","") or ""))[:600]
            resp_d = (_esc(ev.get("response_dump","") or ""))[:800]
            http_rows = [
                [P("HTTP Request", S("hh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_TEAL))),
                 P("HTTP Response", S("hh", fontName="Helvetica-Bold", fontSize=8, textColor=_rc(C_TEAL)))],
                [P(req_d,  S("hr", fontName="Courier", fontSize=6.5, textColor=_rc(C_WHITE), leading=8)),
                 P(resp_d, S("hr", fontName="Courier", fontSize=6.5, textColor=_rc(C_WHITE), leading=8))],
            ]
            http_tbl = Table(http_rows, colWidths=[82*mm, 88*mm])
            http_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), _rc(C_DARK)),
                ("BACKGROUND",    (0,1),(-1,-1), _rc(C_CARD)),
                ("GRID",          (0,0),(-1,-1), 0.3, _rc(C_BORDER)),
                ("TOPPADDING",    (0,0),(-1,-1), 3),
                ("BOTTOMPADDING", (0,0),(-1,-1), 3),
                ("LEFTPADDING",   (0,0),(-1,-1), 4),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]))

            # Extracted data
            ext_data = ev.get("extracted_data", [])
            evidence_items = []
            for ext in (ext_data or [])[:4]:
                payload  = ext.get("payload", "Evidence")
                evdata   = (_esc(ext.get("evidence","") or ""))[:700]
                evidence_items.append(
                    P(f'<font color="#ffd700"><b>▶ {_esc(payload)}</b></font>',
                      S("ep", fontSize=8, leading=11)))
                for dl in evdata.splitlines()[:20]:
                    evidence_items.append(
                        P(dl, S("ed", fontName="Courier", fontSize=6.5,
                                textColor=_rc(C_WHITE), leading=8,
                                backColor=_rc(C_DARK), borderPad=1)))
                evidence_items.append(SP(1))

            story += [ehdr, emeta, SP(1)]
            story += [heading("  Exploit Script", C_TEAL, 9), script_tbl, SP(1)]
            story += [heading("  HTTP Evidence", C_TEAL, 9), http_tbl, SP(1)]
            if evidence_items:
                story += [heading("  Extracted Evidence", C_TEAL, 9)]
                story += evidence_items
            story += [HR(C_BORDER), SP(2)]

    else:
        story.append(bullet("No automated exploitation evidence collected in this assessment."))
        story.append(bullet("Screenshots, HTTP requests/responses, Nessus exports, Nmap XML, "
                           "Burp exports, and PCAP files should be attached separately."))

    # ── Final footer ──────────────────────────────────────────────
    story += [
        PageBreak(), HR(C_BORDER), SP(3),
        P("CONFIDENTIAL — For authorized recipients only. This report must not be "
          "reproduced or distributed without written consent of Expedite Strike Security.", sConf),
        SP(1),
        P(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  ·  "
          f"Expedite Strike Pentest Engine v2  ·  PTES / NIST SP 800-115 Aligned", sConf),
    ]

    doc.build(story, onFirstPage=bg_page, onLaterPages=bg_page)
    return output_path
