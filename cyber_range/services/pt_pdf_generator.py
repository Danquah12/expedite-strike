"""
pt_pdf_generator.py  —  PTES / NIST SP 800-115 Pentest Report
Uses ReportLab (already installed).
"""
from datetime import datetime
from pathlib import Path


# ── palette ──────────────────────────────────────────────────────────────────
def _hex(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16)/255 for i in (0, 2, 4))

C_BG      = _hex("0a0d14")
C_CARD    = _hex("0f1420")
C_DARK    = _hex("1a2235")
C_TEAL    = _hex("00c88c")
C_RED     = _hex("ff3355")
C_ORANGE  = _hex("ff8c00")
C_YELLOW  = _hex("ffd700")
C_BLUE    = _hex("4488ff")
C_PURPLE  = _hex("aa44ff")
C_WHITE   = _hex("e8eaf0")
C_GREY    = _hex("607080")
C_GREEN   = _hex("00be6c")


def _sev_col(s):
    s = (s or "").lower()
    if s == "critical":           return C_RED
    if s == "high":               return C_ORANGE
    if s in ("medium","moderate"):return C_YELLOW
    if s == "low":                return C_BLUE
    return C_GREY


def generate_pdf(results: dict, output_path: str) -> str:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable, KeepTogether
        )
        from reportlab.lib import colors
        from reportlab.platypus.flowables import Flowable
    except ImportError as e:
        return _html_fallback(results, output_path, str(e))

    # ── unpack ────────────────────────────────────────────────────────────────
    target     = results.get("target", "Unknown Target")
    targets    = results.get("targets", [target])
    ts         = results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M"))
    date_str   = ts[:10]
    data       = results.get("data", {})
    phases     = results.get("phases_run", ["passive", "active", "vuln"])

    # ── Debug: write to log file so we can trace issues ───────────────────
    import json as _j
    _dbg_path = str(Path(__file__).resolve().parent.parent.parent / "pdf_debug.log")
    def _dbg(msg):
        try:
            with open(_dbg_path, "a") as _f:
                _f.write(f"{msg}\n")
                _f.flush()
        except: pass
        print(msg)

    _dbg(f"[PDF GEN] ===== PDF GENERATION START =====")
    _dbg(f"[PDF GEN] Target: {target}, Targets: {targets}")
    _dbg(f"[PDF GEN] Data keys received: {list(data.keys())}")
    for _dk, _dv in data.items():
        if isinstance(_dv, dict):
            _sub = {k: (type(v).__name__,len(v) if isinstance(v,list) else '~') for k,v in _dv.items()}
            _dbg(f"[PDF GEN]   {_dk}: {_sub}")


    nuc  = data.get("NUCLEI", {}).get("findings", [])
    zap_data = data.get("ZAP", {})
    zap  = zap_data.get("findings", []) if isinstance(zap_data, dict) else []
    all_f = (
        [dict(f, _src="Nuclei", _sev=f.get("severity","info")) for f in nuc if isinstance(f, dict)] +
        [dict(f, _src="ZAP",    _sev=f.get("risk","info"))     for f in zap if isinstance(f, dict)]
    )
    _dbg(f"[PDF GEN] Nuclei findings: {len(nuc)}, ZAP findings: {len(zap)}")

    # ── Pull NMAP open ports as findings (risky ports = Medium/High) ──────
    nmap_data = data.get("NMAP", {})
    _RISKY_PORTS = {
        21: ("FTP", "high"), 22: ("SSH", "medium"), 23: ("Telnet", "critical"),
        25: ("SMTP", "medium"), 53: ("DNS", "low"), 80: ("HTTP", "low"),
        110: ("POP3", "medium"), 135: ("MSRPC", "high"), 139: ("NetBIOS", "high"),
        443: ("HTTPS", "low"), 445: ("SMB", "critical"), 1433: ("MSSQL", "high"),
        3306: ("MySQL", "high"), 3389: ("RDP", "high"), 5432: ("PostgreSQL", "high"),
        5900: ("VNC", "high"), 6379: ("Redis", "critical"), 8080: ("HTTP-Alt", "low"),
        8443: ("HTTPS-Alt", "low"), 27017: ("MongoDB", "critical"),
    }
    _nmap_hosts = nmap_data.get("hosts", [])
    _nmap_port_list = nmap_data.get("open_ports", [])
    _ports_processed = set()  # track which ports we've handled

    # First: structured host/port data (has service details)
    for host in _nmap_hosts:
        for p in host.get("ports", []):
            pn = p.get("port", 0)
            _ports_processed.add(pn)
            svc = p.get("service", "")
            prod = f"{p.get('product','')} {p.get('version','')}".strip()
            if pn in _RISKY_PORTS:
                label, sev = _RISKY_PORTS[pn]
                all_f.append({
                    "_src": "Nmap", "_sev": sev,
                    "name": f"Open Port: {pn}/{p.get('proto','tcp')} ({label})",
                    "url": target,
                    "description": f"Port {pn} ({svc or label}) is open and exposed externally. "
                                   f"Service: {prod or 'unknown'}. Publicly exposed {label} services "
                                   f"increase the attack surface significantly.",
                    "solution": f"If {label} is not required externally, restrict access via firewall rules. "
                                f"If needed, enforce strong authentication and encryption.",
                })
            elif pn not in (80, 443, 8080, 8443) and pn > 0:
                all_f.append({
                    "_src": "Nmap", "_sev": "low",
                    "name": f"Open Port: {pn}/{p.get('proto','tcp')} ({svc or 'unknown'})",
                    "url": target,
                    "description": f"Port {pn} is open with service: {prod or svc or 'unknown'}.",
                    "solution": "Review whether this service needs external exposure.",
                })

    # Fallback: if hosts[] was empty but open_ports[] has values, generate from port numbers
    for pn in _nmap_port_list:
        if pn in _ports_processed:
            continue
        _ports_processed.add(pn)
        if pn in _RISKY_PORTS:
            label, sev = _RISKY_PORTS[pn]
            all_f.append({
                "_src": "Nmap", "_sev": sev,
                "name": f"Open Port: {pn}/tcp ({label})",
                "url": target,
                "description": f"Port {pn} ({label}) is open and exposed externally.",
                "solution": f"If {label} is not required externally, restrict access via firewall.",
            })
        elif pn not in (80, 443, 8080, 8443) and pn > 0:
            all_f.append({
                "_src": "Nmap", "_sev": "low",
                "name": f"Open Port: {pn}/tcp",
                "url": target,
                "description": f"Port {pn} is open.",
                "solution": "Review whether this service needs external exposure.",
            })
    _dbg(f"[PDF GEN] NMAP: {len(_nmap_hosts)} hosts, {len(_nmap_port_list)} open_ports, {len(_ports_processed)} processed")

    # ── Pull HTTPX missing-header findings (Medium severity) ──────────────
    httpx_data = data.get("HTTPX", {})
    _httpx_added = False
    for ue in httpx_data.get("urls", []):
        missing = ue.get("missing_headers", [])
        if missing:
            all_f.append({
                "_src": "HTTPX", "_sev": "medium",
                "name": f"Missing Security Headers ({len(missing)})",
                "url": ue.get("url", "—"),
                "description": f"The following recommended security headers are absent: {', '.join(missing)}. "
                               "Missing headers can allow clickjacking, MIME sniffing, and XSS attacks.",
                "solution": "Add the following HTTP response headers: " + ", ".join(missing),
                "severity": "medium",
            })
            _httpx_added = True
    # Also extract text-based findings from HTTPX ("WARN: Missing header: X")
    if not _httpx_added:
        for hf in httpx_data.get("findings", []):
            if isinstance(hf, str) and "missing" in hf.lower():
                all_f.append({
                    "_src": "HTTPX", "_sev": "medium",
                    "name": hf.replace("WARN: ", "").strip(),
                    "url": httpx_data.get("target", target),
                    "description": hf,
                    "solution": "Add the missing security header.",
                })
            elif isinstance(hf, str) and hf.strip():
                all_f.append({
                    "_src": "HTTPX", "_sev": "low",
                    "name": hf.replace("WARN: ", "").strip()[:80],
                    "url": httpx_data.get("target", target),
                    "description": hf,
                    "solution": "Review and remediate.",
                })
    _dbg(f"[PDF GEN] HTTPX: {len(httpx_data.get('urls',[]))} urls, {len(httpx_data.get('findings',[]))} text findings")

    # ── Pull FEROXBUSTER/FEROX exposed directories (Low/Medium) ───────────
    # Engine stores under key "FEROX", check both
    ferox = data.get("FEROX", data.get("FEROXBUSTER", {}))
    # Engine stores as "paths" (strings), "directories" (dicts), or "findings" (dicts)
    _ferox_items = (ferox.get("directories", []) or
                    ferox.get("paths", []) or
                    ferox.get("findings", []) or [])[:30]
    for d_item in _ferox_items:
        if isinstance(d_item, dict):
            all_f.append({
                "_src": "Feroxbuster", "_sev": d_item.get("severity", "low"),
                "name": f"Exposed Directory: {d_item.get('path', d_item.get('url', '—'))}",
                "url": d_item.get("url", d_item.get("path", "—")),
                "description": f"Accessible directory/file discovered: {d_item.get('path', '—')} (Status: {d_item.get('status', '?')})",
                "solution": "Review exposed path. Restrict access via authentication or remove if unnecessary.",
            })
        elif isinstance(d_item, str) and d_item.strip():
            # Parse raw feroxbuster/dirb output: "200  http://target/admin"
            _parts = d_item.strip().split()
            _status_code = _parts[0] if _parts and _parts[0].isdigit() else "?"
            _path_url = _parts[-1] if len(_parts) > 1 else d_item
            _sev = "medium" if _status_code == "200" else "low"
            all_f.append({
                "_src": "Feroxbuster", "_sev": _sev,
                "name": f"Discovered Path: {_path_url[:80]}",
                "url": _path_url,
                "description": f"Accessible path discovered (HTTP {_status_code}): {d_item[:120]}",
                "solution": "Review exposed path and restrict access if unnecessary.",
            })
    _dbg(f"[PDF GEN] FEROX: {len(_ferox_items)} paths/dirs from keys={list(ferox.keys()) if ferox else '(empty)'}")

    # ── Pull SSL certificate issues ────────────────────────────────────────
    ssl_data = data.get("SSL", {})
    if ssl_data and not ssl_data.get("error"):
        days_left = ssl_data.get("days_until_expiry")
        if days_left is not None and isinstance(days_left, (int, float)) and days_left < 30:
            sev = "critical" if days_left <= 0 else ("high" if days_left < 7 else "medium")
            all_f.append({
                "_src": "SSL", "_sev": sev,
                "name": f"SSL Certificate {'Expired' if days_left <= 0 else 'Expiring Soon'} ({days_left} days)",
                "url": target,
                "description": f"The SSL/TLS certificate for {target} has {days_left} days until expiry.",
                "solution": "Renew the SSL certificate immediately to avoid service disruption and browser warnings.",
            })

    # ── Pull SHODAN exposed services ───────────────────────────────────────
    shodan = data.get("SHODAN", {})
    for vuln_id in (shodan.get("vulns", []) or [])[:20]:
        all_f.append({
            "_src": "Shodan", "_sev": "high",
            "name": f"Shodan CVE: {vuln_id}",
            "url": target,
            "description": f"Shodan intelligence reports this target is affected by {vuln_id}.",
            "solution": f"Investigate and remediate {vuln_id} per vendor advisory.",
            "cve": [vuln_id] if vuln_id.startswith("CVE-") else [],
        })

    _dbg(f"[PDF GEN] TOTAL findings before sort: {len(all_f)}")
    for _af in all_f[:10]:
        _dbg(f"[PDF GEN]   [{_af.get('_sev','?')}] {_af.get('name','?')[:60]} (src={_af.get('_src','?')})")
    if len(all_f) > 10:
        _dbg(f"[PDF GEN]   ... and {len(all_f)-10} more")

    _o = {"critical":0,"high":1,"medium":2,"moderate":2,"low":3}
    all_f.sort(key=lambda f: _o.get(f.get("_sev","").lower(), 4))

    nc = sum(1 for f in all_f if f.get("_sev","").lower()=="critical")
    nh = sum(1 for f in all_f if f.get("_sev","").lower()=="high")
    nm = sum(1 for f in all_f if f.get("_sev","").lower() in ("medium","moderate"))
    nl = sum(1 for f in all_f if f.get("_sev","").lower()=="low")

    if nc:   posture, pc = "CRITICAL RISK", C_RED
    elif nh>=3: posture, pc = "HIGH RISK",  C_ORANGE
    elif nh:    posture, pc = "ELEVATED",   C_ORANGE
    elif nm:    posture, pc = "MODERATE",   C_YELLOW
    else:       posture, pc = "LOW RISK",   C_GREEN

    open_ports = data.get("NMAP",{}).get("open_ports",[])
    subdomains = data.get("SUBFINDER",{}).get("subdomains",[])

    # ── colours as RL color ───────────────────────────────────────────────────
    def rc(t): return colors.Color(*t)

    # ── styles ────────────────────────────────────────────────────────────────
    W, H = A4
    styles = getSampleStyleSheet()

    def S(name, **kw):
        base = kw.pop("parent", "Normal")
        return ParagraphStyle(name, parent=styles[base], **kw)

    sTitle  = S("sTitle",  fontSize=26, textColor=rc(C_TEAL),   spaceAfter=4,  alignment=TA_CENTER, fontName="Helvetica-Bold")
    sSub    = S("sSub",    fontSize=13, textColor=rc(C_WHITE),  spaceAfter=2,  alignment=TA_CENTER, fontName="Helvetica-Bold")
    sH1     = S("sH1",     fontSize=12, textColor=rc(C_TEAL),   spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold", backColor=rc(C_DARK), leftIndent=4, borderPad=4)
    sH2     = S("sH2",     fontSize=10, textColor=rc(C_TEAL),   spaceBefore=6, spaceAfter=3, fontName="Helvetica-Bold")
    sBody   = S("sBody",   fontSize=8.5,textColor=rc(C_WHITE),  spaceAfter=3,  leading=13)
    sMono   = S("sMono",   fontSize=7.5,textColor=rc(C_TEAL),   fontName="Courier", spaceAfter=2)
    sSmall  = S("sSmall",  fontSize=7.5,textColor=rc(C_GREY),   spaceAfter=2,  leading=11)
    sBullet = S("sBullet", fontSize=8.5,textColor=rc(C_WHITE),  spaceAfter=2,  leftIndent=12, bulletIndent=4, leading=12)

    def _esc(t):
        """Escape XML-special chars for ReportLab Paragraph (which parses pseudo-XML)."""
        import xml.sax.saxutils as _sx
        return _sx.escape(str(t or ""))

    def P(text, style=None, raw=False):
        """Paragraph helper. raw=True skips XML escaping (for intentional markup).
        Auto-detects common ReportLab markup tags and skips escaping if present."""
        t = str(text or "")
        # Auto-detect intentional HTML/XML markup — skip escaping if present
        if not raw and any(tag in t for tag in ("<font", "<b>", "</b>", "<br/>", "<i>", "</i>")):
            raw = True
        if not raw:
            t = _esc(t)
        return Paragraph(t, style or sBody)
    def HR(col=C_TEAL, t=0.5): return HRFlowable(width="100%", thickness=t, color=rc(col), spaceAfter=4, spaceBefore=2)
    def SP(h=4): return Spacer(1, h*mm)

    def heading(text, color=C_TEAL, size=12):
        return P(f'<font color="#{int(color[0]*255):02x}{int(color[1]*255):02x}{int(color[2]*255):02x}"><b>{_esc(text)}</b></font>',
                 S("_h", fontSize=size, textColor=rc(color), spaceBefore=6, spaceAfter=3,
                   fontName="Helvetica-Bold", backColor=rc(C_DARK), borderPad=3, leftIndent=2),
                 raw=True)

    def bullet(text, col=C_WHITE):
        return P(f'• {text}', sBullet)

    def kv_table(rows, col_w=(50*mm, 120*mm)):
        tdata = [[P(f'<b><font color="#00c88c">{_esc(k)}:</font></b>', sSmall, raw=True),
                  P(str(v or "—")[:160], sSmall)] for k,v in rows]
        t = Table(tdata, colWidths=col_w)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), rc(C_DARK)),
            ("TEXTCOLOR",  (0,0),(-1,-1), rc(C_WHITE)),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[rc(C_DARK), rc(C_CARD)]),
            ("GRID",(0,0),(-1,-1),0.2, rc(C_GREY)),
            ("TOPPADDING",(0,0),(-1,-1),2),
            ("BOTTOMPADDING",(0,0),(-1,-1),2),
            ("LEFTPADDING",(0,0),(-1,-1),4),
        ]))
        return t

    def sev_badge(sev):
        col = _sev_col(sev)
        hex_col = "#{:02x}{:02x}{:02x}".format(int(col[0]*255),int(col[1]*255),int(col[2]*255))
        return f'<font color="{hex_col}"><b>[{sev.upper()}]</b></font>'

    # ── document ──────────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=14*mm, bottomMargin=14*mm,
    )
    story = []

    def bg_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(rc(C_BG))
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # header bar
        if doc.page > 1:
            canvas.setFillColor(rc(C_DARK))
            canvas.rect(0, H-10*mm, W, 10*mm, fill=1, stroke=0)
            canvas.setFillColor(rc(C_TEAL))
            canvas.rect(0, H-10*mm, W, 1*mm, fill=1, stroke=0)
            canvas.setFont("Helvetica-Bold", 7)
            canvas.setFillColor(rc(C_TEAL))
            canvas.drawString(18*mm, H-7*mm, f"EXPEDITE STRIKE  |  External Pentest Report  |  {target[:50]}")
            canvas.setFillColor(rc(C_GREY))
            canvas.drawRightString(W-18*mm, H-7*mm, f"CONFIDENTIAL  |  {date_str}  |  Page {doc.page}")
            # footer
            canvas.setFillColor(rc(C_DARK))
            canvas.rect(0, 0, W, 8*mm, fill=1, stroke=0)
            canvas.setFont("Helvetica", 6.5)
            canvas.setFillColor(rc(C_GREY))
            canvas.drawCentredString(W/2, 3*mm,
                f"PTES / NIST SP 800-115 Aligned  ·  CONFIDENTIAL  ·  Generated {ts}")
        canvas.restoreState()

    # ════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ════════════════════════════════════════════════════════════════
    story += [SP(20), P("EXPEDITE STRIKE SECURITY", sTitle), SP(2),
              P("EXTERNAL PENETRATION TEST REPORT", sSub), SP(1),
              P("PTES &amp; NIST SP 800-115 Aligned", sSmall), SP(6),
              HR(C_TEAL, 1.5), SP(4)]

    cover_data = [
        ["Target(s)",      ", ".join(targets[:4]) + ("…" if len(targets)>4 else "")],
        ["Report Date",    date_str],
        ["Assessment Type","External Black-Box Penetration Test"],
        ["Standard",       "PTES / NIST SP 800-115 / OWASP Testing Guide v4.2"],
        ["Phases",         ", ".join(p.title() for p in phases)],
        ["Classification", "CONFIDENTIAL — Authorized Recipients Only"],
    ]
    story.append(kv_table(cover_data, (55*mm, 110*mm)))
    story += [SP(6)]

    # Overall risk badge
    pc_hex = "#{:02x}{:02x}{:02x}".format(int(pc[0]*255),int(pc[1]*255),int(pc[2]*255))
    story.append(P(f'<font color="{pc_hex}"><b>OVERALL RISK POSTURE: {posture}</b></font>',
                   S("risk", fontSize=14, alignment=TA_CENTER, spaceBefore=4, spaceAfter=4,
                     fontName="Helvetica-Bold", backColor=rc(C_DARK), borderPad=8), raw=True))
    story += [SP(4)]

    # Stat table
    stat_data = [["CRITICAL","HIGH","MEDIUM","LOW","OPEN PORTS","SUBDOMAINS"],
                 [str(nc), str(nh), str(nm), str(nl), str(len(open_ports)), str(len(subdomains))]]
    stat_cols = [C_RED, C_ORANGE, C_YELLOW, C_BLUE, C_TEAL, C_GREY]
    st = Table(stat_data, colWidths=[28*mm]*6)
    style_cmds = [
        ("BACKGROUND",(0,0),(-1,-1),rc(C_DARK)),
        ("GRID",(0,0),(-1,-1),0.3,rc(C_GREY)),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTNAME",(0,1),(-1,1),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,0),7),
        ("FONTSIZE",(0,1),(-1,1),18),
        ("TOPPADDING",(0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]
    for i,col in enumerate(stat_cols):
        style_cmds += [
            ("TEXTCOLOR",(i,0),(i,0), rc(col)),
            ("TEXTCOLOR",(i,1),(i,1), rc(col)),
            ("LINEBELOW",(i,0),(i,0), 2, rc(col)),
        ]
    st.setStyle(TableStyle(style_cmds))
    story += [st, SP(6), HR(C_GREY, 0.4), SP(2),
              P("CONFIDENTIAL — This document contains sensitive security findings. "
                "Distribution strictly limited to authorized personnel.", sSmall), PageBreak()]

    # ════════════════════════════════════════════════════════════════
    # TABLE OF CONTENTS
    # ════════════════════════════════════════════════════════════════
    story += [heading("TABLE OF CONTENTS", C_TEAL, 14), SP(2), HR()]
    toc = [
        ("1.", "Executive Summary",           "Risk overview, posture assessment, business impact"),
        ("2.", "Scope &amp; Methodology",     "Targets, rules of engagement, PTES phases, CVSS scale"),
        ("3.", "Attack Surface Overview",     "Subdomains, open ports, SSL/TLS, technology fingerprint"),
        ("4.", "Technical Findings",          "Detailed vulnerabilities with CVSS, PoC, and evidence"),
        ("5.", "Remediation &amp; Recommendations", "Prioritized fixes aligned with CIS Controls"),
        ("6.", "Strategic Security Roadmap",  "90-day plan for security improvement"),
        ("7.", "Appendices",                  "Tools used, DNS records, standards references"),
    ]
    toc_data = [[P(f'<b><font color="#00c88c">{n}</font></b>', sSmall),
                 P(f'<b><font color="#e8eaf0">{t}</font></b>', sSmall),
                 P(d, sSmall)] for n,t,d in toc]
    toc_tbl = Table(toc_data, colWidths=[12*mm, 60*mm, 98*mm])
    toc_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[rc(C_DARK), rc(C_CARD)]),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1),4), ("GRID",(0,0),(-1,-1),0.2,rc(C_GREY)),
    ]))
    story += [toc_tbl, PageBreak()]

    # ════════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════════════════
    story += [heading("1. EXECUTIVE SUMMARY", C_TEAL, 13), HR(), SP(2)]
    story.append(P(f"EXPEDITE STRIKE Security conducted an external penetration test against <b>{target}</b> "
                   f"on <b>{date_str}</b> following PTES and NIST SP 800-115. "
                   f"Phases executed: <b>{', '.join(p.title() for p in phases)}</b>."))
    story += [SP(3),
              P(f'<font color="{pc_hex}"><b>Overall Security Posture: {posture}</b></font>',
                S("pos", fontSize=11, fontName="Helvetica-Bold", backColor=rc(C_DARK),
                  borderPad=6, spaceAfter=6)), SP(2)]

    # Summary table
    summ = [["Severity","Count","CVSS Range","Business Impact"],
            ["Critical", nc, "9.0–10.0", "Immediate exploitation; data breach / RCE risk"],
            ["High",     nh, "7.0–8.9",  "Significant impact; exploitable with moderate effort"],
            ["Medium",   nm, "4.0–6.9",  "Conditional exploit; may chain with other findings"],
            ["Low",      nl, "0.1–3.9",  "Minimal direct impact; defence-in-depth improvement"]]
    sev_colors_row = [None, C_RED, C_ORANGE, C_YELLOW, C_BLUE]
    summ_tbl = Table(summ, colWidths=[28*mm,18*mm,26*mm,98*mm])
    sc = [("BACKGROUND",(0,0),(-1,0),rc(C_DARK)),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
          ("FONTSIZE",(0,0),(-1,-1),8),("GRID",(0,0),(-1,-1),0.3,rc(C_GREY)),
          ("ALIGN",(1,0),(1,-1),"CENTER"),("TOPPADDING",(0,0),(-1,-1),3),
          ("BOTTOMPADDING",(0,0),(-1,-1),3),("LEFTPADDING",(0,0),(-1,-1),4),
          ("TEXTCOLOR",(0,0),(-1,0),rc(C_TEAL))]
    for r,col in enumerate(sev_colors_row):
        if col: sc += [("TEXTCOLOR",(0,r),(1,r),rc(col)), ("ROWBACKGROUNDS",(0,r),(0,r),[rc(C_DARK)])]
    summ_tbl.setStyle(TableStyle(sc))
    story += [summ_tbl, SP(4)]

    story += [heading("Business Impact", C_RED, 10)]
    if nc+nh > 0:
        for txt in [
            "Potential unauthorized access to sensitive systems and customer data",
            "Risk of data exfiltration impacting confidentiality and compliance (GDPR, PCI-DSS)",
            "Reputational and financial impact if vulnerabilities are exploited externally",
        ]: story.append(bullet(txt))
    else:
        story.append(P("No critical or high findings. Maintain current controls and address medium findings.", sBody))
    story += [PageBreak()]

    # ════════════════════════════════════════════════════════════════
    # 2. SCOPE & METHODOLOGY
    # ════════════════════════════════════════════════════════════════
    story += [heading("2. SCOPE &amp; METHODOLOGY", C_BLUE, 13), HR(), SP(2)]
    story.append(kv_table([
        ("Assessment Type",  "External Black-Box Penetration Test"),
        ("Dates",            date_str),
        ("Standard",         "PTES / NIST SP 800-115 / OWASP Testing Guide v4.2"),
        ("Authorization",    "Authorized by engagement agreement prior to testing"),
        ("Targets in Scope", ", ".join(targets[:6])),
        ("Exclusions",       "DoS/DDoS, Social Engineering, Physical access, Production exploitation"),
    ]))
    story += [SP(4), heading("PTES Phases Executed", C_BLUE, 10)]
    ptes = [
        ("Pre-Engagement",        "Scope definition, authorization, objective setting"),
        ("Intelligence Gathering","WHOIS, DNS, SSL, Shodan, OSINT, subdomain enumeration, Google dorks"),
        ("Vulnerability Analysis","Nuclei (CVSS-rated templates), ZAP active scan, HTTP header review"),
        ("Exploitation",          "Non-destructive proof-of-concept verification only"),
        ("Reporting",             "PTES/NIST-aligned findings with remediation guidance"),
    ]
    ptbl = Table([[P(f"<b><font color='#4488ff'>{ph}</font></b>",sSmall), P(desc,sSmall)]
                  for ph,desc in ptes], colWidths=[55*mm,115*mm])
    ptbl.setStyle(TableStyle([("ROWBACKGROUNDS",(0,0),(-1,-1),[rc(C_DARK),rc(C_CARD)]),
                               ("GRID",(0,0),(-1,-1),0.2,rc(C_GREY)),
                               ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                               ("LEFTPADDING",(0,0),(-1,-1),4)]))
    story += [ptbl, SP(4), heading("CVSS v3.1 Scoring Scale", C_BLUE, 10)]
    cvss_data = [["Rating","CVSS Score","Action"],
                 ["Critical","9.0–10.0","Patch IMMEDIATELY — remote exploit, no auth required"],
                 ["High",    "7.0–8.9", "Patch within 72 hours — significant impact"],
                 ["Medium",  "4.0–6.9", "Patch within 30 days — conditional exploit"],
                 ["Low",     "0.1–3.9", "Patch within 90 days — minimal risk"],
                 ["Info",    "0.0",     "Informational — best practice recommendation"]]
    ctbl = Table(cvss_data, colWidths=[22*mm,26*mm,122*mm])
    cc = [("BACKGROUND",(0,0),(-1,0),rc(C_DARK)),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
          ("TEXTCOLOR",(0,0),(-1,0),rc(C_TEAL)),("FONTSIZE",(0,0),(-1,-1),8),
          ("GRID",(0,0),(-1,-1),0.3,rc(C_GREY)),("TOPPADDING",(0,0),(-1,-1),3),
          ("BOTTOMPADDING",(0,0),(-1,-1),3),("LEFTPADDING",(0,0),(-1,-1),4)]
    for r,col in [(1,C_RED),(2,C_ORANGE),(3,C_YELLOW),(4,C_BLUE),(5,C_GREY)]:
        cc.append(("TEXTCOLOR",(0,r),(0,r),rc(col)))
    ctbl.setStyle(TableStyle(cc))
    story += [ctbl, PageBreak()]

    # ════════════════════════════════════════════════════════════════
    # 3. ATTACK SURFACE OVERVIEW
    # ════════════════════════════════════════════════════════════════
    story += [heading("3. ATTACK SURFACE OVERVIEW", C_TEAL, 13), HR(), SP(2)]

    if subdomains:
        story += [heading(f"Subdomain Enumeration — {len(subdomains)} Discovered", C_TEAL, 10)]
        live = set(data.get("SUBFINDER",{}).get("live_subdomains",[]))
        chunks = [subdomains[i:i+3] for i in range(0, min(len(subdomains),60), 3)]
        sub_rows = []
        for row in chunks:
            cells = []
            for s in row:
                col_hex = "#00c88c" if s in live else "#607080"
                cells.append(P(f'<font color="{col_hex}">{"● " if s in live else "○ "}{_esc(s[:30])}</font>', sSmall, raw=True))
            while len(cells) < 3: cells.append(P(""))
            sub_rows.append(cells)
        if sub_rows:
            stbl = Table(sub_rows, colWidths=[57*mm]*3)
            stbl.setStyle(TableStyle([("ROWBACKGROUNDS",(0,0),(-1,-1),[rc(C_DARK),rc(C_CARD)]),
                                       ("GRID",(0,0),(-1,-1),0.2,rc(C_GREY)),
                                       ("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2),
                                       ("LEFTPADDING",(0,0),(-1,-1),4)]))
            story += [stbl, SP(2)]
        if len(subdomains) > 60:
            story.append(P(f"… {len(subdomains)-60} more subdomains (see Appendix)", sSmall))
        story.append(SP(4))

    # Open ports table
    nmap_d = data.get("NMAP",{})
    if nmap_d.get("hosts"):
        all_ports = [p for h in nmap_d["hosts"] for p in h.get("ports",[])]
        story += [heading(f"Port Scan Results — {len(all_ports)} Services Identified", C_ORANGE, 10)]
        risky = {21,22,23,25,53,80,110,135,139,443,445,3306,3389,5900,6379,8080,27017}
        port_rows = [["Port","Service","Product / Version","Risk"]]
        for p in all_ports[:40]:
            pn = p.get("port",0)
            risk = "⚠ REVIEW" if pn in risky else "OK"
            rc_col = "#ff8c00" if pn in risky else "#00be6c"
            port_rows.append([
                P(f'<b><font color="#ff8c00">{pn}</font></b>' if pn in risky else str(pn), sSmall),
                P(p.get("service","")[:16], sSmall),
                P(f"{p.get('product','')} {p.get('version','')}".strip()[:45], sSmall),
                P(f'<font color="{rc_col}"><b>{risk}</b></font>', sSmall, raw=True),
            ])
        ptbl2 = Table(port_rows, colWidths=[18*mm,26*mm,108*mm,18*mm])
        ptbl2.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),rc(C_DARK)),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("TEXTCOLOR",(0,0),(-1,0),rc(C_ORANGE)),("FONTSIZE",(0,0),(-1,-1),8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[rc(C_DARK),rc(C_CARD)]),
            ("GRID",(0,0),(-1,-1),0.3,rc(C_GREY)),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
            ("LEFTPADDING",(0,0),(-1,-1),4)]))
        story += [ptbl2, SP(4)]

    # SSL
    ssl = data.get("SSL",{})
    if ssl and not ssl.get("error"):
        story += [heading("SSL/TLS Certificate", C_TEAL, 10),
                  kv_table([
                      ("Issuer",   str(ssl.get("issuer",{}).get("organizationName","—"))),
                      ("Expires",  ssl.get("expires","—")),
                      ("Days Left",str(ssl.get("days_until_expiry","—"))),
                      ("Protocol", str(ssl.get("cipher",{}).get("protocol","—"))),
                      ("Cipher",   str(ssl.get("cipher",{}).get("name","—"))),
                  ]), SP(4)]

    # HTTP headers
    httpx = data.get("HTTPX",{})
    for ue in httpx.get("urls",[])[:1]:
        if "error" in ue: break
        story += [heading("Web Technology &amp; Security Headers", C_TEAL, 10),
                  kv_table([
                      ("URL",       ue.get("url","—")),
                      ("Server",    ue.get("server","—")),
                      ("Tech Stack",", ".join(ue.get("technologies",[]) or ["—"])[:80]),
                      ("Missing Security Headers", ", ".join(ue.get("missing_headers",[]) or ["None"])),
                  ]), SP(4)]
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════
    # 4. TECHNICAL FINDINGS
    # ════════════════════════════════════════════════════════════════
    story += [heading("4. TECHNICAL FINDINGS", C_PURPLE, 13), HR(), SP(2)]
    if not all_f:
        story.append(P("No automated vulnerabilities identified. Manual testing and periodic "
                       "re-assessment are still recommended.", sBody))
    else:
        story.append(P(f"{len(all_f)} total findings: {nc} Critical · {nh} High · "
                       f"{nm} Medium · {nl} Low.", sBody))
        story.append(SP(4))
        for i, f in enumerate(all_f[:50], 1):
            sev   = f.get("_sev","info")
            col   = _sev_col(sev)
            col_hex = "#{:02x}{:02x}{:02x}".format(int(col[0]*255),int(col[1]*255),int(col[2]*255))
            name  = f.get("name","Unknown Finding")[:80]
            url   = f.get("url","—")[:100]
            desc  = (f.get("description","") or "")[:400]
            fix   = (f.get("solution","") or f.get("remediation","") or "")[:300]
            cves  = f.get("cve") or []
            if isinstance(cves,str): cves=[cves]
            cvss_raw = f.get("cvss_score") or f.get("cvss","N/A")
            try:    cvss_str = f"{float(cvss_raw):.1f}"
            except: cvss_str = "N/A"

            header_rows = [[
                P(f'<b><font color="{col_hex}">Finding #{i:02d} — {_esc(name)}</font></b>', sSmall, raw=True),
                P(f'<font color="{col_hex}"><b>{_esc(sev).upper()} | CVSS {cvss_str}</b></font>',
                  S("fb", fontSize=8, fontName="Helvetica-Bold", alignment=TA_RIGHT), raw=True),
            ]]
            htbl = Table(header_rows, colWidths=[130*mm,40*mm])
            htbl.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),col),
                ("LEFTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),4),
                ("BOTTOMPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),6),
            ]))
            detail_rows = [
                [P("<b>URL / System:</b>",sSmall, raw=True), P(url, sMono)],
                [P("<b>Source:</b>",sSmall, raw=True),       P(f.get("_src",""), sSmall)],
            ]
            if cves: detail_rows.append([P("<b>CVE(s):</b>",sSmall, raw=True), P(", ".join(cves[:5]), sSmall)])
            if desc: detail_rows.append([P("<b>Description:</b>",sSmall, raw=True), P(desc, sSmall)])
            if fix:  detail_rows.append([P("<b>Recommended Fix:</b>",sSmall, raw=True),
                                         P(f'<font color="#00c88c">{_esc(fix)}</font>', sSmall, raw=True)])
            dtbl = Table(detail_rows, colWidths=[32*mm, 138*mm])
            dtbl.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),rc(C_CARD)),
                ("GRID",(0,0),(-1,-1),0.2,rc(C_DARK)),
                ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                ("LEFTPADDING",(0,0),(-1,-1),4),("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))
            story.append(KeepTogether([htbl, dtbl, SP(3)]))

        if len(all_f) > 50:
            story.append(P(f"NOTE: {len(all_f)-50} additional findings available in the EXPEDITE STRIKE platform.", sSmall))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════
    # 5. REMEDIATION
    # ════════════════════════════════════════════════════════════════
    story += [heading("5. REMEDIATION &amp; RECOMMENDATIONS", C_GREEN, 13), HR(), SP(2),
              P("Remediation actions are prioritized by severity and aligned with CIS Critical "
                "Security Controls v8 and NIST SP 800-53 Rev 5.", sBody), SP(4)]

    rem_phases = [
        ("PRIORITY 1 — IMMEDIATE (0–72 hours)", C_RED, [
            f"Remediate all {nc} Critical finding(s) without delay",
            "Apply interim mitigations: WAF rules, firewall ACLs for exposed critical services",
            "Enable enhanced logging and alerting on affected systems",
            "Brief senior stakeholders on highest-risk findings",
        ]),
        ("PRIORITY 2 — SHORT TERM (72 hrs – 2 weeks)", C_ORANGE, [
            f"Remediate all {nh} High severity findings",
            "Patch identified vulnerable software with vendor-supplied updates",
            "Enforce HTTPS everywhere; implement HSTS preloading",
            "Deploy missing security headers (CSP, X-Frame-Options, X-Content-Type-Options)",
        ]),
        ("PRIORITY 3 — MEDIUM TERM (2–8 weeks)", C_YELLOW, [
            f"Remediate all {nm} Medium severity findings",
            "Implement Web Application Firewall (WAF) on all external services",
            "Enforce TLS 1.2+ minimum; disable TLS 1.0/1.1 and weak ciphers",
            "Implement DMARC, DKIM, SPF DNS records if missing",
            "Review and restrict all non-essential exposed ports",
        ]),
        ("PRIORITY 4 — LONG TERM (1–3 months)", C_BLUE, [
            "Establish a continuous vulnerability management programme",
            "Implement subdomain monitoring and takeover prevention",
            "Schedule next external penetration test (minimum: annually)",
            "Align security programme with ISO 27001 or SOC 2 Type II",
        ]),
    ]
    for title, col, items in rem_phases:
        col_hex = "#{:02x}{:02x}{:02x}".format(int(col[0]*255),int(col[1]*255),int(col[2]*255))
        story += [P(f'<font color="{col_hex}"><b>{title}</b></font>',
                    S("rt", fontSize=9, fontName="Helvetica-Bold", spaceBefore=6,
                      spaceAfter=3, backColor=rc(C_DARK), borderPad=4))]
        for item in items: story.append(bullet(item, col))
        story.append(SP(2))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════
    # 6. STRATEGIC ROADMAP
    # ════════════════════════════════════════════════════════════════
    story += [heading("6. STRATEGIC SECURITY ROADMAP", C_TEAL, 13), HR(), SP(2),
              P("A structured 90-day plan for addressing findings and improving overall security posture.", sBody), SP(4)]

    roadmap = [
        ("Days 1–7",   "IMMEDIATE RESPONSE",    C_RED,    ["Confirm all critical findings and apply patches or interim controls","Brief security team and stakeholders","Initiate incident response if active exploitation suspected"]),
        ("Days 8–30",  "SHORT-TERM HARDENING",  C_ORANGE, ["Remediate High findings; verify all critical fixes","Deploy security headers across all web properties","Enforce TLS 1.2+ and disable weak protocols"]),
        ("Days 31–60", "MEDIUM-TERM IMPROVEMENTS",C_YELLOW,["Address Medium findings; improve DNS security","Review and restrict public-facing service exposure","Conduct internal security awareness briefing"]),
        ("Days 61–90", "LONG-TERM MATURITY",    C_TEAL,   ["Establish continuous scanning and vulnerability management","Define security KPIs and monthly reporting cadence","Schedule next penetration test and evaluate WAF deployment"]),
    ]
    rm_rows = []
    for phase, title, col, tasks in roadmap:
        col_hex = "#{:02x}{:02x}{:02x}".format(int(col[0]*255),int(col[1]*255),int(col[2]*255))
        tasks_html = "<br/>".join(f"• {t}" for t in tasks)
        rm_rows.append([
            P(f'<font color="{col_hex}"><b>{phase}</b></font>', sSmall),
            P(f'<b><font color="{col_hex}">{title}</font></b><br/><font color="#e8eaf0">{tasks_html}</font>', sSmall),
        ])
    rm_tbl = Table(rm_rows, colWidths=[30*mm, 140*mm])
    rm_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[rc(C_DARK),rc(C_CARD)]),
        ("GRID",(0,0),(-1,-1),0.3,rc(C_GREY)),
        ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("LEFTPADDING",(0,0),(-1,-1),6),("VALIGN",(0,0),(-1,-1),"TOP"),
    ]))
    story += [rm_tbl, PageBreak()]

    # ════════════════════════════════════════════════════════════════
    # 7. APPENDICES
    # ════════════════════════════════════════════════════════════════
    story += [heading("7. APPENDICES", C_GREY, 13), HR(), SP(2),
              heading("Appendix A: Tools &amp; Versions", C_TEAL, 10)]
    tools = [
        ("WHOIS","python-whois / CLI","Domain registration, registrar, name servers"),
        ("DNS","dig (BIND utils)","A/MX/NS/TXT/SOA record enumeration"),
        ("SSL/TLS","Python ssl / crt.sh","Certificate validity, cipher suite analysis"),
        ("Subfinder","projectdiscovery","Passive subdomain enumeration"),
        ("Shodan","Shodan API","Exposed device intelligence, CVE cross-reference"),
        ("Nmap","Nmap 7.x+","Full TCP port scan; service version detection"),
        ("HTTPX","Custom module","HTTP fingerprinting, security header audit"),
        ("Feroxbuster","feroxbuster","Directory and file discovery"),
        ("Nuclei","projectdiscovery","CVE & misconfiguration template scanning"),
        ("OWASP ZAP","ZAP 2.x+","Active web application scanning"),
    ]
    tool_rows = [["Tool","Version / Source","Purpose"]] + \
                [[P(f'<b><font color="#00c88c">{t}</font></b>',sSmall), P(v,sSmall), P(p,sSmall)]
                 for t,v,p in tools]
    ttbl = Table(tool_rows, colWidths=[24*mm,38*mm,108*mm])
    ttbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),rc(C_DARK)),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("TEXTCOLOR",(0,0),(-1,0),rc(C_TEAL)),("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[rc(C_DARK),rc(C_CARD)]),
        ("GRID",(0,0),(-1,-1),0.3,rc(C_GREY)),
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
        ("LEFTPADDING",(0,0),(-1,-1),4)]))
    story += [ttbl, SP(6), heading("Appendix B: References", C_TEAL, 10)]
    refs = [
        ("PTES","Penetration Testing Execution Standard","http://www.pentest-standard.org/"),
        ("NIST SP 800-115","Technical Guide to Information Security Testing","https://csrc.nist.gov/publications/detail/sp/800-115/final"),
        ("OWASP WSTG v4.2","OWASP Web Security Testing Guide","https://owasp.org/www-project-web-security-testing-guide/"),
        ("CIS Controls v8","CIS Critical Security Controls","https://www.cisecurity.org/controls/"),
        ("CVSS v3.1","Common Vulnerability Scoring System","https://www.first.org/cvss/"),
        ("MITRE ATT&CK","Adversary Tactics, Techniques & Common Knowledge","https://attack.mitre.org/"),
    ]
    for abbr, name, url in refs:
        story.append(P(f'<b><font color="#00c88c">{abbr}</font></b>  '
                       f'<font color="#e8eaf0">{name}</font>  '
                       f'<font color="#4488ff">{url}</font>', sSmall))
    story += [SP(10), HR(), SP(6),
              P("CONFIDENTIAL — For authorized recipients only. "
                "This report must not be reproduced or distributed without written consent.", sSmall)]

    doc.build(story, onFirstPage=bg_page, onLaterPages=bg_page)
    return output_path


def _html_fallback(results, output_path, err):
    """Minimal HTML fallback if ReportLab not available."""
    html_path = output_path.replace(".pdf",".html")
    with open(html_path,"w") as f:
        f.write(f"<html><body><h1>EXPEDITE STRIKE Pentest Report</h1><p>PDF library error: {err}</p>"
                f"<pre>{__import__('json').dumps(results, indent=2, default=str)[:5000]}</pre></body></html>")
    return html_path


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 3:
        print("Usage: python3 pt_pdf_generator.py results.json output.pdf")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        results = json.load(f)
    out = generate_pdf(results, sys.argv[2])
    print(f"✓ Report: {out}")
