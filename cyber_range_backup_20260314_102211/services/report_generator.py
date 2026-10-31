"""
AegisProbe — PTES / NIST 800-115 Penetration Test Report Generator
====================================================================
Transforms raw AegisProbe JSON findings into a professional,
standards-compliant penetration testing report (HTML, print-to-PDF ready).

Standards referenced:
  • PTES (Penetration Testing Execution Standard)
  • NIST SP 800-115 — Technical Guide to Information Security Testing
  • NIST SP 800-30 Rev.1 — Risk Assessment
  • CVSS v3.1 severity banding
"""

import os
import json
import glob
import html
from datetime import datetime, timezone

REPORT_DIR = "/mnt/scans/reports"
SCAN_DIR   = "/mnt/scans/incoming/aegisprobe"

# ── NIST / CVSS severity banding ───────────────────────────────────────
NIST_BAND = {
    "Critical":    {"color": "#c0392b", "bg": "#fdf0ef", "nist": "Very High",   "cvss": "9.0–10.0"},
    "High":        {"color": "#e67e22", "bg": "#fdf5e9", "nist": "High",        "cvss": "7.0–8.9"},
    "Medium":      {"color": "#f39c12", "bg": "#fefbe8", "nist": "Moderate",    "cvss": "4.0–6.9"},
    "Low":         {"color": "#27ae60", "bg": "#eafaf1", "nist": "Low",         "cvss": "0.1–3.9"},
    "Information": {"color": "#2980b9", "bg": "#eaf4fd", "nist": "Informational","cvss": "0.0"},
}

# ── Remediation knowledge base keyed by CWE ────────────────────────────
REMEDIATION = {
    "CWE-89":  {
        "title":   "SQL Injection",
        "impact":  "Attackers may read, modify, or delete database contents; authentication bypass; remote code execution.",
        "remediation": (
            "Use parameterised queries or prepared statements for all database interactions. "
            "Adopt an allow-list input validation approach. Apply the principle of least privilege "
            "to database accounts. Enable WAF rules for SQLi signatures."
        ),
        "refs": ["OWASP A03:2021", "NIST 800-53 SI-10", "CWE-89"],
    },
    "CWE-79":  {
        "title":   "Cross-Site Scripting (XSS)",
        "impact":  "Session hijacking, credential theft, malware distribution, UI defacement.",
        "remediation": (
            "Apply output encoding (HTML, JS, CSS) contextually using a library such as OWASP ESAPI. "
            "Implement a strict Content-Security-Policy header. Sanitise all user-supplied data "
            "before rendering. Set HttpOnly flag on session cookies."
        ),
        "refs": ["OWASP A03:2021", "NIST 800-53 SI-10", "CWE-79"],
    },
    "CWE-918": {
        "title":   "Server-Side Request Forgery (SSRF)",
        "impact":  "Internal network port scanning, cloud metadata theft (AWS/GCP), lateral movement.",
        "remediation": (
            "Validate and sanitise all URLs accepted as input. Use an allow-list of permitted "
            "schemes and destination hosts. Block requests to private RFC-1918 ranges and cloud "
            "metadata endpoints at the network layer. Disable unnecessary URL-fetching functionality."
        ),
        "refs": ["OWASP A10:2021", "NIST 800-53 SC-7", "CWE-918"],
    },
    "CWE-22":  {
        "title":   "Path Traversal (LFI)",
        "impact":  "Sensitive file disclosure (/etc/passwd, application configs, credentials).",
        "remediation": (
            "Canonicalise file paths before use and verify they reside within the intended base directory. "
            "Reject path inputs containing '../' sequences. Apply a allow-list of permitted file names "
            "or resource identifiers. Run applications with minimal OS privileges."
        ),
        "refs": ["OWASP A01:2021", "NIST 800-53 AC-6", "CWE-22"],
    },
    "CWE-78":  {
        "title":   "OS Command Injection",
        "impact":  "Arbitrary command execution with web-server privileges; full host compromise.",
        "remediation": (
            "Avoid invoking OS shell commands from application code. Where unavoidable, use language-level "
            "APIs that accept argument arrays (not shell strings). Apply strict input validation. "
            "Implement application-level sandboxing and run under a restricted OS account."
        ),
        "refs": ["OWASP A03:2021", "NIST 800-53 SI-10", "CWE-78"],
    },
    "CWE-601": {
        "title":   "Open Redirect",
        "impact":  "Phishing, credential harvesting, OAuth token theft.",
        "remediation": (
            "Use an indirect reference map for redirect destinations. Validate redirect targets "
            "against an allow-list of trusted domains. Display an intermediate warning page before "
            "redirecting off-site."
        ),
        "refs": ["OWASP A01:2021", "CWE-601"],
    },
    "CWE-942": {
        "title":   "CORS Misconfiguration",
        "impact":  "Cross-origin data theft including authenticated API responses if credentials are allowed.",
        "remediation": (
            "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins. "
            "Never reflect arbitrary Origin headers. Do not combine Access-Control-Allow-Credentials: true "
            "with a wildcard or reflected origin. Audit all API endpoints for CORS headers."
        ),
        "refs": ["OWASP A05:2021", "CWE-942"],
    },
    "CWE-614": {
        "title":   "Missing Secure Flag on Cookie",
        "impact":  "Session cookie intercepted over plain HTTP, enabling session hijacking.",
        "remediation": "Set the Secure flag on all session and authentication cookies. Enforce HTTPS site-wide.",
        "refs": ["OWASP A02:2021", "CWE-614"],
    },
    "CWE-1004":{
        "title":   "Missing HttpOnly Flag on Cookie",
        "impact":  "Session token accessible via client-side JavaScript, enabling XSS-triggered session theft.",
        "remediation": "Set the HttpOnly flag on all session and authentication cookies.",
        "refs": ["OWASP A02:2021", "CWE-1004"],
    },
    "CWE-639": {
        "title":   "Insecure Direct Object Reference (IDOR)",
        "impact":  "Horizontal / vertical privilege escalation; unauthorised data access.",
        "remediation": (
            "Implement authorisation checks on every resource access, server-side. Use indirect, "
            "unpredictable identifiers (e.g. UUIDs). Apply per-user access control at the data layer."
        ),
        "refs": ["OWASP A01:2021", "NIST 800-53 AC-3", "CWE-639"],
    },
    "CWE-327": {
        "title":   "Weak Cryptographic Algorithm (JWT)",
        "impact":  "Token forgery, authentication bypass, privilege escalation.",
        "remediation": (
            "Use RS256 / ES256 asymmetric algorithms for JWT signing. Explicitly reject the 'none' algorithm. "
            "Rotate signing secrets and enforce minimum secret length (≥256 bits for HS256)."
        ),
        "refs": ["OWASP A02:2021", "NIST 800-53 IA-5", "CWE-327"],
    },
    "CWE-425": {
        "title":   "Forced Browsing / Direct Request",
        "impact":  "Unauthorised access to administrative or restricted functionality.",
        "remediation": (
            "Apply authorisation checks at every endpoint, not just at the UI layer. "
            "Use a centralised access control framework. Remove or restrict access to administrative paths."
        ),
        "refs": ["OWASP A01:2021", "CWE-425"],
    },
    "CWE-538": {
        "title":   "Sensitive File Exposure",
        "impact":  "Credential harvesting, source code disclosure, server configuration leak.",
        "remediation": (
            "Remove sensitive files from the web root. Configure the web server to deny access "
            "to configuration files (.env, .git, web.config). Implement egress filtering and "
            "regular directory listing audits."
        ),
        "refs": ["OWASP A05:2021", "CWE-538"],
    },
    "CWE-1021":{
        "title":   "Clickjacking / UI Redressing",
        "impact":  "Users tricked into performing unintended actions on the victim site.",
        "remediation": (
            "Set X-Frame-Options: DENY or SAMEORIGIN. Implement a Content-Security-Policy "
            "with frame-ancestors 'none' directive."
        ),
        "refs": ["OWASP A05:2021", "CWE-1021"],
    },
    "CWE-200": {
        "title":   "Information Disclosure",
        "impact":  "Leakage of internal architecture, version strings, or file structures aiding further attacks.",
        "remediation": (
            "Remove or suppress verbose error messages, server banners, and X-Powered-By headers. "
            "Configure web server to return minimal header information. Review robots.txt for "
            "inadvertent path disclosure."
        ),
        "refs": ["OWASP A05:2021", "CWE-200"],
    },
    "CWE-319": {
        "title":   "Cleartext Transmission (HSTS)",
        "impact":  "SSL stripping attacks on unsecured networks exposing session tokens and credentials.",
        "remediation": (
            "Enable HTTP Strict Transport Security (HSTS) with a max-age ≥ 31536000 seconds "
            "and includeSubDomains. Submit the domain to the HSTS preload list."
        ),
        "refs": ["OWASP A02:2021", "CWE-319"],
    },
    "CWE-20":  {
        "title":   "Improper Input Validation",
        "impact":  "Unpredictable application behaviour or injection vulnerabilities via malformed input.",
        "remediation": (
            "Implement server-side input validation against a strict allow-list schema. "
            "Reject, not sanitise, malformed input. Apply length, type, and format constraints."
        ),
        "refs": ["OWASP A03:2021", "NIST 800-53 SI-10", "CWE-20"],
    },
}

_GENERIC_REMED = {
    "title":   "Security Vulnerability",
    "impact":  "Potential exposure of application data or functionality to unauthorised parties.",
    "remediation": (
        "Review the affected component against security baseline standards. Apply vendor patches, "
        "enforce least-privilege access, and conduct a targeted code review."
    ),
    "refs": ["NIST 800-115", "OWASP Testing Guide v4"],
}


# ── HTML template ──────────────────────────────────────────────────────
def _css():
    return """
    :root{--red:#c0392b;--org:#e67e22;--yel:#f39c12;--grn:#27ae60;--blu:#2980b9;
          --dk:#1a1a2e;--mid:#16213e;--acc:#0f3460;--txt:#2d3436;--muted:#636e72}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',Arial,sans-serif;color:var(--txt);background:#f8f9fa;font-size:13px;line-height:1.6}
    @media print{.no-print{display:none}.page-break{page-break-before:always}}
    /* Cover */
    .cover{background:linear-gradient(135deg,var(--dk),var(--acc));color:#fff;
           padding:80px 60px;min-height:100vh;display:flex;flex-direction:column;justify-content:center}
    .cover-badge{background:#e74c3c;color:#fff;padding:4px 14px;border-radius:20px;
                 font-size:11px;font-weight:700;display:inline-block;margin-bottom:20px;letter-spacing:1px}
    .cover h1{font-size:38px;font-weight:800;margin-bottom:10px;letter-spacing:-0.5px}
    .cover h2{font-size:20px;font-weight:400;opacity:.8;margin-bottom:40px}
    .cover-meta{border-top:1px solid rgba(255,255,255,.2);padding-top:30px;margin-top:30px;
                display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
    .cover-meta-item label{font-size:10px;opacity:.6;text-transform:uppercase;letter-spacing:1px}
    .cover-meta-item span{display:block;font-size:15px;font-weight:600;margin-top:2px}
    /* TOC */
    .toc{padding:50px 60px;background:#fff;border-bottom:2px solid #ecf0f1}
    .toc h3{font-size:18px;font-weight:700;margin-bottom:20px;color:var(--dk)}
    .toc-item{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px dotted #ddd;
              font-size:13px;color:var(--txt)}
    .toc-item a{text-decoration:none;color:var(--txt);font-weight:500}
    .toc-item a:hover{color:var(--blu)}
    .toc-section{font-weight:700;color:var(--dk);margin-top:12px}
    /* Sections */
    .section{padding:50px 60px;border-bottom:1px solid #ecf0f1;background:#fff}
    .section:nth-child(even){background:#f9fafb}
    .section-header{display:flex;align-items:center;gap:12px;margin-bottom:24px;
                    padding-bottom:12px;border-bottom:3px solid var(--acc)}
    .section-num{background:var(--acc);color:#fff;width:36px;height:36px;border-radius:50%;
                 display:flex;align-items:center;justify-content:center;
                 font-weight:700;font-size:14px;flex-shrink:0}
    .section-title{font-size:22px;font-weight:700;color:var(--dk)}
    /* Exec summary KPIs */
    .kpi-row{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin:20px 0}
    .kpi{border-radius:8px;padding:18px;text-align:center}
    .kpi-num{font-size:36px;font-weight:900}
    .kpi-label{font-size:11px;text-transform:uppercase;letter-spacing:.8px;margin-top:4px;opacity:.7}
    /* Risk bar */
    .risk-bar{display:flex;border-radius:6px;overflow:hidden;height:28px;margin:16px 0}
    .risk-seg{display:flex;align-items:center;justify-content:center;
              font-size:11px;font-weight:700;color:#fff;min-width:24px}
    /* Finding cards */
    .finding{border:1px solid #e0e0e0;border-radius:8px;margin-bottom:20px;overflow:hidden;
             box-shadow:0 1px 4px rgba(0,0,0,.06)}
    .finding-header{padding:12px 16px;display:flex;align-items:center;gap:12px}
    .finding-body{padding:16px;background:#fff}
    .sev-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;
               color:#fff;white-space:nowrap}
    .finding-title{font-size:15px;font-weight:700;color:var(--dk)}
    .finding-meta{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;
                  margin:12px 0;padding:12px;background:#f8f9fa;border-radius:6px;
                  font-size:12px}
    .meta-lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
    .meta-val{font-weight:600;color:var(--dk);margin-top:2px}
    .block-lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;
               color:var(--muted);margin:14px 0 5px}
    .evidence{background:#1e1e2e;color:#a8ff78;font-family:monospace;font-size:11px;
              padding:10px 14px;border-radius:4px;white-space:pre-wrap;word-break:break-all;
              max-height:120px;overflow-y:auto}
    .remed{background:#eafaf1;border-left:4px solid var(--grn);padding:12px;
           border-radius:0 6px 6px 0;font-size:12px;line-height:1.7}
    .impact{background:#fdf5e9;border-left:4px solid var(--org);padding:12px;
            border-radius:0 6px 6px 0;font-size:12px;line-height:1.7}
    .refs{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
    .ref-tag{background:#e8f4fd;color:var(--blu);padding:2px 8px;border-radius:12px;
             font-size:10px;font-weight:600}
    /* Tables */
    table{width:100%;border-collapse:collapse;font-size:12px;margin:12px 0}
    th{background:var(--dk);color:#fff;padding:9px 12px;text-align:left;font-size:11px;
       text-transform:uppercase;letter-spacing:.5px}
    td{padding:8px 12px;border-bottom:1px solid #ecf0f1;vertical-align:top}
    tr:hover td{background:#f8f9fa}
    /* Footer */
    .footer{background:var(--dk);color:rgba(255,255,255,.5);text-align:center;
            padding:20px;font-size:11px}
    """


def _sev_style(sev):
    c = NIST_BAND.get(sev, NIST_BAND["Information"])
    return f'background:{c["color"]}'


def _kpi_card(sev, count):
    c = NIST_BAND.get(sev, NIST_BAND["Information"])
    return f"""<div class="kpi" style="background:{c['bg']};border:1px solid {c['color']}30">
        <div class="kpi-num" style="color:{c['color']}">{count}</div>
        <div class="kpi-label" style="color:{c['color']}">{sev}</div>
      </div>"""


def _risk_bar_seg(sev, count, total):
    if not count: return ""
    c = NIST_BAND[sev]["color"]
    pct = max(count / total * 100, 2)
    label = sev[0] if count < 3 else f"{count}"
    return f'<div class="risk-seg" style="flex:{pct};background:{c}">{label}</div>'


def _finding_card(idx, f, kb):
    sev  = f.get("severity", "Information")
    c    = NIST_BAND.get(sev, NIST_BAND["Information"])
    name = html.escape(f.get("name","Unknown Finding"))
    cwe  = f.get("cwe","")
    cvss = f.get("cvss", 0.0)
    url  = html.escape(str(f.get("url","") or f.get("param","") or ""))
    ev   = html.escape(str(f.get("evidence","") or "")[:500])
    plugin = html.escape(f.get("plugin",""))
    info   = kb.get(cwe, _GENERIC_REMED)
    refs_html = "".join(f'<span class="ref-tag">{html.escape(r)}</span>' for r in info["refs"])

    return f"""
    <div class="finding" id="finding-{idx}">
      <div class="finding-header" style="background:{c['bg']}">
        <span class="sev-badge" style="{_sev_style(sev)}">{sev}</span>
        <span class="finding-title">{name}</span>
      </div>
      <div class="finding-body">
        <div class="finding-meta">
          <div><div class="meta-lbl">Plugin / Module</div><div class="meta-val">{plugin}</div></div>
          <div><div class="meta-lbl">CWE Reference</div><div class="meta-val">{html.escape(cwe) or '—'}</div></div>
          <div><div class="meta-lbl">CVSS Score</div><div class="meta-val">{cvss if cvss else '—'}</div></div>
          <div><div class="meta-lbl">NIST Risk Level</div>
               <div class="meta-val" style="color:{c['color']}">{c['nist']}</div></div>
        </div>
        {"<div class='block-lbl'>URL / Parameter</div><div class='evidence'>" + url + "</div>" if url else ""}
        <div class="block-lbl">Business Impact</div>
        <div class="impact">{html.escape(info['impact'])}</div>
        {"<div class='block-lbl'>Evidence</div><div class='evidence'>" + ev + "</div>" if ev else ""}
        <div class="block-lbl">Remediation Recommendation</div>
        <div class="remed">{html.escape(info['remediation'])}</div>
        <div class="block-lbl">References</div>
        <div class="refs">{refs_html}</div>
      </div>
    </div>"""


def generate_report(scan_json_path: str, meta: dict | None = None) -> str:
    """
    Read an AegisProbe JSON report and return a full PTES/NIST HTML report string.
    Also saves the report to REPORT_DIR.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)

    with open(scan_json_path) as fp:
        data = json.load(fp)

    target    = data.get("target", "Unknown Target")
    timestamp = data.get("timestamp", datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    findings  = data.get("findings", [])
    now_str   = datetime.now().strftime("%B %d, %Y")
    ts_fmt    = timestamp[:4] + "-" + timestamp[4:6] + "-" + timestamp[6:8]

    # Counts
    SEV_ORDER = ["Critical","High","Medium","Low","Information"]
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity","Information")
        if s in counts: counts[s] += 1
    total = len(findings)

    # Risk score (weighted)
    weights = {"Critical":10,"High":7,"Medium":4,"Low":2,"Information":0}
    risk_score = min(100, sum(counts[s]*weights[s] for s in SEV_ORDER))

    overall_risk = "CRITICAL" if counts["Critical"] > 0 else (
        "HIGH" if counts["High"] > 0 else (
        "MEDIUM" if counts["Medium"] > 0 else "LOW"))
    overall_color = {"CRITICAL":"#c0392b","HIGH":"#e67e22","MEDIUM":"#f39c12","LOW":"#27ae60"}[overall_risk]

    # TOC finding list
    toc_findings = "".join(
        f'<div class="toc-item"><a href="#finding-{i+1}">'
        f'{i+1}. {html.escape(f.get("name",""))}</a>'
        f'<span style="color:{NIST_BAND.get(f.get(\"severity\",\"Information\"),NIST_BAND[\"Information\"])[\"color\"]};font-weight:700">'
        f'{f.get("severity","")}</span></div>'
        for i, f in enumerate(findings)
        if f.get("severity","") in ("Critical","High")
    )

    # Risk bar
    bar_html = "".join(_risk_bar_seg(s, counts[s], max(total,1)) for s in SEV_ORDER)

    # KPI pills
    kpi_html = "".join(_kpi_card(s, counts[s]) for s in SEV_ORDER)

    # Findings HTML (Critical+High first, then rest)
    ordered = sorted(findings, key=lambda f: SEV_ORDER.index(f.get("severity","Information")))
    findings_html = "".join(_finding_card(i+1, f, REMEDIATION) for i, f in enumerate(ordered))

    # Remediation summary table
    remediation_rows = ""
    for i, f in enumerate(ordered):
        sev = f.get("severity","Information")
        c   = NIST_BAND.get(sev, NIST_BAND["Information"])
        cwe = f.get("cwe","")
        kb  = REMEDIATION.get(cwe, _GENERIC_REMED)
        prio = {"Critical":"Immediate (< 24h)","High":"Short-term (< 1 week)",
                "Medium":"Medium-term (< 30 days)","Low":"Long-term (< 90 days)",
                "Information":"Best-effort"}.get(sev,"—")
        remediation_rows += f"""<tr>
          <td><span style="color:{c['color']};font-weight:700">{sev}</span></td>
          <td>{html.escape(f.get('name',''))}</td>
          <td>{html.escape(cwe)}</td>
          <td style="color:{c['color']};font-weight:600">{prio}</td>
          <td>{html.escape(kb['title'])}</td>
        </tr>"""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Penetration Test Report — {html.escape(target)}</title>
  <style>{_css()}</style>
</head>
<body>

<!-- ═══ COVER PAGE ═══════════════════════════════════════════════════ -->
<div class="cover">
  <div>
    <div class="cover-badge">CONFIDENTIAL — PTES COMPLIANT PENETRATION TEST REPORT</div>
    <h1>Web Application Penetration Test Report</h1>
    <h2>{html.escape(target)}</h2>
    <p style="opacity:.7;font-size:13px">
      Conducted in accordance with the Penetration Testing Execution Standard (PTES)
      and NIST Special Publication 800-115.
    </p>
    <div style="margin-top:24px;padding:16px 20px;background:rgba(255,255,255,.1);
                border-radius:8px;display:inline-block">
      <span style="font-size:13px;opacity:.7">Overall Risk Rating: </span>
      <span style="font-size:22px;font-weight:900;color:{overall_color}">{overall_risk}</span>
      &nbsp;&nbsp;|&nbsp;&nbsp;
      <span style="font-size:13px;opacity:.7">Risk Score: </span>
      <span style="font-size:22px;font-weight:900">{risk_score}/100</span>
    </div>
  </div>
  <div class="cover-meta">
    <div class="cover-meta-item">
      <label>Target System</label><span>{html.escape(target)}</span>
    </div>
    <div class="cover-meta-item">
      <label>Assessment Date</label><span>{ts_fmt}</span>
    </div>
    <div class="cover-meta-item">
      <label>Report Generated</label><span>{now_str}</span>
    </div>
    <div class="cover-meta-item">
      <label>Assessment Tool</label><span>AegisProbe v2.0</span>
    </div>
    <div class="cover-meta-item">
      <label>Total Findings</label><span>{total}</span>
    </div>
    <div class="cover-meta-item">
      <label>Standard</label><span>PTES / NIST 800-115</span>
    </div>
  </div>
</div>

<!-- ═══ TABLE OF CONTENTS ════════════════════════════════════════════ -->
<div class="toc">
  <h3>Table of Contents</h3>
  <div class="toc-item toc-section"><span>1.  Executive Summary</span></div>
  <div class="toc-item toc-section"><span>2.  Scope &amp; Engagement Overview</span></div>
  <div class="toc-item toc-section"><span>3.  Methodology (PTES Phases)</span></div>
  <div class="toc-item toc-section"><span>4.  Risk Rating Matrix</span></div>
  <div class="toc-item toc-section"><span>5.  Detailed Findings</span></div>
  {toc_findings}
  <div class="toc-item toc-section"><span>6.  Remediation Roadmap</span></div>
  <div class="toc-item toc-section"><span>7.  Appendix — Tool Output Summary</span></div>
</div>

<!-- ═══ SECTION 1: EXECUTIVE SUMMARY ════════════════════════════════ -->
<div class="section page-break" id="s1">
  <div class="section-header">
    <div class="section-num">1</div>
    <div class="section-title">Executive Summary</div>
  </div>
  <p>
    AegisProbe conducted an automated web application penetration test against
    <strong>{html.escape(target)}</strong> on {ts_fmt}.
    The assessment followed the <strong>Penetration Testing Execution Standard (PTES)</strong>
    and was scoped to active black-box testing of the application's HTTP attack surface.
  </p>
  <p style="margin-top:12px">
    The overall risk posture is rated <strong style="color:{overall_color}">{overall_risk}</strong>
    with a composite risk score of <strong>{risk_score}/100</strong>.
    {"The application contains <strong>Critical-severity</strong> vulnerabilities that pose an immediate risk of full compromise and must be remediated without delay." if counts['Critical'] > 0 else ""}
    {"<strong>High-severity</strong> vulnerabilities were identified that require prompt remediation." if counts['High'] > 0 else ""}
  </p>
  <div class="kpi-row" style="margin-top:24px">{kpi_html}</div>
  <p style="font-size:11px;color:var(--muted)">Risk Distribution</p>
  <div class="risk-bar">{bar_html}</div>
  <h4 style="margin-top:24px;margin-bottom:12px;color:var(--dk)">Key Observations</h4>
  <ul style="padding-left:20px;line-height:2">
    {"<li><strong style='color:#c0392b'>Critical:</strong> " + str(counts['Critical']) + " finding(s) — immediate exploitation risk</li>" if counts['Critical'] else ""}
    {"<li><strong style='color:#e67e22'>High:</strong> " + str(counts['High']) + " finding(s) — significant attack surface exposure</li>" if counts['High'] else ""}
    {"<li><strong style='color:#f39c12'>Medium:</strong> " + str(counts['Medium']) + " finding(s) — exploitable under specific conditions</li>" if counts['Medium'] else ""}
    {"<li><strong style='color:#27ae60'>Low:</strong> " + str(counts['Low']) + " finding(s) — defence-in-depth hardening required</li>" if counts['Low'] else ""}
    {"<li><strong style='color:#2980b9'>Informational:</strong> " + str(counts['Information']) + " observation(s) — no immediate risk</li>" if counts['Information'] else ""}
  </ul>
</div>

<!-- ═══ SECTION 2: SCOPE ═════════════════════════════════════════════ -->
<div class="section" id="s2">
  <div class="section-header">
    <div class="section-num">2</div>
    <div class="section-title">Scope &amp; Engagement Overview</div>
  </div>
  <table>
    <tr><th>Parameter</th><th>Detail</th></tr>
    <tr><td>Target URL</td><td><code>{html.escape(target)}</code></td></tr>
    <tr><td>Assessment Type</td><td>Black-Box Web Application Penetration Test</td></tr>
    <tr><td>Assessment Date</td><td>{ts_fmt}</td></tr>
    <tr><td>Tooling</td><td>AegisProbe v2.0 (15-plugin active scanner)</td></tr>
    <tr><td>Standard</td><td>PTES, NIST SP 800-115, OWASP Testing Guide v4</td></tr>
    <tr><td>Authorisation</td><td>Assumed — operator must ensure written authorisation on file</td></tr>
    <tr><td>Plugins Executed</td><td>SecurityHeaders, CookieSecurity, CORS, InfoDisclosure, Crawler,
        SQLi, XSS, SSRF, OpenRedirect, LFI, CommandInjection, IDOR, JWT, AuthBypass, Intruder</td></tr>
  </table>
  <p style="margin-top:14px;font-size:12px;color:var(--muted)">
    <strong>Scope Limitations:</strong> This assessment covers the specified target URL and paths 
    reachable via BFS crawl. Authentication-required areas, APIs behind auth tokens, and network-layer 
    controls are out of scope unless credentials were supplied.
  </p>
</div>

<!-- ═══ SECTION 3: METHODOLOGY ══════════════════════════════════════ -->
<div class="section" id="s3">
  <div class="section-header">
    <div class="section-num">3</div>
    <div class="section-title">Methodology — PTES Phases</div>
  </div>
  <table>
    <tr><th>PTES Phase</th><th>Activities Performed</th><th>Tools</th><th>Status</th></tr>
    <tr><td><strong>1. Pre-Engagement</strong></td>
        <td>Scope definition, target configuration, plugin selection</td>
        <td>AegisProbe UI</td><td style="color:#27ae60">✔ Complete</td></tr>
    <tr><td><strong>2. Intelligence Gathering</strong></td>
        <td>HTTP response header analysis, technology fingerprinting, robots.txt/sitemap enumeration, BFS crawl</td>
        <td>Crawler, InfoDisclosure, SecurityHeaders</td><td style="color:#27ae60">✔ Complete</td></tr>
    <tr><td><strong>3. Threat Modelling</strong></td>
        <td>OWASP Top 10 mapping, CWE classification, NIST risk banding</td>
        <td>AegisProbe Engine</td><td style="color:#27ae60">✔ Complete</td></tr>
    <tr><td><strong>4. Vulnerability Analysis</strong></td>
        <td>Passive header checks, cookie flag analysis, CORS policy review, JS file enumeration</td>
        <td>SecurityHeaders, CookieSecurity, CORS</td><td style="color:#27ae60">✔ Complete</td></tr>
    <tr><td><strong>5. Exploitation (Active)</strong></td>
        <td>SQL injection probing, reflected XSS, SSRF, LFI, command injection, IDOR enumeration, JWT bypass, forced browsing, parameter fuzzing</td>
        <td>SQLi, XSS, SSRF, LFI, CMDI, IDOR, JWT, AuthBypass, Intruder plugins</td><td style="color:#27ae60">✔ Complete</td></tr>
    <tr><td><strong>6. Post-Exploitation</strong></td>
        <td>Finding triage, CVSS scoring, impact assessment</td>
        <td>AegisProbe Engine</td><td style="color:#27ae60">✔ Complete</td></tr>
    <tr><td><strong>7. Reporting</strong></td>
        <td>PTES/NIST compliant report generation with remediation guidance</td>
        <td>AegisProbe Report Generator</td><td style="color:#27ae60">✔ Complete</td></tr>
  </table>
</div>

<!-- ═══ SECTION 4: RISK MATRIX ══════════════════════════════════════ -->
<div class="section" id="s4">
  <div class="section-header">
    <div class="section-num">4</div>
    <div class="section-title">Risk Rating Matrix (NIST SP 800-30 Rev.1 / CVSS v3.1)</div>
  </div>
  <table>
    <tr><th>Severity</th><th>NIST Risk Level</th><th>CVSS v3.1 Range</th><th>Definition</th><th>SLA</th></tr>
    <tr><td><strong style="color:#c0392b">Critical</strong></td><td>Very High</td><td>9.0–10.0</td>
        <td>Exploitation is trivial and results in full system compromise, data breach, or loss of service</td>
        <td>Immediate (&lt;24h)</td></tr>
    <tr><td><strong style="color:#e67e22">High</strong></td><td>High</td><td>7.0–8.9</td>
        <td>Significant risk of unauthorised data access or privilege escalation</td>
        <td>&lt;7 days</td></tr>
    <tr><td><strong style="color:#f39c12">Medium</strong></td><td>Moderate</td><td>4.0–6.9</td>
        <td>Exploitable under specific conditions; meaningful information disclosure risk</td>
        <td>&lt;30 days</td></tr>
    <tr><td><strong style="color:#27ae60">Low</strong></td><td>Low</td><td>0.1–3.9</td>
        <td>Limited impact; defence-in-depth improvements recommended</td>
        <td>&lt;90 days</td></tr>
    <tr><td><strong style="color:#2980b9">Informational</strong></td><td>Informational</td><td>0.0</td>
        <td>Observations with no direct exploitability but worth addressing</td>
        <td>Best effort</td></tr>
  </table>
</div>

<!-- ═══ SECTION 5: DETAILED FINDINGS ═══════════════════════════════ -->
<div class="section page-break" id="s5">
  <div class="section-header">
    <div class="section-num">5</div>
    <div class="section-title">Detailed Findings ({total} Total)</div>
  </div>
  {findings_html if findings_html else '<p style="color:var(--muted);font-style:italic">No actionable findings detected during this assessment.</p>'}
</div>

<!-- ═══ SECTION 6: REMEDIATION ROADMAP ═════════════════════════════ -->
<div class="section page-break" id="s6">
  <div class="section-header">
    <div class="section-num">6</div>
    <div class="section-title">Remediation Roadmap</div>
  </div>
  <p style="margin-bottom:14px">
    The following table lists all findings ordered by severity with recommended remediation
    timelines aligned to NIST SP 800-53 control objectives.
  </p>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>CWE</th><th>SLA</th><th>Remediation Category</th></tr>
    {remediation_rows}
  </table>
</div>

<!-- ═══ SECTION 7: APPENDIX ═════════════════════════════════════════ -->
<div class="section" id="s7">
  <div class="section-header">
    <div class="section-num">7</div>
    <div class="section-title">Appendix — Assessment Summary</div>
  </div>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Findings</td><td>{total}</td></tr>
    <tr><td>Critical</td><td style="color:#c0392b;font-weight:700">{counts['Critical']}</td></tr>
    <tr><td>High</td><td style="color:#e67e22;font-weight:700">{counts['High']}</td></tr>
    <tr><td>Medium</td><td style="color:#f39c12;font-weight:700">{counts['Medium']}</td></tr>
    <tr><td>Low</td><td style="color:#27ae60;font-weight:700">{counts['Low']}</td></tr>
    <tr><td>Informational</td><td style="color:#2980b9;font-weight:700">{counts['Information']}</td></tr>
    <tr><td>Composite Risk Score</td><td><strong>{risk_score}/100</strong></td></tr>
    <tr><td>Overall Risk</td><td><strong style="color:{overall_color}">{overall_risk}</strong></td></tr>
    <tr><td>Source Report</td><td><code>{html.escape(os.path.basename(scan_json_path))}</code></td></tr>
    <tr><td>Report Standard</td><td>PTES + NIST SP 800-115 + NIST SP 800-30 Rev.1</td></tr>
  </table>
  <p style="margin-top:20px;font-size:11px;color:var(--muted);line-height:1.8">
    <strong>Disclaimer:</strong> This report was generated by an automated scanner.
    Automated testing may produce false positives and does not replace a manual
    penetration test conducted by a certified professional (OSCP, CEH, GPEN).
    All findings should be manually verified before remediation activities are prioritised.
    This document must be treated as <strong>CONFIDENTIAL</strong> and shared only with
    authorised personnel on a need-to-know basis.
  </p>
</div>

<div class="footer">
  AegisProbe Penetration Test Report &nbsp;·&nbsp; Generated {now_str} &nbsp;·&nbsp;
  CONFIDENTIAL — NOT FOR DISTRIBUTION &nbsp;·&nbsp; PTES / NIST SP 800-115
</div>

</body>
</html>"""

    # Save report
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    clean = target.replace("://","_").replace("/","_").replace(":","_").replace(".","_")[:50]
    out_path = os.path.join(REPORT_DIR, f"pentest_{clean}_{ts}.html")
    with open(out_path, "w") as fp:
        fp.write(html_doc)

    return out_path, html_doc


def get_latest_report_json() -> str | None:
    """Return path to the most recent aegisprobe JSON report, or None."""
    pattern = os.path.join(SCAN_DIR, "aegis_*.json")
    reports = [f for f in glob.glob(pattern) if not f.endswith(".meta.json")]
    return max(reports, key=os.path.getmtime) if reports else None
