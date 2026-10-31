"""
Expedite Strike -- Standalone Interactive HTML Assessment Report
===============================================================
Generates a portable, responsive, self-contained HTML assessment report
with live filtering, search, collapsible PoC evidence, and SLA matrices.
"""

import html as _html
import json
import time
from typing import Dict, Any, List


def generate_auth_bypass_html(report_data: Dict[str, Any]) -> str:
    """Generate a self-contained interactive HTML report."""
    scan_id = report_data.get("scan_id", "SCAN-000")
    target_url = report_data.get("target_url", "https://target.local")
    protocol = report_data.get("protocol_detected", report_data.get("protocol", "auto")).upper()
    findings: List[dict] = report_data.get("findings", [])
    vuln_count = report_data.get("vulnerable_count", sum(1 for f in findings if f.get("status") == "VULNERABLE"))
    sec_count = report_data.get("secure_count", sum(1 for f in findings if f.get("status") == "SECURE"))
    na_count = report_data.get("na_count", sum(1 for f in findings if f.get("status") == "NOT_APPLICABLE"))
    err_count = report_data.get("error_count", sum(1 for f in findings if f.get("status") == "ERROR"))
    total_checks = report_data.get("checks_run", len(findings))
    summary = report_data.get("summary", "")
    mitre_ids = report_data.get("mitre_ids", [])
    gen_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # Calculate SLA & Effort statistics
    crit_count = sum(1 for f in findings if f.get("status") == "VULNERABLE" and f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("status") == "VULNERABLE" and f.get("severity") == "High")
    med_count  = sum(1 for f in findings if f.get("status") == "VULNERABLE" and f.get("severity") == "Medium")
    low_count  = sum(1 for f in findings if f.get("status") == "VULNERABLE" and f.get("severity") == "Low")

    findings_json = json.dumps(findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Expedite Strike -- Auth Bypass Assessment Report: {_html.escape(target_url)}</title>
<style>
  :root {{
    --bg-main: #080c14;
    --bg-card: #0d1117;
    --bg-card-header: #06090e;
    --border: #1e2a3a;
    --text-main: #e6edf3;
    --text-muted: #8899aa;
    --accent: #00c88c;
    --red: #ff4444;
    --orange: #ff9500;
    --yellow: #ffd700;
    --blue: #00e5ff;
    --gray: #6e7681;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg-main);
    color: var(--text-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.5;
    padding: 24px;
  }}
  .container {{ max-width: 1300px; margin: 0 auto; }}
  header {{
    background: linear-gradient(135deg, #0d1117 0%, #161f2e 100%);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px 30px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .brand-title {{ font-size: 22px; font-weight: 800; color: #fff; letter-spacing: 0.5px; }}
  .brand-badge {{
    background: rgba(0,200,140,0.15);
    color: var(--accent);
    border: 1px solid var(--accent);
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    font-family: monospace;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-top: 14px;
    font-size: 12px;
    color: var(--text-muted);
  }}
  .meta-item strong {{ color: var(--text-main); }}
  
  /* KPI Cards */
  .kpi-row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
  }}
  .kpi-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
  }}
  .kpi-card.vuln {{ border-color: rgba(255,68,68,0.4); background: rgba(255,68,68,0.06); }}
  .kpi-card.secure {{ border-color: rgba(0,200,140,0.4); background: rgba(0,200,140,0.06); }}
  .kpi-card.na {{ border-color: var(--border); }}
  .kpi-card.err {{ border-color: rgba(255,149,0,0.4); background: rgba(255,149,0,0.06); }}
  .kpi-num {{ font-size: 28px; font-weight: 800; margin-bottom: 4px; }}
  .kpi-label {{ font-size: 11px; font-weight: 700; letter-spacing: 1px; color: var(--text-muted); }}

  /* SLA Matrix Card */
  .sla-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
  }}
  .sla-title {{ font-size: 14px; font-weight: 700; margin-bottom: 12px; color: var(--accent); }}
  .sla-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
  }}
  .sla-box {{
    background: #06090e;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
  }}

  /* Controls */
  .toolbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 16px;
  }}
  .filter-group {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent);
    color: #000;
    border-color: var(--accent);
  }}
  .search-input {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-main);
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 12px;
    width: 280px;
  }}

  /* Finding Card */
  .finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 14px;
    overflow: hidden;
    transition: border-color 0.2s;
  }}
  .finding-card.vulnerable {{ border-left: 4px solid var(--red); }}
  .finding-card.secure {{ border-left: 4px solid var(--accent); }}
  .finding-card.na {{ border-left: 4px solid var(--gray); }}
  .finding-card.error {{ border-left: 4px solid var(--orange); }}

  .finding-header {{
    padding: 14px 18px;
    background: var(--bg-card-header);
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    user-select: none;
  }}
  .finding-title-group {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .cid-tag {{ font-family: monospace; font-weight: 700; color: #fff; font-size: 13px; }}
  .proto-tag {{ color: var(--text-muted); font-size: 11px; }}
  .title-text {{ font-weight: 600; font-size: 13px; color: var(--text-main); }}

  .badge {{
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    font-family: monospace;
    text-transform: uppercase;
  }}
  .badge-Critical {{ background: rgba(255,68,68,0.2); color: #ff6b6b; border: 1px solid #ff4444; }}
  .badge-High {{ background: rgba(255,149,0,0.2); color: #ff9500; border: 1px solid #ff9500; }}
  .badge-Medium {{ background: rgba(255,215,0,0.2); color: #ffd700; border: 1px solid #ffd700; }}
  .badge-Low {{ background: rgba(0,229,255,0.2); color: #00e5ff; border: 1px solid #00e5ff; }}
  .badge-Info {{ background: rgba(110,118,129,0.2); color: #8b949e; border: 1px solid #6e7681; }}

  .badge-VULNERABLE {{ background: rgba(255,68,68,0.25); color: #ff6b6b; border: 1px solid #ff4444; }}
  .badge-SECURE {{ background: rgba(0,200,140,0.2); color: #00c88c; border: 1px solid #00c88c; }}
  .badge-NOT_APPLICABLE {{ background: rgba(110,118,129,0.15); color: #8b949e; border: 1px solid #30363d; }}
  .badge-ERROR {{ background: rgba(255,149,0,0.2); color: #ffa94d; border: 1px solid #ff9500; }}

  .finding-body {{
    padding: 16px 20px;
    border-top: 1px solid var(--border);
    display: none;
    font-size: 12px;
  }}
  .finding-body.open {{ display: block; }}
  .detail-section {{ margin-bottom: 12px; }}
  .detail-section h4 {{ font-size: 11px; color: var(--accent); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
  .code-block {{
    background: #06090e;
    border: 1px solid var(--border);
    padding: 10px 14px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 11px;
    color: #e6edf3;
    white-space: pre-wrap;
    word-break: break-all;
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <div style="display:flex; align-items:center; gap:12px; margin-bottom: 6px;">
        <span style="font-size:26px;">🔑</span>
        <span class="brand-title">Universal Authentication Bypass Assessment Report</span>
        <span class="brand-badge">EXPEDITE STRIKE 3.0</span>
      </div>
      <div style="color: var(--text-muted); font-size: 13px;">Target: <strong style="color:#fff;">{_html.escape(target_url)}</strong></div>
      <div class="meta-grid">
        <div class="meta-item">Scan ID: <strong>{scan_id}</strong></div>
        <div class="meta-item">Protocol Scope: <strong>{protocol}</strong></div>
        <div class="meta-item">Generated: <strong>{gen_time}</strong></div>
        <div class="meta-item">Compliance: <strong>OWASP A07:2021 | CREST | PTES | NIST 800-63B</strong></div>
      </div>
    </div>
  </header>

  <!-- KPI Row -->
  <div class="kpi-row">
    <div class="kpi-card vuln">
      <div class="kpi-num" style="color:var(--red);">{vuln_count}</div>
      <div class="kpi-label">VULNERABLE CHECKS</div>
    </div>
    <div class="kpi-card secure">
      <div class="kpi-num" style="color:var(--accent);">{sec_count}</div>
      <div class="kpi-label">SECURE CHECKS</div>
    </div>
    <div class="kpi-card na">
      <div class="kpi-num" style="color:var(--gray);">{na_count}</div>
      <div class="kpi-label">NOT APPLICABLE</div>
    </div>
    <div class="kpi-card err">
      <div class="kpi-num" style="color:var(--orange);">{err_count}</div>
      <div class="kpi-label">ERRORS / TIMEOUT</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color:#fff;">{total_checks}</div>
      <div class="kpi-label">TOTAL CHECKS RUN</div>
    </div>
  </div>

  <!-- SLA & Effort Matrix -->
  <div class="sla-card">
    <div class="sla-title">⚡ Remediation SLA &amp; Triage Matrix</div>
    <div class="sla-grid">
      <div class="sla-box">
        <div style="color:var(--red); font-weight:700; font-size:12px;">CRITICAL ({crit_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>24 Hours</strong> | Effort: High Priority</div>
      </div>
      <div class="sla-box">
        <div style="color:var(--orange); font-weight:700; font-size:12px;">HIGH ({high_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>7 Days</strong> | Effort: Moderate / Configuration</div>
      </div>
      <div class="sla-box">
        <div style="color:var(--yellow); font-weight:700; font-size:12px;">MEDIUM ({med_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>30 Days</strong> | Effort: Standard Patch Cycle</div>
      </div>
      <div class="sla-box">
        <div style="color:var(--blue); font-weight:700; font-size:12px;">LOW / INFO ({low_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>90 Days</strong> | Effort: Hardening &amp; Hygiene</div>
      </div>
    </div>
  </div>

  <!-- Filter & Search Toolbar -->
  <div class="toolbar">
    <div class="filter-group">
      <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total_checks})</button>
      <button class="filter-btn" onclick="filterFindings('VULNERABLE')">Vulnerable ({vuln_count})</button>
      <button class="filter-btn" onclick="filterFindings('SECURE')">Secure ({sec_count})</button>
      <button class="filter-btn" onclick="filterFindings('NOT_APPLICABLE')">N/A ({na_count})</button>
    </div>
    <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search check ID, title, or CVE/CWE..." onkeyup="searchFindings()">
  </div>

  <!-- Findings Container -->
  <div id="findingsContainer">
"""

    for f in findings:
        cid = _html.escape(f.get("check_id", ""))
        proto = _html.escape(f.get("protocol", ""))
        title = _html.escape(f.get("title", ""))
        status = f.get("status", "NOT_APPLICABLE")
        sev = f.get("severity", "Info")
        cvss = f.get("cvss_score", 0.0)
        mitre = _html.escape(f.get("mitre_id", ""))
        cwe = _html.escape(f.get("cwe", ""))
        owasp = _html.escape(f.get("owasp", ""))
        crest = _html.escape(f.get("crest", ""))
        ptes = _html.escape(f.get("ptes", ""))
        evidence = _html.escape(f.get("evidence", ""))
        recom = _html.escape(f.get("recommendation", ""))
        refs = f.get("references", [])
        refs_html = "".join(f"<li>{_html.escape(r)}</li>" for r in refs) if refs else "<li>Standard Auth Verification Reference</li>"

        card_cls = status.lower()

        report_html_chunk = f"""
    <div class="finding-card {card_cls}" data-status="{status}" data-text="{cid.lower()} {proto.lower()} {title.lower()} {mitre.lower()} {cwe.lower()}">
      <div class="finding-header" onclick="toggleDetails(this)">
        <div class="finding-title-group">
          <span class="cid-tag">{cid}</span>
          <span class="proto-tag">[{proto}]</span>
          <span class="title-text">{title}</span>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="badge badge-{sev}">{sev} {f'({cvss})' if cvss else ''}</span>
          <span class="badge badge-{status}">{status}</span>
        </div>
      </div>
      <div class="finding-body">
        <div class="detail-section">
          <h4>Vulnerability Evidence &amp; Proof of Concept</h4>
          <div class="code-block">{evidence or 'No evidence recorded.'}</div>
        </div>
        <div class="detail-section">
          <h4>Remediation Guidance</h4>
          <div style="color:#e6edf3;">{recom or 'Maintain current security controls.'}</div>
        </div>
        <div class="detail-section">
          <h4>Compliance &amp; Standard Mapping</h4>
          <div style="font-size:11px; color:var(--text-muted);">
            <strong>MITRE ATT&CK:</strong> {mitre or 'N/A'} | 
            <strong>CWE:</strong> {cwe or 'N/A'} | 
            <strong>OWASP Top 10:</strong> {owasp or 'N/A'} | 
            <strong>CREST:</strong> {crest or 'N/A'} | 
            <strong>PTES:</strong> {ptes or 'N/A'}
          </div>
        </div>
        <div class="detail-section">
          <h4>Technical References</h4>
          <ul style="padding-left:18px; font-size:11px; color:#63b3ed;">
            {refs_html}
          </ul>
        </div>
      </div>
    </div>
"""
        findings_json_clean = ""  # just to keep syntax clean
        report_html_chunk_filled = report_html_chunk

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Expedite Strike -- Auth Bypass Assessment Report: {_html.escape(target_url)}</title>
<style>
  :root {{
    --bg-main: #080c14;
    --bg-card: #0d1117;
    --bg-card-header: #06090e;
    --border: #1e2a3a;
    --text-main: #e6edf3;
    --text-muted: #8899aa;
    --accent: #00c88c;
    --red: #ff4444;
    --orange: #ff9500;
    --yellow: #ffd700;
    --blue: #00e5ff;
    --gray: #6e7681;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg-main);
    color: var(--text-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.5;
    padding: 24px;
  }}
  .container {{ max-width: 1300px; margin: 0 auto; }}
  header {{
    background: linear-gradient(135deg, #0d1117 0%, #161f2e 100%);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px 30px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .brand-title {{ font-size: 22px; font-weight: 800; color: #fff; letter-spacing: 0.5px; }}
  .brand-badge {{
    background: rgba(0,200,140,0.15);
    color: var(--accent);
    border: 1px solid var(--accent);
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    font-family: monospace;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-top: 14px;
    font-size: 12px;
    color: var(--text-muted);
  }}
  .meta-item strong {{ color: var(--text-main); }}
  
  /* KPI Cards */
  .kpi-row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
  }}
  .kpi-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
  }}
  .kpi-card.vuln {{ border-color: rgba(255,68,68,0.4); background: rgba(255,68,68,0.06); }}
  .kpi-card.secure {{ border-color: rgba(0,200,140,0.4); background: rgba(0,200,140,0.06); }}
  .kpi-card.na {{ border-color: var(--border); }}
  .kpi-card.err {{ border-color: rgba(255,149,0,0.4); background: rgba(255,149,0,0.06); }}
  .kpi-num {{ font-size: 28px; font-weight: 800; margin-bottom: 4px; }}
  .kpi-label {{ font-size: 11px; font-weight: 700; letter-spacing: 1px; color: var(--text-muted); }}

  /* SLA Matrix Card */
  .sla-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
  }}
  .sla-title {{ font-size: 14px; font-weight: 700; margin-bottom: 12px; color: var(--accent); }}
  .sla-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
  }}
  .sla-box {{
    background: #06090e;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
  }}

  /* Controls */
  .toolbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 16px;
  }}
  .filter-group {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent);
    color: #000;
    border-color: var(--accent);
  }}
  .search-input {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-main);
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 12px;
    width: 280px;
  }}

  /* Finding Card */
  .finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 14px;
    overflow: hidden;
    transition: border-color 0.2s;
  }}
  .finding-card.vulnerable {{ border-left: 4px solid var(--red); }}
  .finding-card.secure {{ border-left: 4px solid var(--accent); }}
  .finding-card.not_applicable {{ border-left: 4px solid var(--gray); }}
  .finding-card.error {{ border-left: 4px solid var(--orange); }}

  .finding-header {{
    padding: 14px 18px;
    background: var(--bg-card-header);
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    user-select: none;
  }}
  .finding-title-group {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .cid-tag {{ font-family: monospace; font-weight: 700; color: #fff; font-size: 13px; }}
  .proto-tag {{ color: var(--text-muted); font-size: 11px; }}
  .title-text {{ font-weight: 600; font-size: 13px; color: var(--text-main); }}

  .badge {{
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    font-family: monospace;
    text-transform: uppercase;
  }}
  .badge-Critical {{ background: rgba(255,68,68,0.2); color: #ff6b6b; border: 1px solid #ff4444; }}
  .badge-High {{ background: rgba(255,149,0,0.2); color: #ff9500; border: 1px solid #ff9500; }}
  .badge-Medium {{ background: rgba(255,215,0,0.2); color: #ffd700; border: 1px solid #ffd700; }}
  .badge-Low {{ background: rgba(0,229,255,0.2); color: #00e5ff; border: 1px solid #00e5ff; }}
  .badge-Info {{ background: rgba(110,118,129,0.2); color: #8b949e; border: 1px solid #6e7681; }}

  .badge-VULNERABLE {{ background: rgba(255,68,68,0.25); color: #ff6b6b; border: 1px solid #ff4444; }}
  .badge-SECURE {{ background: rgba(0,200,140,0.2); color: #00c88c; border: 1px solid #00c88c; }}
  .badge-NOT_APPLICABLE {{ background: rgba(110,118,129,0.15); color: #8b949e; border: 1px solid #30363d; }}
  .badge-ERROR {{ background: rgba(255,149,0,0.2); color: #ffa94d; border: 1px solid #ff9500; }}

  .finding-body {{
    padding: 16px 20px;
    border-top: 1px solid var(--border);
    display: none;
    font-size: 12px;
  }}
  .finding-body.open {{ display: block; }}
  .detail-section {{ margin-bottom: 12px; }}
  .detail-section h4 {{ font-size: 11px; color: var(--accent); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
  .code-block {{
    background: #06090e;
    border: 1px solid var(--border);
    padding: 10px 14px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 11px;
    color: #e6edf3;
    white-space: pre-wrap;
    word-break: break-all;
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <div style="display:flex; align-items:center; gap:12px; margin-bottom: 6px;">
        <span style="font-size:26px;">🔑</span>
        <span class="brand-title">Universal Authentication Bypass Assessment Report</span>
        <span class="brand-badge">EXPEDITE STRIKE 3.0</span>
      </div>
      <div style="color: var(--text-muted); font-size: 13px;">Target: <strong style="color:#fff;">{_html.escape(target_url)}</strong></div>
      <div class="meta-grid">
        <div class="meta-item">Scan ID: <strong>{scan_id}</strong></div>
        <div class="meta-item">Protocol Scope: <strong>{protocol}</strong></div>
        <div class="meta-item">Generated: <strong>{gen_time}</strong></div>
        <div class="meta-item">Compliance: <strong>OWASP A07:2021 | CREST | PTES | NIST 800-63B</strong></div>
      </div>
    </div>
  </header>

  <!-- KPI Row -->
  <div class="kpi-row">
    <div class="kpi-card vuln">
      <div class="kpi-num" style="color:var(--red);">{vuln_count}</div>
      <div class="kpi-label">VULNERABLE CHECKS</div>
    </div>
    <div class="kpi-card secure">
      <div class="kpi-num" style="color:var(--accent);">{sec_count}</div>
      <div class="kpi-label">SECURE CHECKS</div>
    </div>
    <div class="kpi-card na">
      <div class="kpi-num" style="color:var(--gray);">{na_count}</div>
      <div class="kpi-label">NOT APPLICABLE</div>
    </div>
    <div class="kpi-card err">
      <div class="kpi-num" style="color:var(--orange);">{err_count}</div>
      <div class="kpi-label">ERRORS / TIMEOUT</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color:#fff;">{total_checks}</div>
      <div class="kpi-label">TOTAL CHECKS RUN</div>
    </div>
  </div>

  <!-- SLA & Effort Matrix -->
  <div class="sla-card">
    <div class="sla-title">⚡ Remediation SLA &amp; Triage Matrix</div>
    <div class="sla-grid">
      <div class="sla-box">
        <div style="color:var(--red); font-weight:700; font-size:12px;">CRITICAL ({crit_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>24 Hours</strong> | Effort: High Priority / Direct Takeover</div>
      </div>
      <div class="sla-box">
        <div style="color:var(--orange); font-weight:700; font-size:12px;">HIGH ({high_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>7 Days</strong> | Effort: Moderate / Protocol Reconfig</div>
      </div>
      <div class="sla-box">
        <div style="color:var(--yellow); font-weight:700; font-size:12px;">MEDIUM ({med_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>30 Days</strong> | Effort: Standard Sprint Cycle</div>
      </div>
      <div class="sla-box">
        <div style="color:var(--blue); font-weight:700; font-size:12px;">LOW / INFO ({low_count})</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">SLA: <strong>90 Days</strong> | Effort: Hardening &amp; Header Hygiene</div>
      </div>
    </div>
  </div>

  <!-- Filter & Search Toolbar -->
  <div class="toolbar">
    <div class="filter-group">
      <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total_checks})</button>
      <button class="filter-btn" onclick="filterFindings('VULNERABLE')">Vulnerable ({vuln_count})</button>
      <button class="filter-btn" onclick="filterFindings('SECURE')">Secure ({sec_count})</button>
      <button class="filter-btn" onclick="filterFindings('NOT_APPLICABLE')">N/A ({na_count})</button>
    </div>
    <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search check ID, title, or CVE/CWE..." onkeyup="searchFindings()">
  </div>

  <!-- Findings Container -->
  <div id="findingsContainer">
    {''.join([
      f'''
      <div class="finding-card {f.get('status','not_applicable').lower()}" data-status="{f.get('status','NOT_APPLICABLE')}" data-text="{_html.escape(f.get('check_id','')).lower()} {_html.escape(f.get('protocol','')).lower()} {_html.escape(f.get('title','')).lower()} {_html.escape(f.get('mitre_id','')).lower()} {_html.escape(f.get('cwe','')).lower()}">
        <div class="finding-header" onclick="toggleDetails(this)">
          <div class="finding-title-group">
            <span class="cid-tag">{_html.escape(f.get('check_id',''))}</span>
            <span class="proto-tag">[{_html.escape(f.get('protocol',''))}]</span>
            <span class="title-text">{_html.escape(f.get('title',''))}</span>
          </div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="badge badge-{f.get('severity','Info')}">{f.get('severity','Info')} {f"({f.get('cvss_score')})" if f.get('cvss_score') else ''}</span>
            <span class="badge badge-{f.get('status','NOT_APPLICABLE')}">{f.get('status','NOT_APPLICABLE')}</span>
          </div>
        </div>
        <div class="finding-body">
          <div class="detail-section">
            <h4>Vulnerability Evidence &amp; Proof of Concept</h4>
            <div class="code-block">{_html.escape(f.get('evidence','No evidence recorded.'))}</div>
          </div>
          <div class="detail-section">
            <h4>Remediation Guidance</h4>
            <div style="color:#e6edf3;">{_html.escape(f.get('recommendation','Maintain current security controls.'))}</div>
          </div>
          <div class="detail-section">
            <h4>Compliance &amp; Standard Mapping</h4>
            <div style="font-size:11px; color:var(--text-muted);">
              <strong>MITRE ATT&CK:</strong> {_html.escape(f.get('mitre_id','N/A'))} | 
              <strong>CWE:</strong> {_html.escape(f.get('cwe','N/A'))} | 
              <strong>OWASP Top 10:</strong> {_html.escape(f.get('owasp','N/A'))} | 
              <strong>CREST:</strong> {_html.escape(f.get('crest','N/A'))} | 
              <strong>PTES:</strong> {_html.escape(f.get('ptes','N/A'))}
            </div>
          </div>
          <div class="detail-section">
            <h4>Technical References</h4>
            <ul style="padding-left:18px; font-size:11px; color:#63b3ed;">
              {''.join(f'<li>{_html.escape(r)}</li>' for r in f.get('references',[])) or '<li>Standard Auth Verification Reference</li>'}
            </ul>
          </div>
        </div>
      </div>
      ''' for f in sorted(
        findings,
        key=lambda x: (
          0 if x.get("status") == "VULNERABLE" else 1 if x.get("status") == "SECURE" else 2,
          -float(x.get("cvss_score") or 0.0),
          x.get("check_id", "")
        )
      )
    ])}
  </div>
</div>

<script>
  function toggleDetails(headerEl) {{
    const body = headerEl.nextElementSibling;
    body.classList.toggle('open');
  }}

  let currentStatus = 'ALL';

  function filterFindings(status) {{
    currentStatus = status;
    document.querySelectorAll('.filter-btn').forEach(btn => {{
      btn.classList.toggle('active', btn.textContent.startsWith(status === 'ALL' ? 'All' : status === 'NOT_APPLICABLE' ? 'N/A' : status.charAt(0) + status.slice(1).toLowerCase()));
    }});
    applyFilters();
  }}

  function searchFindings() {{
    applyFilters();
  }}

  function applyFilters() {{
    const q = document.getElementById('searchInput').value.toLowerCase().trim();
    const cards = document.querySelectorAll('.finding-card');
    cards.forEach(card => {{
      const cardStatus = card.getAttribute('data-status');
      const cardText = card.getAttribute('data-text');
      const matchesStatus = (currentStatus === 'ALL' || cardStatus === currentStatus);
      const matchesSearch = (!q || cardText.includes(q));
      card.style.display = (matchesStatus && matchesSearch) ? 'block' : 'none';
    }});
  }}
</script>
</body>
</html>
"""
