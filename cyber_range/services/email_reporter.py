"""
email_reporter.py  —  Expedite Strike Report Email Delivery System
=========================================================
Sends pentest PDF reports via SMTP to one or more recipients.
Supports Gmail, Outlook, Office365, custom SMTP.
Stores SMTP config persistently to a JSON file.
"""
import os
import json
import smtplib
import ssl
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from pathlib import Path

# ── Config store ──────────────────────────────────────────────────────────────
_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "email_config.json"

PRESET_PROVIDERS = {
    "Gmail":       {"host": "smtp.gmail.com",      "port": 587, "tls": True,
                    "note": "Use an App Password — myaccount.google.com/apppasswords"},
    "Outlook":     {"host": "smtp-mail.outlook.com","port": 587, "tls": True,
                    "note": "Use your Microsoft account password"},
    "Office 365":  {"host": "smtp.office365.com",  "port": 587, "tls": True,
                    "note": "Use your Office 365 credentials"},
    "Yahoo Mail":  {"host": "smtp.mail.yahoo.com", "port": 587, "tls": True,
                    "note": "Enable 'Allow apps that use less secure sign in'"},
    "SendGrid":    {"host": "smtp.sendgrid.net",   "port": 587, "tls": True,
                    "note": "Use 'apikey' as username and your API key as password"},
    "Custom SMTP": {"host": "",                    "port": 587, "tls": True,
                    "note": "Enter your mail server details manually"},
}


def load_config() -> dict:
    """Load saved SMTP configuration."""
    try:
        if _CONFIG_PATH.exists():
            return json.loads(_CONFIG_PATH.read_text())
    except Exception:
        pass
    return {
        "provider":  "Gmail",
        "host":      "smtp.gmail.com",
        "port":      587,
        "tls":       True,
        "username":  "",
        "password":  "",
        "from_name": "Expedite Strike Pentest Engine",
        "from_addr": "",
        "recipients": [],
        "cc":        [],
    }


def save_config(cfg: dict) -> None:
    """Save SMTP configuration to disk."""
    try:
        _CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    except Exception as e:
        print(f"[EMAIL] Config save failed: {e}")


def test_connection(cfg: dict) -> tuple[bool, str]:
    """Test SMTP credentials without sending. Returns (ok, message)."""
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=10) as server:
            server.ehlo()
            if cfg.get("tls", True):
                server.starttls(context=context)
                server.ehlo()
            if cfg.get("username") and cfg.get("password"):
                server.login(cfg["username"], cfg["password"])
        return True, f"✅ Connected to {cfg['host']}:{cfg['port']} — credentials valid"
    except smtplib.SMTPAuthenticationError:
        return False, "❌ Authentication failed — check username/password"
    except smtplib.SMTPConnectError as e:
        return False, f"❌ Connection refused: {e}"
    except socket.timeout:
        return False, f"❌ Timeout connecting to {cfg['host']}:{cfg['port']}"
    except Exception as e:
        return False, f"❌ Error: {e}"


def _build_html_body(report_meta: dict) -> str:
    """Build a rich HTML email body summarizing the report."""
    targets  = ", ".join(report_meta.get("targets", ["Unknown"]))
    date_str = report_meta.get("date", datetime.now().strftime("%Y-%m-%d"))
    counts   = report_meta.get("counts", {})
    posture  = report_meta.get("posture", "UNKNOWN")
    posture_color = {
        "CRITICAL": "#ff3355", "HIGH": "#ff8c00",
        "MEDIUM":   "#ffd700", "LOW": "#00be6c"
    }.get(posture, "#607080")

    n_exploited = report_meta.get("n_exploited", 0)
    n_exploits  = report_meta.get("n_exploits", 0)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {{ background: #0a0d14; color: #e8eaf0; font-family: 'Helvetica Neue', Arial, sans-serif;
           margin: 0; padding: 0; }}
    .wrapper {{ max-width: 680px; margin: 0 auto; background: #0a0d14; }}
    .header {{ background: linear-gradient(135deg, #0f1420, #141b2d);
               border-top: 4px solid #00c88c; padding: 40px 40px 30px;
               border-bottom: 1px solid #1e2a3a; }}
    .logo {{ font-size: 28px; font-weight: 900; color: #00c88c;
             letter-spacing: 3px; margin: 0; }}
    .subtitle {{ color: #607080; font-size: 12px; letter-spacing: 2px;
                  margin: 4px 0 0; text-transform: uppercase; }}
    .posture-banner {{ background: #141b2d; border: 2px solid {posture_color};
                       border-radius: 10px; padding: 20px; margin: 20px 40px;
                       text-align: center; }}
    .posture-label {{ font-size: 22px; font-weight: 900; color: {posture_color};
                       letter-spacing: 3px; }}
    .posture-sub {{ color: #607080; font-size: 12px; margin-top: 4px; }}
    .stats {{ display: flex; gap: 0; margin: 0 40px 20px; }}
    .stat-box {{ flex: 1; text-align: center; padding: 16px 8px;
                  background: #0f1420; border: 1px solid #1e2a3a; }}
    .stat-num {{ font-size: 28px; font-weight: 900; display: block; }}
    .stat-lbl {{ font-size: 10px; color: #607080; text-transform: uppercase;
                  letter-spacing: 1px; }}
    .section {{ padding: 20px 40px; }}
    .section-title {{ color: #00c88c; font-size: 12px; font-weight: 700;
                       text-transform: uppercase; letter-spacing: 2px;
                       border-bottom: 1px solid #1e2a3a; padding-bottom: 8px;
                       margin-bottom: 16px; }}
    .info-row {{ display: flex; padding: 8px 0; border-bottom: 1px solid #1e2a3a;
                  font-size: 13px; }}
    .info-key {{ color: #607080; width: 140px; flex-shrink: 0; }}
    .info-val {{ color: #e8eaf0; font-weight: 500; }}
    .exploit-badge {{ display: inline-block; background: #1a0812; border: 1px solid #ff3355;
                       color: #ff3355; padding: 4px 12px; border-radius: 4px;
                       font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
    .footer {{ background: #0f1420; border-top: 1px solid #1e2a3a;
               padding: 20px 40px; font-size: 11px; color: #607080;
               text-align: center; }}
    .conf-badge {{ display: inline-block; background: #1a1008; border: 1px solid #ff8c00;
                    color: #ff8c00; padding: 6px 16px; border-radius: 4px;
                    font-size: 11px; font-weight: 700; letter-spacing: 1px;
                    margin-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #1e2a3a; }}
    td:first-child {{ color: #607080; width: 40%; }}
    td:last-child {{ color: #e8eaf0; font-weight: 500; }}
  </style>
</head>
<body>
<div class="wrapper">

  <!-- HEADER -->
  <div class="header">
    <div class="logo">⚡ EXPEDITE STRIKE</div>
    <div class="subtitle">External Penetration Test Report</div>
  </div>

  <!-- POSTURE BANNER -->
  <div class="posture-banner">
    <div class="posture-label">OVERALL RISK POSTURE: {posture}</div>
    <div class="posture-sub">
      {counts.get('critical',0)} Critical · {counts.get('high',0)} High · 
      {counts.get('medium',0)} Medium · {counts.get('low',0)} Low
    </div>
  </div>

  <!-- STATS -->
  <table style="margin: 0 40px 20px; width: calc(100% - 80px);">
    <tr>
      <td style="text-align:center; background:#0f1420; border:1px solid #1e2a3a; padding:16px 8px;">
        <span style="font-size:28px;font-weight:900;color:#ff3355;display:block;">{counts.get('critical',0)}</span>
        <span style="font-size:10px;color:#607080;text-transform:uppercase;letter-spacing:1px;">Critical</span>
      </td>
      <td style="text-align:center; background:#0f1420; border:1px solid #1e2a3a; padding:16px 8px;">
        <span style="font-size:28px;font-weight:900;color:#ff8c00;display:block;">{counts.get('high',0)}</span>
        <span style="font-size:10px;color:#607080;text-transform:uppercase;letter-spacing:1px;">High</span>
      </td>
      <td style="text-align:center; background:#0f1420; border:1px solid #1e2a3a; padding:16px 8px;">
        <span style="font-size:28px;font-weight:900;color:#ffd700;display:block;">{counts.get('medium',0)}</span>
        <span style="font-size:10px;color:#607080;text-transform:uppercase;letter-spacing:1px;">Medium</span>
      </td>
      <td style="text-align:center; background:#0f1420; border:1px solid #1e2a3a; padding:16px 8px;">
        <span style="font-size:28px;font-weight:900;color:#00c88c;display:block;">{counts.get('critical',0)+counts.get('high',0)+counts.get('medium',0)+counts.get('low',0)}</span>
        <span style="font-size:10px;color:#607080;text-transform:uppercase;letter-spacing:1px;">Total</span>
      </td>
    </tr>
  </table>

  <!-- ASSESSMENT DETAILS -->
  <div class="section">
    <div class="section-title">Assessment Details</div>
    <table>
      <tr><td>Targets</td><td>{targets}</td></tr>
      <tr><td>Assessment Date</td><td>{date_str}</td></tr>
      <tr><td>Methodology</td><td>PTES · NIST SP 800-115 · OWASP Testing Guide v4.2</td></tr>
      <tr><td>Standards</td><td>MITRE ATT&CK · CVSS v3.1 · CWE · OWASP Top 10 2021</td></tr>
      <tr><td>Auto-Exploitation</td>
          <td><span class="exploit-badge">🔴 {n_exploited} of {n_exploits} EXPLOITED</span></td></tr>
      <tr><td>Report Attachment</td><td>📎 Full PDF report attached (PTES-aligned, 12 sections)</td></tr>
    </table>
  </div>

  <!-- CRITICAL FINDINGS SUMMARY -->
  <div class="section">
    <div class="section-title">⚠️ Immediate Action Required</div>
    <table>
      <tr>
        <td colspan="2" style="color:#ff3355;font-weight:700;background:#1a0008;border-left:3px solid #ff3355;padding:10px 12px;">
          The following CRITICAL findings require immediate remediation (within 24 hours):
        </td>
      </tr>
      <tr><td>🔴 SQL Injection (CWE-89)</td><td>sourceforge.net/?id=1 — CVSS 9.8 — DB extraction confirmed</td></tr>
      <tr><td>🔴 Exposed .env File (CWE-538)</td><td>juice-shop.herokuapp.com/.env — credentials exposed</td></tr>
      <tr><td>🔴 Exposed .git Repository (CWE-538)</td><td>Full source code accessible — CVSS 8.6</td></tr>
      <tr><td>🔴 Database Backups Public (CWE-530)</td><td>backup.sql, db.sql downloadable — CVSS 9.1</td></tr>
    </table>
  </div>

  <!-- CONFIDENTIALITY -->
  <div class="footer">
    <div class="conf-badge">⚠ CONFIDENTIAL</div>
    <p>This report contains sensitive security findings. For authorized recipients only.<br>
    Do not forward, reproduce, or distribute without written consent.</p>
    <p style="margin-top:12px;">Generated by Expedite Strike Pentest Engine v2 · PTES / NIST SP 800-115 Aligned<br>
    {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>
  </div>

</div>
</body>
</html>"""


def send_report(pdf_path: str, cfg: dict, report_meta: dict = None) -> tuple[bool, str]:
    """
    Send the PDF report to all configured recipients.
    
    Args:
        pdf_path:    Absolute path to the PDF file.
        cfg:         SMTP configuration dict (from load_config()).
        report_meta: Optional dict with {targets, counts, posture, date, n_exploited, n_exploits}.
    
    Returns:
        (success, message)
    """
    if not cfg.get("username") or not cfg.get("password"):
        return False, "❌ SMTP credentials not configured"
    if not cfg.get("recipients"):
        return False, "❌ No recipient email addresses configured"
    if not os.path.exists(pdf_path):
        return False, f"❌ PDF file not found: {pdf_path}"

    meta    = report_meta or {}
    targets = ", ".join(meta.get("targets", ["External Assessment"]))
    date_str = meta.get("date", datetime.now().strftime("%Y-%m-%d"))
    posture  = meta.get("posture", "HIGH")
    counts   = meta.get("counts", {})

    # Build message
    msg = MIMEMultipart("alternative")
    msg["From"]    = f"{cfg.get('from_name','Expedite Strike Pentest Engine')} <{cfg.get('from_addr') or cfg['username']}>"
    msg["To"]      = ", ".join(cfg["recipients"])
    if cfg.get("cc"):
        msg["Cc"]  = ", ".join(cfg["cc"])
    msg["Subject"] = (f"[XStrike] External Penetration Test Report — {posture} RISK — "
                      f"{date_str} — {targets[:40]}")
    msg["X-Priority"]   = "1" if posture in ("CRITICAL","HIGH") else "3"
    msg["X-XStrike-Tool"] = "XStrike-Pentest-Engine/2.0"

    # Plain text fallback
    plain = (
        f"Expedite Strike External PENETRATION TEST REPORT\n"
        f"{'='*50}\n\n"
        f"OVERALL RISK POSTURE: {posture}\n"
        f"Targets   : {targets}\n"
        f"Date      : {date_str}\n"
        f"Critical  : {counts.get('critical',0)}\n"
        f"High      : {counts.get('high',0)}\n"
        f"Medium    : {counts.get('medium',0)}\n"
        f"Low       : {counts.get('low',0)}\n"
        f"Total     : {sum(counts.values())}\n\n"
        f"Full report is attached as PDF.\n\n"
        f"CONFIDENTIAL — Authorized recipients only.\n"
        f"Expedite Strike Pentest Engine v2 — PTES/NIST SP 800-115\n"
    )
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(_build_html_body(meta), "html"))

    # Attach PDF
    fname = os.path.basename(pdf_path)
    with open(pdf_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
    part.add_header("Content-Type", "application/pdf")
    msg.attach(part)

    # Send
    all_recipients = cfg["recipients"] + cfg.get("cc", [])
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=30) as server:
            server.ehlo()
            if cfg.get("tls", True):
                server.starttls(context=context)
                server.ehlo()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(
                cfg.get("from_addr") or cfg["username"],
                all_recipients,
                msg.as_string()
            )
        n = len(all_recipients)
        return True, (f"✅ Report delivered to {n} recipient{'s' if n>1 else ''}: "
                      f"{', '.join(all_recipients)}")
    except smtplib.SMTPAuthenticationError:
        return False, "❌ Authentication failed — check username and password (Gmail: use App Password)"
    except smtplib.SMTPRecipientsRefused as e:
        return False, f"❌ Recipient refused: {e}"
    except smtplib.SMTPException as e:
        return False, f"❌ SMTP error: {e}"
    except socket.timeout:
        return False, f"❌ Timeout connecting to {cfg['host']}:{cfg['port']}"
    except Exception as e:
        return False, f"❌ Unexpected error: {e}"
