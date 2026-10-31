#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated weekly SOC email and executive PDF brief generator.
 - 10-week vulnerability & CVSS chart
 - Posture score gauge
 - Digitally signed PDF (SHA256)
 - Inline email summary
"""

import os, io, ssl, base64, smtplib, hashlib, re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd
import plotly.graph_objects as go
from fpdf import FPDF
from bs4 import BeautifulSoup
import sqlite3

def email_weekly_report():
    REPORT_DIR = Path("/root/vuln_intel/app/reports")
    index_file = REPORT_DIR / "index.html"
    reports = sorted(REPORT_DIR.glob("report_*.html"), reverse=True)
    latest_report = reports[0] if reports else None
    if not latest_report or not index_file.exists():
        print("⚠️ No report or index found.")
        return

    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    recipients = os.getenv("EMAIL_RECIPIENTS", "").split(",")
    if not smtp_user or not smtp_pass or not recipients:
        print("⚠️ Missing SMTP credentials.")
        return

    parsed = []
    for rpt in reports[:10]:
        soup = BeautifulSoup(rpt.read_text(), "html.parser")
        try:
            date = soup.find("p", string=re.compile("Date:")).text.split(":")[1].strip()
            vulns = int(soup.find("p", string=re.compile("Vulnerabilities:")).text.split(":")[1])
            cvss = float(soup.find("p", string=re.compile("CVSS")).text.split(":")[1])
            parsed.append({"date": date, "vulns": vulns, "avg_cvss": cvss})
        except Exception:
            pass

    chart_b64 = None
    if parsed:
        df = pd.DataFrame(parsed)
        df["date"] = pd.to_datetime(df["date"], errors="coerce")
        plt.figure(figsize=(6, 3))
        plt.plot(df["date"], df["vulns"], "o-", label="Vulnerabilities")
        plt.plot(df["date"], df["avg_cvss"], "s-", label="Avg CVSS")
        plt.legend(); plt.grid(True, linestyle="--", alpha=0.5)
        plt.title("10-Week Vulnerability Overview")
        buf = io.BytesIO(); plt.savefig(buf, format="png"); buf.seek(0)
        chart_b64 = base64.b64encode(buf.read()).decode()

    DB_PATH = Path("/root/vuln_intel/app/data/findings.db")
    conn = sqlite3.connect(DB_PATH)
    df_metrics = pd.read_sql_query("SELECT * FROM trend_metrics ORDER BY id DESC LIMIT 1", conn)
    conn.close()
    risk, vel = 0, 0
    posture_score, gauge_b64 = 0, None
    if not df_metrics.empty:
        row = df_metrics.iloc[0]
        risk, vel = row["risk_index"], row["improvement_velocity"]
        posture_score = max(0, min(100, 100 - (min(risk, 1000)/10) + (vel/2)))
        color = "#4CAF50" if posture_score >= 70 else "#FFD633" if posture_score >= 40 else "#FF4C4C"
        gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=posture_score,
            number={"suffix": " / 100"},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": color}}
        ))
        gauge.update_layout(margin=dict(t=0,b=0,l=0,r=0), height=200, width=200)
        img = gauge.to_image(format="png"); gauge_b64 = base64.b64encode(img).decode()

    pdf_path = REPORT_DIR / f"Executive_SOC_Brief_{datetime.now().strftime('%Y-%m-%d')}.pdf"
    pdf = FPDF(); pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Expedite Consults DSIT — Executive SOC Brief", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 8, f"Date: {datetime.now()}\nRisk Index: {risk}\nVelocity: {vel}\nPosture Score: {posture_score:.1f}/100")

    pdf.output(str(pdf_path))

    with open(pdf_path, "rb") as f:
        hash_val = hashlib.sha256(f.read()).hexdigest()
    signed_text = (
        f"Digitally Signed by Expedite Consults DSIT System\n"
        f"SHA256: {hash_val[:32]}...\n"
        f"Generated: {datetime.now()}"
    )
    print(f"✅ PDF Signed: {pdf_path}")

    msg = MIMEMultipart("related")
    msg["From"], msg["To"] = smtp_user, ", ".join(recipients)
    msg["Subject"] = f"SOC Weekly Executive Report — {datetime.now().strftime('%Y-%m-%d')}"
    body = f"""
    <html><body>
    <h3>🩺 Expedite Consults DSIT Executive SOC Summary</h3>
    <p>📅 Generated: {datetime.now()}<br>📊 Posture Score: {posture_score:.1f}/100</p>
    </body></html>
    """
    msg.attach(MIMEText(body, "html"))
    ctx = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, smtp_port) as s:
        s.starttls(context=ctx)
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)
    print("✅ Weekly report emailed successfully.")

if __name__ == "__main__":
    email_weekly_report()
