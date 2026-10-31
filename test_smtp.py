#!/usr/bin/env python3
"""
SMTP test for Ægis GRC questionnaire email delivery.
Usage:
  python test_smtp.py "your-16-char-app-password"
"""
import sys, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import date

FROM_ADDR = "kasiedu@expedite-consults.com"
TO_ADDR   = "asiedudanquah@gmail.com"
PASSWORD  = sys.argv[1] if len(sys.argv) > 1 else input("Enter App Password: ")

msg = MIMEMultipart("alternative")
msg["Subject"] = "✅ Ægis GRC — Assessment Questionnaire Test"
msg["From"]    = f"Ægis GRC <{FROM_ADDR}>"
msg["To"]      = TO_ADDR
msg.attach(MIMEText(f"""<html><body>
<h2 style='color:#1a3a6c'>📋 Ægis GRC Test Email</h2>
<p>SMTP delivery confirmed from <strong>{FROM_ADDR}</strong>.</p>
<p>Date: {date.today()}</p><p style='color:green'>✅ Success!</p>
</body></html>""", "html"))

try:
    print(f"[*] Connecting via SSL/465 ...")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as sv:
        sv.login(FROM_ADDR, PASSWORD)
        sv.sendmail(FROM_ADDR, [TO_ADDR], msg.as_string())
    print(f"[✓] Email delivered to {TO_ADDR}")
except smtplib.SMTPAuthenticationError:
    print("[!] Auth failed — trying STARTTLS/587 ...")
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as sv:
            sv.ehlo(); sv.starttls()
            sv.login(FROM_ADDR, PASSWORD)
            sv.sendmail(FROM_ADDR, [TO_ADDR], msg.as_string())
        print(f"[✓] Email delivered to {TO_ADDR}")
    except smtplib.SMTPAuthenticationError as e:
        print(f"""
[✗] Google rejected the password: {str(e)[:80]}

This means you need a Google App Password (not your regular password).

Steps to get one:
  1. Open:  https://myaccount.google.com/security
     Log in as kasiedu@expedite-consults.com
  2. Enable 2-Step Verification (if not already on)
  3. Open:  https://myaccount.google.com/apppasswords
  4. App name: Ægis  →  click Generate
  5. Copy the 16-character code shown
  6. Run:  python test_smtp.py "abcd efgh ijkl mnop"
""")
