import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

host = "in-v3.mailjet.com"
port = 587
user = "ed080ab53685d60a92f1e7db6ec6d834"
pwd  = "b078ec1cd223ec2c7c5ef09dd8fd7462"
frm  = "asiedudanquah@gmail.com"
to   = "kasiedu@expedite-consults.com"

msg = MIMEMultipart("alternative")
msg["Subject"] = "Mailjet Diagnostic Test"
msg["From"]    = frm
msg["To"]      = to
msg.attach(MIMEText("This is a test of the Mailjet relay.", "html"))

try:
    print("Connecting to Mailjet...")
    sv = smtplib.SMTP(host, port)
    sv.set_debuglevel(1)  # Print full SMTP conversation
    sv.ehlo()
    sv.starttls()
    sv.login(user, pwd)
    print("\nSending email...")
    resp = sv.sendmail(frm, [to], msg.as_string())
    print(f"\nSendmail response: {resp}")
    sv.quit()
    print("Success. If it's not in the inbox, Mailjet is queuing or dropping it internally.")
except Exception as e:
    print(f"Error: {e}")
