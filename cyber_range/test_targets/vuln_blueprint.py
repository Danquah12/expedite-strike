"""
EXPEDITE STRIKE Vulnerable Test Target — Flask Blueprint
===============================================
Serves a deliberately vulnerable web app on /vuln-target/
for testing the 35 exploit database scripts.
"""
from flask import Blueprint, request, Response, redirect
import sqlite3, os, re

vuln_bp = Blueprint("vuln_target", __name__)

# ─── Hardcoded creds (CWE-798) ────────────────────────────────────
_DB_PASSWORD = "SuperSecret123!"
_API_KEY = "sk-EXPEDITE STRIKETEST1234567890abcdefghijklmnopqrstuvwxyz1234"
_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

_STYLE = """
body { font-family: monospace; background: #111; color: #0f0; padding: 20px; }
h1 { color: #f00; } h2 { color: #ff0; }
a { color: #0ff; } .vuln { background: #300; padding: 10px; margin: 10px 0; border: 1px solid #f00; }
pre { background: #222; padding: 10px; overflow-x: auto; }
input,textarea { background: #222; color: #0f0; border: 1px solid #0f0; padding: 5px; }
table { border-collapse: collapse; } th,td { border: 1px solid #0f0; padding: 5px; }
"""

def _html(body, title="EXPEDITE STRIKE Vuln Target"):
    # Deliberately NO security headers (CWE-693, CWE-1021)
    return Response(f"""<!DOCTYPE html><html><head><title>{title}</title>
<style>{_STYLE}</style></head><body>
<h1>⚠ EXPEDITE STRIKE VULNERABLE TEST TARGET</h1>
<p>This app is <b>DELIBERATELY VULNERABLE</b>. For testing only.</p>
<nav>
<a href="/vuln-target/">Home</a> |
<a href="/vuln-target/sqli?id=1">SQLi</a> |
<a href="/vuln-target/xss?q=test">XSS</a> |
<a href="/vuln-target/cmdi?host=127.0.0.1">CMDi</a> |
<a href="/vuln-target/lfi?file=/etc/hostname">LFI</a> |
<a href="/vuln-target/ssrf?url=http://127.0.0.1:9010/">SSRF</a> |
<a href="/vuln-target/redirect">Redirect</a> |
<a href="/vuln-target/upload">Upload</a> |
<a href="/vuln-target/xxe">XXE</a> |
<a href="/vuln-target/idor?user_id=1">IDOR</a> |
<a href="/vuln-target/ssti?name=World">SSTI</a> |
<a href="/vuln-target/csrf">CSRF</a>
</nav><hr>{body}
<hr><p style="color:#666">EXPEDITE STRIKE Test Target v1.0 — Flask</p>
</body></html>""", mimetype="text/html")


@vuln_bp.route("/")
def home():
    rows = [
        ("SQL Injection", "CWE-89", "A03", "/vuln-target/sqli?id=1"),
        ("XSS Reflected", "CWE-79", "A03", "/vuln-target/xss?q=test"),
        ("Command Injection", "CWE-78", "A03", "/vuln-target/cmdi?host=127.0.0.1"),
        ("LFI / Path Traversal", "CWE-22", "A01", "/vuln-target/lfi?file=/etc/passwd"),
        ("SSRF", "CWE-918", "A10", "/vuln-target/ssrf?url=http://127.0.0.1:22"),
        ("Open Redirect", "CWE-601", "A01", "/vuln-target/redirect"),
        ("File Upload", "CWE-434", "A04", "/vuln-target/upload"),
        ("XXE", "CWE-611", "A05", "/vuln-target/xxe"),
        ("IDOR", "CWE-639", "A01", "/vuln-target/idor?user_id=1"),
        ("SSTI", "CWE-94", "A03", "/vuln-target/ssti?name={{7*7}}"),
        ("CSRF", "CWE-352", "A01", "/vuln-target/csrf"),
    ]
    tbl = '<h2>Vulnerability Modules</h2><table><tr><th>Module</th><th>CWE</th><th>OWASP</th><th>Link</th></tr>'
    for name, cwe, owasp, link in rows:
        tbl += f'<tr><td>{name}</td><td>{cwe}</td><td>{owasp}</td><td><a href="{link}">Test →</a></td></tr>'
    tbl += '</table>'
    tbl += '<h3>Also vulnerable to:</h3><ul>'
    tbl += '<li>Missing security headers (CSP, HSTS, X-Frame-Options)</li>'
    tbl += '<li>Hardcoded credentials in source (API_KEY, AWS keys)</li>'
    tbl += '<li>CORS misconfiguration (reflects Origin)</li>'
    tbl += '<li>Information disclosure (.env, phpinfo, debug)</li>'
    tbl += '<li>Clickjacking (no X-Frame-Options)</li>'
    tbl += '</ul>'
    return _html(tbl)


# ─── .env exposure (CWE-200) ─────────────────────────────────────
@vuln_bp.route("/.env")
def dot_env():
    return Response(f"""DB_PASSWORD={_DB_PASSWORD}
API_KEY={_API_KEY}
AWS_ACCESS_KEY_ID={_AWS_KEY}
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=mysql://root:password@localhost/production
SECRET_KEY=EXPEDITE STRIKE-test-secret-key-do-not-use
""", mimetype="text/plain")


# ─── SQL Injection (CWE-89) ──────────────────────────────────────
@vuln_bp.route("/sqli")
def sqli():
    uid = request.args.get("id", "1")
    db = sqlite3.connect("/tmp/EXPEDITE STRIKE_vuln.db")
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT)")
    try:
        db.execute("INSERT INTO users VALUES (1,'admin','admin@test.com','password123')")
        db.execute("INSERT INTO users VALUES (2,'user','user@test.com','letmein')")
        db.execute("INSERT INTO users VALUES (3,'guest','guest@test.com','guest')")
        db.commit()
    except Exception:
        pass
    # VULNERABLE: direct concatenation
    query = f"SELECT * FROM users WHERE id = {uid}"
    body = f'<div class="vuln"><h2>SQL Injection (CWE-89)</h2>'
    body += f'<form><input type="hidden" name="page" value="sqli">User ID: <input name="id" value="{uid}"><input type="submit" value="Search"></form>'
    body += f'<pre>Query: {query}</pre>'
    try:
        rows = db.execute(query).fetchall()
        for r in rows:
            body += f"<pre>{r}</pre>"
    except Exception as e:
        body += f"<pre>Error: {e}</pre>"
    body += '</div>'
    return _html(body)


# ─── XSS Reflected (CWE-79) ──────────────────────────────────────
@vuln_bp.route("/xss")
def xss():
    q = request.args.get("q", "")
    body = '<div class="vuln"><h2>XSS — Reflected (CWE-79)</h2>'
    body += f'<form>Search: <input name="q" value="{q}"><input type="submit"></form>'
    if q:
        # VULNERABLE: no output encoding
        body += f"<p>Results for: {q}</p>"
    # Stored XSS guestbook
    body += '<h3>Guestbook (Stored XSS)</h3>'
    body += '<form method="POST">Name: <input name="name"><br>Message: <textarea name="message"></textarea><br>'
    body += '<input type="submit" value="Post"></form>'
    gb = "/tmp/EXPEDITE STRIKE_guestbook.txt"
    if request.method == "POST" and request.form.get("message"):
        with open(gb, "a") as f:
            f.write(f"{request.form['name']}: {request.form['message']}\n")
    if os.path.exists(gb):
        body += f"<pre>{open(gb).read()}</pre>"
    body += '</div>'
    return _html(body)


# ─── Command Injection (CWE-78) ──────────────────────────────────
@vuln_bp.route("/cmdi")
def cmdi():
    host = request.args.get("host", "127.0.0.1")
    body = '<div class="vuln"><h2>OS Command Injection (CWE-78)</h2>'
    body += f'<form>Ping host: <input name="host" value="{host}"><input type="submit" value="Ping"></form>'
    if host:
        import subprocess
        # VULNERABLE: shell=True with user input
        cmd = f"ping -c 2 {host}"
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            body += f"<pre>$ {cmd}\n{r.stdout}{r.stderr}</pre>"
        except Exception as e:
            body += f"<pre>Error: {e}</pre>"
    body += '</div>'
    return _html(body)


# ─── LFI (CWE-22) ────────────────────────────────────────────────
@vuln_bp.route("/lfi")
def lfi():
    f = request.args.get("file", "/etc/hostname")
    body = '<div class="vuln"><h2>LFI / Path Traversal (CWE-22)</h2>'
    body += f'<form>File: <input name="file" value="{f}" size="40"><input type="submit" value="Read"></form>'
    try:
        content = open(f).read()
        body += f"<pre>{content[:3000]}</pre>"
    except Exception as e:
        body += f"<p>Error: {e}</p>"
    body += '</div>'
    return _html(body)


# ─── SSRF (CWE-918) ──────────────────────────────────────────────
@vuln_bp.route("/ssrf")
def ssrf():
    url = request.args.get("url", "http://127.0.0.1:9010/")
    body = '<div class="vuln"><h2>SSRF (CWE-918)</h2>'
    body += f'<form>Fetch URL: <input name="url" value="{url}" size="50"><input type="submit" value="Fetch"></form>'
    if url:
        import urllib.request
        try:
            content = urllib.request.urlopen(url, timeout=5).read().decode("utf-8", errors="ignore")[:2000]
            body += f"<pre>{content}</pre>"
        except Exception as e:
            body += f"<p>Error: {e}</p>"
    body += '</div>'
    return _html(body)


# ─── Open Redirect (CWE-601) ─────────────────────────────────────
@vuln_bp.route("/redirect")
def open_redir():
    redir = request.args.get("redirect", "")
    if redir:
        return redirect(redir)  # VULNERABLE
    body = '<div class="vuln"><h2>Open Redirect (CWE-601)</h2>'
    body += '<form>Redirect to: <input name="redirect" value="https://example.com"><input type="submit"></form></div>'
    return _html(body)


# ─── File Upload (CWE-434) ───────────────────────────────────────
@vuln_bp.route("/upload", methods=["GET", "POST"])
def upload():
    body = '<div class="vuln"><h2>File Upload (CWE-434)</h2>'
    body += '<form method="POST" enctype="multipart/form-data"><input type="file" name="uploaded_file"><br>'
    body += '<input type="submit" value="Upload"></form>'
    if request.method == "POST" and "uploaded_file" in request.files:
        f = request.files["uploaded_file"]
        os.makedirs("/tmp/uploads", exist_ok=True)
        path = f"/tmp/uploads/{f.filename}"
        f.save(path)
        body += f"<p>✅ Uploaded: {path}</p>"
    body += '</div>'
    return _html(body)


# ─── XXE (CWE-611) ───────────────────────────────────────────────
@vuln_bp.route("/xxe", methods=["GET", "POST"])
def xxe():
    body = '<div class="vuln"><h2>XXE (CWE-611)</h2>'
    body += '<form method="POST"><textarea name="xml" rows="5" cols="50">'
    body += '&lt;?xml version="1.0"?&gt;\n&lt;user&gt;&lt;name&gt;test&lt;/name&gt;&lt;/user&gt;'
    body += '</textarea><br><input type="submit" value="Parse XML"></form>'
    if request.method == "POST" and request.form.get("xml"):
        from lxml import etree
        try:
            parser = etree.XMLParser(resolve_entities=True, dtd_validation=False)
            doc = etree.fromstring(request.form["xml"].encode(), parser)
            body += f"<pre>Parsed: {etree.tostring(doc, pretty_print=True).decode()}</pre>"
        except Exception as e:
            body += f"<pre>Parse error: {e}</pre>"
    body += '</div>'
    return _html(body)


# ─── IDOR (CWE-639) ──────────────────────────────────────────────
@vuln_bp.route("/idor")
def idor():
    users = {
        1: {"name": "Admin", "email": "admin@corp.com", "salary": "$150,000", "ssn": "123-45-6789"},
        2: {"name": "John", "email": "john@corp.com", "salary": "$85,000", "ssn": "987-65-4321"},
        3: {"name": "Jane", "email": "jane@corp.com", "salary": "$92,000", "ssn": "555-12-3456"},
    }
    uid = int(request.args.get("user_id", 1))
    body = '<div class="vuln"><h2>IDOR (CWE-639)</h2>'
    # VULNERABLE: no authorization check
    if uid in users:
        body += f"<pre>{users[uid]}</pre>"
    else:
        body += "<p>User not found</p>"
    body += '<p>Try: ?user_id=1, 2, or 3</p></div>'
    return _html(body)


# ─── SSTI (CWE-94) ───────────────────────────────────────────────
@vuln_bp.route("/ssti")
def ssti():
    name = request.args.get("name", "World")
    body = '<div class="vuln"><h2>Template Injection (CWE-94)</h2>'
    body += f'<form>Name: <input name="name" value="{name}"><input type="submit" value="Greet"></form>'
    # VULNERABLE: render_template_string
    import re as _re
    m = _re.search(r'\{\{(.+?)\}\}', name)
    if m:
        try:
            result = eval(m.group(1))
            name = name.replace(m.group(0), str(result))
        except Exception:
            pass
    body += f"<p>Hello, {name}!</p></div>"
    return _html(body)


# ─── CSRF (CWE-352) ──────────────────────────────────────────────
@vuln_bp.route("/csrf", methods=["GET", "POST"])
def csrf():
    body = '<div class="vuln"><h2>CSRF — No Token (CWE-352)</h2>'
    body += '<form method="POST">New Password: <input type="password" name="password"><br>'
    body += '<input type="submit" value="Change Password"></form>'
    if request.method == "POST" and request.form.get("password"):
        body += f"<p>✅ Password changed!</p>"
    body += '</div>'
    return _html(body)


# ─── CORS (CWE-942) — Reflects any origin ────────────────────────
@vuln_bp.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    # Deliberately NO security headers
    return response
