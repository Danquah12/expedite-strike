#!/usr/bin/env python3
"""
vulnerable_api_server.py
────────────────────────
Deliberately VULNERABLE test API server for Expedite Strike API Assessment scanner.
Purpose: demonstration / SAST + DAST scanner validation ONLY.
DO NOT deploy on a public network.

Exposed weaknesses (intentional):
  OWASP API Top 10:
    API1  – BOLA/IDOR        (no authorisation on /api/users/{id})
    API2  – Broken Auth      (weak JWT, no rate-limit on /api/login)
    API3  – Excessive Data   (returns full user objects incl. passwords)
    API4  – Rate Limiting    (unlimited requests accepted)
    API5  – Func-Level Auth  (admin routes accessible without admin role)
    API6  – Mass Assignment  (PATCH /api/users accepts any field)
    API7  – Misconfiguration (CORS *, debug headers, verbose errors)
    API8  – Injection        (SQL-like query in /api/search?q=)
    API9  – Asset Mgmt       (v1 and v0 both live, swagger exposed)
    API10 – Insufficient Log (no access logging on sensitive routes)
  OWASP Web Top 10:
    A01   – Broken Access    (path traversal /files?path=)
    A02   – Crypto Failure   (HTTP + plaintext passwords in response)
    A03   – Injection        (XSS reflected, SQLi error messages)
    A04   – Insecure Design  (/.env, /phpinfo.php, /backup.zip stubs)
    A05   – Misconfiguration (Server: Apache/2.2, X-Powered-By: PHP/5)
    A06   – Outdated Comp.   (version headers)
    A07   – Auth/Session     (session cookie without Secure/HttpOnly)
    A08   – Integrity        (no CSP, open redirect)
    A09   – Logging          (verbose stack trace on /crash)
    A10   – SSRF             (?url= parameter fetches arbitrary URLs)

Usage:
  pip install flask
  python vulnerable_api_server.py
  # Server starts on http://127.0.0.1:7777

Then in Expedite Strike API Assessment:
  Base URL  : http://127.0.0.1:7777
  Auth Header: Authorization: Bearer test-token-123
  OpenAPI   : (paste content of swagger stub below or leave blank)
"""

from flask import Flask, request, jsonify, redirect, make_response, render_template_string
import json, time, os

app = Flask(__name__)
app.config["DEBUG"] = True          # API7: debug mode on
app.secret_key = "hardcoded_secret" # API2: weak secret

# ── Fake database ─────────────────────────────────────────────────────────────
USERS = {
    1: {"id": 1, "username": "admin",    "password": "Admin1234!", "role": "admin",  "email": "admin@corp.local",  "ssn": "123-45-6789", "credit_card": "4111-1111-1111-1111"},
    2: {"id": 2, "username": "alice",    "password": "alice123",   "role": "user",   "email": "alice@corp.local",  "ssn": "987-65-4321"},
    3: {"id": 3, "username": "bob",      "password": "password",   "role": "user",   "email": "bob@corp.local",    "api_key": "sk-prod-abc123xyz"},
    4: {"id": 4, "username": "svc_acct", "password": "svc_pass_01","role": "service","email": "svc@corp.local"},
}


def _add_vuln_headers(resp):
    """API7 / A05: Add intentionally bad headers to every response."""
    resp.headers["Server"]           = "Apache/2.2.34"     # A06: outdated
    resp.headers["X-Powered-By"]     = "PHP/5.6.40"        # A06: outdated
    resp.headers["X-Debug-Token"]    = "vuln-server-debug"  # API7
    resp.headers["Access-Control-Allow-Origin"] = "*"       # API7: CORS *
    resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    # A08: deliberately missing CSP, X-Frame-Options, etc.
    return resp


@app.after_request
def after_request(resp):
    return _add_vuln_headers(resp)


# ── Home / info ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string("""
    <html><body style="background:#0d0f18;color:#e0e0e0;font-family:monospace;padding:30px">
    <h2>🔴 Vulnerable Test API Server</h2>
    <p>Running on port 7777 — for Expedite Strike scanner testing only.</p>
    <ul>
      <li><a href="/swagger.json" style="color:#42b9f5">/swagger.json</a> — OpenAPI spec</li>
      <li><a href="/api/v1/users" style="color:#42b9f5">/api/v1/users</a> — BOLA / IDOR target</li>
      <li><a href="/api/search?q=test" style="color:#42b9f5">/api/search?q=test</a> — Injection target</li>
      <li><a href="/.env" style="color:#42b9f5">/.env</a> — Exposed secrets</li>
      <li><a href="/phpinfo.php" style="color:#42b9f5">/phpinfo.php</a> — Info disclosure</li>
      <li><a href="/crash" style="color:#42b9f5">/crash</a> — Verbose 500 error</li>
    </ul>
    <p style="color:#f54254;margin-top:20px">⚠ This server intentionally has vulnerabilities. LAN use only.</p>
    </body></html>
    """)


# ── A04 / API9: Exposed sensitive files ──────────────────────────────────────
@app.route("/.env")
def dot_env():
    return ("DB_HOST=localhost\nDB_USER=root\nDB_PASSWORD=superSecret123\n"
            "API_KEY=sk-prod-supersecret\nSECRET_KEY=hardcoded_secret\n"
            "JWT_SECRET=jwt_secret_key_do_not_share\n"), 200, {"Content-Type": "text/plain"}


@app.route("/phpinfo.php")
def phpinfo():
    return ("<html><body>PHP Version 5.6.40<br>System: Linux vuln-server 5.x<br>"
            "Server API: Apache 2.2.34<br>PHP Credits: Rasmus Lerdorf</body></html>"), 200


@app.route("/backup.zip")
def backup():
    return b"PK\x03\x04", 200, {"Content-Type": "application/zip"}  # fake ZIP magic bytes


@app.route("/.git/HEAD")
def git_head():
    return "ref: refs/heads/main\n", 200, {"Content-Type": "text/plain"}


@app.route("/server-status")
def server_status():
    return ("<html><body><h1>Apache Server Status for localhost</h1>"
            "<p>Server Version: Apache/2.2.34. Server uptime: 42 days</p></body></html>"), 200


# ── A09: Verbose errors ───────────────────────────────────────────────────────
@app.route("/crash")
def crash():
    raise Exception("Traceback (most recent call last):\n  File 'app.py', line 42, in crash\nAttributeError: 'NoneType' has no attribute 'password'\n  at java.lang.Thread.run(Thread.java:748)")


@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({
        "error": str(e),
        "traceback": "  File 'app.py', line 42\n  stack trace: NullPointerException at java.lang.Thread.run",
        "exception": "AttributeError",
        "file": "/opt/vuln/app.py",
    }), 500


# ── A07: Insecure cookies ─────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST", "GET"])
def login():
    """API2 / A07: weak auth, no rate limit, insecure cookie."""
    data = request.json or request.form
    uname = data.get("username", data.get("user", ""))
    pw    = data.get("password", data.get("pass", ""))
    for uid, u in USERS.items():
        if u["username"] == uname and u["password"] == pw:
            resp = make_response(jsonify({"token": "test-token-123", "role": u["role"],
                                          "message": "Login successful", "dashboard": "/api/v1/users"}))
            # A07: cookie missing Secure + HttpOnly + SameSite
            resp.set_cookie("session", f"user_id={uid}|role={u['role']}", secure=False,
                            httponly=False)
            return resp
    return jsonify({"error": "Invalid credentials"}), 401


# ── API1 / BOLA: No authorisation on user ID ─────────────────────────────────
@app.route("/api/v1/users")
@app.route("/api/users")
def list_users():
    """API1 + API3: Returns all users including passwords (excessive data)."""
    return jsonify(list(USERS.values()))   # exposes SSN, credit card, password


@app.route("/api/v1/users/<int:uid>")
@app.route("/api/users/<int:uid>")
def get_user(uid):
    """API1: BOLA — any token can access any user ID."""
    u = USERS.get(uid)
    if not u:
        return jsonify({"error": "User not found"}), 404
    return jsonify(u)   # API3: full object returned incl. password


# ── API5 / A01: Admin functions with no role check ───────────────────────────
@app.route("/api/admin/users")
@app.route("/api/v1/admin/users")
def admin_users():
    """API5: Function-level auth failure — no admin check."""
    return jsonify({"admin_dashboard": True, "users": list(USERS.values()),
                    "server_config": {"db": "postgres://root:superSecret123@localhost/prod"}})


# ── API6: Mass assignment ─────────────────────────────────────────────────────
@app.route("/api/v1/users/<int:uid>", methods=["PATCH"])
def update_user(uid):
    """API6: Mass assignment — accepts any field including role."""
    data = request.json or {}
    u = USERS.get(uid, {})
    u.update(data)   # blindly applies all submitted fields, including role=admin
    USERS[uid] = u
    return jsonify({"updated": True, "user": u})


# ── API8 / A03: Injection ─────────────────────────────────────────────────────
@app.route("/api/search")
@app.route("/search")
def search():
    """API8 / A03: Reflects query parameter (XSS) & fakes SQLi error."""
    q = request.args.get("q", "")
    xss_sigs = ["<script", "javascript:", "<svg", "onerror", "alert("]
    if any(s.lower() in q.lower() for s in xss_sigs):
        # A03: Reflected XSS — echoes payload verbatim in HTML
        return f"<html><body>Search results for: {q}</body></html>", 200
    sql_sigs = ["'", " or ", "union select", "waitfor", "sleep("]
    if any(s.lower() in q.lower() for s in sql_sigs):
        # A03: SQL syntax error leaked
        return jsonify({
            "error": "sql syntax error near '" + q + "'",
            "detail": "mysql_fetch_array(): expects parameter 1 to be resource",
        }), 500
    return jsonify({"results": [f"Result for: {q}"], "total": 1})


# ── A08: Open redirect ────────────────────────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    """A08: Open redirect via ?url= parameter."""
    url = request.args.get("url", "/")
    return redirect(url)


@app.route("/")  # duplicate route used for redirect testing
def index_redirect():
    url = request.args.get("next", request.args.get("goto", request.args.get("return", None)))
    if url:
        return redirect(url)
    return index()


# ── A10 / SSRF: Fetch arbitrary URL ──────────────────────────────────────────
@app.route("/api/fetch")
@app.route("/fetch")
def fetch_url():
    """A10: SSRF — fetches any URL from ?url= parameter."""
    import urllib.request
    url = request.args.get("url", request.args.get("path",
          request.args.get("src", request.args.get("href", ""))))
    if not url:
        return jsonify({"error": "url param required"}), 400
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            body = r.read(512)
        return body, 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── A01: Path traversal ───────────────────────────────────────────────────────
@app.route("/files")
@app.route("/api/files")
def read_file():
    """A01: Path traversal via ?path= parameter — reads arbitrary files."""
    path = request.args.get("path", "welcome.txt")
    try:
        with open(path) as f:
            return f.read(), 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return jsonify({"error": str(e)}), 404


# ── API7 / A05: Directory listing ────────────────────────────────────────────
@app.route("/uploads/")
@app.route("/static/")
@app.route("/files/")
def dir_listing():
    """A05: Directory listing enabled."""
    return ("<html><body><h1>Index of /uploads/</h1><ul>"
            "<li><a href='backup_20240101.sql'>backup_20240101.sql</a></li>"
            "<li><a href='users_export.csv'>users_export.csv</a></li>"
            "<li><a href='config.bak'>config.bak</a></li>"
            "</ul></body></html>"), 200


# ── API3 / A02: Sensitive data exposure ──────────────────────────────────────
@app.route("/api/v1/profile")
@app.route("/api/profile")
def profile():
    """API3 / A02: Returns password + secrets + PII in plain JSON."""
    return jsonify({
        "user": "alice",
        "password": "alice123",            # plaintext password in response
        "ssn": "987-65-4321",
        "credit_card": "4111-1111-1111-1111",
        "api_key": "sk-prod-abc123xyz",
        "secret": "jwt_secret_key_do_not_share",
    })


# ── API9: Version disclosure ─────────────────────────────────────────────────
@app.route("/api/v0/users")
def legacy_users():
    """API9: Old version still active."""
    return jsonify({"legacy": True, "version": "v0", "users": list(USERS.values())})


@app.route("/api-docs")
@app.route("/swagger.json")
@app.route("/openapi.json")
def swagger():
    """API9: API documentation exposed."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Vulnerable Test API", "version": "1.0.0"},
        "servers": [{"url": "http://127.0.0.1:7777"}],
        "paths": {
            "/api/v1/users":          {"get":   {"summary": "List all users"}},
            "/api/v1/users/{id}":     {"get":   {"summary": "Get user by ID"},
                                       "patch": {"summary": "Update user (mass assignment)"}},
            "/api/login":             {"post":  {"summary": "Login (no rate limit)"}},
            "/api/admin/users":       {"get":   {"summary": "Admin — no auth check"}},
            "/api/search":            {"get":   {"summary": "Search (SQLi + XSS)"}},
            "/api/fetch":             {"get":   {"summary": "SSRF fetch proxy"}},
            "/api/profile":           {"get":   {"summary": "Profile (excessive data)"}},
            "/api/v0/users":          {"get":   {"summary": "Legacy endpoint (API9)"}},
        }
    }
    return jsonify(spec)


# ── Health / status (benign) ──────────────────────────────────────────────────
@app.route("/health")
@app.route("/status")
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "environment": "production"})


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🔴 VULNERABLE TEST API SERVER")
    print("  URL: http://127.0.0.1:7777")
    print("  Paste in Expedite Strike API Assessment → Base URL")
    print("  Auth Header: Authorization: Bearer test-token-123")
    print("  Swagger: http://127.0.0.1:7777/swagger.json")
    print("="*60 + "\n")
    app.run(host="127.0.0.1", port=7777, debug=True, use_reloader=False)
