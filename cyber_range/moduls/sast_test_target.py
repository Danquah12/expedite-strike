#!/usr/bin/env python3
# coding: utf-8
"""
vulnerable_test_app.py — Deliberately Vulnerable Flask App
===========================================================
PURPOSE : SAST scanner test target — covers all 22 plugin rules.
WARNING : Never deploy this code. It is intentionally insecure.
"""

# ── Imports ────────────────────────────────────────────────────────────────────
import os
import re
import sys
import json
import pickle
import yaml
import hashlib
import sqlite3
import subprocess
import xml.etree.ElementTree as ET   # XXE risk (Bandit blacklist)
from pathlib import Path

import jwt
import requests
from flask import Flask, request, render_template_string, redirect, send_file

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# 1. HARDCODED SECRETS (triggers: Regex SEC-001/002, Plugin-Secrets PI-SEC-*)
# ══════════════════════════════════════════════════════════════════════════════
DB_PASSWORD   = "SuperSecret123!"          # PI-SEC-003 — hardcoded password
API_KEY       = "api_key = 'abc12345xyz'"  # PI-SEC-004 — hardcoded API key
SECRET_KEY    = "mysecret"                 # PI-AUTH-006 — weak JWT secret
GITHUB_TOKEN  = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"  # PI-SEC-008
OPENAI_KEY    = "sk-abcdefgh1234567890ABCDEFGHIJKLMNOP"  # PI-SEC-009
AWS_KEY_ID    = "AKIAIOSFODNN7EXAMPLE"     # PI-SEC-001 — AWS key pattern

app.secret_key = "changeme"               # PI-AUTH-003

# ══════════════════════════════════════════════════════════════════════════════
# 2. WEAK CRYPTOGRAPHY (triggers: Plugin-Crypto PI-CRY-*)
# ══════════════════════════════════════════════════════════════════════════════
import random

def hash_password_weak(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()    # PI-CRY-001 — MD5

def hash_backup(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()   # PI-CRY-002 — SHA-1

def generate_token_insecure() -> str:
    return str(random.randint(100000, 999999))           # PI-CRY-005 — not CSPRNG

# ══════════════════════════════════════════════════════════════════════════════
# 3. SQL INJECTION (triggers: Plugin-SQLi, Taint, SSA, Program Slicing)
# ══════════════════════════════════════════════════════════════════════════════
conn = sqlite3.connect(":memory:")

@app.route("/user")
def get_user():
    user_id = request.args.get("id")                    # SOURCE
    # PI-SQL-001 — string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    conn.execute(query)                                  # SINK (taint flows here)
    return "ok"

@app.route("/search")
def search():
    term = request.args.get("q")                        # SOURCE
    # PI-SQL-002 — %-format
    sql = "SELECT * FROM items WHERE name LIKE '%s'" % term
    conn.execute(sql)                                    # SINK
    return "ok"

# ══════════════════════════════════════════════════════════════════════════════
# 4. COMMAND INJECTION (triggers: Plugin-CmdInj, Taint PI-TA-003/004)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/ping")
def ping():
    host = request.args.get("host")                     # SOURCE
    os.system("ping -c 1 " + host)                      # PI-CMD-001 SINK
    return "pinged"

@app.route("/run")
def run_cmd():
    cmd = request.form.get("cmd")                       # SOURCE
    subprocess.Popen(cmd, shell=True)                   # PI-CMD-002 + PI-CMD-004 SINK
    return "ran"

@app.route("/exec")
def run_exec():
    code = request.args.get("code")                     # SOURCE
    exec(code)                                          # PI-CMD-006 SINK
    return "executed"

# ══════════════════════════════════════════════════════════════════════════════
# 5. XSS (triggers: Plugin-XSS PI-XSS-005/007)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/greet")
def greet():
    name = request.args.get("name")                     # SOURCE
    # PI-XSS-005 — user input rendered into template string
    return render_template_string(f"<h1>Hello {name}</h1>")  # SINK

@app.route("/profile")
def profile():
    bio = request.args.get("bio")
    # Reflected output without escaping
    return f"<div>{bio}</div>"                          # PI-XSS-005

# ══════════════════════════════════════════════════════════════════════════════
# 6. PATH TRAVERSAL (triggers: Plugin-PathTrav, Taint PI-TA-007)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/download")
def download():
    filename = request.args.get("file")                 # SOURCE
    path = "/var/www/files/" + filename                 # joined unsafely
    return send_file(path)                              # PI-PT-001 SINK

@app.route("/read")
def read_file():
    filename = request.args.get("name")                 # SOURCE
    full_path = os.path.join("/var/data", filename)     # PI-PT-003
    with open(full_path) as f:                          # PI-TA-007 SINK
        return f.read()

# ══════════════════════════════════════════════════════════════════════════════
# 7. SSRF (triggers: Plugin-SSRF, Taint PI-TA-*)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")                       # SOURCE
    resp = requests.get(url)                            # PI-SSRF-001 SINK
    return resp.text

@app.route("/proxy")
def proxy():
    target = request.form.get("target")                 # SOURCE
    return requests.post(f"http://{target}/api").text   # PI-SSRF-002 SINK

# ══════════════════════════════════════════════════════════════════════════════
# 8. INSECURE DESERIALIZATION (triggers: Plugin-Deser PI-DES-*)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/load", methods=["POST"])
def load_object():
    data = request.data
    obj  = pickle.loads(data)                           # PI-DES-001 SINK
    return str(obj)

@app.route("/config")
def load_config():
    cfg = request.args.get("config")
    return str(yaml.load(cfg, Loader=yaml.Loader))      # PI-DES-002 SINK

# ══════════════════════════════════════════════════════════════════════════════
# 9. JWT / AUTH ISSUES (triggers: Plugin-Auth PI-AUTH-*)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if password == "admin":                             # PI-AUTH-004 — plaintext compare
        token = jwt.encode({"user": username}, SECRET_KEY, algorithm="HS256")
        return token
    return "fail"

@app.route("/verify")
def verify_token():
    token = request.args.get("token")
    # PI-AUTH-002 — jwt verify=False
    decoded = jwt.decode(token, options={"verify_signature": False})
    return str(decoded)

@app.route("/admin-bypass")
def admin_bypass():
    is_admin = True                                     # PI-AUTH-005 — hardcoded auth flag
    if is_admin:
        return "Welcome admin"

# ══════════════════════════════════════════════════════════════════════════════
# 10. OPEN REDIRECT (triggers: Taint PI-TA-013)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next")                 # SOURCE
    return redirect(next_url)                           # PI-TA-013 SINK

# ══════════════════════════════════════════════════════════════════════════════
# 11. INTERPROCEDURAL TAINT — taint flows across function calls
# ══════════════════════════════════════════════════════════════════════════════
def get_search_term():
    return request.args.get("q")                        # SOURCE in helper fn

def build_query(term):
    return "SELECT * FROM products WHERE name = '" + term + "'"  # propagation

@app.route("/products")
def products():
    term  = get_search_term()                           # taint from helper
    query = build_query(term)                           # taint propagates
    conn.execute(query)                                 # SINK (interprocedural)
    return "ok"

# ══════════════════════════════════════════════════════════════════════════════
# 12. VULNERABLE DEPENDENCIES (triggers: Plugin-Deps PI-DEP-*)
# ══════════════════════════════════════════════════════════════════════════════
# requirements would include:
#   django==1.2
#   log4j:2.14.0
#   lodash: "^3.0.0"
#   pyyaml==3.13

# ══════════════════════════════════════════════════════════════════════════════
# 13. DEBUG MODE + BIND ALL (Bandit: hardcoded_bind_all_interface)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Insecure SSL + debug
    verify = False                                      # PI-CRY-008 — TLS verify disabled
    app.run(host="0.0.0.0", port=5000, debug=True)     # Regex: Debug Mode Enabled


# ══════════════════════════════════════════════════════════════════════════════
# 14. HIGH CYCLOMATIC COMPLEXITY (triggers: CPG PI-CPG-CC)
# ══════════════════════════════════════════════════════════════════════════════
def complex_validator(data, mode, flag1, flag2, flag3):
    """Intentionally high McCabe complexity (≥10 branches)."""
    result = []
    if mode == "strict":
        if flag1:
            if data:
                for item in data:
                    if item > 0:
                        if flag2:
                            result.append(item * 2)
                        elif flag3:
                            result.append(item * 3)
                        else:
                            result.append(item)
                    elif item == 0:
                        if flag2 and flag3:
                            result.append(-1)
                        else:
                            result.append(0)
                    else:
                        result.append(abs(item))
            else:
                return []
        elif flag2:
            result = [x for x in data if x > 0]
        else:
            result = list(data)
    elif mode == "loose":
        result = list(data)
    else:
        for item in data:
            try:
                result.append(int(item))
            except (ValueError, TypeError):
                pass
    return result
