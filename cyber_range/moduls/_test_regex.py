import re

TEST_CODE = """
from flask import Flask, request, render_template_string
import sqlite3, hashlib, pickle, jwt, requests

SECRET = 'hardcoded_secret'

def get_user():
    user_id = request.args.get('id')
    query = 'SELECT * FROM users WHERE id=' + user_id
    cursor.execute(query)

def weak_crypto():
    password = request.args.get('password')
    hash_value = hashlib.md5(password.encode()).hexdigest()

def deserialize():
    data = request.data
    obj = pickle.loads(data)

def fetch_url():
    url = request.args.get('url')
    r = requests.get(url)

def search():
    q = request.args.get('q')
    return render_template_string('<h1>Search results for: %s</h1>' % q)

def login():
    if username == 'admin' and password == 'admin':
        return 'Logged in'

app.run(debug=True, port=5000)
"""

rules = [
    ('SQL-001',   r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*["\'].*\+|f["\'].*SELECT|execute\s*\(\s*["\'].*%'),
    ('CRY-001',   r'\bmd5\s*\('),
    ('DES-001',   r'\bpickle\.(loads|load)\s*\('),
    ('SSRF-001',  r'requests\.(get|post|put|delete)\s*\(.*request\.'),
    ('SEC-001',   r'(?i)(password|passwd|pwd|secret)\s*=\s*["\'][^"\']{4,}["\']'),
    ('INJ-005',   r'(?i)(render_template_string|from_string)\s*\(.*request\.'),
    ('CRY-004',   r'(?i)(password|token|secret|hash)\s*==\s*'),
    ('CFG-001',   r'(?i)debug\s*=\s*(true|1|yes)'),
    ('INJ-003',   r'(subprocess\.call|subprocess\.run|os\.system|os\.popen|shell_exec|system\s*\()\s*\('),
]

print("Pattern diagnosis:")
for rid, pat in rules:
    matches = re.findall(pat, TEST_CODE, re.IGNORECASE | re.MULTILINE)
    hit = bool(matches)
    symbol = "MATCH" if hit else "MISS"
    print(f"  {rid}: {symbol}  {matches[:1] if hit else ''}")
