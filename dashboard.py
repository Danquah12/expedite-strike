#!/usr/bin/env python3
from flask import Flask, render_template, jsonify
import sqlite3
import os

app = Flask(__name__, template_folder="templates")
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vuln_intel.db"))

def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(query, args)
    rows = cur.fetchall()
    conn.close()
    return (rows[0] if rows else None) if one else rows

@app.route("/")
def index():
    # show latest 25 findings
    rows = query_db("SELECT id, host, port, title, severity, source, import_date FROM findings ORDER BY import_date DESC LIMIT 25;")
    findings = [dict(r) for r in rows]
    return render_template("index.html", findings=findings)

@app.route("/api/stats")
def stats():
    rows = query_db("""
        SELECT COALESCE(severity, 'Unknown') AS severity, COUNT(*) AS count
        FROM findings
        GROUP BY severity
        ORDER BY count DESC;
    """)
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    # local dev server
    app.run(host="0.0.0.0", port=8080, debug=True)
