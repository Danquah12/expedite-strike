import sqlite3

db_path = r'D:\Software Engineering\Software-Engineering-Project-main\Software-Engineering-Project-main\tuhousing\AEGIS ON WINDOWS\app\data\vuln_intel.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Get all findings
cur.execute("SELECT * FROM platform_findings ORDER BY id")
for row in cur.fetchall():
    print(f"  [{row['severity']:8s}] {row['module']:15s} | {row['host']:15s} | {row['title'][:60]}")

# Summary stats
cur.execute("SELECT severity, COUNT(*) as cnt FROM platform_findings WHERE status='Open' GROUP BY severity")
print("\nOpen findings by severity:")
for row in cur.fetchall():
    print(f"  {row['severity']}: {row['cnt']}")

# Get unique hosts
cur.execute("SELECT DISTINCT host FROM platform_findings")
hosts = [r['host'] for r in cur.fetchall()]
print(f"\nUnique hosts: {hosts}")

# Get unique modules  
cur.execute("SELECT DISTINCT module FROM platform_findings")
modules = [r['module'] for r in cur.fetchall()]
print(f"Modules: {modules}")

conn.close()
