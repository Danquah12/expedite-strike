import sys
sys.path.append("/Backup/vuln_intel/app")
from dotenv import load_dotenv
load_dotenv("/Backup/vuln_intel/.env")
from cyber_range.services.exploit_ai import ExploitModeler
modeler = ExploitModeler()
res = modeler.analyze_vulnerability({"name": "CVE-2016-1908"})
print(res[:200])
