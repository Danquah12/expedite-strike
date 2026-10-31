import glob, os
from nmap_importer import import_nmap
from openvas_importer import import_openvas
from zap_importer import import_zap
from burp_importer import import_burp

BASE = "/opt/vuln_intel/imports"

print("=== Running Nmap imports ===")
for f in glob.glob(f"{BASE}/nmap/*.xml"):
    print(f"Importing {f}")
    import_nmap(f)

print("=== Running OpenVAS imports ===")
for f in glob.glob(f"{BASE}/openvas/*.xml"):
    print(f"Importing {f}")
    import_openvas(f)

print("=== Running ZAP imports ===")
for f in glob.glob(f"{BASE}/zap/*.xml"):
    print(f"Importing {f}")
    import_zap(f)

print("=== Running Burp imports ===")
for f in glob.glob(f"{BASE}/burp/*.xml"):
    print(f"Importing {f}")
    import_burp(f)

print("=== DONE ===")
