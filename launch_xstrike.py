"""
Expedite Strike — Autonomous Pentest Engine Launcher
=====================================================
One-command startup: python launch_xstrike.py

Checks dependencies, installs missing packages, detects available
tools, and starts the Dash application.
"""

import sys
import os
import subprocess
import socket
import shutil

# ── Configuration ────────────────────────────────────────────────
APP_DIR = os.path.dirname(os.path.abspath(__file__))
APP_PORT = 9011
PYTHON = sys.executable

REQUIRED_PACKAGES = [
    "dash", "dash-bootstrap-components", "dash-cytoscape",
    "flask", "plotly", "reportlab", "requests",
]

OPTIONAL_PACKAGES = {
    "paramiko":         "SSH exploitation & lateral movement",
    "ldap3":            "Active Directory LDAP scanning",
    "pymysql":          "MySQL database exploitation",
    "psycopg2-binary":  "PostgreSQL exploitation & findings DB",
    "google-generativeai": "AI-powered reasoning (Gemini LLM)",
    "zapv2":            "OWASP ZAP integration",
}

NMAP_PATHS = [
    r"D:\Agentic-AI\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\nmap\nmap.exe",
]


def banner():
    print(r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║          EXPEDITE STRIKE • AUTONOMOUS PENTEST ENGINE     ║
    ║                    Standalone Launcher                    ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def check_python():
    v = sys.version_info
    print(f"  [✓] Python {v.major}.{v.minor}.{v.micro}")
    if v.major < 3 or (v.major == 3 and v.minor < 10):
        print("  [!] Python 3.10+ required")
        sys.exit(1)


def install_packages():
    print("\n  ── Checking required packages ──")
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg.replace("-", "_"))
            print(f"  [✓] {pkg}")
        except ImportError:
            missing.append(pkg)
            print(f"  [✗] {pkg} — will install")

    if missing:
        print(f"\n  Installing {len(missing)} missing packages...")
        subprocess.check_call([PYTHON, "-m", "pip", "install", "--quiet"] + missing)
        print("  [✓] Required packages installed")

    print("\n  ── Checking optional packages ──")
    for pkg, desc in OPTIONAL_PACKAGES.items():
        try:
            __import__(pkg.replace("-", "_").split("-")[0])
            print(f"  [✓] {pkg} — {desc}")
        except ImportError:
            print(f"  [○] {pkg} — {desc} (optional, not installed)")


def detect_tools():
    print("\n  ── Detecting external tools ──")

    # Nmap
    nmap_found = False
    for p in NMAP_PATHS:
        if os.path.isfile(p):
            print(f"  [✓] Nmap: {p}")
            nmap_found = True
            break
    if not nmap_found:
        nmap_path = shutil.which("nmap")
        if nmap_path:
            print(f"  [✓] Nmap: {nmap_path}")
            nmap_found = True
        else:
            print("  [○] Nmap: Not found — using built-in TCP scanner")

    # ZAP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 8090))
        s.close()
        print("  [✓] ZAP: Running on port 8090")
    except Exception:
        print("  [○] ZAP: Not running — using built-in OWASP engine")

    # GVM/OpenVAS
    try:
        result = subprocess.run(["docker", "inspect", "aegis-openvas"],
                                capture_output=True, timeout=5)
        if result.returncode == 0:
            print("  [✓] OpenVAS/GVM: Docker container found")
        else:
            print("  [○] OpenVAS/GVM: Not found — using built-in CVE scanner")
    except Exception:
        print("  [○] OpenVAS/GVM: Docker not available — using built-in CVE scanner")

    # Neo4j
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 7687))
        s.close()
        print("  [✓] Neo4j: Running on port 7687")
    except Exception:
        print("  [○] Neo4j: Not running — using in-memory mock graph")

    # Built-in scanner
    print("  [✓] XStrike Built-in CVE Scanner: Always available")
    print("  [✓] XStrike Exploit Engine (25+ modules): Always available")
    print("  [✓] XStrike OWASP Engine (A01-A10): Always available")
    print("  [✓] XStrike AegisProbe Web Scanner: Always available")


def start_app():
    print(f"\n  ── Starting Expedite Strike on port {APP_PORT} ──")
    print(f"  App directory: {APP_DIR}")

    # Set environment
    os.environ["PYTHONIOENCODING"] = "utf-8"

    # Check for Gemini API key
    if not os.environ.get("GEMINI_API_KEY") and not os.environ.get("GOOGLE_API_KEY"):
        print("  [○] No GEMINI_API_KEY set — LLM reasoning disabled")

    # Add Agentic-AI to PATH if it exists
    agentic_path = r"D:\Agentic-AI"
    if os.path.isdir(agentic_path) and agentic_path not in os.environ.get("Path", ""):
        os.environ["Path"] = agentic_path + ";" + os.environ.get("Path", "")

    print(f"\n  ╔═══════════════════════════════════════════════════╗")
    print(f"  ║  🚀 Navigate to: http://127.0.0.1:{APP_PORT}/app/  ║")
    print(f"  ╚═══════════════════════════════════════════════════╝\n")

    # Launch
    os.chdir(APP_DIR)
    os.execv(PYTHON, [PYTHON, "app.py"])


def main():
    banner()

    if "--check" in sys.argv:
        check_python()
        install_packages()
        detect_tools()
        print("\n  ✅ Dependency check complete.\n")
        return

    check_python()
    install_packages()
    detect_tools()
    start_app()


if __name__ == "__main__":
    main()
