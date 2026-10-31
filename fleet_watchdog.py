import socket
import subprocess
import time
import os
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
STOP_FILE = os.path.join(APP_DIR, '.stop_fleet')
LOG_DIR = os.path.join(APP_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'fleet_watchdog.log')

os.makedirs(LOG_DIR, exist_ok=True)

SERVICES = [
    {'name': 'Mission Control', 'port': 9000, 'cmd': [PYTHON, 'launchpad_server.py', '--port', '9000']},
    {'name': 'Aegis SOC & ASPM', 'port': 9011, 'cmd': [PYTHON, 'app.py']},
    {'name': 'Expedite Strike & Fusion', 'port': 9012, 'cmd': [PYTHON, 'external_assessment_app.py', '--port', '9012']},
    {'name': 'Red Team Ops', 'port': 9013, 'cmd': [PYTHON, 'red_team_app.py', '--port', '9013']},
    {'name': 'Cloud Pentest', 'port': 9014, 'cmd': [PYTHON, 'red_team_suite_app.py', '--port', '9014']},
    {'name': 'Cyber Defence', 'port': 9015, 'cmd': [PYTHON, 'defence_app.py', '--port', '9015']},
    {'name': 'Ransomware Recovery', 'port': 9016, 'cmd': [PYTHON, 'specialised_app.py', '--port', '9016']},
    {'name': 'Unified SOAR & GRC', 'port': 9017, 'cmd': [PYTHON, 'grc_app.py', '--port', '9017']},
    {'name': 'CERBERUS-RE DFIR', 'port': 9018, 'cmd': [PYTHON, 'dfir_app.py', '--port', '9018']},
    {'name': 'Platform Infrastructure', 'port': 9019, 'cmd': [PYTHON, 'platform_app.py', '--port', '9019']},
    {'name': 'PenTest Console', 'port': 9020, 'cmd': [PYTHON, 'pentest_console.py', '--port', '9020']},
    {'name': 'Reporting Suite', 'port': 9021, 'cmd': [PYTHON, 'reports_app.py', '--port', '9021']}
]

def log(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{ts}] {msg}'
    print(line, flush=True)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass

def is_port_listening(port, timeout=1.0):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def start_service(svc):
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONUTF8'] = '1'
    name = svc['name']
    port = svc['port']
    log(f"[Revive] Starting {name} on port {port}...")
    try:
        subprocess.Popen(
            svc['cmd'],
            cwd=APP_DIR,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        log(f"[Error] Failed to start {name}: {e}")

def main():
    if '--stop' in sys.argv:
        with open(STOP_FILE, 'w') as f:
            f.write('stop')
        log('Stop signal created — watchdog will exit.')
        return

    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)

    log('======================================================')
    log('Aegis High-Availability Fleet Watchdog Started')
    log(f'Monitoring {len(SERVICES)} microservices on ports 9000-9021')
    log('======================================================')

    while True:
        if os.path.exists(STOP_FILE):
            log('Stop file detected — watchdog shutting down.')
            break

        for svc in SERVICES:
            port = svc['port']
            if not is_port_listening(port):
                name = svc['name']
                log(f'[Warning] Port {port} ({name}) is NOT listening.')
                start_service(svc)
                time.sleep(1)

        time.sleep(8)

if __name__ == '__main__':
    main()
