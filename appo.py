# -*- coding: utf-8 -*-

"""
Towson University — AI-Augmented Vulnerability Intelligence Dashboard
Authoritative Architecture:
Scanners → Shared Artifacts → Neo4j Ingestor → Analytics / AI / Dash
"""
ENABLE_OPENVAS = False
ENABLE_BURP = False

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mitre_loader import run_full_mitre_loader

# ==========================================================
# ENVIRONMENT & SYSTEM SETUP
# ==========================================================
import os
import time
import threading
from collections import deque
from dotenv import load_dotenv
from openai import OpenAI
import psutil

# Load environment variables
load_dotenv("/root/vuln_intel/.env", override=True)

# Explicitly disable proxies (OpenAI stability)
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ[k] = ""

# ==========================================================
# GLOBAL UI / LLM STATE (SAFE)
# ==========================================================
CHAT_HISTORY = deque(maxlen=6)

LAST_LLM_CALL = 0
LLM_LOCK = threading.Lock()
LAST_GLOBAL_LLM_CALL = 0
GLOBAL_LLM_COOLDOWN = 8  # seconds

# ==========================================================
# GLOBAL LLM ENTRY POINT (TPM SAFE)
# ==========================================================
def call_llm(prompt: str) -> str:
    global LAST_GLOBAL_LLM_CALL

    with LLM_LOCK:
        now = time.time()
        if now - LAST_GLOBAL_LLM_CALL < GLOBAL_LLM_COOLDOWN:
            return (
                "⚠️ System is temporarily rate-limited to avoid exceeding AI usage limits."
            )

        LAST_GLOBAL_LLM_CALL = now

        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=500,
        )

        return response.choices[0].message.content.strip()

# ==========================================================
# DASH / UI IMPORTS
# ==========================================================
from dash import Dash, html, dcc, Input, Output, State, callback
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
import dash_daq as daq
import pandas as pd
import plotly.express as px

# ==========================================================
# DATABASE / GRAPH
# ==========================================================
from neo4j import GraphDatabase
from cyber_range.services.neo4j_engine import Neo4jEngine

# ==========================================================
# SCANNER SERVICES (EXPORT-ONLY)
# ==========================================================
# ❗ These DO NOT touch Neo4j
# ❗ They ONLY write artifacts into shared storage
from cyber_range.services.zap_ingest import ZAPScanner
from cyber_range.services.openvas_ingest import OpenVASScanner
from cyber_range.services.nmap_ingest import NmapScanner
from cyber_range.services.zap_ingest import ZAPScanner

# ==========================================================
# INGESTION PIPELINE (DOWNSTREAM)
# ==========================================================
# ❗ This is the ONLY component allowed to talk to Neo4j
from cyber_range.ingest.neo4j_ingestor import Neo4jIngestor

# ==========================================================
# INTELLIGENCE / ENRICHMENT
# ==========================================================
from cyber_range.services.mitre_mapper import map_vulnerabilities_to_mitre
from cyber_range.services.killchain import KillChainGenerator
from cyber_range.services.digital_twin import DigitalTwin
from cyber_range.services.exploit_ai import ExploitModeler
from cyber_range.services.remediation_ai import RemediationAI
from cyber_range.services.ti_feed import ThreatIntelFeed
from cyber_range.services.nmap_ingest import NmapIngestor

# ==========================================================
# CYBER RANGE UI MODULES
# ==========================================================
from cyber_range.moduls.ui_killchain import killchain_tab
from cyber_range.moduls.ui_digital_twin import (
    digital_twin_tab,
    register_callbacks as dt_callbacks,
)
from cyber_range.moduls.ui_honeypot import (
    honeypot_tab,
    register_callbacks as hp_callbacks,
)
from cyber_range.moduls.ui_exploit_ai import (
    exploit_ai_tab,
    register_callbacks as exp_callbacks,
)
from cyber_range.moduls.ui_wargame_ai import (
    wargame_tab,
    register_callbacks as wg_callbacks,
)
from cyber_range.moduls.ui_ti_feed import (
    ti_feed_tab,
    register_callbacks as ti_callbacks,
)
from cyber_range.moduls.ui_remediation import (
    remediation_tab,
    register_callbacks as rm_callbacks,
)
from cyber_range.moduls.ui_attack_chain import (
    attack_chain_simulator_layout,
    aggressive_attack_layout,
)

# ==========================================================
# DASH APPLICATION INITIALIZATION
# ==========================================================
app = Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    suppress_callback_exceptions=True,
)

# ==========================================================
# SERVICE INITIALIZATION
# ==========================================================
# Scanners (artifact producers)
zap_scanner = ZAPScanner()
openvas_scanner = OpenVASScanner()
nmap_scanner = NmapScanner()

# Ingestor (artifact consumer → Neo4j)
neo4j_ingestor = Neo4jIngestor()

# Intelligence engines
killchain_engine = KillChainGenerator()
digital_twin_engine = DigitalTwin()
exploit_engine = ExploitModeler()
remediation_engine = RemediationAI()
ti_feed_engine = ThreatIntelFeed()

# ==========================================================
# NOTE:
#  - Scanners write to: data/scans/incoming/{zap,nmap,openvas}
#  - Neo4jIngestor watches & processes artifacts
#  - Dash reads ONLY from Neo4j
# ==========================================================


# ==========================================================
#  NEO4J CONFIGURATION (GLOBAL - REQUIRE THIS)
# ==========================================================
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"



# Automatically rebuild MITRE ATT&CK graph on startup
print("[APP] Running MITRE Enterprise Loader (STRICT)…")
run_full_mitre_loader()

DB_PATH = "/opt/vuln_intel/vuln_intel.db"

# =====================================================================
#  UNIVERSAL SCAN ENGINE (Nmap → SQLite → Neo4j)
# =====================================================================

import os
import sqlite3
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase

# =====================================================================
#  UNIVERSAL SCAN ENGINE (Nmap → SQLite → Neo4j)
# =====================================================================
import os
import sqlite3
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase

# ==================================================
# GLOBAL SCAN STATE (REQUIRED)
# ==================================================
import threading

scan_running = False
scan_log_buffer = []
scan_lock = threading.Lock()


def run_nmap_scan(targets):
    xml_path = "/opt/vuln_intel/scans/nmap_output.xml"
    cmd = f"nmap -A -sV -sC -O -T4 -p- {targets} -oX {xml_path}"
    os.system(cmd)
    return xml_path

def import_results_to_sqlite(xml_path):
    conn = sqlite3.connect("/opt/vuln_intel/vuln_intel.db")
    cur = conn.cursor()
    root = ET.parse(xml_path).getroot()

    for host in root.findall("host"):
        status = host.find("status").get("state")
        if status != "up":
            continue

        ip = host.find("address").get("addr")
        cur.execute("INSERT OR IGNORE INTO assets (ip, state, source) VALUES (?, ?, 'nmap')",
                    (ip, status))

        for port in host.findall("ports/port"):
            portid = port.get("portid")
            protocol = port.get("protocol")
            svc = port.find("service")
            if svc is None:
                continue
            name = svc.get("name", "unknown")

            cur.execute("""
                INSERT INTO services (ip, port, protocol, name, source)
                VALUES (?, ?, ?, ?, 'nmap')
            """, (ip, portid, protocol, name))

    conn.commit()
    conn.close()

def import_results_to_neo4j(xml_path):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","Adomaa12@"))
    root = ET.parse(xml_path).getroot()

    with driver.session() as session:
        for host in root.findall("host"):
            status = host.find("status").get("state")
            if status != "up":
                continue

            ip = host.find("address").get("addr")
            session.run("MERGE (a:Asset {ip:$ip}) SET a.state=$state",
                        ip=ip, state=status)

            for port in host.findall("ports/port"):
                portid = port.get("portid")
                protocol = port.get("protocol")

                svc = port.find("service")
                if svc is None:
                    continue

                name = svc.get("name", "unknown")
                sid = f"{ip}:{portid}"

                session.run("""
                    MERGE (s:Service {id:$sid})
                    SET s.ip=$ip, s.port=$portid, s.protocol=$protocol, s.name=$name
                    MERGE (a:Asset {ip:$ip})
                    MERGE (a)-[:HAS_SERVICE]->(s)
                """, sid=sid, ip=ip, portid=portid, protocol=protocol, name=name)

    driver.close()


def get_raw_targets(raw_input):
    """Return exactly what the user typed."""
    return raw_input.strip()


def run_nmap_scan(targets):
    """Execute a full aggressive Nmap scan."""
    xml_path = "/opt/vuln_intel/scans/nmap_output.xml"
    cmd = f"nmap -A -sV -sC -O -T4 -p- {targets} -oX {xml_path}"
    os.system(cmd)
    return xml_path


def import_results_to_sqlite(xml_path):
    """Parse Nmap XML and store Assets + Services in SQLite."""
    conn = sqlite3.connect("/opt/vuln_intel/vuln_intel.db")
    cur = conn.cursor()

    root = ET.parse(xml_path).getroot()

    for host in root.findall("host"):
        status = host.find("status").get("state")
        if status != "up":
            continue

        ip = host.find("address").get("addr")

        cur.execute("""
            INSERT OR IGNORE INTO assets (ip, state, source)
            VALUES (?, ?, 'nmap')
        """, (ip, status))

        for port in host.findall("ports/port"):
            portid = port.get("portid")
            protocol = port.get("protocol")

            service_el = port.find("service")
            if service_el is None:
                continue

            service_name = service_el.get("name", "unknown")

            cur.execute("""
                INSERT INTO services (ip, port, protocol, name, source)
                VALUES (?, ?, ?, ?, 'nmap')
            """, (ip, portid, protocol, service_name))

    conn.commit()
    conn.close()


def import_results_to_neo4j(xml_path):
    """Insert Assets + Services into Neo4j graph."""
    root = ET.parse(xml_path).getroot()
    driver = GraphDatabase.driver("bolt://localhost:7687",
                                  auth=("neo4j", "Adomaa12@"))

    with driver.session() as session:
        for host in root.findall("host"):
            status = host.find("status").get("state")
            if status != "up":
                continue

            ip = host.find("address").get("addr")

            session.run("""
                MERGE (a:Asset {ip: $ip})
                SET a.state = $state
            """, ip=ip, state=status)

            for port in host.findall("ports/port"):
                portid = port.get("portid")
                protocol = port.get("protocol")

                service_el = port.find("service")
                if service_el is None:
                    continue

                service_name = service_el.get("name", "unknown")
                sid = f"{ip}:{portid}"

                session.run("""
                    MERGE (s:Service {id: $sid})
                    SET s.ip = $ip,
                        s.port = $port,
                        s.protocol = $protocol,
                        s.name = $service_name
                    MERGE (a:Asset {ip: $ip})
                    MERGE (a)-[:HAS_SERVICE]->(s)
                """,
                sid=sid, ip=ip, port=portid,
                protocol=protocol, service_name=service_name)

    driver.close()


def insert_finding(row):
    """
    Insert parsed finding into SQLite using your exact schema.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    sql = """
    INSERT INTO findings (
        asset_id, host, port, service, title, severity,
        cvss, cve_id, description, evidence, remediation,
        vuln_name, path, source, import_date, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    cur.execute(sql, row)
    conn.commit()
    conn.close()


def parse_nmap_xml(content):
    """
    Parse Nmap XML content → list of DB rows.
    """
    rows = []
    root = ET.fromstring(content)

    for host in root.findall("host"):
        addr = host.find("address").attrib["addr"]

        for port in host.findall(".//port"):
            portid = port.attrib.get("portid")
            service_el = port.find("service")

            service_name = service_el.attrib.get("name") if service_el is not None else "unknown"

            row = [
                None,                        # asset_id
                addr,                        # host
                portid,                      # port
                service_name,                # service
                f"{service_name} detected",  # title
                "info",                      # severity
                None,                        # cvss
                None,                        # cve_id
                None,                        # description
                None,                        # evidence
                None,                        # remediation
                service_name,                # vuln_name
                None,                        # path
                "nmap",                      # source
                datetime.now().strftime("%Y-%m-%d"),
                datetime.now().strftime("%H:%M:%S")
            ]
            rows.append(row)

    return rows


# =====================================================================
#  GRAPH TYPES & CYPHER QUERIES  (OPTION A - 7 CATEGORIES • 20 TYPES)
# =====================================================================

GRAPH_TYPES = {

    # ----------------------------------------------------------
    # 1) CORE RELATIONSHIP GRAPHS
    # ----------------------------------------------------------
    "Core Relationship Graphs": [
        {"label": "Asset ↔ Service Mapping", "value": "core_asset_service"},
        {"label": "Asset ↔ Vulnerability Mapping", "value": "core_asset_vuln"},
        {"label": "Service ↔ Vulnerabilities", "value": "core_service_vuln"},
        {"label": "Asset ↔ Dependencies", "value": "core_asset_dependency"},
    ],

    # ----------------------------------------------------------
    # 2) VULNERABILITY GRAPHS
    # ----------------------------------------------------------
    "Vulnerability Graphs": [
        {"label": "All Vulnerabilities Overview", "value": "vuln_all"},
        {"label": "CVSS Severity Tiers", "value": "vuln_cvss_tiers"},
        {"label": "Exploitable Vulnerabilities", "value": "vuln_exploitable"},
        {"label": "Vulnerability Attack Surface", "value": "vuln_attack_surface"},
    ],

    # ----------------------------------------------------------
    # 3) THREAT INTELLIGENCE
    # ----------------------------------------------------------
    "Threat Intelligence Graphs": [
        {"label": "ThreatActor → Exploit → Vulnerability", "value": "ti_actor_exploit_vuln"},
        {"label": "Exploit ↔ Vulnerability Mapping", "value": "ti_exploit_vuln"},
        {"label": "MITRE ATT&CK Techniques", "value": "ti_attack_techniques"},
    ],

    # ----------------------------------------------------------
    # 4) ATTACK PATH
    # ----------------------------------------------------------
    "Attack Path Graphs": [
        {"label": "Shortest Attack Path → Crown Jewel", "value": "ap_shortest_to_cj"},
        {"label": "Privilege Escalation Paths", "value": "ap_privilege_escalation"},
        {"label": "User → Asset → Vulnerability Chain", "value": "ap_user_asset_vuln"},
        {"label": "Lateral Movement Chains", "value": "ap_lateral_movement"},
    ],

    # ----------------------------------------------------------
    # 5) NETWORK
    # ----------------------------------------------------------
    "Network Graphs": [
        {"label": "Network Segments ↔ Assets", "value": "net_segments_assets"},
        {"label": "Firewall Allowed Paths", "value": "net_firewall_paths"},
        {"label": "Inbound / Outbound Exposure Graph", "value": "net_exposure"},
    ],

    # ----------------------------------------------------------
    # 6) COMPLIANCE
    # ----------------------------------------------------------
    "Compliance Graphs": [
        {"label": "Control → Gap → POAM", "value": "comp_control_gap_poam"},
        {"label": "Control Family Overview", "value": "comp_control_families"},
        {"label": "Control Coverage Map", "value": "comp_coverage"},
    ],

    # ----------------------------------------------------------
    # 7) CLOUD SECURITY
    # ----------------------------------------------------------
    "Cloud Security Graphs": [
        {"label": "CloudAsset ↔ SecurityGroup", "value": "cloud_asset_sg"},
        {"label": "IAM Role Assignments", "value": "cloud_iam_paths"},
        {"label": "Cloud Misconfigurations", "value": "cloud_misconfigs"},
    ],
}

# ======================================================================
#   NEO4J GRAPH QUERIES FOR GRAPH INTELLIGENCE
# ======================================================================

GRAPH_QUERIES = {

    # ----------------------------------------------------------
    # 1) CORE RELATIONSHIP GRAPH QUERIES
    # ----------------------------------------------------------
    "Core Relationship Graphs": {

        "core_asset_service": """
            MATCH (a:Asset)-[r:HAS_SERVICE]->(s:Service)
            RETURN a, r, s
        """,

        "core_asset_vuln": """
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, v
        """,

        "core_service_vuln": """
            MATCH (s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN s, v
        """,

        "core_asset_dependency": """
            MATCH (a:Asset)-[r:DEPENDS_ON]->(b:Asset)
            RETURN a, r, b
        """,
    },

    # ----------------------------------------------------------
    # 2) VULNERABILITY GRAPH QUERIES
    # ----------------------------------------------------------
    "Vulnerability Graphs": {

        "vuln_all": """
            MATCH (v:Vulnerability)
            RETURN v
        """,

        "vuln_cvss_tiers": """
            MATCH (v:Vulnerability)
            RETURN v
        """,

        "vuln_exploitable": """
            MATCH (v:Vulnerability {exploitable: true})
            RETURN v
        """,

        "vuln_attack_surface": """
            MATCH p = (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN p
        """,
    },

    # ----------------------------------------------------------
    # 3) THREAT INTELLIGENCE GRAPH QUERIES
    # ----------------------------------------------------------
    "Threat Intelligence Graphs": {

        "ti_actor_exploit_vuln": """
            MATCH p = (ta:ThreatActor)-[:USES_EXPLOIT]->(e:Exploit)
                        -[:TARGETS]->(v:Vulnerability)
            RETURN p
        """,

        "ti_exploit_vuln": """
            MATCH (e:Exploit)-[:TARGETS]->(v:Vulnerability)
            RETURN e, v
        """,

        "ti_attack_techniques": """
            MATCH (tech:Technique)
            RETURN tech
        """,
    },

    # ----------------------------------------------------------
    # 4) ATTACK PATH GRAPH QUERIES
    # ----------------------------------------------------------
    "Attack Path Graphs": {

        "ap_shortest_to_cj": """
            MATCH (cj:CrownJewel)
            MATCH p = shortestPath((a:Asset)-[:HAS_VULNERABILITY*..5]->(cj))
            RETURN p
        """,

        "ap_privilege_escalation": """
            MATCH p = (u:User)-[:HAS_ACCESS]->(a:Asset)
                      -[:HAS_VULNERABILITY]->(v:Vulnerability)
                      -[:ALLOWS_PRIV_ESC]->(tech:Technique)
            RETURN p
        """,

        "ap_user_asset_vuln": """
            MATCH p = (u:User)-[:USES]->(a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN p
        """,

        "ap_lateral_movement": """
            MATCH p = (a1:Asset)-[:LATERAL_MOVE]->(a2:Asset)
            RETURN p
        """,
    },

    # ----------------------------------------------------------
    # 5) NETWORK GRAPH QUERIES
    # ----------------------------------------------------------
    "Network Graphs": {

        "net_segments_assets": """
            MATCH (n:NetworkSegment)-[:CONTAINS]->(a:Asset)
            RETURN n, a
        """,

        "net_firewall_paths": """
            MATCH p = (src:Asset)-[:ALLOWED_BY_FW*1..3]->(dst:Asset)
            RETURN p
        """,

        "net_exposure": """
            MATCH p = (a:Asset)-[:EXPOSED_TO]->(i:Internet)
            RETURN p
        """,
    },

    # ----------------------------------------------------------
    # 6) COMPLIANCE GRAPH QUERIES
    # ----------------------------------------------------------
    "Compliance Graphs": {

        "comp_control_gap_poam": """
            MATCH p = (c:Control)-[:HAS_GAP]->(g:Gap)-[:GENERATES_POAM]->(p:POAM)
            RETURN p
        """,

        "comp_control_families": """
            MATCH (cf:ControlFamily)-[:CONTAINS]->(c:Control)
            RETURN cf, c
        """,

        "comp_coverage": """
            MATCH (c:Control)-[:COVERED_BY]->(e:Evidence)
            RETURN c, e
        """,
    },

    # ----------------------------------------------------------
    # 7) CLOUD SECURITY GRAPH QUERIES
    # ----------------------------------------------------------
    "Cloud Security Graphs": {

        "cloud_asset_sg": """
            MATCH (ca:CloudAsset)-[:ASSIGNED_TO]->(sg:SecurityGroup)
            RETURN ca, sg
        """,

        "cloud_iam_paths": """
            MATCH p = (u:CloudUser)-[:ASSUMES_ROLE]->(r:Role)-[:PERMITS]->(a:CloudAsset)
            RETURN p
        """,

        "cloud_misconfigs": """
            MATCH (m:Misconfiguration)-[:AFFECTS]->(ca:CloudAsset)
            RETURN m, ca
        """,
    },
}


# ==========================================================
#  ENVIRONMENT SETUP
# ==========================================================
PROJECT_ROOT = "/opt/vuln_intel"
DB_PATH = f"{PROJECT_ROOT}/vuln_intel.db"
STATUS_LOG = "/opt/vuln_intel/app/status.log"

# Create or clear the status log file on startup
Path(STATUS_LOG).write_text("=== Dashboard initialized ===\n")

# OpenAI API (if used in other modules)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-4o"

print(f"[+] DB path: {DB_PATH}")
print("[+] Environment initialized successfully.")

# ==========================================================
#  DASH INITIALIZATION
# ==========================================================
external_stylesheets = [dbc.themes.DARKLY]
app = Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=external_stylesheets)
app.title = "Towson Vulnerability Intelligence Dashboard"
server = app.server

print(f"[+] DB path: {DB_PATH}")
print("[+] Environment initialized successfully.")

# ==========================================================
#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    """Load vulnerability data from SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings LIMIT 1000", conn)
        conn.close()
        return df
    except Exception as e:
        print("Error loading findings:", e)
        return pd.DataFrame(columns=["id", "host", "severity", "cvss", "source"])



from openai import OpenAI
client = OpenAI()

def call_llm(prompt):
    """Query OpenAI GPT model using the new Responses API."""
    try:
        response = client.responses.create(
            model="gpt-5.2",
            input=prompt
        )
        return response.output_text
    except Exception as e:
        return f"LLM error: {e}"




# ==================================================
# CALLBACK: TAB ROUTING
# ==================================================
@callback(
    Output("tab-content", "children"),
    Input("tabs", "active_tab"),
)
def render_tab(active_tab):

    if active_tab == "system":
        return system_health_layout()

    elif active_tab == "assessment":
        return assessment_tab

    elif active_tab == "vuln":
        return vulnerability_tab()

    elif active_tab == "llm":
        return llm_tab

    elif active_tab == "chatbot":
        return chatbot_tab

    elif active_tab == "neo4j":
        return neo4j_graphs_tab()

    elif active_tab == "mitre":
        return mitre_tab_layout()

    elif active_tab == "reporting":
        return reporting_tab

    elif active_tab == "voice":
        return voice_tab()

    return html.Div("Tab not implemented", className="text-danger")

# ==========================================================
#  TAB 1: SYSTEM HEALTH
# ==========================================================
def system_health_layout():
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent

    health_df = pd.DataFrame({
        "Metric": ["CPU Usage", "Memory Usage", "Disk Usage"],
        "Value": [cpu, mem, disk]
    })
    fig = px.bar(health_df, x="Metric", y="Value", text="Value", color="Value",
                 color_continuous_scale="inferno", title="System Resource Utilization (%)")

    return dbc.Container([
        html.H3("🖥️ System Health Overview", className="text-warning mb-3"),
        dcc.Graph(figure=fig),
        html.Div(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 style={"textAlign": "center", "color": "#bbb"})
    ])


# ==========================================================
#  ENVIRONMENT SETUP
# ==========================================================
PROJECT_ROOT = "/opt/vuln_intel"
DB_PATH = f"{PROJECT_ROOT}/vuln_intel.db"
STATUS_LOG = f"{PROJECT_ROOT}/app/status.log"

# Create or clear status log file
Path(STATUS_LOG).write_text("=== Dashboard initialized ===\n")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-4o"

print(f"[+] DB path: {DB_PATH}")
print("[+] Environment initialized successfully.")


# ==========================================================
#  DASH INITIALIZATION
# ==========================================================
# -------------------------------------------------
# App setup (ONLY ONCE)
# -------------------------------------------------
external_stylesheets = [dbc.themes.DARKLY]

app = Dash(
    __name__,
    suppress_callback_exceptions=True,
    external_stylesheets=external_stylesheets,
)
server = app.server


#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    ...


# ==========================================================
#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    ...



# ==========================================================
#  HELPER FUNCTIONS
# ==========================================================
def load_findings():
    """Example helper for loading vulnerability data from SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings", conn)
        conn.close()
        print(f"[+] Loaded {len(df)} findings from {DB_PATH}")
        return df
    except Exception as e:
        print(f"[!] Could not load findings: {e}")
        return pd.DataFrame()


# ==========================================================
#  TAB 2: VULNERABILITY DASHBOARD  (AUTHORITATIVE / SINGLE SOURCE: NEO4J)
# ==========================================================

import re
import pandas as pd
import plotly.express as px
from datetime import datetime
from neo4j import GraphDatabase
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
from dash.dependencies import Input, Output


def vulnerability_tab():
    return dbc.Container([
        html.H3("📊 Vulnerability Dashboard", className="text-warning mb-3"),

        dbc.Button("🔄 Refresh Dashboard", id="nessus-refresh", color="warning", className="mb-3"),

        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardHeader("Total Assets"),
                dbc.CardBody(html.H3(id="metric-assets", className="text-center"))
            ], color="dark", inverse=True), width=3),

            dbc.Col(dbc.Card([
                dbc.CardHeader("Total Services"),
                dbc.CardBody(html.H3(id="metric-services", className="text-center"))
            ], color="secondary", inverse=True), width=3),

            dbc.Col(dbc.Card([
                dbc.CardHeader("Total Vulnerabilities"),
                dbc.CardBody(html.H3(id="metric-vulns", className="text-center"))
            ], color="danger", inverse=True), width=3),
        ], className="mb-4"),

        html.H5("Filter Attack Surface", className="text-light mt-4"),
        dcc.Dropdown(
            id="graph-filter",
            options=[
                {"label": "FTP", "value": "service:ftp"},
                {"label": "SSH", "value": "service:ssh"},
                {"label": "SFTP", "value": "service:sftp"},
                {"label": "HTTP", "value": "service:http"},
                {"label": "HTTPS", "value": "service:https"},

                {"label": "Critical", "value": "severity:critical"},
                {"label": "High", "value": "severity:high"},
                {"label": "Medium", "value": "severity:medium"},
                {"label": "Low", "value": "severity:low"},
                {"label": "Informational", "value": "severity:info"},
            ],
            multi=True,
            placeholder="Select filters (service, severity)...",
            style={"backgroundColor": "#222", "color": "#000"}
        ),

        html.Br(),

        html.H5("Attack Surface Graph", className="text-light mt-4"),
        cyto.Cytoscape(
            id="vuln-graph",
            layout={'name': 'cose'},
            style={'width': '100%', 'height': '520px', 'backgroundColor': '#1b1b1b'},
            elements=[],
            stylesheet=[
                # Assets (bigger)
                {
                    'selector': '[type="asset"]',
                    'style': {
                        'background-color': '#28a745',
                        'label': 'data(label)',
                        'font-size': '12px',
                        'color': '#fff',
                        'width': 26,
                        'height': 26
                    }
                },
                # Services
                {
                    'selector': '[type="service"]',
                    'style': {
                        'background-color': '#007bff',
                        'label': 'data(label)',
                        'font-size': '10px',
                        'color': '#fff',
                        'width': 22,
                        'height': 22
                    }
                },
                # Vulnerabilities (bigger + colored by severity)
                {
                    'selector': '[type="vulnerability"]',
                    'style': {
                        'label': 'data(label)',
                        'font-size': '9px',
                        'color': '#fff',
                        'text-wrap': 'wrap',
                        'text-max-width': '120px',
                        'width': 18,
                        'height': 18
                    }
                },
                {'selector': '[severity="critical"]', 'style': {'background-color': '#ff073a'}},
                {'selector': '[severity="high"]', 'style': {'background-color': '#ff8800'}},
                {'selector': '[severity="medium"]', 'style': {'background-color': '#ffc107'}},
                {'selector': '[severity="low"]', 'style': {'background-color': '#28a745'}},
                {'selector': '[severity="info"]', 'style': {'background-color': '#6c757d'}},

                {'selector': 'edge', 'style': {'line-color': '#999'}}
            ]
        ),

        html.Br(),

        html.H5("CVSS Severity Distribution", className="text-light"),
        dcc.Graph(id="cvss-heatmap", style={"height": "350px"}),

        html.Br(),

        html.H5("Asset & Service Summary", className="text-light mt-3"),
        dash_table.DataTable(
            id="vuln-table",
            columns=[
                {"name": "Asset", "id": "Asset"},
                {"name": "Service", "id": "Service"},
                {"name": "Port", "id": "Port"},
                {"name": "Vulnerability (click CVE)", "id": "Vulnerability", "presentation": "markdown"},
                {"name": "Severity", "id": "Severity"},
                {"name": "CVSS", "id": "CVSS"},
            ],
            markdown_options={"html": True, "link_target": "_blank"},
            style_table={"overflowX": "auto", "backgroundColor": "#111"},
            style_header={
                "backgroundColor": "#EAAA00",
                "color": "black",
                "fontWeight": "bold"
            },
            style_cell={
                "backgroundColor": "#222",
                "color": "white",
                "padding": "8px",
                "whiteSpace": "normal",
                "textAlign": "left"
            },
            page_size=12
        ),

        dcc.Interval(id="interval-refresh", interval=30 * 1000, n_intervals=0),
        html.Div(id="alert-banner"),
        html.Div(id="last-updated", style={"textAlign": "center", "color": "#bbb", "marginTop": "10px"})
    ], fluid=True)


# ==========================================================
#  SINGLE AUTHORITATIVE CALLBACK: refresh + filter + table + graph + chart
# ==========================================================

def _safe_id(x: str) -> str:
    """Cytoscape IDs cannot be empty and should not include weird chars."""
    if x is None:
        return ""
    x = str(x).strip()
    x = re.sub(r"\s+", "_", x)
    x = re.sub(r"[^A-Za-z0-9_\-:\.]", "_", x)
    return x[:180]


def _sev_from_cvss(cvss):
    try:
        if cvss is None:
            return "info"
        cvss = float(cvss)
    except Exception:
        return "info"

    if cvss >= 9:
        return "critical"
    if cvss >= 7:
        return "high"
    if cvss >= 4:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _extract_filters(filters):
    filters = filters or []
    services = set()
    severities = set()

    for f in filters:
        if isinstance(f, str) and f.startswith("service:"):
            services.add(f.split("service:", 1)[1].strip().lower())
        if isinstance(f, str) and f.startswith("severity:"):
            severities.add(f.split("severity:", 1)[1].strip().lower())

    return services, severities


@app.callback(
    [
        Output("metric-assets", "children", allow_duplicate=True),
        Output("metric-services", "children", allow_duplicate=True),
        Output("metric-vulns", "children", allow_duplicate=True),
        Output("vuln-graph", "elements", allow_duplicate=True),
        Output("vuln-table", "data", allow_duplicate=True),
        Output("cvss-heatmap", "figure", allow_duplicate=True),
        Output("alert-banner", "children", allow_duplicate=True),
        Output("last-updated", "children", allow_duplicate=True),
    ],
    [
        Input("interval-refresh", "n_intervals"),
        Input("nessus-refresh", "n_clicks"),
        Input("graph-filter", "value"),
    ],
    prevent_initial_call=True
)
def update_vuln_dashboard(n_intervals, refresh_clicks, graph_filters):
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "Adomaa12@"

    selected_services, selected_sevs = _extract_filters(graph_filters)

    assets_set = set()
    services_set = set()
    vuln_key_set = set()

    nodes = []
    edges = []
    table_data = []

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    high_or_critical_found = 0

    # --- IMPORTANT: this query tolerates missing vuln nodes and missing CVSS ---
    q = """
    MATCH (a:Asset)-[:HAS_SERVICE]->(s:Service)
    OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
    RETURN
        coalesce(a.ip, a.host, a.name, a.asset, a.address) AS asset,
        coalesce(s.name, s.service, s.proto, "unknown") AS service,
        coalesce(s.port, s.p, s.number, -1) AS port,
        coalesce(v.cve, v.plugin_id, v.id, v.name, v.title, "NO_VULN") AS vuln_key,
        coalesce(v.name, v.title, v.vuln_name, v.plugin_name, v.cve, "No vulnerability name") AS vuln_name,
        coalesce(toFloat(v.cvss), toFloat(v.severity), null) AS cvss
    """

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            results = list(session.run(q))
        driver.close()
    except Exception as e:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fig = px.scatter(title=f"Neo4j Error: {e}")
        return ("0", "0", "0", [], [], fig, f"Neo4j Error: {e}", f"Last updated: {now}")

    # If Neo4j returned nothing, show empty-but-valid UI
    if not results:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fig = px.scatter(title="No data returned from Neo4j")
        return ("0", "0", "0", [], [], fig, "", f"Last updated: {now}")

    for r in results:
        asset = (r.get("asset") or "").strip()
        service = (r.get("service") or "").strip()
        port = r.get("port")
        vuln_key = (r.get("vuln_key") or "").strip()
        vuln_name = (r.get("vuln_name") or "").strip()
        cvss = r.get("cvss")

        # Normalize
        asset_id = _safe_id(asset)
        service_lc = service.lower()
        sev = _sev_from_cvss(cvss)

        # Apply filters
        if selected_services and service_lc not in selected_services:
            continue
        if selected_sevs and sev not in selected_sevs:
            continue

        # Count assets/services even if vuln missing
        if asset_id:
            assets_set.add(asset_id)
        if service:
            services_set.add(f"{service_lc}:{port}")

        # --- Build nodes/edges ---
        if asset_id:
            nodes.append({"data": {"id": asset_id, "label": asset, "type": "asset"}})

        sid = _safe_id(f"{service_lc}:{port}")
        if sid:
            nodes.append({"data": {"id": sid, "label": f"{service_lc}:{port}", "type": "service"}})
            if asset_id:
                edges.append({"data": {"source": asset_id, "target": sid}})

        # If vuln_key is placeholder (NO_VULN), don't create vuln node, but still keep table row for service exposure
        has_real_vuln = vuln_key and vuln_key != "NO_VULN"

        if has_real_vuln:
            v_id = _safe_id(f"VULN:{vuln_key}")
            vuln_key_set.add(v_id)

            severity_counts[sev] += 1
            if sev in ("critical", "high"):
                high_or_critical_found += 1

            # Clickable NVD link only if looks like a CVE
            vuln_display = vuln_name
            if re.match(r"^CVE-\d{4}-\d{4,}$", vuln_key, re.IGNORECASE):
                vuln_display = f"[{vuln_key}](https://nvd.nist.gov/vuln/detail/{vuln_key}) — {vuln_name}"
            else:
                vuln_display = f"{vuln_key} — {vuln_name}"

            nodes.append({
                "data": {
                    "id": v_id,
                    "label": (vuln_key[:28] + "…") if len(vuln_key) > 28 else vuln_key,
                    "type": "vulnerability",
                    "severity": sev
                }
            })

            if sid:
                edges.append({"data": {"source": sid, "target": v_id}})

            table_data.append({
                "Asset": asset,
                "Service": service_lc,
                "Port": "" if port in (None, -1) else str(port),
                "Vulnerability": vuln_display,
                "Severity": sev.upper(),
                "CVSS": "" if cvss is None else str(cvss)
            })
        else:
            # Service-only row (still useful)
            table_data.append({
                "Asset": asset,
                "Service": service_lc,
                "Port": "" if port in (None, -1) else str(port),
                "Vulnerability": "Service discovered (no vuln node linked yet)",
                "Severity": "INFO",
                "CVSS": ""
            })

    # Deduplicate nodes
    node_map = {}
    for n in nodes:
        nid = n.get("data", {}).get("id", "")
        if nid:
            node_map[nid] = n

    elements = list(node_map.values()) + edges

    # --- Metrics ---
    total_assets = len({x for x in assets_set if x})
    total_services = len({x for x in services_set if x})

    # AUTHORITATIVE: vulnerabilities count must not be 0 just because plugin_id/cvss missing.
    # We count unique vuln nodes created (derived from vuln_key).
    total_vulns = len(vuln_key_set)

    # --- Chart (severity distribution) ---
    df_counts = pd.DataFrame([
        {"Severity": "Critical", "Count": severity_counts["critical"]},
        {"Severity": "High", "Count": severity_counts["high"]},
        {"Severity": "Medium", "Count": severity_counts["medium"]},
        {"Severity": "Low", "Count": severity_counts["low"]},
        {"Severity": "Info", "Count": severity_counts["info"]},
    ])

    if df_counts["Count"].sum() == 0:
        fig = px.bar(
            pd.DataFrame([{"Severity": "Info", "Count": 1}]),
            x="Severity",
            y="Count",
            title="CVSS Severity Distribution (No numeric scores found)"
        )
    else:
        fig = px.bar(
            df_counts,
            x="Severity",
            y="Count",
            title="CVSS Severity Distribution"
        )

    alert_banner = (
        f"🚨 {high_or_critical_found} High/Critical vulnerabilities detected!"
        if high_or_critical_found > 0 else ""
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return (
        str(total_assets),
        str(total_services),
        str(total_vulns),
        elements,
        table_data[:500],  # guard: keep UI fast
        fig,
        alert_banner,
        f"Last updated: {now}"
    )





# ==========================================================
#  TAB 3: LLM REQUEST
# ==========================================================
llm_tab = html.Div([
    html.H3("🧠 LLM Request Interface", className="text-warning mb-3"),
    html.P("Summarize or analyze findings using OpenAI GPT-4o."),
    dcc.Textarea(
        id="llm-prompt",
        placeholder="Ask about vulnerabilities...",
        style={"width": "100%", "height": "150px"}
    ),
    html.Br(),
    dbc.Button("Run LLM Analysis", id="llm-btn", color="warning"),
    html.Div(
        id="llm-output",
        style={
            "whiteSpace": "pre-wrap",
            "marginTop": "10px",
            "color": "#EAAA00"
        }
    )
])

@app.callback(
    Output("llm-output", "children"),
    Input("llm-btn", "n_clicks"),
    State("llm-prompt", "value"),
    prevent_initial_call=True
)
def process_llm(n_clicks, text):
    if not text:
        raise dash.exceptions.PreventUpdate

    # ==========================================================
    # 1. SQLITE — SAFE, AGGREGATED FINDINGS
    # ==========================================================
    vuln_summary = {}
    try:
        df = load_findings()
        if not df.empty and "severity" in df.columns:
            vuln_summary = (
                df.groupby("severity")
                  .size()
                  .sort_values(ascending=False)
                  .to_dict()
            )
        else:
            vuln_summary = {"info": "No findings available"}
    except Exception as e:
        vuln_summary = {"error": f"SQLite error: {e}"}

    # ==========================================================
    # 2. NEO4J — SAFE, LIMITED GRAPH CONTEXT
    # ==========================================================
    graph_summary = []
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            query = """
            MATCH (a:Asset)-[:HAS_FINDING]->(f:Finding)
            WITH a, count(f) AS finding_count
            RETURN a.host AS asset, finding_count
            ORDER BY finding_count DESC
            LIMIT 10
            """
            graph_summary = [
                {
                    "asset": record["asset"],
                    "finding_count": record["finding_count"]
                }
                for record in session.run(query)
            ]
        driver.close()
    except Exception as e:
        graph_summary = [{"error": f"Neo4j error: {e}"}]

    # ==========================================================
    # 3. RECOMMENDATION LOGIC (DETERMINISTIC)
    # ==========================================================
    recommendations = []

    critical = vuln_summary.get("CRITICAL", 0)
    high = vuln_summary.get("HIGH", 0)

    if critical:
        recommendations.append(
            "Immediately remediate CRITICAL vulnerabilities and validate exploitability."
        )

    if high and high > 10:
        recommendations.append(
            "Prioritize HIGH severity findings on externally exposed or high-value assets."
        )

    if graph_summary:
        recommendations.append(
            "Focus remediation efforts on assets with the highest concentration of findings."
        )

    if not recommendations:
        recommendations.append(
            "Maintain continuous monitoring and validate existing security controls."
        )

    # ==========================================================
    # 4. LLM PROMPT — SMALL, STRUCTURED, SAFE
    # ==========================================================
    prompt = f"""
You are a senior cybersecurity analyst.

Use ONLY the structured data below.
Do NOT infer vulnerabilities not present in the data.

USER QUESTION:
{text}

VULNERABILITY SUMMARY (by severity):
{vuln_summary}

TOP RISK ASSETS:
{graph_summary}

RECOMMENDATIONS:
{recommendations}

Provide:
- A concise risk summary
- Key observations
- Prioritized remediation guidance
"""

    # ==========================================================
    # 5. HARD SAFETY GUARD
    # ==========================================================
    if len(prompt) > 15000:
        return (
            "⚠️ Request too large for safe analysis. "
            "Please narrow the question (e.g., top risk assets, severity overview)."
        )

    return call_llm(prompt)


# ==========================================================
#  TAB 4: CHATBOT
# ==========================================================

chatbot_tab = html.Div([
    html.H3("🛡️ AI Security Analyst Assistant", className="text-warning mb-3"),

    html.Div(id="chatbot-history", style={
        "height": "420px",
        "overflowY": "scroll",
        "border": "1px solid #444",
        "padding": "10px",
        "backgroundColor": "#111",
        "color": "white",
        "borderRadius": "8px"
    }),

    html.Br(),

    dcc.Input(
        id="chatbot-input",
        type="text",
        placeholder="Ask a security question or issue a command...",
        style={"width": "70%", "padding": "10px"}
    ),
    dbc.Button("Send", id="chatbot-send", color="warning",
               style={"marginLeft": "10px"}),

    html.Br(), html.Br(),

    dcc.Upload(
        id="chatbot-upload",
        children=html.Div(["Drag & Drop or Select Scan Files (XML)"]),
        style={
            "width": "90%", "height": "70px",
            "lineHeight": "70px",
            "borderWidth": "1px",
            "borderStyle": "dashed",
            "borderRadius": "5px",
            "textAlign": "center",
            "backgroundColor": "#222",
            "color": "white"
        },
        accept=".xml"
    ),

    html.Div(id="upload-status", className="text-info mt-2"),
], className="p-3")


@app.callback(
    Output("chatbot-history", "children", allow_duplicate=True),
    Input("chatbot-send", "n_clicks"),
    State("chatbot-input", "value"),
    prevent_initial_call=True
)
def chatbot_handler(n_clicks, user_text):
    global LAST_LLM_CALL

    if not user_text:
        raise dash.exceptions.PreventUpdate

    # --------------------------------------------------
    # 1. Normalize user input (HARD BOUND)
    # --------------------------------------------------
    user_text = user_text.strip()[:300]

    # Store for UI ONLY (never sent to LLM)
    CHAT_HISTORY.append({
        "role": "user",
        "content": user_text
    })

    # --------------------------------------------------
    # 2. UI-level rate limit (UX throttle, NOT TPM)
    #    1 request every 6 seconds per user
    # --------------------------------------------------
    now = time.time()
    if now - LAST_LLM_CALL < 6:
        assistant_reply = (
            "⚠️ Please wait a few seconds before asking another question "
            "to avoid rate limits."
        )
    else:
        LAST_LLM_CALL = now

        # --------------------------------------------------
        # 3. SQLite aggregation (BOUNDED, SAFE)
        # --------------------------------------------------
        vuln_summary = {}
        try:
            df = load_findings()
            if not df.empty and "severity" in df.columns:
                vuln_summary = (
                    df.groupby("severity")
                      .size()
                      .to_dict()
                )
        except Exception:
            vuln_summary = {}

        # --------------------------------------------------
        # 4. Neo4j aggregation (BOUNDED, SAFE)
        # --------------------------------------------------
        top_assets = []
        try:
            driver = GraphDatabase.driver(
                "bolt://localhost:7687",
                auth=("neo4j", "Adomaa12@")
            )
            with driver.session() as session:
                query = """
                MATCH (a:Asset)-[:HAS_FINDING]->(f:Finding)
                RETURN a.host AS asset, count(f) AS findings
                ORDER BY findings DESC
                LIMIT 3
                """
                top_assets = [
                    {"asset": r["asset"], "findings": r["findings"]}
                    for r in session.run(query)
                ]
            driver.close()
        except Exception:
            pass

        # --------------------------------------------------
        # 5. Build STRICT, SMALL CHATBOT PROMPT
        # --------------------------------------------------
        prompt = f"""
You are an AI Security Analyst Assistant.

Rules:
- NEVER dump raw vulnerability data
- NEVER output scan evidence
- NEVER invent vulnerabilities or assets

Current security posture:
Vulnerabilities by severity: {vuln_summary}
Top risk assets: {top_assets}

User question:
{user_text}

Respond concisely and professionally.
"""

        # --------------------------------------------------
        # 6. FINAL CHATBOT SAFETY GUARD (TAB 4 ONLY)
        # --------------------------------------------------
        if len(prompt) > 6000:
            assistant_reply = (
                "⚠️ That question is too broad. "
                "Please ask about risk posture, priorities, or top assets."
            )
        else:
            # IMPORTANT:
            # call_llm() MUST include the GLOBAL LLM LOCK + COOLDOWN
            assistant_reply = call_llm(prompt)

    # --------------------------------------------------
    # 7. Store assistant response (UI ONLY)
    # --------------------------------------------------
    CHAT_HISTORY.append({
        "role": "assistant",
        "content": assistant_reply[:500]
    })

    # --------------------------------------------------
    # 8. Render chat history (UI ONLY)
    # --------------------------------------------------
    return [
        html.Div(
            f"{msg['role'].upper()}: {msg['content']}",
            style={
                "marginBottom": "8px",
                "color": "#EAAA00" if msg["role"] == "assistant" else "#FFFFFF"
            }
        )
        for msg in CHAT_HISTORY
    ]



# ==========================================================
#  PLACEHOLDER TABS (Reporting, Voice, Attack)
# ==========================================================
reporting_tab = html.Div([html.H3("📄 Reporting (Under Development)")])
# ==========================================================
#  VOICE ASSISTANT TAB (FULL UI)
# ==========================================================

def voice_tab():
    return html.Div(
        [
            # Hidden store for receiving browser → Dash voice input
            dcc.Store(id="voice-input"),

            html.H2("🎤 Voice Assistant", className="text-warning mb-4"),

            # ======================================================
            #  CONTROL BUTTONS
            # ======================================================
            html.Div(
                [
                    dbc.Button(
                        "Start Recording",
                        id="voice-record-btn",
                        color="success",
                        className="me-2",
                        n_clicks=0,
                    ),
                    dbc.Button(
                        "Stop Recording",
                        id="voice-stop-btn",
                        color="danger",
                        n_clicks=0,
                    ),
                ],
                className="mb-3",
            ),

            # Status text ("Listening...", "Stopped", etc)
            html.Div(id="voice-status", className="text-info mb-3"),

            # ======================================================
            #  RAW TRANSCRIPTION
            # ======================================================
            html.H4("Transcription", className="text-warning"),
            html.Pre(
                id="voice-transcript",
                className="bg-dark text-light p-3",
                style={"minHeight": "120px", "border": "1px solid #555"},
            ),

            # ======================================================
            #  AI ASSISTANT RESPONSE
            # ======================================================
            html.H4("Assistant Response", className="text-warning mt-4"),
            html.Pre(
                id="voice-response",
                className="bg-secondary text-light p-3",
                style={"minHeight": "160px", "border": "1px solid #444"},
            ),
        ],
        style={"padding": "20px"},
    )


# ==========================================================
#  REPORTING TAB — Fully Functional
# ==========================================================
reporting_tab = html.Div([
    html.H3("📄 Automated Reporting", className="text-warning mb-3"),

    html.P("Generate compliance-ready reports based on parsed Nmap, Nessus, OpenVAS, and ZAP findings.",
           className="text-light"),

    # ----------------------------------------
    # PDF Report
    # ----------------------------------------
    html.H4("📘 Security Assessment Report", className="text-warning mt-4"),
    dbc.Button("Generate PDF Report", id="pdf-btn", color="warning", className="mb-3"),
    dcc.Download(id="pdf-download"),

    html.Hr(style={"borderColor": "#444"}),

    # ----------------------------------------
    # POA&M
    # ----------------------------------------
    html.H4("📝 POA&M (Plan of Action & Milestones)", className="text-warning mt-4"),
    dbc.Button("Generate POA&M CSV", id="poam-btn", color="danger", className="mb-3"),
    dcc.Download(id="poam-download"),

    html.Hr(style={"borderColor": "#444"}),

    # ----------------------------------------
    # NIST Mapping
    # ----------------------------------------
    html.H4("📚 NIST 800-53 Control Mapping", className="text-warning mt-4"),
    dbc.Button("Generate NIST Mapping", id="nist-btn", color="info", className="mb-3"),
    dcc.Download(id="nist-download"),

], className="p-4")


# ======================================================================
#  TAB 8 — NEO4J GRAPH VISUALIZATION (STANDARD VERSION — CLEAN & FAST)
# ======================================================================
import dash_cytoscape as cyto
cyto.load_extra_layouts()

def neo4j_graphs_tab():
    return html.Div(
        [
            # ==========================================================
            # TITLE
            # ==========================================================
            html.H3("🧠 Neo4j Graph Visualizations", className="text-warning mb-4"),

            # ==========================================================
            # GRAPH CATEGORY
            # ==========================================================
            html.Label("Graph Category:", className="text-light"),
            dcc.Dropdown(
                id="graph-category",
                options=[{"label": c, "value": c} for c in GRAPH_TYPES.keys()],
                value="Core Relationship Graphs",
                clearable=False,
                style={"width": "60%", "marginBottom": "20px"},
            ),

            # ==========================================================
            # GRAPH TYPE
            # ==========================================================
            html.Label("Graph Type:", className="text-light"),
            dcc.Dropdown(
                id="graph-type",
                placeholder="Select Graph Type",
                options=[],
                style={"width": "60%", "marginBottom": "30px"},
            ),

            html.Hr(style={"borderColor": "#EAAA00"}),
            html.Div(id="graph-title", className="text-warning text-center mb-3"),

            # ==========================================================
            # CYTOSCAPE GRAPH
            # ==========================================================
            cyto.Cytoscape(
                id="neo4j-graph",
                layout={"name": "cose"},
                style={"width": "100%", "height": "600px", "backgroundColor": "#111"},
                elements=[],

                # CLEAN stylesheet
                stylesheet=[
                    # ------------------------------- GENERAL NODE STYLE
                    {
                        "selector": "node",
                        "style": {
                            "label": "data(label)",
                            "font-size": "12px",
                            "color": "white",
                            "background-color": "#666",
                            "width": "40px",
                            "height": "40px",
                            "text-outline-width": 1,
                            "text-outline-color": "#222",
                        },
                    },

                    # ------------------------------- ASSET
                    {
                        "selector": "node[type='Asset']",
                        "style": {"background-color": "#00A8E8", "shape": "round-rectangle"},
                    },

                    # ------------------------------- SERVICE
                    {
                        "selector": "node[type='Service']",
                        "style": {"background-color": "#007BFF", "shape": "hexagon"},
                    },

                    # ------------------------------- VULNERABILITY (CVSS COLORS)
                    {"selector": "node[type='Vulnerability'][cvss < 4]", "style": {"background-color": "#2ECC71"}},
                    {"selector": "node[type='Vulnerability'][cvss >= 4][cvss < 7]", "style": {"background-color": "#F1C40F"}},
                    {"selector": "node[type='Vulnerability'][cvss >= 7][cvss < 9]", "style": {"background-color": "#E67E22"}},
                    {"selector": "node[type='Vulnerability'][cvss >= 9]", "style": {"background-color": "#C0392B"}},

                    # ------------------------------- EXPLOIT
                    {
                        "selector": "node[type='Exploit']",
                        "style": {"background-color": "#8E44AD", "shape": "diamond"},
                    },

                    # ------------------------------- THREAT ACTOR
                    {
                        "selector": "node[type='ThreatActor']",
                        "style": {"background-color": "#FF5733", "shape": "octagon"},
                    },

                    # ------------------------------- USER / PRIVILEGE
                    {"selector": "node[type='User']", "style": {"background-color": "#1ABC9C"}},
                    {"selector": "node[type='Privilege']", "style": {"background-color": "#27AE60"}},

                    # ------------------------------- CROWN JEWEL
                    {"selector": "node[type='CrownJewel']", "style": {"background-color": "#F39C12", "shape": "star"}},

                    # ------------------------------- NETWORK ZONE
                    {"selector": "node[type='NetworkZone']", "style": {"background-color": "#34495E"}},

                    # ------------------------------- COMPLIANCE
                    {"selector": "node[type='Control']", "style": {"background-color": "#2980B9"}},
                    {"selector": "node[type='Gap']", "style": {"background-color": "#E74C3C"}},
                    {"selector": "node[type='POAM']", "style": {"background-color": "#F39C12"}},

                    # ------------------------------- CLOUD
                    {"selector": "node[type='CloudAsset']", "style": {"background-color": "#9B59B6"}},
                    {"selector": "node[type='SecurityGroup']", "style": {"background-color": "#E74C3C"}},
                    {"selector": "node[type='Role']", "style": {"background-color": "#1ABC9C"}},
                    {"selector": "node[type='Misconfiguration']", "style": {"background-color": "#D35400"}},

                    # ------------------------------- EDGES
                    {
                        "selector": "edge",
                        "style": {
                            "line-color": "#EAAA00",
                            "width": 2,
                            "target-arrow-shape": "triangle",
                            "target-arrow-color": "#EAAA00",
                            "curve-style": "bezier",
                        },
                    },

                    # ------------------------------- SELECTED NODE
                    {"selector": "node:selected", "style": {"border-width": 3, "border-color": "white"}},
                ],
            ),

            # ==========================================================
            # NODE INFO PANEL
            # ==========================================================
            html.Div(
                id="node-info-panel",
                className="text-light mt-4 p-3",
                style={
                    "backgroundColor": "#222",
                    "border": "1px solid #444",
                    "borderRadius": "8px",
                    "display": "none",
                    "whiteSpace": "pre-wrap",
                },
            ),

            # ==========================================================
            # LAYOUT SELECTOR
            # ==========================================================
            html.Div(
                [
                    html.Label("Graph Layout:", className="text-light mt-4"),
                    dcc.Dropdown(
                        id="layout-selector",
                        options=[
                            {"label": "CoSE", "value": "cose"},
                            {"label": "Circle", "value": "circle"},
                            {"label": "Grid", "value": "grid"},
                            {"label": "Concentric", "value": "concentric"},
                            {"label": "Breadth First", "value": "breadthfirst"},
                        ],
                        value="cose",
                        clearable=False,
                        style={"width": "40%", "color": "#000"},
                    ),
                ],
                className="mt-4",
            ),

            # ==========================================================
            # SEARCH BAR
            # ==========================================================
            html.Div(
                [
                    html.Label("Search Graph:", className="text-light mt-4"),
                    dcc.Input(
                        id="graph-search-input",
                        type="text",
                        debounce=True,
                        placeholder="Search by label, type, CVE...",
                        style={"width": "60%", "padding": "8px", "color": "#000"},
                    ),
                ],
                className="mb-4",
            ),

            # ==========================================================
            # ATTACK PATH CONTROLS (BASIC)
            # ==========================================================
            html.Div(
                [
                    html.H4("⚔ Attack Path Analysis", className="text-warning mt-4"),
                    dcc.Dropdown(
                        id="attack-start-node",
                        placeholder="Start Node",
                        options=[],
                        style={"width": "50%", "marginBottom": "10px"},
                    ),
                    dcc.Dropdown(
                        id="attack-target-node",
                        placeholder="Target Node (e.g., Crown Jewel)",
                        options=[],
                        style={"width": "50%", "marginBottom": "10px"},
                    ),
                    html.Button(
                        "🚀 Trace Attack Path",
                        id="attack-path-btn",
                        className="btn btn-danger",
                        n_clicks=0,
                    ),
                ]
            ),

            html.Div(
                id="attack-path-panel",
                className="text-light mt-4 p-3",
                style={
                    "backgroundColor": "#111",
                    "border": "1px solid #444",
                    "borderRadius": "8px",
                    "whiteSpace": "pre-wrap",
                },
            ),

            # ==========================================================
            # EXPORT BUTTONS
            # ==========================================================
            html.Div(
                [
                    html.Button("📄 Export JSON", id="export-json-btn",
                                className="btn btn-primary me-3"),
                    html.Button("📊 Export CSV", id="export-csv-btn",
                                className="btn btn-success"),
                    dcc.Download(id="neo4j-export-download"),
                ],
                className="mt-5",
            ),

            # ==========================================================
            # DATA STORES
            # ==========================================================
            dcc.Store(id="right-click-node"),
            dcc.Store(id="original-elements"),
            dcc.Store(id="last-attack-path"),
        ]
    )

 

def neo4j_preset_graphs_tab():
    return dbc.Container([

        html.H2("Neo4j Graph Presets", className="mt-3 mb-4 text-info"),

        dbc.Row([
            # -------- LEFT SIDE BUTTONS ----------
            dbc.Col([

                dbc.Button("Show Asset Graph", id="btn-assets",
                           color="primary", className="mb-2 w-100"),

                dbc.Button("Show Vulnerability Graph", id="btn-vuln",
                           color="secondary", className="mb-2 w-100"),

                dbc.Button("Show Technique → Tactic", id="btn-tech-tac",
                           color="warning", className="mb-2 w-100"),

                dbc.Button("Show Techniques → Subtechniques", id="btn-subtech",
                           color="dark", className="mb-2 w-100"),

                dbc.Button("Show Attack Paths (Asset → Vuln → Technique → Tactic)",
                           id="btn-attack-path", color="danger", className="mb-2 w-100"),

                # ---------- LEGEND ----------
                html.Div([
                    html.H4("Legend", className="text-info mt-4"),
                    html.Div([
                        html.Div("🟦 Asset", style={"color": "#4A90E2", "font-size": "18px"}),
                        html.Div("🔴 Vulnerability", style={"color": "#D0021B", "font-size": "18px"}),
                        html.Div("🟧 Technique", style={"color": "#F5A623", "font-size": "18px"}),
                        html.Div("🟨 SubTechnique", style={"color": "#F8E71C", "font-size": "18px"}),
                        html.Div("🟪 Tactic", style={"color": "#9013FE", "font-size": "18px"}),
                        html.Div("➡ Relationship", style={"color": "#CCCCCC", "font-size": "18px"}),
                    ])
                ], className="mt-4 p-3 rounded", style={"background-color": "#1c1c1c"}),

            ], width=3),

            # ---------- RIGHT SIDE GRAPH ----------
            dbc.Col([

                # Tooltip Div (hidden by default)
                html.Div(id="cy-tooltip", style={
                    "position": "absolute",
                    "zIndex": 999,
                    "padding": "6px 10px",
                    "background": "#222",
                    "color": "white",
                    "border": "1px solid #555",
                    "borderRadius": "4px",
                    "display": "none",
                }),

                cyto.Cytoscape(
                    id="neo4j-preset-graph",
                    style={"height": "780px", "backgroundColor": "#111111"},
                    layout={"name": "cose", "animate": True},
                    elements=[],

                    stylesheet=[

                        # ----- GLOBAL NODE STYLE -----
                        {
                            "selector": "node",
                            "style": {
                                "label": "data(label)",
                                "font-size": "17px",
                                "color": "#FFFFFF",
                                "text-outline-width": 2,
                                "text-outline-color": "#333333",
                                "background-color": "#4A90E2",
                                "width": 50,
                                "height": 50,
                            }
                        },

                        {"selector": "[type='Asset']",
                         "style": {"background-color": "#4A90E2"}},

                        {"selector": "[type='Vulnerability']",
                         "style": {"background-color": "#D0021B"}},

                        {"selector": "[type='Technique']",
                         "style": {"background-color": "#F5A623"}},

                        {"selector": "[type='SubTechnique']",
                         "style": {"background-color": "#F8E71C", "color": "#000"}},

                        {"selector": "[type='Tactic']",
                         "style": {"background-color": "#9013FE"}},

                        # ----- EDGES -----
                        {
                            "selector": "edge",
                            "style": {
                                "width": 3,
                                "line-color": "#BBBBBB",
                                "target-arrow-color": "#BBBBBB",
                                "target-arrow-shape": "triangle",
                                "curve-style": "bezier",
                            }
                        },

                        # ----- SELECTED -----
                        {
                            "selector": ":selected",
                            "style": {
                                "border-width": 4,
                                "border-color": "#FFD700",
                                "background-color": "#FFF176",
                                "color": "#000",
                            }
                        }
                    ]
                )
            ], width=9)
        ])
    ], fluid=True)



def import_feeds_layout():
    return dbc.Container(
        [
            html.H2("🗂 Import Vulnerability Feeds", className="text-warning mt-4"),

            dbc.Row(
                [
                    dbc.Col(
                        dbc.Button("Import Nmap", id="btn-import-nmap", color="primary", className="mb-3"),
                        md=3,
                    ),
                    dbc.Col(
                        dbc.Button("Import OpenVAS", id="btn-import-openvas", color="success", className="mb-3"),
                        md=3,
                    ),
                    dbc.Col(
                        dbc.Button("Import ZAP", id="btn-import-zap", color="info", className="mb-3"),
                        md=3,
                    ),
                    dbc.Col(
                        dbc.Button("Import Burp", id="btn-import-burp", color="warning", className="mb-3"),
                        md=3,
                    ),
                ]
            ),

            dbc.Row(
                [
                    dbc.Col(
                        dbc.Button("Run MITRE Enrichment", id="btn-import-mitre", color="danger", className="mb-3"),
                        md=3,
                    )
                ]
            ),

            html.Hr(),
            html.H4("Import Output", className="text-light"),
            html.Pre(id="import-output", className="bg-dark text-light p-3", style={"height": "300px", "overflow": "auto"})
        ],
        fluid=True
    )


# ==========================================================
#  CALLBACK: EXECUTE NMAP + INGEST RESULTS
# ==========================================================
import subprocess, tempfile, os, xml.etree.ElementTree as ET
from dash import ctx
from cyber_range.services.neo4j_engine import Neo4jEngine
from cyber_range.services.nmap_graph_builder import NmapGraphBuilder
import sqlite3
import pandas as pd

neo = Neo4jEngine()
builder = NmapGraphBuilder()


@app.callback(
    Output("scan-log", "children", allow_duplicate=True),
    Input("run-scan-btn", "n_clicks"),
    State("scan-targets", "value"),
    prevent_initial_call=True
)
def run_nmap_scan(_, targets):

    if not targets:
        return "⚠ No targets provided."

    log_output = []
    log_output.append(f"[+] Starting Nmap scan on: {targets}")

    # ======================================================
    # 1. RUN NMAP AND SAVE XML
    # ======================================================
    xml_path = f"/opt/vuln_intel/data/scans/nmap_{targets.replace('/', '_')}.xml"

    cmd = ["nmap", "-A", "-T4", "-oX", xml_path, targets]
    log_output.append(f"[+] Executing: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, capture_output=True, text=True)
        log_output.append(f"[+] Scan complete. Output saved to: {xml_path}")
    except Exception as e:
        return f"❌ Nmap execution failed: {e}"

    # ======================================================
    # 2. PARSE XML → HOSTS + PORTS
    # ======================================================
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return f"❌ XML Parse Error: {e}"

    discovered_ips = []
    scan_results = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        ip = addr_el.get("addr")
        discovered_ips.append(ip)

        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                if p.find("state").get("state") == "open":
                    ports.append(int(p.get("portid")))

        scan_results.append({"ip": ip, "ports": ports})

    log_output.append(f"[+] Discovered hosts: {discovered_ips}")

    # ======================================================
    # 3. INGEST INTO SQLITE
    # ======================================================
    db = "/opt/vuln_intel/vuln_intel.db"
    conn = sqlite3.connect(db)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    for entry in scan_results:
        for p in entry["ports"]:
            cur.execute(
                "INSERT INTO scan_findings (ip, port) VALUES (?, ?)",
                (entry["ip"], p)
            )

    conn.commit()
    conn.close()

    log_output.append("[+] Inserted scan findings into SQLite.")

    # ======================================================
    # 4. INGEST INTO NEO4J (Assets + Services)
    # ======================================================
    for entry in scan_results:

        neo.query("""
            MERGE (a:Asset {ip:$ip})
            SET a.last_seen = timestamp()
        """, {"ip": entry["ip"]})

        for p in entry["ports"]:
            neo.query("""
                MATCH (a:Asset {ip:$ip})
                MERGE (s:Service {name:'tcp', port:$port})
                MERGE (a)-[:HAS_SERVICE]->(s)
            """, {"ip": entry["ip"], "port": p})

    log_output.append("[+] Neo4j Asset + Service ingestion complete.")

    # ======================================================
    # 5. BUILD CONNECTED GRAPH FOR DIGITAL TWIN
    # ======================================================
    if len(discovered_ips) > 1:
        builder.connect_by_subnet(discovered_ips)      # Recommended
        builder.connect_discovered_hosts(discovered_ips)
        builder.connect_by_services(scan_results)

    log_output.append("[+] CONNECTED relationships built for Digital Twin.")

    # ======================================================
    # 6. RETURN LOG OUTPUT
    # ======================================================
    return html.Pre("\n".join(log_output))


# ======================================================================
#   CALLBACK: Populate graph types when category changes
# ======================================================================
@app.callback(
    Output("graph-type", "options"),
    Input("graph-category", "value"),
)
def update_graph_type_dropdown(category):
    return GRAPH_TYPES.get(category, [])


# ======================================================================
# CALLBACK: Load Neo4j Graph Intelligence (Main Graph)
# ======================================================================

@app.callback(
    [
        Output("neo4j-graph", "elements"),
        Output("graph-title", "children", allow_duplicate=True)

    ],
    [
        Input("graph-category", "value"),
        Input("graph-type", "value")
    ],
    prevent_initial_call=True
)
def load_neo4j_graph(category, graph_type):
    from neo4j import GraphDatabase

    if not category or not graph_type:
        return [], "⚠ Select a graph type"

    # Get Cypher for selected graph
    cypher_query = GRAPH_QUERIES.get(category, {}).get(graph_type)
    if not cypher_query:
        return [], f"⚠ No query found for: {graph_type}"

    # Connect
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(uri, auth=("neo4j", "Adomaa12@"))

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            result = session.run(cypher_query)

            for record in result:
                # Path-based results
                if "p" in record:
                    path = record["p"]

                    for node in path.nodes:
                        nid = str(node.id)
                        if nid not in nodes:
                            nodes[nid] = {"data": {
                                "id": nid,
                                "label": node.get("name") or node.get("id") or list(node.labels)[0],
                                "type": list(node.labels)[0]
                            }}

                    for rel in path.relationships:
                        edges.append({"data": {
                            "source": str(rel.start_node.id),
                            "target": str(rel.end_node.id),
                            "label": rel.type
                        }})

                # Direct node/rel
                else:
                    for key, val in record.items():
                        if hasattr(val, "labels"):
                            nid = str(val.id)
                            nodes[nid] = {"data": {
                                "id": nid,
                                "label": val.get("name") or nid,
                                "type": list(val.labels)[0]
                            }}
                        if hasattr(val, "type"):
                            start, end = val.nodes
                            edges.append({"data": {
                                "source": str(start.id),
                                "target": str(end.id),
                            }})

    except Exception as e:
        return [], f"❌ Neo4j Error: {e}"

    finally:
        driver.close()

    return list(nodes.values()) + edges, f"📊 Graph View: {graph_type}"



# ======================================================================
#   CALLBACK: Load Neo4j Graph Elements Based on Graph Type
# ======================================================================

@app.callback(
    Output("neo4j-preset-graph", "elements"),
    [
        Input("btn-assets", "n_clicks"),
        Input("btn-vuln", "n_clicks"),
        Input("btn-tech-tac", "n_clicks"),
        Input("btn-subtech", "n_clicks"),
        Input("btn-attack-path", "n_clicks"),
    ],
     prevent_initial_call=True
)
def load_preset_graph(btn_assets, btn_vuln, btn_tech_tac, btn_subtech, btn_attack_path):

    # Determine which button fired
    ctx = dash.callback_context
    if not ctx.triggered:
        return []

    clicked = ctx.triggered[0]["prop_id"].split(".")[0]

    # Neo4j driver using your new constants
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # PRESET CYPHER QUERIES
    cypher_queries = {
        "btn-assets": """
            MATCH (a:Asset)-[r]->(b)
            RETURN a, r, b
        """,

        "btn-vuln": """
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, v
        """,

        "btn-tech-tac": """
            MATCH (tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN tech, tac
        """,

        "btn-subtech": """
            MATCH (p:Technique)-[:HAS_SUBTECHNIQUE]->(c:SubTechnique)
            RETURN p, c
        """,

        "btn-attack-path": """
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN a, v, tech, tac
        """,
    }

    query = cypher_queries.get(clicked)
    if not query:
        return []

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            results = session.run(query)

            for row in results:
                for key, val in row.items():

                    # Node
                    if hasattr(val, "labels"):
                        node_id = str(val.id)
                        label = list(val.labels)[0]
                        name = val.get("name") or val.get("id") or label

                        nodes[node_id] = {"data": {"id": node_id, "label": name}}

                    # Relationship
                    if hasattr(val, "type"):
                        start, end = val.nodes
                        edges.append({
                            "data": {
                                "source": str(start.id),
                                "target": str(end.id)
                            }
                        })

        driver.close()
        return list(nodes.values()) + edges

    except Exception as e:
        driver.close()
        print(f"[Preset Graph Error] {e}")
        return []

@app.callback(
    Output("cy-tooltip", "style"),
    Output("cy-tooltip", "children"),
    Input("neo4j-preset-graph", "mouseoverNodeData"),
    Input("neo4j-preset-graph", "mouseoverEdgeData"),
)
def show_tooltip(node, edge):

    # ----- Node Hover -----
    if node:
        return (
            {
                "position": "absolute",
                "zIndex": 999,
                "top": "20px",
                "left": "20px",
                "padding": "6px 10px",
                "background": "#222",
                "color": "white",
                "border": "1px solid #555",
                "borderRadius": "4px",
                "display": "block",
            },
            f"Node: {node.get('label', 'Unknown')}"
        )

    # ----- Edge Hover -----
    if edge:
        return (
            {
                "position": "absolute",
                "zIndex": 999,
                "top": "20px",
                "left": "20px",
                "padding": "6px 10px",
                "background": "#222",
                "color": "white",
                "border": "1px solid #555",
                "borderRadius": "4px",
                "display": "block",
            },
            f"Edge: {edge.get('label', 'relationship')}"
        )

    # ----- Nothing Hovered -----
    return {"display": "none"}, ""


    # --------------------------------------
    # 1. Map graph_type → Cypher query
    # --------------------------------------
    CYPHER_MAP = {

        # ---------------- CORE GRAPHS ----------------
        "core_asset_service": """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            RETURN a, s
        """,

        "core_asset_vuln": """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, s, v
        """,

        "core_service_vuln": """
            MATCH (s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN s, v
        """,

        # ---------------- VULN GRAPHS ----------------
        "vuln_all": """
            MATCH (v:Vulnerability)
            RETURN v
        """,

        "vuln_attack_surface": """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a, s, v
        """,

        # ---------------- ATTACK PATH ----------------
        "ap_user_asset_vuln": """
            MATCH (u:User)-[:ACCESS]->(a:Asset)
            MATCH (a)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN u, a, s, v
        """,

        "ap_shortest_to_cj": """
            MATCH (cj:CrownJewel)
            MATCH p = shortestPath(
                (a:Asset)-[*..6]->(cj)
            )
            RETURN p
        """,

        # ---------------- THREAT INTEL ----------------
        "ti_attack_techniques": """
            MATCH (t:Tactic)<-[:PART_OF]-(tech:Technique)
            OPTIONAL MATCH (tech)<-[:MAPS_TO_TECHNIQUE]-(v:Vulnerability)
            RETURN t, tech, v
        """,
    }

    if graph_type not in CYPHER_MAP:
        return [], f"⚠ No query defined for graph type: {graph_type}"

    cypher_query = CYPHER_MAP[graph_type]

    # --------------------------------------
    # 2. Connect to Neo4j
    # --------------------------------------
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "Adomaa12@"

    driver = GraphDatabase.driver(uri, auth=(user, password))

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            result = session.run(cypher_query)

            # --------------------------------------
            # 3. Process Neo4j records → Nodes + Edges
            # --------------------------------------
            for record in result:

                # Case A: query returns a PATH
                if "p" in record.keys():
                    path = record["p"]
                    for node in path.nodes:
                        nid = str(node.id)
                        if nid not in nodes:
                            nodes[nid] = {
                                "data": {
                                    "id": nid,
                                    "label": node.get("host") or node.get("name") or node.get("id"),
                                    "type": list(node.labels)[0]
                                }
                            }

                    for rel in path.relationships:
                        edges.append({
                            "data": {
                                "source": str(rel.start_node.id),
                                "target": str(rel.end_node.id),
                                "label": rel.type
                            }
                        })

                # Case B: individual nodes
                else:
                    for key in record.keys():
                        node = record[key]
                        if hasattr(node, "id"):
                            nid = str(node.id)
                            if nid not in nodes:
                                nodes[nid] = {
                                    "data": {
                                        "id": nid,
                                        "label": node.get("host") or node.get("name") or node.get("id"),
                                        "type": list(node.labels)[0]
                                    }
                                }

            elements = list(nodes.values()) + edges

            return elements, f"📊 Graph View: {graph_type}"

    except Exception as e:
        return [], f"❌ Neo4j Error: {e}"

    finally:
        driver.close()



# ======================================================================
#   CALLBACK: Show Node Info Panel
# ======================================================================
@app.callback(
    Output("node-info-panel", "children"),
    Output("node-info-panel", "style"),
    Input("neo4j-graph", "tapNodeData"),
)
def show_node_info(data):
    if not data:
        return "", {"display": "none"}

    info = "\n".join([f"{k}: {v}" for k, v in data.items()])

    return info, {
        "display": "block",
        "backgroundColor": "#222",
        "border": "1px solid #444",
        "borderRadius": "8px",
        "padding": "10px",
    }


# ======================================================================
#   CALLBACK: Switch Graph Layout
# ======================================================================
@app.callback(
    Output("neo4j-graph", "layout"),
    Input("layout-selector", "value"),
)
def update_layout(layout):
    return {"name": layout}


# ======================================================================
#   CALLBACK: Search Highlight
# ======================================================================
@app.callback(
    Output("neo4j-graph", "stylesheet"),
    Input("graph-search-input", "value"),
    State("neo4j-graph", "stylesheet"),
)
def update_search(query, stylesheet):
    if not query:
        return stylesheet

    new_style = stylesheet + [
        {
            "selector": f"[label *= '{query}']",
            "style": {
                "background-color": "#FFFF00",
                "border-width": 3,
                "border-color": "black",
            }
        }
    ]

    return new_style


# ======================================================================
#   CLIENTSIDE CALLBACK — Right-click Context Menu Popup
# ======================================================================

app.clientside_callback(
    """
    function(data) {
        if (!data) return window.dash_clientside.no_update;

        // Fallback position values since context tap is unavailable
        const menu = document.getElementById("context-menu");
        menu.style.left = "200px";   // static/fixed position
        menu.style.top = "200px";
        menu.style.display = "block";

        return data.id;
    }
    """,
    Output("right-click-node", "data"),
    Input("neo4j-graph", "tapNodeData")
)



@app.callback(
    Output("neo4j-graph", "elements", allow_duplicate=True),
    [
        Input("ctx-hide", "n_clicks"),
        Input("ctx-reset", "n_clicks"),
        Input("ctx-neighbors", "n_clicks"),
        Input("ctx-isolate", "n_clicks"),
    ],
    [
        State("right-click-node", "data"),
        State("original-elements", "data"),
        State("neo4j-graph", "elements"),
    ],
    prevent_initial_call=True
)


def right_click_actions(hide, reset, neighbors, isolate, node_id, original, current):

    triggered = ctx.triggered_id

    if not triggered or not node_id:
        return current

    if triggered == "ctx-reset":
        return original

    if triggered == "ctx-hide":
        return [el for el in current if el["data"].get("id") != node_id]

    if triggered == "ctx-isolate":
        return [el for el in current if el["data"].get("id") == node_id]

    if triggered == "ctx-neighbors":
        neighbor_ids = set()
        for edge in current:
            if "source" in edge["data"]:
                if edge["data"]["source"] == node_id:
                    neighbor_ids.add(edge["data"]["target"])
                if edge["data"]["target"] == node_id:
                    neighbor_ids.add(edge["data"]["source"])

        return [
            el for el in current
            if el["data"].get("id") in neighbor_ids or
               el["data"].get("id") == node_id or
               (
                   "source" in el["data"] and
                   (el["data"]["source"] == node_id or el["data"]["target"] == node_id)
               )
        ]

    return current



# ======================================================================
#   CALLBACK: Export JSON / CSV / PNG
# ======================================================================
@app.callback(
    Output("neo4j-export-download", "data"),
    [
        Input("export-json-btn", "n_clicks"),
        Input("export-csv-btn", "n_clicks"),
    ],
    State("neo4j-graph", "elements"),
    prevent_initial_call=True
)
def export_graph(json_btn, csv_btn, elements):

    triggered = ctx.triggered_id

    if triggered == "export-json-btn":
        return dict(content=json.dumps(elements, indent=2), filename="neo4j_graph.json")

    if triggered == "export-csv-btn":
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["id", "label", "type", "source", "target"])

        for el in elements:
            d = el["data"]
            writer.writerow([
                d.get("id"),
                d.get("label"),
                d.get("type"),
                d.get("source"),
                d.get("target")
            ])

        return dict(content=output.getvalue(), filename="neo4j_graph.csv")

    return None



# ======================================================================
#  BATCH 8 — MITRE ATT&CK INTELLIGENCE TAB (UI LAYOUT)
# ======================================================================

def mitre_tab_layout():
    return dbc.Container([

        html.H2("MITRE ATT&CK Intelligence", className="text-info mt-3 mb-4"),



        # ===============================
        # TOP SEARCH + FILTER BAR
        # ===============================
        dbc.Row([
            dbc.Col([
                html.Label("Search Technique / Tactic"),
                dcc.Input(
                    id="mitre-search-box",
                    type="text",
                    placeholder="Example: T1059, Discovery, WMI, Privilege Escalation…",
                    debounce=True,
                    className="form-control"
                )
            ], width=6),

            dbc.Col([
                html.Label("Filter by Tactic"),
                dcc.Dropdown(
                    id="mitre-tactic-dropdown",
                    options=[],
                    placeholder="Choose Tactic (TAxxxx)",
                    clearable=True
                )
            ], width=6),
        ], className="mb-4"),

        html.Hr(),

        # ===============================
        # GRAPHS + DETAILS PANEL
        # ===============================
        dbc.Row([
            dbc.Col([
                html.H4("Technique–Tactic Graph"),
                cyto.Cytoscape(
                    id="mitre-cytoscape",
                    layout={"name": "cose"},
                    style={"height": "700px"},
                    elements=[],
                    stylesheet=[
                        {"selector": ".tactic", "style": {"background-color": "#ffbf00", "label": "data(label)"}},
                        {"selector": ".technique", "style": {"background-color": "#00aaff", "label": "data(label)"}},
                        {"selector": ".subtech", "style": {"background-color": "#7f00ff", "label": "data(label)"}},
                    ]
                ),
            ], width=8),

            dbc.Col([
                html.H4("ATT&CK Item Details"),
                dbc.Card([
                    dbc.CardBody([
                        html.H5(id="mitre-detail-title", className="text-warning"),
                        html.Div(id="mitre-detail-body", className="mt-2")
                    ])
                ])
            ], width=4),
        ]),

        html.Hr(className="mt-5"),

        # ===============================
        # 3 NEW PANELS: HEATMAP + CVE MAPPING + ATTACK PATHS
        # ===============================
        dbc.Row([
            dbc.Col([
                html.H4("🔥 ATT&CK Technique Heatmap (Counts by Tactic)"),
                dcc.Graph(id="mitre-heatmap")
            ], width=6),

            dbc.Col([
                html.H4("🔗 CVE → MITRE Technique Mapping"),
                dcc.Input(
                    id="mitre-cve-box",
                    type="text",
                    placeholder="Example: CVE-2021-44228",
                    debounce=True,
                    className="form-control"
                ),
                html.Div(id="mitre-cve-results", className="mt-3")
            ], width=6),
        ], className="mt-4"),

        html.Hr(),

        dbc.Row([
            dbc.Col([
                html.H4("🚀 Attack Path Simulation"),
                html.P("Map: Asset → Vulnerability → Technique → Tactic"),
                dcc.Input(
                    id="mitre-attack-path-asset",
                    type="text",
                    placeholder="Hostname, IP, or Asset ID",
                    debounce=True,
                    className="form-control"
                ),
                dcc.Graph(id="mitre-attack-path-graph")
            ], width=12)
        ])
    ], fluid=True)




# ==========================================================
#  BATCH 1 — MITRE ATT&CK DEFINITIONS (TACTICS & TECHNIQUES)
# ==========================================================

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
}

# --------------------------------------------------------------
# MITRE TECHNIQUES (subset, expandable)
# --------------------------------------------------------------
MITRE_TECHNIQUES = {
    "T1003": "OS Credential Dumping",
    "T1059": "Command and Scripting Interpreter",
    "T1046": "Network Service Scanning",
    "T1021": "Remote Services",
    "T1069": "Permission Groups Discovery",
    "T1078": "Valid Accounts",
    "T1105": "Ingress Tool Transfer",
    "T1204": "User Execution",
    "T1566": "Phishing",
    "T1486": "Data Encrypted for Impact",
}

# --------------------------------------------------------------
# TECHNIQUE → TACTIC MAPPING
# --------------------------------------------------------------
MITRE_TECHNIQUE_TO_TACTIC = {
    "T1003": "TA0006",  # Credential Access
    "T1059": "TA0002",  # Execution
    "T1046": "TA0007",  # Discovery
    "T1021": "TA0008",  # Lateral Movement
    "T1069": "TA0007",  # Discovery
    "T1078": "TA0001",  # Initial Access
    "T1105": "TA0002",  # Execution
    "T1204": "TA0002",  # Execution
    "T1566": "TA0001",  # Initial Access
    "T1486": "TA0010",  # Exfiltration / Impact
}

# --------------------------------------------------------------
# TECHNIQUE DETAILS / LONG DESCRIPTION
# --------------------------------------------------------------
MITRE_TECHNIQUE_DETAILS = {
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries dump credentials from operating systems using LSASS, SAM, or other sources.",
        "link": "https://attack.mitre.org/techniques/T1003/"
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Attackers run commands via PowerShell, Bash, Python, or other CLI interfaces.",
        "link": "https://attack.mitre.org/techniques/T1059/"
    },
    "T1046": {
        "name": "Network Service Scanning",
        "description": "Attackers scan ports, services, and network endpoints to map attack surfaces.",
        "link": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1021": {
        "name": "Remote Services",
        "description": "Adversaries laterally move using SMB, SSH, WinRM, etc.",
        "link": "https://attack.mitre.org/techniques/T1021/"
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "description": "Attackers enumerate user groups and permissions.",
        "link": "https://attack.mitre.org/techniques/T1069/"
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Attackers use legitimate credentials to evade defenses.",
        "link": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "description": "Malware, payloads, or tools transferred into environment.",
        "link": "https://attack.mitre.org/techniques/T1105/"
    },
    "T1204": {
        "name": "User Execution",
        "description": "Execution triggered by a user action such as opening an attachment.",
        "link": "https://attack.mitre.org/techniques/T1204/"
    },
    "T1566": {
        "name": "Phishing",
        "description": "Adversaries send malicious emails to users.",
        "link": "https://attack.mitre.org/techniques/T1566/"
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "description": "Ransomware encrypts files or systems to disrupt availability.",
        "link": "https://attack.mitre.org/techniques/T1486/"
    },
}


# ==========================================================
#  BATCH 2 — MITRE DATA LAYER (NEO4J CORRELATION ENGINE)
# ==========================================================

def insert_mitre_into_neo4j():
    """
    Populates Neo4j with MITRE Tactic + Technique nodes
    and links techniques to their parent tactic.
    This only needs to run once, but is safe to run multiple times.
    """
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687",
                                      auth=("neo4j", "Adomaa12@"))

        with driver.session() as session:

            # ---------------------------
            # Create MITRE Tactic Nodes
            # ---------------------------
            for tid, tname in MITRE_TACTICS.items():
                session.run("""
                    MERGE (t:Tactic {id: $id})
                    SET t.name = $name
                """, id=tid, name=tname)

            # ---------------------------
            # Create MITRE Technique Nodes
            # ---------------------------
            for tech_id, tech_name in MITRE_TECHNIQUES.items():
                detail = MITRE_TECHNIQUE_DETAILS.get(tech_id, {})
                session.run("""
                    MERGE (x:Technique {id: $id})
                    SET x.name = $name,
                        x.description = $desc,
                        x.link = $link
                """, id=tech_id,
                     name=tech_name,
                     desc=detail.get("description", ""),
                     link=detail.get("link", ""))

            # ---------------------------
            # Link Technique → Tactic
            # ---------------------------
            for tech, tactic in MITRE_TECHNIQUE_TO_TACTIC.items():
                session.run("""
                    MATCH (tech:Technique {id: $tech})
                    MATCH (tac:Tactic {id: $tactic})
                    MERGE (tech)-[:PART_OF]->(tac)
                """, tech=tech, tactic=tactic)

        driver.close()
        print("✅ MITRE data inserted into Neo4j")

    except Exception as e:
        print(f"❌ MITRE insertion error: {e}")


def correlate_cves_to_mitre():
    import requests
    import json

    print("[+] Downloading MITRE CVE → ATT&CK mapping...")

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/relationships.json"

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        raw_text = resp.text.strip()

        # ---------------------------------------------------------
        # FIX: The MITRE file is NDJSON (each line is a JSON object)
        # ---------------------------------------------------------
        relationships = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                relationships.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # Ignore malformed lines

        print(f"[+] Parsed {len(relationships)} MITRE relationships.")

    except Exception as e:
        print("[!] MITRE correlation failed while downloading:", e)
        return

    # ---------------------------------------------------------
    # Insert MITRE → CVE relationships into Neo4j
    # ---------------------------------------------------------
    try:
        driver = get_driver()
        with driver.session() as session:

            for rel in relationships:
                src = rel.get("source_ref")
                dst = rel.get("target_ref")

                if not src or not dst:
                    continue

                # Only handle Technique → CVE mappings
                if src.startswith("attack-pattern") and "cve" in dst.lower():
                    session.run("""
                        MATCH (tech:Technique {id:$tech})
                        MATCH (v:Vulnerability {id:$cve})
                        MERGE (v)-[:MAPS_TO_TECHNIQUE]->(tech)
                    """, tech=src, cve=dst.upper())

        print("[+] MITRE CVE correlation successfully saved to Neo4j.")

    except Exception as e:
        print("[!] MITRE correlation failed:", e)


# ======================================================================
#  BATCH 3 — TAB 9: MITRE ATT&CK INTELLIGENCE LAYOUT (UI PANEL)
# ======================================================================

def mitre_tab_layout():
    return html.Div(
        [
            # ----------------------------------------------------------
            # TITLE & DESCRIPTION
            # ----------------------------------------------------------
            html.H2("🧩 MITRE ATT&CK Intelligence Portal",
                    className="text-warning mb-2",
                    style={"fontWeight": "bold"}),

            html.P(
                "Explore tactics, techniques, sub-techniques, and their mapped vulnerabilities "
                "directly from your Neo4j knowledge graph.",
                className="text-light",
                style={"opacity": "0.85", "fontSize": "18px"}
            ),

            html.Hr(style={"borderColor": "#444"}),

            # ----------------------------------------------------------
            # DROPDOWNS FOR TACTIC → TECHNIQUE
            # ----------------------------------------------------------
            html.Div(
                [
                    html.Label("Select MITRE Tactic:", className="text-warning"),
                    dcc.Dropdown(
                        id="mitre-tactic",
                        options=[{"label": MITRE_TACTICS[k], "value": k} for k in MITRE_TACTICS],
                        placeholder="TA0001 – TA0011",
                        style={"width": "60%", "color": "black", "marginBottom": "20px"},
                        clearable=True,
                    ),

                    html.Label("Select Technique (Optional):", className="text-warning"),
                    dcc.Dropdown(
                        id="mitre-technique",
                        options=[],  # Filled dynamically
                        placeholder="Technique (e.g., T1059)",
                        style={"width": "60%", "color": "black", "marginBottom": "20px"},
                        clearable=True,
                    ),

                    dbc.Button(
                        "🔍 Load MITRE Graph",
                        id="mitre-load-btn",
                        color="warning",
                        className="mt-2 mb-4",
                    ),
                ]
            ),

            # ----------------------------------------------------------
            # GRAPH TITLE
            # ----------------------------------------------------------
            html.Div(
                id="mitre-graph-title",
                className="text-warning mb-3",
                style={"fontSize": "22px", "fontWeight": "bold"},
            ),

            # ----------------------------------------------------------
            # MITRE GRAPH PANEL
            # ----------------------------------------------------------
            cyto.Cytoscape(
                id="mitre-graph",
                layout={"name": "cose"},
                style={
                    "width": "100%",
                    "height": "650px",
                    "backgroundColor": "#0d0d0d",
                    "border": "1px solid #333",
                    "borderRadius": "10px",
                },
                elements=[],
                stylesheet=[
                    # General node style
                    {
                        "selector": "node",
                        "style": {
                            "label": "data(label)",
                            "font-size": "12px",
                            "color": "white",
                            "background-color": "#666",
                            "text-outline-color": "#222",
                            "text-outline-width": 1,
                        },
                    },
                    {"selector": "node[type='Tactic']", "style": {"background-color": "#FF5733"}},
                    {"selector": "node[type='Technique']", "style": {"background-color": "#8E44AD"}},
                    {"selector": "node[type='SubTechnique']", "style": {"background-color": "#3498DB"}},
                    {"selector": "node[type='Vulnerability']", "style": {"background-color": "#C0392B"}},
                    {
                        "selector": "edge",
                        "style": {
                            "line-color": "#EAAA00",
                            "width": 2,
                            "target-arrow-shape": "triangle",
                            "target-arrow-color": "#EAAA00",
                        },
                    },
                ],
            ),

            html.Br(),

            # ----------------------------------------------------------
            # RAW JSON (OPTIONAL)
            # ----------------------------------------------------------
            html.Div(
                [
                    html.H4("🗂 Raw MITRE Data (Debugging)", className="text-warning"),
                    html.Pre(
                        id="mitre-raw-json",
                        style={
                            "whiteSpace": "pre-wrap",
                            "backgroundColor": "#111",
                            "color": "#EAAA00",
                            "padding": "10px",
                            "border": "1px solid #333",
                            "borderRadius": "6px",
                            "fontSize": "12px",
                            "display": "none",  # Hidden by default
                        },
                    ),
                ],
                className="mt-4",
            ),
        ],
        style={"padding": "20px"},
    )






# ======================================================================
# FIXED MITRE CALLBACKS — NO get_driver(), NO invalid queries
# ======================================================================

def neo_driver():
    return GraphDatabase.driver("bolt://localhost:7687",
                                auth=("neo4j", "Adomaa12@"))

@app.callback(
    Output("mitre-technique", "options"),
    Input("mitre-tactic", "value"),
)
def update_mitre_techniques_fixed(tactic_id):

    if not tactic_id:
        return []

    try:
        driver = neo_driver()
        with driver.session() as session:
            q = """
            MATCH (tech:Technique)-[:PART_OF]->(t:Tactic {id:$id})
            RETURN tech.id AS id, tech.name AS name
            ORDER BY id
            """
            result = session.run(q, id=tactic_id)
            return [{"label": r["name"], "value": r["id"]} for r in result]

    except Exception as e:
        print("[MITRE] Technique load error:", e)
        return []


@app.callback(
    Output("mitre-graph", "elements"),
    [
        Input("mitre-load-btn", "n_clicks"),
        State("mitre-tactic", "value"),
        State("mitre-technique", "value"),
    ],
    prevent_initial_call=True,
)
def load_mitre_graph_fixed(n_clicks, tactic_id, technique_id):

    if not tactic_id and not technique_id:
        return []

    driver = neo_driver()

    if tactic_id and technique_id:
        cypher = """
        MATCH (t:Tactic {id:$tac})
        MATCH (tech:Technique {id:$tech})-[:PART_OF]->(t)
        OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
        RETURN t, tech, v
        """
    elif tactic_id:
        cypher = """
        MATCH (t:Tactic {id:$tac})
        MATCH (tech:Technique)-[:PART_OF]->(t)
        RETURN t, tech
        """
    else:
        cypher = """
        MATCH (tech:Technique {id:$tech})
        OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
        RETURN tech, v
        """

    nodes = {}
    edges = []

    try:
        with driver.session() as session:
            rows = session.run(cypher, tac=tactic_id, tech=technique_id)

            for rec in rows:
                for k in rec.keys():
                    node = rec[k]
                    if not node:
                        continue

                    nid = str(node.id)
                    if nid not in nodes:
                        nodes[nid] = {
                            "data": {
                                "id": nid,
                                "label": node.get("name") or node.get("id"),   # FIXED
                                "type": list(node.labels)[0],
                            }
                        }

            # Relationship fetch
            if tactic_id and technique_id:
                rel_query = """
                MATCH p=(tech:Technique {id:$tech})-[:PART_OF]->(t:Tactic {id:$tac})
                OPTIONAL MATCH p2=(v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
                RETURN p, p2
                """
            elif tactic_id:
                rel_query = """
                MATCH p=(tech:Technique)-[:PART_OF]->(t:Tactic {id:$tac})
                RETURN p
                """
            else:
                rel_query = """
                MATCH p=(tech:Technique {id:$tech})
                OPTIONAL MATCH p2=(v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(tech)
                RETURN p, p2
                """

            rels = session.run(rel_query, tac=tactic_id, tech=technique_id)

            for rec in rels:
                for key in rec.keys():
                    if rec[key] is None:
                        continue
                    path = rec[key]
                    for rel in path.relationships:
                        edges.append({
                            "data": {
                                "id": str(rel.id),
                                "source": str(rel.start_node.id),
                                "target": str(rel.end_node.id),
                                "label": rel.type
                            }
                        })

        return list(nodes.values()) + edges

    except Exception as e:
        print("[MITRE ERROR FIXED]", e)
        return []

    finally:
        driver.close()



# ======================================================================
#  BATCH 5 — MITRE ↔ CVE ↔ Neo4j Correlation Engine
# ======================================================================

def correlate_cves_to_mitre():
    """
    Connects existing Nmap/OpenVAS/ZAP/Burp CVEs inside Neo4j
    to MITRE Techniques (Txxxx) using public CVE → MITRE mappings.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "Adomaa12@")
        )

        # -------------------------------------------------------------
        # 1) Pull MITRE CVE → Technique mapping from official source
        # -------------------------------------------------------------
        print("[+] Downloading MITRE CVE → ATT&CK mapping...")
        mapping_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-mapping.json"

        mapping_json = requests.get(mapping_url, timeout=20).json()

        # Each entry: {"cve": "CVE-XXXX-YYYY", "techniqueID": "T####"}
        cve_map = mapping_json.get("CVE_mappings", [])

        print(f"[+] Loaded {len(cve_map)} MITRE mappings.")

        # -------------------------------------------------------------
        # 2) Insert relationships into Neo4j
        # -------------------------------------------------------------
        with driver.session() as session:
            for entry in cve_map:
                cve = entry.get("cve")
                technique = entry.get("techniqueID")

                if not cve or not technique:
                    continue

                session.run(
                    """
                    MATCH (v:Vulnerability {id: $cve})
                    MATCH (t:Technique {id: $tech})
                    MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
                    """,
                    cve=cve,
                    tech=technique
                )

        print("[+] CVE ↔ MITRE technique correlation completed.")

    except Exception as e:
        print("[!] MITRE correlation failed:", e)



# ======================================================================
#  BATCH 5B — Insert MITRE ATT&CK Ontology into Neo4j
# ======================================================================

def insert_mitre_into_neo4j():
    """
    Loads MITRE ATT&CK tactics, techniques, and sub-techniques into Neo4j.
    ONLY needs to be run once.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "Adomaa12@")
        )

        print("[+] Loading MITRE ATT&CK Data into Neo4j...")

        # ---------------------------------------------------------
        # Download the official MITRE ATT&CK Enterprise STIX dataset
        # ---------------------------------------------------------
        mitre_url = (
            "https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json"
        )
        data = requests.get(mitre_url, timeout=20).json()
        objects = data.get("objects", [])

        with driver.session() as session:

            for obj in objects:
                stix_type = obj.get("type")
                stix_id = obj.get("id")
                name = obj.get("name")

                # =============================
                # TACTIC
                # =============================
                if stix_type == "x-mitre-tactic":
                    session.run(
                        """
                        MERGE (t:Tactic {id: $id})
                        SET t.label = $name
                        """,
                        id=obj["external_references"][0]["external_id"],
                        name=name,
                    )

                # =============================
                # TECHNIQUE
                # =============================
                if stix_type == "attack-pattern":
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id")
                            session.run(
                                """
                                MERGE (t:Technique {id: $id})
                                SET t.label = $name
                                """,
                                id=tech_id,
                                name=name,
                            )

                # =============================
                # SUB-TECHNIQUE (T####.###)
                # =============================
                # Format contains a dot when it's a sub-technique
                if stix_type == "attack-pattern":
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tid = ref.get("external_id")
                            if "." in tid:
                                sub_tid = tid
                                parent_tid = tid.split(".")[0]
                                session.run(
                                    """
                                    MATCH (parent:Technique {id: $parent})
                                    MERGE (s:SubTechnique {id: $child})
                                    SET s.label = $name
                                    MERGE (parent)-[:HAS_SUBTECHNIQUE]->(s)
                                    """,
                                    parent=parent_tid,
                                    child=sub_tid,
                                    name=name,
                                )

        print("[+] MITRE ATT&CK data imported successfully!")

    except Exception as e:
        print("[!] Failed to insert MITRE ATT&CK data:", e)


# ======================================================================
#  BATCH 6 — MITRE ATT&CK ANALYTICS ENGINE (PhD Research Version)
# ======================================================================

def mitre_get_techniques_by_tactic(tactic_id):
    """
    Returns all Techniques belonging to a given MITRE Tactic (TA000X).
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH (ta:Tactic {id: $tactic})<-[:BELONGS_TO]-(tech:Technique)
                RETURN tech.id AS id, tech.label AS name
                ORDER BY tech.id
                """,
                tactic=tactic_id
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE tactic lookup error:", e)
        return []


def mitre_get_cves_for_technique(tech_id):
    """
    Returns all CVEs mapped to a MITRE Technique.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t:Technique {id: $tech})
                RETURN v.id AS cve, v.cvss AS cvss
                ORDER BY v.id
                """,
                tech=tech_id
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE CVE lookup error:", e)
        return []


def mitre_get_attack_chains(target_asset=None):
    """
    Returns likely attack chains based on MITRE + CVE + Graph Structure.
    Used for lateral movement, privilege escalation, and kill chain modeling.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )

        with driver.session() as session:

            # ===============================================
            # GENERAL ATTACK CHAIN QUERY
            # ===============================================
            query = """
            MATCH p=(u:User)-[:ACCESS]->(a:Asset)-[:RUNS_SERVICE]->(s:Service)
                  -[:HAS_VULNERABILITY]->(v:Vulnerability)
                  -[:MAPS_TO_TECHNIQUE]->(t:Technique)
            RETURN p LIMIT 25
            """

            if target_asset:
                query = query.replace(
                    "RETURN p LIMIT 25",
                    "WHERE a.host = $asset RETURN p LIMIT 25"
                )

            results = session.run(query, asset=target_asset)

            chains = []
            for record in results:
                path = record["p"]
                chain = []
                for node in path.nodes:
                    chain.append({
                        "id": node.get("id") or node.get("name"),
                        "type": list(node.labels)[0]
                    })
                chains.append(chain)

            return chains

    except Exception as e:
        print("[!] Attack chain inference failed:", e)
        return []


def mitre_frequency_heatmap():
    """
    Produces a MITRE Technique frequency map:
    Technique → number of CVEs mapped.
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
                RETURN t.id AS id, t.label AS name, COUNT(v) AS cve_count
                ORDER BY cve_count DESC
                LIMIT 50
                """
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE frequency error:", e)
        return []


def mitre_privilege_escalation_paths():
    """
    Query to identify Privilege Escalation patterns:
    Vulnerability → Technique → Target Privilege
    """
    try:
        driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=("neo4j", "Adomaa12@")
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH p=(v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->
                         (t:Technique)-[:HAS_SUBTECHNIQUE*0..1]->
                         (st:SubTechnique)
                WHERE t.id STARTS WITH 'T' AND st.id STARTS WITH 'T'
                RETURN DISTINCT t.id AS technique,
                       t.label AS name,
                       COLLECT(DISTINCT v.id)[0..10] AS sample_cves
                LIMIT 40
                """
            )
            return [dict(r) for r in result]
    except Exception as e:
        print("[!] MITRE PrivEsc error:", e)
        return []


# ======================================================================
#  BATCH 7 — MITRE AI CALLBACK ENGINE (PhD-Level)
# ======================================================================

@app.callback(
    [
        Output("mitre-techniques-table", "data"),
        Output("mitre-cve-table", "data"),
        Output("mitre-ai-output", "children"),
    ],
    [
        Input("mitre-tactic-dropdown", "value"),
        Input("mitre-technique-dropdown", "value"),
        Input("mitre-ai-btn", "n_clicks"),
    ],
    [
        State("mitre-analysis-input", "value"),
    ],
    prevent_initial_call=True
)
def mitre_ai_workflow(tactic_id, technique_id, ai_click, user_prompt):

    triggered = ctx.triggered_id

    # ------------------------------------------------------
    # 1) USER SELECTED A MITRE TACTIC
    # ------------------------------------------------------
    if triggered == "mitre-tactic-dropdown":
        if not tactic_id:
            return [], [], ""
        techniques = mitre_get_techniques_by_tactic(tactic_id)
        return techniques, [], ""

    # ------------------------------------------------------
    # 2) USER SELECTED A TECHNIQUE
    # ------------------------------------------------------
    if triggered == "mitre-technique-dropdown":
        if not technique_id:
            return [], [], ""
        cves = mitre_get_cves_for_technique(technique_id)
        return no_update, cves, ""

    # ------------------------------------------------------
    # 3) RUN FULL AI ANALYSIS
    # ------------------------------------------------------
    if triggered == "mitre-ai-btn":
        if not user_prompt:
            return no_update, no_update, "⚠ Please enter a question."

        # --------------------------------------------------
        # 3.1 — GPT-4o
        # --------------------------------------------------
        gpt_answer = call_llm(
            f"MITRE ATT&CK Analysis Request:\n"
            f"Tactic: {tactic_id}\n"
            f"Technique: {technique_id}\n"
            f"Question: {user_prompt}\n"
        )

        # --------------------------------------------------
        # 3.2 — Vulners API
        # --------------------------------------------------
        try:
            vulners_resp = requests.get(
                "https://vulners.com/api/v3/search/lucene/",
                params={"query": user_prompt, "size": 5},
                headers={"X-Api-Key": os.getenv("VULNERS_API_KEY")},
                timeout=10
            ).json()
            vulners_text = json.dumps(vulners_resp, indent=2)
        except:
            vulners_text = "⚠ Vulners API unavailable."

        # --------------------------------------------------
        # 3.3 — Exploit-DB (searchsploit)
        # --------------------------------------------------
        try:
            proc = subprocess.run(
                ["searchsploit", user_prompt, "--json"],
                capture_output=True,
                text=True,
            )
            exploit_text = proc.stdout
        except:
            exploit_text = "⚠ searchsploit unavailable."

        # --------------------------------------------------
        # 3.4 — Build Unified Output Panel
        # --------------------------------------------------
        ai_panel = html.Div([
            html.H4("🧠 GPT-4o Analysis", className="text-warning"),
            html.Pre(gpt_answer, style=_mitre_panel_style()),

            html.H4("📘 Vulners Intelligence", className="text-primary mt-4"),
            html.Pre(vulners_text, style=_mitre_panel_style()),

            html.H4("💥 Exploit-DB Results", className="text-danger mt-4"),
            html.Pre(exploit_text, style=_mitre_panel_style()),
        ])

        return no_update, no_update, ai_panel

    return no_update, no_update, ""

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

@app.callback(
    Output("pdf-download", "data"),
    Input("pdf-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_pdf_report(n_clicks):

    df = load_findings()
    findings_summary = df.to_string(index=False) if not df.empty else "No findings available."

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Security Assessment Report", styles["Title"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
    story.append(Paragraph(
        "This document summarizes vulnerabilities identified across Nmap, Nessus, "
        "OpenVAS, and ZAP scans.", styles["BodyText"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Findings Summary</b>", styles["Heading2"]))
    story.append(Paragraph(findings_summary.replace("\n", "<br/>"), styles["Code"]))

    pdf_path = "/tmp/security_report.pdf"
    pdf = SimpleDocTemplate(pdf_path, pagesize=letter)
    pdf.build(story)

    return dcc.send_file(pdf_path)


import csv
import io
from datetime import datetime, timedelta

@app.callback(
    Output("poam-download", "data"),
    Input("poam-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_poam(n):
    df = load_findings()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Weakness ID", "Description", "Source", "Severity", "Recommended Fix", "Due Date"])

    for _, row in df.iterrows():
        due_date = (datetime.today() + timedelta(days=30)).strftime("%Y-%m-%d")
        mitigation = f"Apply vendor patch for {row['id']} and implement system hardening."

        writer.writerow([
            row["id"],
            row["source"],
            row["source"],
            row.get("cvss", "N/A"),
            mitigation,
            due_date
        ])

    return dict(
        content=output.getvalue(),
        filename="POAM.csv"
    )



NIST_MAP = {
    "tls": ["SC-13", "SC-23"],
    "http": ["SC-7", "AC-4"],
    "ftp": ["AC-4", "CM-7"],
    "cve": ["RA-5", "SI-2"],
    "outdated": ["CM-2", "CM-6"],
    "weak": ["SC-12", "SC-28"]
}

@app.callback(
    Output("nist-download", "data"),
    Input("nist-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_nist_mapping(n):

    df = load_findings()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Finding", "Source", "Mapped NIST Controls"])

    for _, row in df.iterrows():

        text = str(row["id"]).lower()
        controls = []

        for keyword, control_list in NIST_MAP.items():
            if keyword in text:
                controls.extend(control_list)

        if not controls:
            controls = ["RA-5"]  # Default vulnerability management control

        writer.writerow([
            row["id"],
            row["source"],
            "; ".join(controls)
        ])

    return dict(
        content=output.getvalue(),
        filename="nist_mapping.csv"
    )




    # --------------------------------------
    # 1. Load SQLite Findings
    # --------------------------------------
    try:
        df = load_findings()
        sqlite_summary = df.to_string(index=False) if not df.empty else "No findings."
    except Exception as e:
        sqlite_summary = f"SQLite Error: {e}"

    # --------------------------------------
    # 2. Load Neo4j Attack Graph
    # --------------------------------------
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
        with driver.session() as session:
            q = """
            MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a.host AS asset, s.name AS service, s.port AS port,
                   v.id AS vuln, v.cvss AS cvss, v.source AS source
            """
            records = list(session.run(q))
            graph_summary = "\n".join(str(r) for r in records) if records else "No graph data."
        driver.close()
    except Exception as e:
        graph_summary = f"Neo4j Error: {e}"

    # --------------------------------------
    # 3. Load XML Scan Snippets
    # --------------------------------------
    xml_context = ""
    try:
        xml_dir = "/opt/vuln_intel/xml"

        if os.path.exists(xml_dir):
            for f in os.listdir(xml_dir)[:3]:  # limit to 3
                if f.endswith(".xml"):
                    path = os.path.join(xml_dir, f)
                    snippet = Path(path).read_text(errors="ignore")[:3000]
                    xml_context += f"\n--- {f} ---\n{snippet}\n"
        else:
            xml_context = "XML directory missing."
    except Exception as e:
        xml_context = f"XML Error: {e}"

    # --------------------------------------
    # 4. Build Security-Aware LLM Prompt
    # --------------------------------------
    full_context = f"""
You are an AI cybersecurity analyst. Use ONLY the data provided below:

====================
USER QUESTION
====================
{user_msg}

====================
SQLITE FINDINGS (Parsed Nmap/Nessus/OpenVAS/ZAP)
====================
{sqlite_summary}

====================
NEO4J ATTACK GRAPH (Assets → Services → Vulnerabilities)
====================
{graph_summary}

====================
RAW XML SNIPPETS
====================
{xml_context}

TASKS:
- Answer the question accurately.
- Use real assets, ports, CVEs, severities, and relationships.
- Provide MITRE ATT&CK techniques if relevant.
- Provide risk analysis.
- Provide recommended remediations.
- Never hallucinate information not found in the datasets.
"""

    ai_response = call_llm(full_context)

    # Format message history
    history = history or []
    history += [
        html.Div(f"👤 You: {user_msg}", style={"marginTop": "8px"}),
        html.Div(f"🛡️ AI: {ai_response}", style={"marginTop": "8px", "color": "#EAAA00"})
    ]

    return history




# ======================================================================
# Helper: Panel style for AI output
# ======================================================================
def _mitre_panel_style():
    return {
        "whiteSpace": "pre-wrap",
        "backgroundColor": "#000",
        "padding": "10px",
        "border": "1px solid #333",
        "borderRadius": "6px",
        "fontSize": "12px",
        "color": "#EAAA00",
        "maxHeight": "450px",
        "overflowY": "scroll",
    }



@app.callback(
    Output("upload-status", "children"),
    Input("upload-scan-file", "contents"),
    State("upload-scan-file", "filename"),
    prevent_initial_call=True
)
def process_uploaded_file(contents, filename):
    if not contents:
        return "No file uploaded."

    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)

    try:
        if filename.endswith(".xml"):
            rows = parse_nmap_xml(decoded)  # You can replace this with the corresponding parser for Burp, ZAP, etc.
            for r in rows:
                insert_finding(r)  # Insert findings into Neo4j or wherever needed
            return f"Imported {len(rows)} items from {filename}"

        return "Unsupported file type."

    except Exception as e:
        return f"Error processing file: {e}"




@app.callback(
    Output("download-json", "data"),
    Input("export-json", "n_clicks"),
    prevent_initial_call=True
)
def export_json(n):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM findings", conn)
    conn.close()
    return dict(content=df.to_json(orient="records"), filename="findings.json")

@app.callback(
    Output("download-csv", "data"),
    Input("export-csv", "n_clicks"),
    prevent_initial_call=True
)
def export_csv(n):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM findings", conn)
    conn.close()
    return dict(content=df.to_csv(index=False), filename="findings.csv")



[{"label": "T1059 (Technique)", "value": "T1059"}, ...]




@app.callback(
    Output("mitre-attack-path-graph", "figure"),
    Input("mitre-attack-path-asset", "value")
)
def mitre_attack_path(asset):

    if not asset:
        return go.Figure()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    q = """
    MATCH (a:Asset {name:$x})-[:HAS_VULN]->(v:Vulnerability)
    OPTIONAL MATCH (v)-[:EXPLOITS]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
    RETURN a, v, tech, tac
    """

    rows = []
    with driver.session() as session:
        rows = [r.data() for r in session.run(q, x=asset)]

    edges = []
    nodes = set()

    for r in rows:
        a = r["a"]["name"]
        v = r["v"]["id"]
        tech = r["tech"]["id"] if r["tech"] else None
        tac = r["tac"]["id"] if r["tac"] else None

        nodes.add(a)
        nodes.add(v)

        edges.append((a, v))

        if tech:
            nodes.add(tech)
            edges.append((v, tech))

        if tac:
            nodes.add(tac)
            edges.append((tech, tac))

    # Build networkx graph → plotly
    import networkx as nx
    G = nx.DiGraph()
    for n in nodes: G.add_node(n)
    for e in edges: G.add_edge(e[0], e[1])

    pos = nx.spring_layout(G)

    # create figure
    fig = go.Figure()

    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            mode='lines',
            line=dict(width=2, color='gray')
        ))

    for node in G.nodes():
        x, y = pos[node]
        fig.add_trace(go.Scatter(
            x=[x], y=[y], mode='markers+text',
            text=node, textposition="top center",
            marker=dict(size=12)
        ))

    fig.update_layout(title=f"Attack Path for Asset: {asset}")

    return fig

    # PRESET NEO4J QUERIES
    cypher = {
        "btn-assets": """
            MATCH (a:Asset)-[r]->(b)
            RETURN a, r, b
        """,
        "btn-vuln": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            RETURN a, v
        """,
        "btn-tech-tac": """
            MATCH (tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN tech, tac
        """,
        "btn-subtech": """
            MATCH (p:Technique)-[:HAS_SUBTECHNIQUE]->(c:SubTechnique)
            RETURN p, c
        """,
        "btn-attack-path": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:EXPLOITS]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN a, v, tech, tac
        """
    }[clicked]

    nodes = {}
    edges = []

    with driver.session() as session:
        results = session.run(cypher)

        for row in results:
            for key, val in row.items():

                # Skip null values
                if val is None:
                    continue

                # Handle nodes safely
                if hasattr(val, "labels"):
                    nid = val.id
                    label = list(val.labels)[0] if val.labels else "Node"
                    text = val.get("name") or val.get("id") or label

                    nodes[nid] = {"data": {"id": nid, "label": text}}

                # Handle relationships safely
                elif hasattr(val, "type") and hasattr(val, "nodes"):
                    try:
                        n1, n2 = val.nodes
                        if n1 and n2:
                            edges.append({
                                "data": {"source": n1.id, "target": n2.id}
                            })
                    except:
                        pass  # skip broken relationships

    # Return EMPTY list if no graph
    elements = list(nodes.values()) + edges
    return elements if elements else []


def load_preset_graph(btn_assets, btn_vuln, btn_tech_tac, btn_subtech, btn_attack_path):

    from dash import callback_context
    ctx = callback_context


def load_preset_graph(btn_assets, btn_vuln, btn_tech_tac, btn_subtech, btn_attack_path):

    from dash import callback_context
    ctx = callback_context
    if not ctx.triggered:
        return []

    clicked = ctx.triggered[0]["prop_id"].split(".")[0]

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # All preset Cypher queries
    cypher_queries = {
        "btn-assets": """
            MATCH (a:Asset)-[r]->(b)
            RETURN a, r, b
        """,

        "btn-vuln": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            RETURN a, v
        """,

        "btn-tech-tac": """
            MATCH (tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN tech, tac
        """,

        "btn-subtech": """
            MATCH (p:Technique)-[:HAS_SUBTECHNIQUE]->(c:SubTechnique)
            RETURN p, c
        """,

        "btn-attack-path": """
            MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:EXPLOITS]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
            RETURN a, v, tech, tac
        """,
    }

    query = cypher_queries[clicked]

    nodes = {}
    edges = []

    with driver.session() as session:
        results = session.run(query)
        for row in results:
            for key, val in row.items():

                if hasattr(val, "labels"):   # Node
                    nid = val.id
                    label = list(val.labels)[0]
                    text = val.get("name") or val.get("id") or label

                    nodes[nid] = {"data": {"id": nid, "label": text}}

                if hasattr(val, "type"):     # Relationship
                    start, end = val.nodes
                    edges.append({"data": {"source": start.id, "target": end.id}})

    return list(nodes.values()) + edges


# ==========================================================
#  TAB — ATTACK CHAIN SIMULATOR
# ==========================================================

def attack_chain_simulator_tab():
    return html.Div(
        [
            html.H3("⚔️ Attack Chain Simulator", className="text-warning mb-3"),

            html.P(
                "Simulate attacker movement using real graph data (Assets → Services → Vulnerabilities → Techniques).",
                className="text-light"
            ),

            html.Hr(),

            # Start node
            html.Label("Start Asset / Node:", className="text-light"),
            dcc.Dropdown(
                id="acs-start",
                placeholder="Select start node...",
                options=[],
                style={"width": "60%", "marginBottom": "20px"},
            ),

            # Target node
            html.Label("Target Node (e.g., Crown Jewel):", className="text-light"),
            dcc.Dropdown(
                id="acs-target",
                placeholder="Select target node...",
                options=[],
                style={"width": "60%", "marginBottom": "20px"},
            ),

            dbc.Button(
                "🚀 Simulate Attack Path",
                id="acs-run",
                color="danger",
                className="mt-3 mb-4"
            ),

            html.Div(
                id="acs-output",
                style={
                    "whiteSpace": "pre-wrap",
                    "backgroundColor": "#111",
                    "padding": "15px",
                    "border": "1px solid #333",
                    "borderRadius": "6px",
                    "color": "#EAAA00",
                }
            ),
        ],
        className="p-4"
    )

# ======================================================================
# POPULATE Attack Chain Simulator DROPDOWNS
# ======================================================================
@app.callback(
    [
        Output("acs-start", "options", allow_duplicate=True),
        Output("acs-target", "options", allow_duplicate=True),
    ],
    Input("neo4j-graph", "elements"),
    prevent_initial_call=True    # REQUIRED when allow_duplicate=True
)
def populate_attack_nodes(elements):
    if not elements:
        return [], []

    options = []
    seen = set()

    for el in elements:
        if "data" in el and "id" in el["data"]:
            nid = el["data"]["id"]
            label = el["data"].get("label", nid)
            if nid not in seen:
                seen.add(nid)
                options.append({"label": label, "value": nid})

    return options, options

import subprocess

def run_script(path):
    try:
        output = subprocess.check_output(["python3", path], stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()





# === CYBER RANGE CALLBACK REGISTRATIONS ===
dt_callbacks(app)
hp_callbacks(app)
exp_callbacks(app)
wg_callbacks(app)
ti_callbacks(app)
rm_callbacks(app)


# ==================================================
# TAB: ASSESSMENT (MUST BE DEFINED BEFORE app.layout)
# ==================================================

# =================================
# TAB: ASSESSMENT (Nmap + ZAP ONLY)
# =================================

import subprocess
import dash
from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc

assessment_tab = dbc.Container(
    [
        html.H3("🧪 Vulnerability Assessment", className="text-warning"),
        html.P(
            "Run network and web vulnerability scans using Nmap and OWASP ZAP. "
            "Scan results are stored centrally and ingested on demand."
        ),
        html.Hr(),

        # -------------------------------------------------
        # Scanner Selection
        # -------------------------------------------------
        html.H5("🛠 Scanner Selection", className="text-warning"),
        dcc.Dropdown(
            id="scanner-select",
            options=[
                {
                    "label": "Nmap — Network Discovery & Service Enumeration",
                    "value": "nmap",
                },
                {
                    "label": "OWASP ZAP — Web Application Security Scan",
                    "value": "zap",
                },
            ],
            placeholder="Select a scanner…",
            clearable=False,
            style={"width": "55%"},
        ),

        html.Br(),

        # -------------------------------------------------
        # Target Input
        # -------------------------------------------------
        html.H5("🎯 Scan Targets", className="text-warning"),
        dcc.Textarea(
            id="target-input",
            placeholder=(
                "Enter scan targets (one per line)\n\n"
                "Nmap examples:\n"
                "192.168.1.113\n"
                "10.0.0.0/24\n\n"
                "ZAP examples:\n"
                "http://example.com\n"
                "https://app.example.com"
            ),
            style={
                "width": "75%",
                "height": "170px",
                "backgroundColor": "#111",
                "color": "#ffffff",
                "border": "1px solid #444",
                "fontFamily": "monospace",
                "fontSize": "0.95rem",
                "padding": "10px",
            },
        ),

        html.Br(),
        html.Br(),

        # -------------------------------------------------
        # Action Buttons
        # -------------------------------------------------
        dbc.Row(
            [
                dbc.Col(
                    dbc.Button(
                        "▶ Run Scan",
                        id="scan-btn",
                        color="warning",
                        n_clicks=0,
                    ),
                    width="auto",
                ),
                dbc.Col(
                    dbc.Button(
                        "⛔ Cancel Scan",
                        id="cancel-btn",
                        color="danger",
                        n_clicks=0,
                        disabled=True,
                    ),
                    width="auto",
                ),
                dbc.Col(
                    dbc.Button(
                        "📥 Ingest to Neo4j",
                        id="ingest-btn",
                        color="success",
                        n_clicks=0,
                        disabled=True,  # enabled after scan completes
                    ),
                    width="auto",
                ),
            ],
            className="g-3",
        ),

        html.Hr(),

        # -------------------------------------------------
        # Scan Log Output
        # -------------------------------------------------
        html.H4("📜 Scan Log Output", className="text-warning"),
        html.Div(
            id="scan-log-output",
            children="Waiting for scan to start…",
            style={
                "whiteSpace": "pre-wrap",
                "backgroundColor": "#0b0b0b",
                "color": "#00ff66",
                "padding": "14px",
                "borderRadius": "6px",
                "minHeight": "220px",
                "fontFamily": "monospace",
                "fontSize": "0.9rem",
                "border": "1px solid #333",
                "overflowY": "auto",
            },
        ),

        html.Br(),

        html.Small(
            "ℹ️ Scans run asynchronously. Results are written to shared storage "
            "and ingested into Neo4j on demand.",
            style={"color": "#888"},
        ),
    ],
    fluid=True,
)

# ========================================================
# Callback – Cancel Scan
# ========================================================
@callback(
    Output("scan-log-output", "children", allow_duplicate=True),
    Output("ingest-btn", "disabled"),   # 👈 NEW
    Input("scan-btn", "n_clicks"),
    State("scanner-select", "value"),
    State("target-input", "value"),
    prevent_initial_call=True,
)
def trigger_scan(n_clicks, scanner, targets):
    if not scanner or not targets:
        return "❌ Scanner and target required.", True

    targets = [t.strip() for t in targets.splitlines() if t.strip()]
    if not targets:
        return "❌ No valid targets.", True

    logs = []

    def log(msg):
        logs.append(msg)

    if scanner == "nmap":
        from cyber_range.services.nmap_ingest import NmapIngestor

        log("[*] Starting Nmap scan...")
        scanner_obj = NmapIngestor()
        scanner_obj.start_scan(
            targets,
            on_output=lambda line: log(line.strip()),
            on_complete=lambda cancelled: log(
                "❌ Scan cancelled" if cancelled else "✅ Scan completed"
            ),
        )

    elif scanner == "zap":
        from cyber_range.services.zap_ingest import ZAPScanner

        log("[*] Starting ZAP scan...")
        zap = ZAPScanner()
        zap.run_scan(targets[0], progress_cb=log)

        log("✅ ZAP scan completed")

    # ✅ ENABLE INGEST BUTTON AFTER SCAN
    return "\n".join(logs), False


# ========================================================
# Callback – Ingest Scan Results into Neo4j
# ========================================================

@callback(
    Output("scan-log-output", "children", allow_duplicate=True),
    Output("cancel-btn", "disabled"),
    Input("cancel-btn", "n_clicks"),
    prevent_initial_call=True,
)
def cancel_scan(_):
    from cyber_range.services.nmap_ingest import NmapIngestor

    scanner = NmapIngestor()
    if scanner.cancel_scan():
        return "⛔ Scan cancelled by user.", True

    return "⚠️ No active scan to cancel.", True
@callback(
    Output("scan-log-output", "children", allow_duplicate=True),
    Output("ingest-btn", "disabled"),
    Input("ingest-btn", "n_clicks"),
    prevent_initial_call=True,
)
def ingest_to_neo4j(n_clicks):
    import subprocess

    try:
        result = subprocess.run(
            ["python", "main_ingest.py"],
            cwd="/root/vuln_intel/app",
            capture_output=True,
            text=True,
            check=True,
        )

        return (
            "📥 Ingesting scan results into Neo4j...\n\n"
            + result.stdout
            + "\n✔ Ingestion completed successfully."
        ), True

    except subprocess.CalledProcessError as e:
        return (
            "❌ Neo4j ingestion failed.\n\n"
            + (e.stdout or "")
            + "\n"
            + (e.stderr or "")
        ), False


# ========================================================
# Callback – Assessment Scan (Nmap / ZAP)
# ========================================================
@callback(
    Output("scan-log-output", "children", allow_duplicate=True),
    Output("ingest-btn", "disabled"),
    Output("cancel-btn", "disabled"),
    Input("scan-btn", "n_clicks"),
    State("scanner-select", "value"),
    State("target-input", "value"),
    prevent_initial_call=True,
)
def trigger_scan(n_clicks, scanner, targets):
    if not scanner or not targets:
        return "❌ Scanner and target required.", True, True

    targets = [t.strip() for t in targets.splitlines() if t.strip()]
    if not targets:
        return "❌ No valid targets.", True, True

    logs = []

    def log(msg):
        logs.append(msg)

    # Disable ingest until scan completes
    ingest_disabled = True
    cancel_disabled = False

    if scanner == "nmap":
        from cyber_range.services.nmap_ingest import NmapIngestor

        log("[*] Starting Nmap scan...")
        scanner_obj = NmapIngestor()

        def on_complete(cancelled):
            if cancelled:
                log("❌ Scan cancelled.")
            else:
                log("✅ Scan completed successfully.")
            # Enable ingestion after scan
            nonlocal ingest_disabled
            ingest_disabled = False

        scanner_obj.start_scan(
            targets,
            on_output=lambda line: log(line.strip()),
            on_complete=on_complete,
        )

    elif scanner == "zap":
        from cyber_range.services.zap_ingest import ZAPScanner

        log("[*] Starting OWASP ZAP scan...")
        zap = ZAPScanner()
        zap.run_scan(
            targets[0],
            progress_cb=log,
        )

        log("✅ ZAP scan completed successfully.")
        ingest_disabled = False

    return "\n".join(logs), ingest_disabled, cancel_disabled



# ==========================================================
# FINAL CLEAN DASHBOARD LAYOUT (NO DUPLICATES, FULL MODULE SET)
# ==========================================================

app.layout = dbc.Container(
    [
        html.H2(
            "Vulnerability Intelligence Dashboard",
            className="text-warning mt-3 mb-4"
        ),

        dbc.Tabs(
            id="tabs",
            active_tab="system",
            children=[

                # -------------------------------------------------
                # 1. System
                # -------------------------------------------------
                dbc.Tab(system_health_layout(), label="System", tab_id="system"),

                # -------------------------------------------------
                # 2. Assessment
                # -------------------------------------------------
                dbc.Tab(assessment_tab, label="Assessment", tab_id="assessment"),

                # -------------------------------------------------
                # 3. Import Feeds
                # -------------------------------------------------
                dbc.Tab(import_feeds_layout(), label="Import Feeds", tab_id="import_feeds"),

                # -------------------------------------------------
                # 4. Vulnerabilities
                # -------------------------------------------------
                dbc.Tab(vulnerability_tab(), label="Vulnerabilities", tab_id="vuln"),

                # -------------------------------------------------
                # 5. LLM
                # -------------------------------------------------
                dbc.Tab(llm_tab, label="LLM", tab_id="llm"),

                # -------------------------------------------------
                # 6. Chatbot
                # -------------------------------------------------
                dbc.Tab(chatbot_tab, label="Chatbot", tab_id="chatbot"),

                # -------------------------------------------------
                # 7. Neo4j Graph Intelligence
                # -------------------------------------------------
                dbc.Tab(
                    neo4j_graphs_tab(),
                    label="Neo4j Graph Intelligence",
                    tab_id="neo4j"
                ),

                # -------------------------------------------------
                # 8. Neo4j Graph Presets
                # -------------------------------------------------
                dbc.Tab(
                    neo4j_preset_graphs_tab(),
                    label="Neo4j Graph Presets",
                    tab_id="neo4j_presets"
                ),

                # -------------------------------------------------
                # 9. MITRE ATT&CK Intelligence
                # -------------------------------------------------
                dbc.Tab(
                    mitre_tab_layout(),
                    label="MITRE ATT&CK Intelligence",
                    tab_id="mitre"
                ),

                # -------------------------------------------------
                # 10. Attack Chain Simulator + Aggressive Mode
                # -------------------------------------------------
                dbc.Tab(
                    html.Div(
                        [
                            attack_chain_simulator_layout(),
                            html.Hr(),
                            aggressive_attack_layout(),
                        ],
                        className="p-3",
                    ),
                    label="Attack Chain",
                    tab_id="attack_chain",
                ),

                # =====================================================
                # CYBER-RANGE ADVANCED MODULES
                # =====================================================
                dbc.Tab(killchain_tab(),     label="Kill Chain",    tab_id="killchain"),
                dbc.Tab(digital_twin_tab(), label="Digital Twin",  tab_id="digital_twin"),
                dbc.Tab(honeypot_tab(),     label="Honeypots",     tab_id="honeypots"),
                dbc.Tab(exploit_ai_tab(),   label="Exploit AI",    tab_id="exploit_ai"),
                dbc.Tab(wargame_tab(),      label="Wargame AI",    tab_id="wargame"),

                # -------------------------------------------------
                # Reporting
                # -------------------------------------------------
                dbc.Tab(reporting_tab, label="Reporting", tab_id="reporting"),

                # -------------------------------------------------
                # Voice
                # -------------------------------------------------
                dbc.Tab(voice_tab(), label="Voice", tab_id="voice"),
            ],
        ),

        html.Div(id="tabs-content"),
    ],
    fluid=True,
)



# ============================================
# AI Narrative Callback (FIXED & RESTORED)
# ============================================
from openai import OpenAI
client = OpenAI()

@app.callback(
    Output("ai-narrative", "children"),
    [
        Input("metric-vulns", "children"),
        Input("metric-assets", "children"),
        Input("metric-services", "children"),
    ],
    prevent_initial_call=False
)
def update_ai_narrative(vuln_count, asset_count, service_count):
    try:
        summary = f"""
        Vulnerabilities: {vuln_count}
        Assets: {asset_count}
        Services: {service_count}
        """

        prompt = f"""
        Based on this environment summary, generate a concise cybersecurity narrative:
        {summary}

        Focus on:
        - Likely attack paths
        - Business impact
        - Urgency
        - Recommended immediate actions
        """

        response = client.chat.completions.create(
            model="gpt-5.2",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        # Correct OpenAI SDK usage
        narrative = response.choices[0].message.content
        return narrative

    except Exception as e:
        return f"[AI Narrative Error] {str(e)}"


from cyber_range.services.neo4j_engine import Neo4jEngine
neo = Neo4jEngine()


def load_full_graph():
    """Return full Neo4j graph in Cytoscape format."""
    query = """
    MATCH (n)-[r]->(m)
    RETURN n, r, m
    """
    records = neo.run_query(query)

    nodes = {}
    edges = []

    for rec in records:
        n = rec["n"]
        m = rec["m"]
        r = rec["r"]

        # ---- Nodes ----
        for node in [n, m]:
            nid = node.id
            if nid not in nodes:   # duplicate-safe
                label = next(iter(node.labels))
                nodes[nid] = {
                    "data": {
                        "id": nid,
                        "label": label,
                        "raw": node._properties,
                    },
                    "classes": label.lower()
                }

        # ---- Relationship ----
        edges.append({
            "data": {
                "source": n.id,
                "target": m.id,
                "label": r.type,
            }
        })

    # Final Cytoscape element list
    return list(nodes.values()) + edges


# ==========================================================
# CALLBACK WITH allow_duplicate=True
# ==========================================================
@app.callback(
    Output("neo4j-graph", "elements", allow_duplicate=True),
    Input("neo4j-refresh", "n_clicks"),
    prevent_initial_call=True
)
def update_graph(n):
    return load_full_graph()


@app.callback(
    Output("voice-response", "children"),
    Input("voice-output", "children"),
    prevent_initial_call=True
)
def process_voice_input(text):
    if not text:
        return "No voice text received."

    # send to LLM engine
    from llm_engine import call_llm
    response = call_llm(f"Voice command: {text}")
    return response

# ================================================================
#  VOICE → AI COMMAND INTERPRETER
# ================================================================

# ==========================================================
#  VOICE ENGINE — Unified Callback (STT + LLM + UI Updates)
# ==========================================================

from dash.exceptions import PreventUpdate
import dash
import json
from llm_engine import call_llm


@app.callback(
    [
        Output("voice-transcript", "children", allow_duplicate=True),
        Output("voice-response", "children", allow_duplicate=True),
        Output("voice-status", "children", allow_duplicate=True),
    ],
    [
        Input("voice-record-btn", "n_clicks"),
        Input("voice-stop-btn", "n_clicks"),
        Input("voice-input", "data"),   # Browser sends STT text here
    ],
    prevent_initial_call=True
)
def voice_engine(record_clicks, stop_clicks, voice_data):
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate

    trigger = ctx.triggered[0]["prop_id"].split(".")[0]

    # ----------------------------------------------------
    # 1. Record button clicked
    # ----------------------------------------------------
    if trigger == "voice-record-btn":
        return (
            "",                       # transcript
            "Voice recording started…", 
            "🎤 Listening…"           # status
        )

    # ----------------------------------------------------
    # 2. Stop button clicked
    # ----------------------------------------------------
    if trigger == "voice-stop-btn":
        return (
            "", 
            "Voice recording stopped.",
            "🛑 Stopped."
        )

    # ----------------------------------------------------
    # 3. Speech Recognized → from voice-input.store.data
    # ----------------------------------------------------
    if trigger == "voice-input" and voice_data:
        # voice_data is Python dict already
        text = voice_data.get("text", "")

        if not text:
            raise PreventUpdate

        ai_response = call_llm(f"Voice command: {text}")

        return (
            text,                               # transcript
            ai_response,                        # LLM Response
            f"Processed voice input: {text}"    # status
        )

    raise PreventUpdate



#==============================================================
# IMPORT FEEDS (OPENVAS + ZAP + NMAP + BURP)
#==============================================================
from dash import ctx
from neo4j import GraphDatabase
import os

from cyber_range.services.openvas_ingest import OpenVASIngestor
from cyber_range.services.zap_ingest import ZAPIngestor
from cyber_range.services.nmap_ingest import NmapIngestor
from cyber_range.services.burp_ingest import BurpIngestor
from cyber_range.services.mitre_mapper import map_vulnerabilities_to_mitre


#==============================================================
# IMPORT FEEDS (OPENVAS + ZAP + NMAP + BURP)
#==============================================================
from dash import ctx
from dash.dependencies import Input, Output
from neo4j import GraphDatabase
import os

from cyber_range.services.openvas_ingest import OpenVASIngestor
from cyber_range.services.zap_ingest import ZAPIngestor
from cyber_range.services.nmap_ingest import NmapIngestor
from cyber_range.services.burp_ingest import BurpIngestor
from cyber_range.services.mitre_mapper import map_vulnerabilities_to_mitre


@app.callback(
    Output("import-output", "children"),
    Input("btn-import-openvas", "n_clicks"),
    Input("btn-import-zap", "n_clicks"),
    Input("btn-import-nmap", "n_clicks"),
    Input("btn-import-burp", "n_clicks"),
    prevent_initial_call=True
)
def import_feeds(openvas, zap, nmap, burp):
    try:
        trigger = ctx.triggered_id

        neo4j_password = os.getenv("NEO4J_PASSWORD")
        driver = GraphDatabase.driver(
            "bolt://127.0.0.1:7687",
            auth=("neo4j", neo4j_password)
        )

        # ---------------- OPENVAS ----------------
        if trigger == "btn-import-openvas":
            ing = OpenVASIngestor()

            # 1️⃣ Ingest OpenVAS
            report_id, count = ing.ingest_latest_report()

            # 2️⃣ MITRE mapping
            with driver.session() as session:
                map_vulnerabilities_to_mitre(session)

            # 3️⃣ Fetch verbose vulnerability list
            vuln_lines = ing.list_imported_vulnerabilities(limit=200)

            driver.close()

            # 4️⃣ Build verbose output
            output = [
                "✅ OpenVAS Import Successful\n",
                f"Report ID: {report_id}\n",
                f"Vulnerabilities Imported: {count}\n",
                "MITRE Techniques Linked\n",
                "\n--- Imported Vulnerabilities ---\n",
            ]

            for i, line in enumerate(vuln_lines, start=1):
                output.append(f"[{i}] {line}")

            return "\n".join(output)

        # ---------------- ZAP (IMPORT ONLY) ----------------
        elif trigger == "btn-import-zap":
            ing = ZAPIngestor()
            count = ing.ingest()  # import-only

            with driver.session() as session:
                map_vulnerabilities_to_mitre(session)

            driver.close()

            return (
                "✅ ZAP Import Successful\n\n"
                f"Vulnerabilities Imported: {count}\n"
                "MITRE Techniques Linked"
            )

        # ---------------- NMAP ----------------
        elif trigger == "btn-import-nmap":
            ing = NmapIngestor()
            stats, inventory, path = ing.ingest_latest()

            driver.close()

            output = (
                "✅ Nmap Import Successful\n\n"
                f"📄 Scan File:\n{path}\n\n"
                f"🖥️ Assets Discovered: {stats['assets']}\n"
                f"🔌 Services Identified: {stats['services']}\n\n"
                "=====================================\n"
                "📋 INVENTORY DETAILS\n"
                "=====================================\n"
            )

            for host in inventory:
                output += f"\n🖥️ {host['ip']}\n"

                if host["services"]:
                    output += "  🔌 Services:\n"
                    for s in host["services"]:
                        output += (
                            f"    - {s['name']} "
                            f"{s['protocol']}/{s['port']} "
                            f"{s.get('product','')} "
                            f"{s.get('version','')}\n"
                        )
                else:
                    output += "  🔌 Services: None\n"

                if host["vulnerabilities"]:
                    output += "  ⚠️ Vulnerabilities:\n"
                    for v in host["vulnerabilities"]:
                        output += (
                            f"    - {v['id']} | {v['name']} | "
                            f"{v['severity']} [{v.get('source')}]\n"
                        )
                else:
                    output += "  ⚠️ Vulnerabilities: None\n"

            return output

        # ---------------- BURP ----------------
        elif trigger == "btn-import-burp":
            ing = BurpIngestor()
            count = ing.ingest("/root/vuln_intel/app/uploads/burp.xml")

            with driver.session() as session:
                map_vulnerabilities_to_mitre(session)

            driver.close()

            return (
                "✅ Burp Import Successful\n\n"
                f"Vulnerabilities Imported: {count}\n"
                "MITRE Techniques Linked"
            )

        driver.close()
        return "⚠️ No import action detected."

    except Exception as e:
        return f"❌ Import Failed\n\n{str(e)}"

# app.py

from dash import Dash, html, dcc, Input, Output, State, callback
import dash_bootstrap_components as dbc
import traceback

# -------------------------------------------------
# Import ingestors ONLY (no executors)
# -------------------------------------------------
from cyber_range.services.nmap_ingest import NmapIngestor
from cyber_range.services.openvas_ingest import OpenVASIngestor
from cyber_range.services.zap_ingest import ZAPIngestor
from cyber_range.services.burp_ingest import BurpIngestor

# -------------------------------------------------
# App setup
# -------------------------------------------------



# ==================================================
# TAB: ASSESSMENT
# ==================================================

assessment_tab = dbc.Container(
    [
        html.H3("🧪 Vulnerability Assessment", className="text-warning"),
        html.P(
            "Select a scanner and run or ingest a single vulnerability assessment."
        ),
        html.Hr(),

        # -------------------------------------------------
        # Scanner Selection
        # -------------------------------------------------
        html.H5("🛠 Scanner Selection", className="text-warning"),
        dcc.Dropdown(
            id="scanner-select",
            options=[
                {"label": "Nmap — Network Discovery", "value": "nmap"},
                {"label": "OpenVAS — Vulnerability Scanner", "value": "openvas"},
                {"label": "OWASP ZAP — Web Application Scanner", "value": "zap"},
                {"label": "Burp Suite — Web Application Scanner", "value": "burp"},
            ],
            placeholder="Select a scanner…",
            clearable=False,
            style={"width": "50%"},
        ),

        html.Br(),

        # -------------------------------------------------
        # Target Input
        # -------------------------------------------------
        html.H5("🎯 Scan Targets", className="text-warning"),
        dcc.Textarea(
            id="target-input",
            placeholder=(
                "Enter targets (one per line)\n\n"
                "Examples:\n"
                "192.168.1.10\n"
                "10.0.0.0/24\n"
                "example.com\n"
                "https://app.example.com"
            ),
            style={
                "width": "70%",
                "height": "160px",
                "backgroundColor": "#111",
                "color": "#fff",
                "border": "1px solid #444",
                "fontFamily": "monospace",
            },
        ),

        html.Br(),
        html.Br(),

        # -------------------------------------------------
        # Action Buttons (NO gutter — DBC 2.0.4 compatible)
        # -------------------------------------------------
        dbc.Row(
            [
                dbc.Col(
                    dbc.Button(
                        "▶ Run Scan",
                        id="scan-btn",
                        color="warning",
                        n_clicks=0,
                    ),
                    width="auto",
                ),
                dbc.Col(
                    dbc.Button(
                        "⛔ Cancel Scan",
                        id="cancel-btn",
                        color="danger",
                        n_clicks=0,
                    ),
                    width="auto",
                ),
            ],
            className="g-3",  # Bootstrap spacing (safe replacement)
        ),

        html.Hr(),

        # -------------------------------------------------
        # Log Output
        # -------------------------------------------------
        html.H4("📜 Scan Log Output", className="text-warning"),
        html.Div(
            id="scan-log-output",
            children="Waiting for scan to start…",
            style={
                "whiteSpace": "pre-wrap",
                "backgroundColor": "#111",
                "color": "#0f0",
                "padding": "12px",
                "borderRadius": "5px",
                "minHeight": "200px",
                "fontFamily": "monospace",
                "border": "1px solid #333",
            },
        ),
    ],
    fluid=True,
)

####################################################
# CALLBACKS
###################################################

# ==================================================
# CALLBACK: RUN SCANNERS
# ==================================================

# ==================================================
# CALLBACK: RUN SCANNERS
# ==================================================
@callback(
    Output("scan-log-output", "children", allow_duplicate=True),
    Input("scan-btn", "n_clicks"),
    State("scanner-select", "value"),
    State("target-input", "value"),
    prevent_initial_call=True,
)
def run_scanner(n_clicks, scanner, targets):
    global scan_running, active_nmap_ingestor

    if not scanner:
        return "❌ No scanner selected."

    # Normalize targets
    target_list = []
    if targets:
        target_list = [t.strip() for t in targets.splitlines() if t.strip()]

    # =================================================
    # NMAP — LIVE / ASYNC
    # =================================================
    if scanner == "nmap":
        if not target_list:
            return "❌ Nmap requires at least one target."

        if scan_running:
            return "❌ A scan is already running."

        with scan_lock:
            scan_log_buffer.clear()
            scan_running = True
            scan_log_buffer.append("[*] Running Nmap scan...\n")

        def on_output(line):
            with scan_lock:
                scan_log_buffer.append(line)

        def on_complete(cancelled=False):
            global scan_running
            with scan_lock:
                scan_running = False
                if cancelled:
                    scan_log_buffer.append("\n[!] Nmap scan cancelled.\n")
                else:
                    scan_log_buffer.append("\n[✓] Nmap scan completed.\n")

        active_nmap_ingestor = NmapIngestor()
        active_nmap_ingestor.start_scan(
            targets=target_list,
            on_output=on_output,
            on_complete=on_complete,
        )

        return "".join(scan_log_buffer)

    # =================================================
    # OPENVAS — ACTIVE SCAN + INGEST
    # =================================================
    elif scanner == "openvas":
        if not target_list:
            return "❌ OpenVAS requires at least one target."

        log = ["[*] Starting OpenVAS scan..."]

        try:
            ingestor = OpenVASIngestor()
            report_id, count = ingestor.run_scan(target_list)

            log.append(
                f"[✓] OpenVAS scan completed — report {report_id} "
                f"({count} findings ingested)"
            )
            return "\n".join(log)

        except Exception as e:
            return (
                "❌ OpenVAS scan failed\n"
                f"{str(e)}\n\n"
                f"{traceback.format_exc()}"
            )

    # =================================================
    # ZAP — FULL SCAN (SPIDER + ACTIVE) + INGEST
    # =================================================
    elif scanner == "zap":
        if not target_list:
            return "❌ ZAP requires at least one URL target."

        log = ["[*] Starting ZAP scan..."]

        def progress(msg):
            log.append(msg)

        try:
            count = ZAPIngestor().run_scan(
                target_list[0],
                progress_cb=progress,
            )

            log.append(f"[✓] ZAP scan completed — {count} findings ingested")
            return "\n".join(log)

        except Exception as e:
            return (
                "❌ ZAP scan failed\n"
                f"{str(e)}\n\n"
                f"{traceback.format_exc()}"
            )

    # =================================================
    # BURP — FULL SCAN + INGEST (BLOCKING)
    # =================================================
    elif scanner == "burp":
        if not target_list:
            return "❌ Burp requires at least one web target."

        log = ["[*] Starting Burp scan..."]

        try:
            ingestor = BurpIngestor()

            # Burp supports ONE primary URL at a time
            target = target_list[0]

            log.append(f"[*] Target: {target}")
            log.append("[*] Launching active scan...")

            count = ingestor.run_scan_and_ingest(target)

            log.append("[✓] Burp scan completed")
            log.append(f"[✓] {count} findings ingested")

            return "\n".join(log)

        except Exception as e:
            return (
                "❌ Burp scan failed\n"
                f"{str(e)}\n\n"
                f"{traceback.format_exc()}"
            )



# Main
# -------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=9000,
        debug=True,
        use_reloader=False
    )
