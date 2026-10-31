"""
ui_forensics.py
Digital Forensics Tab — Disk Imaging · File System Analysis · Memory Forensics ·
Network Forensics · Timeline Analysis · Artifact Recovery · AI Case Reporting
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from datetime import datetime
from typing import Any

from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

# ── Styling ───────────────────────────────────────────────────────────────────
DARK_BG  = "#0d0d0d"
CARD_BG  = "#111317"
BORDER   = "1px solid #1e2230"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "6px", "fontSize": "13px"}
BTN_SM   = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL    = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
            "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}
MONO     = {"fontFamily": "monospace", "fontSize": "11px"}

# ── In-memory state ───────────────────────────────────────────────────────────
_CMD_OUTPUTS: dict[str, str] = {}
_FINDINGS:    list[dict]    = []
_LOCK = threading.Lock()


# ── Tool catalogue ────────────────────────────────────────────────────────────
TOOL_CATEGORIES = {
    "💾 Disk Imaging": [
        {"name": "dd",        "desc": "Raw disk image acquisition (built-in)", "open": True},
        {"name": "dc3dd",     "desc": "Forensic dd with hash verification",     "open": True},
        {"name": "ddrescue",  "desc": "Data recovery from failing media",        "open": True},
        {"name": "ewfacquire","desc": "Expert Witness Format (E01) imaging",     "open": True},
        {"name": "FTK Imager","desc": "GUI disk imaging & hash verification",    "open": False},
        {"name": "EnCase",    "desc": "Enterprise-grade evidence acquisition",   "open": False},
    ],
    "📁 File System": [
        {"name": "Autopsy",    "desc": "GUI forensic platform (open-source)",    "open": True},
        {"name": "TSK fls",    "desc": "List files in disk image",               "open": True},
        {"name": "TSK icat",   "desc": "Extract file by inode number",           "open": True},
        {"name": "TSK tsk_recover","desc": "Recover deleted files",              "open": True},
        {"name": "TSK mactime","desc": "Generate MAC timeline",                  "open": True},
        {"name": "foremost",   "desc": "File carving by header/footer",          "open": True},
        {"name": "scalpel",    "desc": "Fast file carving tool",                 "open": True},
        {"name": "PhotoRec",   "desc": "File recovery from disk images",         "open": True},
    ],
    "🧠 Memory Forensics": [
        {"name": "Volatility3", "desc": "Memory analysis framework (vol3)",      "open": True},
        {"name": "Volatility2", "desc": "Legacy memory analysis (vol2)",         "open": True},
        {"name": "LiME",        "desc": "Linux Memory Extractor (kernel module)","open": True},
        {"name": "winpmem",     "desc": "Windows memory acquisition",            "open": True},
        {"name": "Rekall",      "desc": "Memory forensic framework by Google",   "open": True},
    ],
    "🌐 Network Forensics": [
        {"name": "Wireshark",  "desc": "GUI packet analysis",                    "open": True},
        {"name": "tshark",     "desc": "CLI packet analysis",                    "open": True},
        {"name": "NetworkMiner","desc": "Passive network sniffer/analyzer",      "open": True},
        {"name": "ngrep",      "desc": "Network grep — pattern matching",        "open": True},
        {"name": "tcpdump",    "desc": "CLI packet capture",                     "open": True},
        {"name": "zeek",       "desc": "Network traffic analysis framework",     "open": True},
    ],
    "🔬 Artifact Analysis": [
        {"name": "bulk_extractor","desc": "Extract emails, URLs, credit cards", "open": True},
        {"name": "RegRipper",    "desc": "Windows registry artifact extraction", "open": True},
        {"name": "plaso",        "desc": "Timeline super-parser (log2timeline)","open": True},
        {"name": "Hindsight",    "desc": "Chrome/Chromium browser forensics",    "open": True},
        {"name": "KAPE",         "desc": "Kroll Artifact Parser and Extractor",  "open": False},
    ],
    "🔐 Crypto & Hash": [
        {"name": "hashdeep",  "desc": "Recursive hash computation/audit",        "open": True},
        {"name": "md5sum",    "desc": "MD5 file integrity check",                "open": True},
        {"name": "sha256sum", "desc": "SHA-256 file integrity check",            "open": True},
        {"name": "openssl",   "desc": "Decrypt/analyse encrypted evidence",      "open": True},
    ],
}


# ── UI helpers ────────────────────────────────────────────────────────────────
def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)


def _label(text):
    return html.Div(text, style=LABEL)


def _cmd_badge(cmd: str) -> html.Span:
    return html.Div(cmd, style={**MONO, "color": "#50fa7b",
                                "background": "#0d0d0d", "padding": "3px 8px",
                                "borderRadius": "4px", "marginBottom": "3px"})


def _tool_pill(name: str, open_src: bool) -> html.Span:
    color = "#27ae60" if open_src else "#e67e22"
    label_txt = "OSS" if open_src else "Commercial"
    return html.Div([
        html.Span(name, style={"color": "#e0e0e0", "fontSize": "12px",
                               "fontWeight": "600"}),
        html.Span(f" [{label_txt}]", style={"color": color, "fontSize": "10px"}),
    ], style={"padding": "4px 8px", "borderBottom": f"1px solid {DARK_BG}"})


def _finding_row(idx: int, f: dict) -> html.Div:
    sev_colors = {"Critical": "#c0392b", "High": "#e67e22",
                  "Medium": "#f1c40f", "Low": "#27ae60", "Info": "#3498db"}
    sev = f.get("severity", "Info")
    return html.Div([
        html.Span(f"[{sev}]", style={"color": sev_colors.get(sev, "#3498db"),
                                      "fontSize": "10px", "fontWeight": "700",
                                      "marginRight": "6px"}),
        html.Span(f.get("title", ""), style={"color": "#e0e0e0", "fontSize": "12px"}),
        html.Div(f.get("detail", ""), style={"color": "#8e9eb0", "fontSize": "10px",
                                              "marginLeft": "48px"}),
    ], style={"padding": "5px 8px", "borderBottom": f"1px solid {DARK_BG}"})


# ── Command builders ──────────────────────────────────────────────────────────
def _disk_imaging_cmds(evidence_path: str, case_dir: str) -> str:
    ep = evidence_path or "/dev/sdb"
    cd = case_dir or "/cases/case001"
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    return f"""# ── Disk Imaging Commands ─────────────────────────────────────────────
# 1. Basic dd imaging
sudo dd if={ep} of={cd}/image_{ts}.dd bs=512 conv=noerror,sync status=progress

# 2. dc3dd with hash verification (forensically sound)
sudo dc3dd if={ep} of={cd}/image_{ts}.dd hash=md5 hash=sha256 log={cd}/dc3dd_{ts}.log

# 3. ddrescue (for damaged media)
sudo ddrescue -d -r3 {ep} {cd}/image_{ts}.dd {cd}/mapfile.map

# 4. EWF format (EnCase compatible) with ewfacquire
sudo ewfacquire -t {cd}/image_{ts} {ep}

# 5. Verify image integrity
md5sum {cd}/image_{ts}.dd | tee {cd}/md5.txt
sha256sum {cd}/image_{ts}.dd | tee {cd}/sha256.txt

# 6. Mount image read-only for analysis
sudo mount -o ro,loop,noatime {cd}/image_{ts}.dd /mnt/evidence"""


def _filesystem_cmds(image_path: str, case_dir: str) -> str:
    ip = image_path or "/cases/case001/image.dd"
    cd = case_dir or "/cases/case001"
    return f"""# ── File System Analysis (Sleuth Kit) ────────────────────────────────
# 1. Identify partitions and file systems
mmls {ip}
fsstat -o OFFSET {ip}

# 2. List all files including deleted
fls -r -d -o OFFSET {ip} | tee {cd}/deleted_files.txt

# 3. List ALL files recursively (with inodes)
fls -r -l -o OFFSET {ip} | tee {cd}/all_files.txt

# 4. Recover deleted files
tsk_recover -e -o OFFSET {ip} {cd}/recovered/

# 5. Extract specific file by inode
icat -o OFFSET {ip} INODE_NUMBER > {cd}/extracted_file.bin

# 6. Generate MAC timeline
fls -r -m / -o OFFSET {ip} | tee {cd}/body.txt
mactime -b {cd}/body.txt -d > {cd}/timeline.csv

# 7. Search for keyword in image
sigfind -b 512 -t JPEG {ip}
blkls -o OFFSET {ip} | strings | grep -i "password"

# 8. File carving with foremost
foremost -t all -i {ip} -o {cd}/carved/

# 9. Scalpel carving (faster)
scalpel {ip} -o {cd}/scalpel_output/

# 10. Run Autopsy (GUI)
autopsy  # Then open http://localhost:9999"""


def _memory_cmds(mem_path: str, profile: str) -> str:
    mp = mem_path or "/cases/case001/memory.raw"
    pf = profile or "Win10x64_19041"
    return f"""# ── Memory Forensics (Volatility 3) ─────────────────────────────────
# 1. Acquire memory dump
# Windows: winpmem_mini_x86_rc2.exe /tmp/memory.raw
# Linux:   sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=raw"

# 2. Identify OS profile
vol3 -f {mp} windows.info
vol3 -f {mp} linux.bash

# 3. Process analysis
vol3 -f {mp} windows.pslist
vol3 -f {mp} windows.pstree
vol3 -f {mp} windows.cmdline

# 4. Malware hunting
vol3 -f {mp} windows.malfind          # Find injected code
vol3 -f {mp} windows.dlllist          # List DLLs per process
vol3 -f {mp} windows.handles          # Open handles
vol3 -f {mp} windows.netscan          # Network connections

# 5. Credential extraction
vol3 -f {mp} windows.hashdump         # Password hashes
vol3 -f {mp} windows.lsadump          # LSA secrets

# 6. Registry analysis
vol3 -f {mp} windows.registry.hivelist
vol3 -f {mp} windows.registry.printkey --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# 7. File extraction from memory
vol3 -f {mp} windows.filescan | tee /tmp/filescan.txt
vol3 -f {mp} windows.dumpfiles --physaddr ADDR -o /cases/case001/dumped/

# Volatility 2 (with profile)
vol2 --profile={pf} -f {mp} pslist
vol2 --profile={pf} -f {mp} malfind -D /cases/case001/malfind/"""


def _network_cmds(pcap_path: str) -> str:
    pp = pcap_path or "/cases/case001/capture.pcap"
    return f"""# ── Network Forensics ────────────────────────────────────────────────
# 1. Capture live traffic
sudo tcpdump -i eth0 -w {pp} -s 0
sudo tshark -i eth0 -w {pp}

# 2. Analyse PCAP
tshark -r {pp} -q -z conv,tcp         # TCP conversations
tshark -r {pp} -Y "http" -T fields -e http.host -e http.request.uri
tshark -r {pp} -Y "dns" -T fields -e dns.qry.name | sort | uniq
tshark -r {pp} -Y "smtp or pop or imap" -T text   # Email traffic

# 3. Extract files from PCAP
tshark -r {pp} --export-objects http,/cases/case001/http_objects/
tshark -r {pp} --export-objects smb,/cases/case001/smb_objects/

# 4. NetworkMiner (Linux via Mono)
mono NetworkMiner.exe {pp}

# 5. Detect suspicious patterns
tshark -r {pp} -Y "ip.flags.mf == 1"        # Fragmented packets
tshark -r {pp} -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \\
       -T fields -e ip.src | sort | uniq -c | sort -rn  # Port scan

# 6. Zeek analysis
zeek -r {pp} -C local
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | head -50

# 7. ngrep pattern search
ngrep -I {pp} -q "password|passwd|secret|token" tcp"""


def _artifact_cmds(case_dir: str, evidence_path: str) -> str:
    cd = case_dir or "/cases/case001"
    ep = evidence_path or "/mnt/evidence"
    return f"""# ── Artifact & Log Analysis ──────────────────────────────────────────
# 1. Bulk Extractor (emails, URLs, credit cards, phone numbers)
bulk_extractor -o {cd}/bulk_output/ -R {ep}
# Review: {cd}/bulk_output/email.txt, url.txt, ccn.txt

# 2. Windows Registry (RegRipper)
rip.pl -r {ep}/Windows/System32/config/SAM    -f sam    > {cd}/sam.txt
rip.pl -r {ep}/Windows/System32/config/SYSTEM  -f system > {cd}/system.txt
rip.pl -r {ep}/Windows/System32/config/SOFTWARE -f software > {cd}/software.txt
rip.pl -r {ep}/Users/USER/NTUSER.DAT -f ntuser > {cd}/ntuser.txt

# 3. Event logs
evtxdump.py {ep}/Windows/System32/winevt/Logs/Security.evtx | head -200
evtxdump.py {ep}/Windows/System32/winevt/Logs/System.evtx | \\
  grep -E "EventID|TimeCreated|Message" | head -100

# 4. Browser forensics (Chrome)
hindsight.py -i "{ep}/Users/USER/AppData/Local/Google/Chrome/User Data" -o {cd}/chrome/ -f sqlite

# 5. Prefetch files (execution evidence)
python3 prefetch_parser.py {ep}/Windows/Prefetch/ | sort -k2

# 6. LNK files (recently accessed)
lnkparse {ep}/Users/USER/AppData/Roaming/Microsoft/Windows/Recent/ -a | head -50

# 7. Timeline via plaso (log2timeline)
log2timeline.py {cd}/timeline.plaso {ep}
psort.py -z UTC -o l2tcsv {cd}/timeline.plaso "date > '2024-01-01 00:00:00'" > {cd}/timeline.csv

# 8. Linux artifacts
cat {ep}/etc/passwd
cat {ep}/etc/shadow
cat {ep}/var/log/auth.log | grep -E "Failed|Invalid|Accepted" | tail -50
cat {ep}/var/log/syslog | grep -E "cron|sudo|su" | tail -50
find {ep}/tmp {ep}/var/tmp -type f -newer /tmp/ref 2>/dev/null"""


# ── Phase tab content builders ────────────────────────────────────────────────

def _cmd_runner_card(phase_id: str, title: str, default_cmd: str,
                     extra_inputs=None):
    """Standard command runner card for each forensics phase."""
    return _card(
        html.Div(title, style={"color": "#e0e0e0", "fontWeight": "600",
                               "marginBottom": "10px"}),
        *(extra_inputs or []),
        _label("Command"),
        dbc.Textarea(id=f"for-{phase_id}-cmd", value=default_cmd,
                     style={**INPUT_STY, "height": "200px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "marginBottom": "8px"}),
        dbc.Row([
            dbc.Col(dbc.Button("▶ Execute", id=f"for-{phase_id}-run",
                               color="danger", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
            dbc.Col(dbc.Button("✨ AI Analyse", id=f"for-{phase_id}-ai",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
            dbc.Col(dbc.Button("📋 Add Finding", id=f"for-{phase_id}-find",
                               color="outline-warning", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
        ], style={"marginBottom": "8px"}),
        _label("Output"),
        dbc.Textarea(id=f"for-{phase_id}-output", value="", readOnly=True,
                     style={**INPUT_STY, "height": "180px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "color": "#50fa7b", "marginBottom": "6px"}),
        html.Div(id=f"for-{phase_id}-ai-out",
                 style={"color": "#b0b0b0", "fontSize": "12px",
                        "marginTop": "6px", "whiteSpace": "pre-wrap",
                        "maxHeight": "200px", "overflowY": "auto"}),
    )


# ── Main layout ───────────────────────────────────────────────────────────────
def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="for-case",    data={}),
        dcc.Store(id="for-findings",data=[]),

        # Header
        html.Div([
            html.H4("🔬 Digital Forensics Laboratory",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("Disk Imaging · File System · Memory · Network · Artifacts · AI Case Reporting",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left: Case Setup ─────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🗂️ Case Details", style={"color": "#e0e0e0",
                                                        "fontWeight": "600",
                                                        "marginBottom": "12px"}),
                    _label("Case Number"),
                    dbc.Input(id="for-case-num",
                              placeholder="e.g. CASE-2024-001",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Investigator"),
                    dbc.Input(id="for-investigator",
                              placeholder="Your name",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Case Directory"),
                    dbc.Input(id="for-case-dir",
                              placeholder="/cases/case001",
                              value="/cases/case001",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Evidence Path"),
                    dbc.Input(id="for-evidence-path",
                              placeholder="/dev/sdb or /cases/image.dd",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Memory Dump"),
                    dbc.Input(id="for-mem-path",
                              placeholder="/cases/case001/memory.raw",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("PCAP File"),
                    dbc.Input(id="for-pcap-path",
                              placeholder="/cases/case001/capture.pcap",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Volatility Profile"),
                    dbc.Input(id="for-vol-profile",
                              placeholder="Win10x64_19041",
                              value="Win10x64_19041",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("🔄 Update All Commands", id="for-update-cmds",
                               color="primary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "4px"}),
                    html.Div(id="for-case-status",
                             style={"color": "#636e72", "fontSize": "11px",
                                    "minHeight": "14px"}),
                ),

                _card(
                    html.Div("🛠️ Tool Reference", style={"color": "#e0e0e0",
                                                           "fontWeight": "600",
                                                           "marginBottom": "10px"}),
                    dbc.Select(
                        id="for-tool-cat",
                        options=[{"label": k, "value": k}
                                 for k in TOOL_CATEGORIES],
                        value=list(TOOL_CATEGORIES.keys())[0],
                        style={**INPUT_STY, "marginBottom": "8px"},
                    ),
                    html.Div(id="for-tool-list"),
                ),

                _card(
                    html.Div("📤 Export Case", style={"color": "#e0e0e0",
                                                       "fontWeight": "600",
                                                       "marginBottom": "10px"}),
                    dbc.Button("✨ Generate AI Report", id="for-ai-report-btn",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("📥 Export HTML Report", id="for-export-btn",
                               color="outline-secondary", size="sm",
                               style={**BTN_SM, "width": "100%"}),
                    dcc.Download(id="for-report-download"),
                ),
            ], width=3),

            # ── Centre: Phase tabs ───────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="for-tabs", active_tab="for-imaging",
                         style={"marginBottom": "12px"}, children=[
                     dbc.Tab(label="💾 Disk Imaging",   tab_id="for-imaging"),
                     dbc.Tab(label="📁 File System",    tab_id="for-filesystem"),
                     dbc.Tab(label="🧠 Memory",         tab_id="for-memory"),
                     dbc.Tab(label="🌐 Network",        tab_id="for-network"),
                     dbc.Tab(label="🔬 Artifacts",      tab_id="for-artifacts"),
                     dbc.Tab(label="📋 Findings",       tab_id="for-findings-tab"),
                 ]),
                html.Div(id="for-phase-content"),
            ], width=6),

            # ── Right: AI + Chain of Custody ────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🧠 AI Forensics Assistant",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    dbc.Row([
                        dbc.Col(dbc.Button("🕵 Malware Hunt", id="for-ai-malware",
                                           color="outline-danger", size="sm",
                                           style={**BTN_SM, "width": "100%",
                                                  "marginBottom": "6px"}), width=12),
                    ]),
                    dbc.Row([
                        dbc.Col(dbc.Button("📅 Timeline", id="for-ai-timeline",
                                           color="outline-warning", size="sm",
                                           style={**BTN_SM, "width": "100%",
                                                  "marginBottom": "6px"}), width=12),
                    ]),
                    dbc.Row([
                        dbc.Col(dbc.Button("👤 Attribution", id="for-ai-attrib",
                                           color="outline-info", size="sm",
                                           style={**BTN_SM, "width": "100%",
                                                  "marginBottom": "8px"}), width=12),
                    ]),
                    html.Div(id="for-ai-global-out",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "300px", "overflowY": "auto"}),
                ),

                _card(
                    html.Div("⛓️ Chain of Custody", style={"color": "#e0e0e0",
                                                              "fontWeight": "600",
                                                              "marginBottom": "10px"}),
                    html.Div(id="for-chain-panel",
                             children=[html.Div("Enter case details →",
                                                style={"color": "#636e72",
                                                       "fontSize": "12px"})]),
                ),

                _card(
                    html.Div("📋 Quick Ref — TSK", style={"color": "#e0e0e0",
                                                            "fontWeight": "600",
                                                            "marginBottom": "10px"}),
                    *[_cmd_badge(c) for c in [
                        "mmls image.dd",
                        "fsstat -o OFFSET image.dd",
                        "fls -r -d -o OFFSET image.dd",
                        "tsk_recover -e -o OFF image.dd out/",
                        "icat -o OFFSET image.dd INODE",
                        "blkstat -o OFFSET image.dd",
                        "vol3 -f mem.raw windows.pslist",
                        "vol3 -f mem.raw windows.malfind",
                        "foremost -i image.dd -o carved/",
                        "bulk_extractor -o out/ -R /evidence",
                    ]],
                ),
            ], width=3),
        ]),

        # AI Report modal area
        _card(
            html.Div("📄 AI Case Report", style={"color": "#e0e0e0",
                                                   "fontWeight": "600",
                                                   "marginBottom": "8px"}),
            html.Pre(id="for-ai-report-out",
                     style={"color": "#b0b0b0", "fontSize": "11px",
                            "whiteSpace": "pre-wrap", "maxHeight": "400px",
                            "overflowY": "auto", "minHeight": "50px"}),
        ),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


# ── Tool list renderer ────────────────────────────────────────────────────────

@callback(
    Output("for-tool-list", "children"),
    Input("for-tool-cat", "value"),
)
def render_tool_list(cat):
    tools = TOOL_CATEGORIES.get(cat, [])
    return html.Div([
        html.Div([
            _tool_pill(t["name"], t["open"]),
            html.Div(t["desc"], style={"color": "#636e72", "fontSize": "10px",
                                        "paddingLeft": "8px",
                                        "paddingBottom": "4px"}),
        ]) for t in tools
    ])


# ── Phase router ──────────────────────────────────────────────────────────────

@callback(
    Output("for-phase-content", "children"),
    Output("for-case-status",   "children"),
    Output("for-chain-panel",   "children"),
    Input("for-tabs",           "active_tab"),
    Input("for-update-cmds",    "n_clicks"),
    State("for-case-num",       "value"),
    State("for-investigator",   "value"),
    State("for-case-dir",       "value"),
    State("for-evidence-path",  "value"),
    State("for-mem-path",       "value"),
    State("for-pcap-path",      "value"),
    State("for-vol-profile",    "value"),
    State("for-findings",       "data"),
)
def render_phase(tab, upd_n, case_num, investigator, case_dir,
                 evidence_path, mem_path, pcap_path, vol_profile, findings):
    case_dir      = case_dir or "/cases/case001"
    evidence_path = evidence_path or "/dev/sdb"
    mem_path      = mem_path or "/cases/case001/memory.raw"
    pcap_path     = pcap_path or "/cases/case001/capture.pcap"
    vol_profile   = vol_profile or "Win10x64_19041"

    status = f"✅ Case {case_num or 'N/A'} | {datetime.now().strftime('%H:%M:%S')}" if upd_n else ""

    # Chain of custody panel
    ts_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chain = html.Div([
        html.Div(f"Case:        {case_num or '—'}",
                 style={**MONO, "color": "#e0e0e0", "fontSize": "11px"}),
        html.Div(f"Investigator: {investigator or '—'}",
                 style={**MONO, "color": "#b0b0b0", "fontSize": "11px"}),
        html.Div(f"Case Dir:    {case_dir}",
                 style={**MONO, "color": "#b0b0b0", "fontSize": "11px"}),
        html.Div(f"Evidence:    {evidence_path}",
                 style={**MONO, "color": "#b0b0b0", "fontSize": "11px"}),
        html.Div(f"Session:     {ts_now}",
                 style={**MONO, "color": "#636e72", "fontSize": "10px",
                        "marginTop": "6px"}),
        html.Div(f"Findings:    {len(findings or [])} recorded",
                 style={**MONO, "color": "#f39c12", "fontSize": "11px"}),
    ])

    if tab == "for-imaging":
        content = _cmd_runner_card(
            "imaging", "💾 Disk Acquisition",
            _disk_imaging_cmds(evidence_path, case_dir),
            extra_inputs=[
                dbc.Row([
                    dbc.Col([
                        _label("Source Device"),
                        dbc.Input(id="for-imaging-src",
                                  value=evidence_path,
                                  style={**INPUT_STY, "marginBottom": "8px"}),
                    ], width=6),
                    dbc.Col([
                        _label("Output Format"),
                        dbc.Select(id="for-imaging-fmt",
                                   options=[
                                       {"label": "Raw (dd)",    "value": "dd"},
                                       {"label": "EWF (E01)",   "value": "ewf"},
                                       {"label": "AFF4",        "value": "aff4"},
                                   ], value="dd",
                                   style={**INPUT_STY, "marginBottom": "8px"}),
                    ], width=6),
                ]),
            ]
        )

    elif tab == "for-filesystem":
        content = _cmd_runner_card(
            "filesystem", "📁 File System Analysis (TSK + Foremost)",
            _filesystem_cmds(evidence_path, case_dir),
        )

    elif tab == "for-memory":
        content = _cmd_runner_card(
            "memory", "🧠 Memory Forensics (Volatility 3)",
            _memory_cmds(mem_path, vol_profile),
            extra_inputs=[
                dbc.Row([
                    dbc.Col([
                        _label("Memory Image"),
                        dbc.Input(id="for-mem-img",
                                  value=mem_path,
                                  style={**INPUT_STY, "marginBottom": "8px"}),
                    ], width=6),
                    dbc.Col([
                        _label("Volatility Plugin"),
                        dbc.Select(id="for-vol-plugin",
                                   options=[
                                       {"label": "windows.pslist",   "value": "windows.pslist"},
                                       {"label": "windows.pstree",   "value": "windows.pstree"},
                                       {"label": "windows.malfind",  "value": "windows.malfind"},
                                       {"label": "windows.netscan",  "value": "windows.netscan"},
                                       {"label": "windows.hashdump", "value": "windows.hashdump"},
                                       {"label": "windows.cmdline",  "value": "windows.cmdline"},
                                       {"label": "windows.dlllist",  "value": "windows.dlllist"},
                                       {"label": "windows.handles",  "value": "windows.handles"},
                                       {"label": "linux.bash",       "value": "linux.bash"},
                                       {"label": "linux.pslist",     "value": "linux.pslist"},
                                   ], value="windows.pslist",
                                   style={**INPUT_STY, "marginBottom": "8px"}),
                    ], width=6),
                ]),
            ]
        )

    elif tab == "for-network":
        content = _cmd_runner_card(
            "network", "🌐 Network Forensics (tshark + Zeek)",
            _network_cmds(pcap_path),
        )

    elif tab == "for-artifacts":
        content = _cmd_runner_card(
            "artifacts", "🔬 Artifact & Log Analysis",
            _artifact_cmds(case_dir, "/mnt/evidence"),
        )

    elif tab == "for-findings-tab":
        findings = findings or []
        rows = [_finding_row(i, f) for i, f in enumerate(findings)]
        content = _card(
            html.Div(f"📋 {len(findings)} Forensic Findings",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div(rows or [html.Div("No findings recorded yet. Use '📋 Add Finding' "
                                        "in each analysis tab.",
                                        style={"color": "#636e72", "fontSize": "12px"})],
                     style={"maxHeight": "500px", "overflowY": "auto"}),
        )
    else:
        content = html.Div()

    return content, status, chain


# ── Command execution helper ──────────────────────────────────────────────────

def _run_bg(cmd: str, key: str):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        out = r.stdout + ("\n[STDERR]\n" + r.stderr if r.stderr else "")
    except subprocess.TimeoutExpired:
        out = "[TIMEOUT] Command timed out after 60 seconds"
    except Exception as e:
        out = f"[ERROR] {e}"
    with _LOCK:
        _CMD_OUTPUTS[key] = out


# ── Per-phase run + AI callbacks ──────────────────────────────────────────────

def _make_phase_callbacks(phase_id: str, phase_label: str):
    """Factory to create run + AI callbacks for each forensics phase."""

    @callback(
        Output(f"for-{phase_id}-output", "value"),
        Input(f"for-{phase_id}-run",  "n_clicks"),
        State(f"for-{phase_id}-cmd",  "value"),
        prevent_initial_call=True,
    )
    def run_phase(n, cmd, _phase=phase_id):
        if not n or not cmd:
            raise PreventUpdate
        threading.Thread(target=_run_bg, args=(cmd, _phase), daemon=True).start()
        time.sleep(4)
        with _LOCK:
            return _CMD_OUTPUTS.get(_phase, "[Running…]")

    run_phase.__name__ = f"run_{phase_id}"

    @callback(
        Output(f"for-{phase_id}-ai-out", "children"),
        Input(f"for-{phase_id}-ai",   "n_clicks"),
        State(f"for-{phase_id}-output","value"),
        State("for-case-num", "value"),
        prevent_initial_call=True,
    )
    def ai_phase(n, output, case_num, _label=phase_label):
        if not n:
            raise PreventUpdate
        prompt = (
            f"You are a digital forensics expert. Analyse this {_label} output "
            f"from case '{case_num or 'N/A'}':\n\n"
            f"{output or '(no output yet)'}\n\n"
            f"Provide:\n"
            f"1) **Key Findings** — what was discovered\n"
            f"2) **Indicators of Compromise** (IOCs) identified\n"
            f"3) **Artefacts of Interest** — specific files/processes/connections\n"
            f"4) **Next Investigative Steps** — what to do next\n"
            f"5) **Evidence to Preserve** — for chain of custody"
        )
        try:
            return call_llm(prompt)
        except Exception as e:
            return f"LLM error: {e}"

    ai_phase.__name__ = f"ai_{phase_id}"


# Register callbacks for all phases
for _pid, _plabel in [
    ("imaging",    "Disk Imaging"),
    ("filesystem", "File System Analysis"),
    ("memory",     "Memory Forensics"),
    ("network",    "Network Forensics"),
    ("artifacts",  "Artifact Analysis"),
]:
    _make_phase_callbacks(_pid, _plabel)


# ── Global AI callbacks ───────────────────────────────────────────────────────

@callback(
    Output("for-ai-global-out",  "children"),
    Input("for-ai-malware",      "n_clicks"),
    Input("for-ai-timeline",     "n_clicks"),
    Input("for-ai-attrib",       "n_clicks"),
    State("for-case-num",        "value"),
    State("for-findings",        "data"),
    prevent_initial_call=True,
)
def global_ai(mal_n, tl_n, att_n, case_num, findings):
    if not ctx.triggered_id:
        raise PreventUpdate
    findings = findings or []
    f_text = "\n".join(
        f"[{f.get('severity','?')}] {f.get('title','')} — {f.get('detail','')}"
        for f in findings[:10]
    )
    with _LOCK:
        all_outputs = "\n\n".join(
            f"[{k.upper()}]:\n{v[:500]}" for k, v in _CMD_OUTPUTS.items()
        )

    triggered = ctx.triggered_id
    if triggered == "for-ai-malware":
        prompt = (
            f"Digital Forensics — Malware Hunt Analysis\n"
            f"Case: {case_num or 'N/A'}\n\n"
            f"Tool outputs:\n{all_outputs}\n\n"
            f"Findings:\n{f_text}\n\n"
            f"Identify:\n"
            f"1) **Malware Indicators** (processes, DLLs, registry keys, network IOCs)\n"
            f"2) **Persistence Mechanisms** found\n"
            f"3) **Lateral Movement Evidence**\n"
            f"4) **Data Exfiltration Indicators**\n"
            f"5) **Malware Family** (if identifiable from patterns)"
        )
    elif triggered == "for-ai-timeline":
        prompt = (
            f"Digital Forensics — Timeline Reconstruction\n"
            f"Case: {case_num or 'N/A'}\n\n"
            f"Tool outputs:\n{all_outputs}\n\n"
            f"Reconstruct:\n"
            f"1) **Chronological attack timeline** with timestamps\n"
            f"2) **Initial access vector** and earliest evidence\n"
            f"3) **Key events** in order (execution, persistence, lateral movement)\n"
            f"4) **Data theft timeline** if applicable\n"
            f"5) **Gaps in evidence** that need further investigation"
        )
    else:  # attribution
        prompt = (
            f"Digital Forensics — Threat Actor Attribution\n"
            f"Case: {case_num or 'N/A'}\n\n"
            f"Tool outputs:\n{all_outputs}\n\n"
            f"Assess:\n"
            f"1) **Threat Actor Profile** — skill level, tooling, motivation\n"
            f"2) **TTPs** (MITRE ATT&CK techniques observed)\n"
            f"3) **Attribution Indicators** — language, timezone, code style\n"
            f"4) **Known Group Similarities** — APT/criminal group matches\n"
            f"5) **Confidence Level** and evidence quality"
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ── Full AI case report ───────────────────────────────────────────────────────

@callback(
    Output("for-ai-report-out",  "children"),
    Input("for-ai-report-btn",   "n_clicks"),
    State("for-case-num",        "value"),
    State("for-investigator",    "value"),
    State("for-case-dir",        "value"),
    State("for-evidence-path",   "value"),
    State("for-findings",        "data"),
    prevent_initial_call=True,
)
def generate_report(n, case_num, investigator, case_dir, evidence_path, findings):
    if not n:
        raise PreventUpdate
    findings = findings or []
    f_text = "\n".join(
        f"[{f.get('severity','?')}] {f.get('title','')} — {f.get('detail','')}"
        for f in findings
    )
    with _LOCK:
        all_outputs = "\n\n".join(
            f"[{k.upper()}]:\n{v[:400]}" for k, v in _CMD_OUTPUTS.items()
        )
    prompt = (
        f"Write a professional digital forensics case report.\n\n"
        f"Case Number: {case_num or 'N/A'}\n"
        f"Investigator: {investigator or 'N/A'}\n"
        f"Case Directory: {case_dir or 'N/A'}\n"
        f"Evidence: {evidence_path or 'N/A'}\n"
        f"Date: {datetime.now().strftime('%Y-%m-%d')}\n\n"
        f"Forensic Findings ({len(findings)} recorded):\n{f_text}\n\n"
        f"Tool Output Summaries:\n{all_outputs}\n\n"
        f"Write a complete forensic report including:\n"
        f"1. Executive Summary\n"
        f"2. Case Background\n"
        f"3. Evidence Acquired (with chain of custody)\n"
        f"4. Methodology\n"
        f"5. Findings (categorised by severity)\n"
        f"6. Indicators of Compromise\n"
        f"7. Timeline of Events\n"
        f"8. Attribution (if possible)\n"
        f"9. Recommendations\n"
        f"10. Conclusion\n\n"
        f"Format as professional markdown. Include NIST references where applicable."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ── HTML export ───────────────────────────────────────────────────────────────

@callback(
    Output("for-report-download", "data"),
    Input("for-export-btn",       "n_clicks"),
    State("for-ai-report-out",    "children"),
    State("for-case-num",         "value"),
    State("for-investigator",     "value"),
    prevent_initial_call=True,
)
def export_report(n, report_text, case_num, investigator):
    if not n or not report_text:
        raise PreventUpdate
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    html_content = f"""<!DOCTYPE html>
<html><head>
<meta charset='utf-8'>
<title>Forensics Report — {case_num or 'Case'}</title>
<style>
  body{{font-family:Arial,sans-serif;background:#0d1117;color:#e0e0e0;
       max-width:960px;margin:40px auto;padding:0 20px;}}
  h1,h2,h3{{color:#f39c12;}} h4{{color:#3498db;}}
  pre{{background:#161b22;padding:12px;border-radius:6px;
       color:#50fa7b;font-size:12px;white-space:pre-wrap;overflow-x:auto;}}
  table{{border-collapse:collapse;width:100%;margin:16px 0;}}
  th{{background:#2c3347;color:#e0e0e0;padding:8px;text-align:left;}}
  td{{padding:6px 8px;border-bottom:1px solid #2c3347;color:#b0b0b0;}}
  .header{{background:#161b22;border:1px solid #30363d;border-radius:8px;
           padding:16px;margin-bottom:24px;}}
</style>
</head><body>
<div class='header'>
  <h1>🔬 Digital Forensics Case Report</h1>
  <table>
    <tr><td><b>Case Number</b></td><td>{case_num or '—'}</td></tr>
    <tr><td><b>Investigator</b></td><td>{investigator or '—'}</td></tr>
    <tr><td><b>Report Date</b></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M')}</td></tr>
  </table>
</div>
<pre>{report_text}</pre>
<hr>
<p style='color:#636e72;font-size:11px;'>
  Generated by Vulnerability Intelligence Dashboard — Digital Forensics Module
</p>
</body></html>"""
    return dcc.send_string(html_content, f"forensics_report_{case_num or 'case'}_{ts}.html")
