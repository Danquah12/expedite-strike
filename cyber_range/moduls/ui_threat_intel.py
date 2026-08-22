"""
ui_threat_intel.py
Threat Intelligence Tab — IOC Search · Live Feeds · CVE Trending · Threat Actors · AI Analysis
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests
from dash import callback, dcc, html, Input, Output, State, ALL
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

# ── Styling constants ─────────────────────────────────────────────────────────
DARK_BG  = "#0d0d0d"
CARD_BG  = "#111317"
BORDER   = "1px solid #1e2230"
INPUT_STY = {
    "background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
    "borderRadius": "6px", "fontSize": "13px",
}
BTN_SM   = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL    = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
            "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}
SEV_COLOR = {"Critical": "#c0392b", "High": "#e67e22",
             "Medium":   "#f1c40f", "Low":  "#27ae60", "Info": "#2980b9"}

# ── In-memory cache ───────────────────────────────────────────────────────────
_CACHE: dict[str, Any] = {}
_LOCK  = threading.Lock()
_CACHE_TTL = 300   # seconds before feed refresh


def _cache_get(key: str) -> Any | None:
    with _LOCK:
        item = _CACHE.get(key)
        if item and time.time() - item["ts"] < _CACHE_TTL:
            return item["data"]
    return None


def _cache_set(key: str, data: Any):
    with _LOCK:
        _CACHE[key] = {"ts": time.time(), "data": data}


# ── Threat actor static profiles ──────────────────────────────────────────────
THREAT_ACTORS = {
    "APT28 (Fancy Bear)": {
        "nation": "Russia", "sector": "Government, Military, Aerospace",
        "ttps": ["Spearphishing (T1566)", "Credential Dumping (T1003)",
                 "Living off the Land (T1218)", "Lateral Tool Transfer (T1570)"],
        "tools": ["Mimikatz", "X-Agent", "Sofacy", "LoJax"],
        "iocs": ["185.220.101.0/24", "first-vds.net", "microsofit.com"],
        "mitre": "G0007",
    },
    "APT29 (Cozy Bear)": {
        "nation": "Russia", "sector": "Government, Think Tanks, Healthcare",
        "ttps": ["Supply Chain Compromise (T1195)", "OAuth Abuse (T1528)",
                 "Steganography C2 (T1001)", "WMI Execution (T1047)"],
        "tools": ["SUNBURST", "Cobalt Strike", "WellMail", "MiniDuke"],
        "iocs": ["avsvmcloud.com (SUNBURST C2)", "solarwinds.com (hijacked)"],
        "mitre": "G0016",
    },
    "Lazarus Group": {
        "nation": "North Korea", "sector": "Financial, Crypto, Defence",
        "ttps": ["Watering Hole (T1189)", "Fake Job Listings", "Crypto Theft",
                 "Supply Chain (T1195)", "RAT Deployment (T1105)"],
        "tools": ["HIDDEN COBRA", "AppleJeus", "BLINDINGCAN", "DTrack"],
        "iocs": ["185.62.190.0/24", "bigbiginter.net", "weinsteinfog.com"],
        "mitre": "G0032",
    },
    "Scattered Spider": {
        "nation": "Western (criminal)", "sector": "Hospitality, Telecom, Retail, Cloud",
        "ttps": ["SIM Swapping", "MFA Fatigue (T1621)", "Helpdesk Social Engineering",
                 "Identity Provider Abuse", "Azure AD Compromise"],
        "tools": ["Okta abuse", "Azure AD phishing", "AnyDesk RAT", "Crypto ransomware"],
        "iocs": ["scatter-spider-infra.net (known infra)", "1.1.1.1 (not IOC — placeholder)"],
        "mitre": "G1015",
    },
    "Black Basta": {
        "nation": "Russia-linked (criminal)", "sector": "Manufacturing, Healthcare, Legal",
        "ttps": ["QakBot dropper (T1204)", "Cobalt Strike beacon",
                 "AD recon & lateral move", "Double extortion ransomware"],
        "tools": ["QakBot", "Cobalt Strike", "Black Basta Ransomware", "ExMatter exfil"],
        "iocs": ["195.123.246.0/24", "qakbot-c2.net", "basta.news (leak site)"],
        "mitre": "G0135",
    },
    "Volt Typhoon": {
        "nation": "China", "sector": "Critical Infrastructure, Utilities, Military",
        "ttps": ["Living off the Land (T1218)", "SOHO Router Compromise",
                 "VPN Abuse (T1133)", "KV-Botnet C2"],
        "tools": ["Impacket", "FRP proxy", "built-in Windows tools only"],
        "iocs": ["SOHO router IPs (rotating)", "certutil.exe abuse"],
        "mitre": "G1017",
    },
}


# ── Feed fetch helpers ────────────────────────────────────────────────────────

def _safe_get(url: str, headers: dict | None = None,
              timeout: int = 8, **kw) -> requests.Response | None:
    try:
        return requests.get(url, headers=headers or {}, timeout=timeout,
                            verify=False, **kw)
    except Exception:
        return None


def _fetch_urlhaus() -> list[dict]:
    """URLhaus recent malicious URLs — no key required."""
    cached = _cache_get("urlhaus")
    if cached is not None:
        return cached
    r = _safe_get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/",
                  headers={"Content-Type": "application/json"}, timeout=10)
    if not r:
        return []
    try:
        data = r.json()
        rows = []
        for u in data.get("urls", [])[:50]:
            rows.append({
                "url":      u.get("url", ""),
                "host":     u.get("host", ""),
                "status":   u.get("url_status", ""),
                "tags":     ", ".join(u.get("tags") or []),
                "added":    u.get("date_added", "")[:10],
                "threat":   u.get("threat", ""),
            })
        _cache_set("urlhaus", rows)
        return rows
    except Exception:
        return []


def _fetch_feodotracker() -> list[dict]:
    """FeodoTracker C2 botnet IPs — no key required."""
    cached = _cache_get("feodo")
    if cached is not None:
        return cached
    r = _safe_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=10)
    if not r:
        return []
    try:
        data = r.json()
        rows = []
        for h in data[:50]:
            rows.append({
                "ip":       h.get("ip_address", ""),
                "port":     h.get("port", ""),
                "status":   h.get("status", ""),
                "malware":  h.get("malware", ""),
                "country":  h.get("country", ""),
                "added":    (h.get("first_seen") or "")[:10],
            })
        _cache_set("feodo", rows)
        return rows
    except Exception:
        return []


def _fetch_cisa_kev() -> list[dict]:
    """CISA Known Exploited Vulnerabilities catalog."""
    cached = _cache_get("cisa_kev")
    if cached is not None:
        return cached
    r = _safe_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                  timeout=12)
    if not r:
        return []
    try:
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        # Sort by dateAdded descending, take top 30
        vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        rows = []
        for v in vulns[:30]:
            rows.append({
                "cve":         v.get("cveID", ""),
                "vendor":      v.get("vendorProject", ""),
                "product":     v.get("product", ""),
                "desc":        v.get("shortDescription", "")[:80],
                "due_date":    v.get("dueDate", ""),
                "added":       v.get("dateAdded", ""),
            })
        _cache_set("cisa_kev", rows)
        return rows
    except Exception:
        return []


def _fetch_nvd_recent() -> list[dict]:
    """NVD recent CVEs with CVSS ≥ 8.0."""
    cached = _cache_get("nvd_recent")
    if cached is not None:
        return cached
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           "?cvssV3Severity=CRITICAL&resultsPerPage=20&startIndex=0")
    r = _safe_get(url, timeout=12)
    if not r:
        # fallback: HIGH severity
        url2 = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
                "?cvssV3Severity=HIGH&resultsPerPage=20&startIndex=0")
        r = _safe_get(url2, timeout=12)
    if not r:
        return []
    try:
        data = r.json()
        rows = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score = None
            severity = "Unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m_list = metrics.get(key, [])
                if m_list:
                    cvss_data = m_list[0].get("cvssData", {})
                    score     = cvss_data.get("baseScore")
                    severity  = cvss_data.get("baseSeverity", "Unknown")
                    break
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
            rows.append({
                "cve":       cve.get("id", ""),
                "score":     score,
                "severity":  severity,
                "desc":      desc[:100],
                "published": cve.get("published", "")[:10],
            })
        rows.sort(key=lambda r: r.get("score") or 0, reverse=True)
        _cache_set("nvd_recent", rows)
        return rows
    except Exception:
        return []


def _search_abuseipdb(ip: str) -> dict:
    """AbuseIPDB lookup — returns dict of intel."""
    key = os.environ.get("ABUSEIPDB_KEY", "")
    if not key:
        return {"error": "ABUSEIPDB_KEY not set — add to .env for live lookups"}
    r = _safe_get("https://api.abuseipdb.com/api/v2/check",
                  headers={"Key": key, "Accept": "application/json"},
                  params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""})
    if not r:
        return {"error": "Request failed"}
    try:
        d = r.json().get("data", {})
        return {
            "ip":           d.get("ipAddress", ip),
            "score":        d.get("abuseConfidenceScore", 0),
            "country":      d.get("countryCode", ""),
            "isp":          d.get("isp", ""),
            "usage_type":   d.get("usageType", ""),
            "reports":      d.get("totalReports", 0),
            "last_seen":    d.get("lastReportedAt", "")[:10] if d.get("lastReportedAt") else "",
            "categories":   d.get("reports", []),
            "is_tor":       d.get("isTor", False),
            "is_public":    d.get("isPublic", True),
        }
    except Exception as e:
        return {"error": str(e)}


def _search_otx(indicator: str) -> dict:
    """OTX AlienVault lookup"""
    key = os.environ.get("OTX_KEY", "")
    if not key:
        return {"error": "OTX_KEY not set — add to .env for live lookups"}
    # Detect type
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", indicator):
        itype = "IPv4"
    elif re.match(r"^[a-f0-9]{32,64}$", indicator, re.I):
        itype = "file"
    else:
        itype = "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{itype}/{indicator}/general"
    r = _safe_get(url, headers={"X-OTX-API-KEY": key}, timeout=10)
    if not r:
        return {"error": "OTX request failed"}
    try:
        d = r.json()
        return {
            "indicator":    indicator,
            "type":         itype,
            "pulse_count":  d.get("pulse_info", {}).get("count", 0),
            "pulses":       [p.get("name") for p in d.get("pulse_info", {}).get("pulses", [])[:5]],
            "tags":         d.get("tags", [])[:10],
            "country":      d.get("country_name", ""),
            "asn":          d.get("asn", ""),
            "reputation":   d.get("reputation", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def _score_to_severity(score: float | None) -> str:
    if score is None:
        return "Info"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


# ── UI helpers ────────────────────────────────────────────────────────────────

def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)


def _label(text: str):
    return html.Div(text, style=LABEL)


def _badge(text: str, severity: str = "Info"):
    color = SEV_COLOR.get(severity, "#636e72")
    return html.Span(text, style={
        "background": color, "color": "#fff" if severity in ("Critical", "High", "Info") else "#000",
        "fontSize": "10px", "fontWeight": "700", "borderRadius": "4px",
        "padding": "2px 6px", "marginRight": "4px",
    })


def _feed_table(headers: list[str], rows: list[list], max_rows: int = 25) -> html.Div:
    if not rows:
        return html.Div("No data — feed unavailable or cached.",
                        style={"color": "#636e72", "fontSize": "12px"})
    th_style = {"padding": "6px 10px", "color": "#8e9eb0", "fontSize": "11px",
                "textAlign": "left", "fontWeight": "600",
                "borderBottom": "1px solid #1e2230", "background": "#0d0d0d"}
    td_style = {"padding": "5px 10px", "color": "#b0b0b0", "fontSize": "11px",
                "borderBottom": "1px solid #111317", "maxWidth": "220px",
                "overflow": "hidden", "textOverflow": "ellipsis", "whiteSpace": "nowrap"}
    return html.Div(
        html.Table([
            html.Thead(html.Tr([html.Th(h, style=th_style) for h in headers])),
            html.Tbody([
                html.Tr([html.Td(str(cell)[:60], style=td_style) for cell in row])
                for row in rows[:max_rows]
            ]),
        ], style={"width": "100%", "borderCollapse": "collapse"}),
        style={"maxHeight": "320px", "overflowY": "auto"},
    )


# ── Main layout ───────────────────────────────────────────────────────────────

def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="ti-selected-ioc"),
        dcc.Store(id="ti-feed-data", data={}),
        dcc.Interval(id="ti-init", interval=60_000, n_intervals=0, max_intervals=1),

        # Header
        html.Div([
            html.H4("🌍 Threat Intelligence",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("IOC Search · Live Feeds · CISA KEV · CVE Trending · Threat Actors · AI Analysis",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "20px"}),

        # Stats bar
        html.Div(id="ti-stats-bar", style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left column: IOC Search + Actor Profiles ──────────────────
            dbc.Col([
                _card(
                    html.Div("🔍 IOC Search", style={"color": "#e0e0e0", "fontWeight": "600",
                                                      "marginBottom": "12px"}),
                    _label("Indicator (IP, Domain, URL, Hash)"),
                    dbc.Input(id="ti-ioc-input",
                              placeholder="e.g. 1.2.3.4 or evil.com or SHA256…",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Sources"),
                    dbc.Checklist(
                        id="ti-sources",
                        options=[
                            {"label": "AbuseIPDB", "value": "abuseipdb"},
                            {"label": "OTX AlienVault", "value": "otx"},
                            {"label": "URLhaus",     "value": "urlhaus"},
                            {"label": "FeodoTracker","value": "feodo"},
                        ],
                        value=["abuseipdb", "otx", "urlhaus", "feodo"],
                        style={"color": "#b0b0b0", "fontSize": "12px"},
                        inputStyle={"marginRight": "6px"},
                    ),
                    html.Div([
                        dbc.Button("🔍 Search", id="ti-search-btn",
                                   color="danger", size="sm",
                                   style={**BTN_SM, "width": "100%", "marginTop": "10px"}),
                    ]),
                    html.Div(id="ti-ioc-result",
                             style={"marginTop": "12px", "fontSize": "12px",
                                    "color": "#b0b0b0", "minHeight": "40px"}),
                ),

                _card(
                    html.Div("🎭 Threat Actor Profiles",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    _label("Select Actor"),
                    dbc.Select(
                        id="ti-actor-select",
                        options=[{"label": k, "value": k} for k in THREAT_ACTORS],
                        value=list(THREAT_ACTORS.keys())[0],
                        style={**INPUT_STY, "marginBottom": "8px"},
                    ),
                    html.Div(id="ti-actor-detail",
                             style={"fontSize": "12px", "color": "#b0b0b0",
                                    "minHeight": "80px"}),
                    dbc.Button("✨ AI Enrichment", id="ti-actor-ai-btn",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "marginTop": "8px", "width": "100%"}),
                    html.Div(id="ti-actor-ai-out",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "marginTop": "8px", "whiteSpace": "pre-wrap"}),
                ),
            ], width=3),

            # ── Centre column: Live Feeds ──────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="ti-feed-tabs", active_tab="tab-cisa", style={"marginBottom": "12px"},
                         children=[
                             dbc.Tab(label="🚨 CISA KEV",         tab_id="tab-cisa"),
                             dbc.Tab(label="📡 NVD Critical CVEs", tab_id="tab-nvd"),
                             dbc.Tab(label="🦠 URLhaus",           tab_id="tab-urlhaus"),
                             dbc.Tab(label="🤖 FeodoTracker C2",   tab_id="tab-feodo"),
                         ]),
                html.Div(id="ti-feed-content"),
            ], width=6),

            # ── Right column: AI analysis + export ────────────────────────
            dbc.Col([
                _card(
                    html.Div("🤖 AI Threat Analysis",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    html.Div("Select an IOC or click a finding, then:", 
                             style={"color":"#636e72","fontSize":"11px","marginBottom":"8px"}),
                    dbc.Button("✨ Analyse IOC with AI", id="ti-ioc-ai-btn",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%", "marginBottom": "8px"}),
                    dbc.Button("✨ Analyse Feed Item", id="ti-feed-ai-btn",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%", "marginBottom": "8px"}),
                    html.Div(id="ti-ai-output",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "minHeight": "120px", "whiteSpace": "pre-wrap",
                                    "marginTop": "8px"}),
                ),

                _card(
                    html.Div("📊 Feed Summary", style={"color": "#e0e0e0", "fontWeight": "600",
                                                        "marginBottom": "10px"}),
                    html.Div(id="ti-feed-summary",
                             style={"color": "#b0b0b0", "fontSize": "12px"}),
                ),

                _card(
                    html.Div("📤 Export", style={"color": "#e0e0e0", "fontWeight": "600",
                                                  "marginBottom": "10px"}),
                    dbc.Row([
                        dbc.Col(dbc.Button("⬇ JSON", id="ti-export-json",
                                           color="outline-secondary", size="sm",
                                           style=BTN_SM), width=6),
                        dbc.Col(dbc.Button("⬇ CSV",  id="ti-export-csv",
                                           color="outline-secondary", size="sm",
                                           style=BTN_SM), width=6),
                    ]),
                    dcc.Download(id="ti-download"),
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


# ── Callbacks ─────────────────────────────────────────────────────────────────

@callback(
    Output("ti-stats-bar", "children"),
    Input("ti-init", "n_intervals"),
)
def build_stats_bar(n):
    """Load feeds in background and show stats bar."""
    def _load():
        _fetch_urlhaus()
        _fetch_feodotracker()
        _fetch_cisa_kev()
        _fetch_nvd_recent()
    threading.Thread(target=_load, daemon=True).start()

    kev   = len(_fetch_cisa_kev())
    feodo = len(_fetch_feodotracker())
    uh    = len(_fetch_urlhaus())
    nvd   = len(_fetch_nvd_recent())

    def _stat(label, value, color="#e0e0e0"):
        return html.Div([
            html.Div(str(value), style={"fontSize": "24px", "fontWeight": "700",
                                         "color": color}),
            html.Div(label, style={"fontSize": "11px", "color": "#636e72"}),
        ], style={"background": CARD_BG, "border": BORDER, "borderRadius": "8px",
                  "padding": "12px 20px", "textAlign": "center"})

    return dbc.Row([
        dbc.Col(_stat("CISA KEV",      kev,   "#c0392b"), width=3),
        dbc.Col(_stat("C2 IPs (Feodo)",feodo, "#e67e22"), width=3),
        dbc.Col(_stat("Malicious URLs",uh,    "#f39c12"), width=3),
        dbc.Col(_stat("Critical CVEs", nvd,   "#9b59b6"), width=3),
    ])


@callback(
    Output("ti-feed-content", "children"),
    Input("ti-feed-tabs", "active_tab"),
)
def render_feed(tab):
    if tab == "tab-cisa":
        rows = _fetch_cisa_kev()
        data = [[r["cve"], r["vendor"], r["product"], r["desc"][:60], r["added"]]
                for r in rows]
        return _card(
            html.Div("🚨 CISA Known Exploited Vulnerabilities (latest 30)",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div(f"{len(rows)} vulnerabilities | Requires immediate patching per CISA BOD 22-01",
                     style={"color": "#636e72", "fontSize": "11px", "marginBottom": "8px"}),
            _feed_table(["CVE", "Vendor", "Product", "Description", "Added"], data),
        )
    elif tab == "tab-nvd":
        rows = _fetch_nvd_recent()
        data = [[r["cve"], r["score"], r["severity"], r["desc"][:70], r["published"]]
                for r in rows]
        return _card(
            html.Div("📡 NVD Critical CVEs (latest 20)",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            _feed_table(["CVE", "CVSS", "Severity", "Description", "Published"], data),
        )
    elif tab == "tab-urlhaus":
        rows = _fetch_urlhaus()
        data = [[r["host"], r["url"][:50], r["threat"], r["tags"], r["status"], r["added"]]
                for r in rows]
        return _card(
            html.Div("🦠 URLhaus — Active Malicious URLs",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div("Source: abuse.ch URLhaus | Updated every 5 min",
                     style={"color": "#636e72", "fontSize": "11px", "marginBottom": "8px"}),
            _feed_table(["Host", "URL", "Threat", "Tags", "Status", "Added"], data),
        )
    elif tab == "tab-feodo":
        rows = _fetch_feodotracker()
        data = [[r["ip"], r["port"], r["malware"], r["country"], r["status"], r["added"]]
                for r in rows]
        return _card(
            html.Div("🤖 FeodoTracker — Botnet C2 IPs",
                     style={"color": "#e0e0e0", "fontWeight": "600", "marginBottom": "10px"}),
            html.Div("Source: abuse.ch FeodoTracker | C2 infrastructure for Emotet, QakBot, etc.",
                     style={"color": "#636e72", "fontSize": "11px", "marginBottom": "8px"}),
            _feed_table(["IP", "Port", "Malware", "Country", "Status", "Added"], data),
        )
    return html.Div("Select a feed tab above.")


@callback(
    Output("ti-feed-summary", "children"),
    Input("ti-feed-tabs", "active_tab"),
)
def feed_summary(tab):
    lines = []
    kev_rows = _fetch_cisa_kev()
    if kev_rows:
        vendors = list({r["vendor"] for r in kev_rows})[:5]
        lines.append(f"🚨 CISA KEV: {len(kev_rows)} vulns, top vendors: {', '.join(vendors)}")
    feodo = _fetch_feodotracker()
    if feodo:
        malwares = list({r["malware"] for r in feodo})[:4]
        lines.append(f"🤖 Feodo: {len(feodo)} C2 IPs — {', '.join(malwares)}")
    uh = _fetch_urlhaus()
    if uh:
        threats = list({r["threat"] for r in uh if r["threat"]})[:4]
        lines.append(f"🦠 URLhaus: {len(uh)} URLs — {', '.join(threats)}")
    nvd = _fetch_nvd_recent()
    if nvd:
        lines.append(f"📡 NVD: {len(nvd)} Critical CVEs, top: {nvd[0]['cve']} (CVSS {nvd[0]['score']})")
    if not lines:
        return html.Div("Loading feeds…", style={"color": "#636e72", "fontSize": "12px"})
    return html.Div([html.Div(l, style={"marginBottom": "6px"}) for l in lines])


@callback(
    Output("ti-ioc-result",    "children"),
    Output("ti-selected-ioc",  "data"),
    Input("ti-search-btn",     "n_clicks"),
    State("ti-ioc-input",      "value"),
    State("ti-sources",        "value"),
    prevent_initial_call=True,
)
def search_ioc(n, indicator, sources):
    if not n or not indicator:
        raise PreventUpdate
    indicator = indicator.strip()
    results = []
    sources = sources or []

    # AbuseIPDB (IP only)
    if "abuseipdb" in sources and re.match(r"^\d+\.\d+\.\d+\.\d+$", indicator):
        d = _search_abuseipdb(indicator)
        if "error" in d:
            results.append(html.Div(f"AbuseIPDB: {d['error']}",
                                    style={"color": "#636e72", "fontSize": "11px"}))
        else:
            sev = "Critical" if d["score"] >= 80 else "High" if d["score"] >= 50 else \
                  "Medium" if d["score"] >= 20 else "Low"
            results += [
                html.Div([_badge("AbuseIPDB", sev),
                          html.Strong(f" {indicator}",
                                      style={"color": "#e0e0e0"})]),
                html.Div(f"Confidence: {d['score']}%  |  Country: {d['country']}  |  ISP: {d['isp']}",
                         style={"color": "#b0b0b0", "fontSize": "11px", "margin": "4px 0"}),
                html.Div(f"Reports: {d['reports']}  |  Last seen: {d['last_seen']}  |  TOR: {d['is_tor']}",
                         style={"color": "#b0b0b0", "fontSize": "11px", "marginBottom": "8px"}),
            ]

    # OTX
    if "otx" in sources:
        d = _search_otx(indicator)
        if "error" in d:
            results.append(html.Div(f"OTX: {d['error']}",
                                    style={"color": "#636e72", "fontSize": "11px"}))
        else:
            sev = "High" if d["pulse_count"] >= 5 else \
                  "Medium" if d["pulse_count"] >= 1 else "Info"
            results += [
                html.Div([_badge("OTX AlienVault", sev)]),
                html.Div(f"Pulses: {d['pulse_count']}  |  Type: {d['type']}  |  Country: {d['country']}",
                         style={"color": "#b0b0b0", "fontSize": "11px", "margin": "4px 0"}),
                html.Div("Pulse names: " + (", ".join(d["pulses"]) or "none"),
                         style={"color": "#b0b0b0", "fontSize": "11px", "marginBottom": "8px"}),
            ]

    # URLhaus local check
    if "urlhaus" in sources:
        uh_rows = _fetch_urlhaus()
        matches = [r for r in uh_rows if indicator in r.get("host", "") or
                   indicator in r.get("url", "")]
        if matches:
            results += [
                html.Div([_badge("URLhaus", "Critical")]),
                html.Div(f"{len(matches)} matching entries in URLhaus malicious URL feed",
                         style={"color": "#b0b0b0", "fontSize": "11px", "marginBottom": "8px"}),
            ]

    # FeodoTracker local check
    if "feodo" in sources:
        feodo_rows = _fetch_feodotracker()
        f_matches = [r for r in feodo_rows if indicator == r.get("ip", "")]
        if f_matches:
            fm = f_matches[0]
            results += [
                html.Div([_badge("FeodoTracker", "Critical")]),
                html.Div(f"C2 IP: {fm['ip']}  |  Malware: {fm['malware']}  |  Port: {fm['port']}",
                         style={"color": "#b0b0b0", "fontSize": "11px", "marginBottom": "8px"}),
            ]

    if not results:
        results = [html.Div("No threat intel found for this indicator — it may be clean.",
                            style={"color": "#27ae60", "fontSize": "12px"})]

    return html.Div(results), indicator


@callback(
    Output("ti-actor-detail", "children"),
    Input("ti-actor-select", "value"),
)
def show_actor(actor_name):
    if not actor_name or actor_name not in THREAT_ACTORS:
        raise PreventUpdate
    a = THREAT_ACTORS[actor_name]
    return html.Div([
        html.Div([
            html.Span("Nation: ", style={"color": "#8e9eb0", "fontWeight": "600"}),
            html.Span(a["nation"], style={"color": "#e0e0e0"}),
        ], style={"marginBottom": "4px"}),
        html.Div([
            html.Span("Targets: ", style={"color": "#8e9eb0", "fontWeight": "600"}),
            html.Span(a["sector"], style={"color": "#e0e0e0"}),
        ], style={"marginBottom": "4px"}),
        html.Div([
            html.Span("MITRE ID: ", style={"color": "#8e9eb0", "fontWeight": "600"}),
            html.Span(a["mitre"], style={"color": "#3498db"}),
        ], style={"marginBottom": "8px"}),
        html.Div("TTPs:", style={"color": "#8e9eb0", "fontWeight": "600", "fontSize": "11px"}),
        html.Ul([html.Li(t, style={"color": "#b0b0b0", "fontSize": "11px"})
                 for t in a["ttps"]], style={"paddingLeft": "16px", "margin": "4px 0 8px"}),
        html.Div("Tools:", style={"color": "#8e9eb0", "fontWeight": "600", "fontSize": "11px"}),
        html.Div(", ".join(a["tools"]),
                 style={"color": "#f39c12", "fontSize": "11px", "marginBottom": "8px"}),
        html.Div("Sample IOCs:", style={"color": "#8e9eb0", "fontWeight": "600", "fontSize": "11px"}),
        html.Div([html.Div(i, style={"color": "#c0392b", "fontSize": "10px",
                                     "fontFamily": "monospace"})
                  for i in a["iocs"]]),
    ])


@callback(
    Output("ti-actor-ai-out", "children"),
    Input("ti-actor-ai-btn", "n_clicks"),
    State("ti-actor-select",  "value"),
    prevent_initial_call=True,
)
def actor_ai(n, actor_name):
    if not n or not actor_name:
        raise PreventUpdate
    a = THREAT_ACTORS.get(actor_name, {})
    prompt = (
        f"You are a CTI (Cyber Threat Intelligence) analyst. Provide a detailed threat briefing for "
        f"{actor_name}.\n"
        f"Nation: {a.get('nation')}, Targets: {a.get('sector')}\n"
        f"Known TTPs: {', '.join(a.get('ttps', []))}\n"
        f"Known Tools: {', '.join(a.get('tools', []))}\n\n"
        f"Write a 3-paragraph threat briefing covering: 1) Motivation and objectives, "
        f"2) Current campaign activities and recent incidents, "
        f"3) Defensive recommendations for a SOC team."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


@callback(
    Output("ti-ai-output", "children"),
    Input("ti-ioc-ai-btn", "n_clicks"),
    State("ti-selected-ioc", "data"),
    prevent_initial_call=True,
)
def ioc_ai(n, ioc):
    if not n:
        raise PreventUpdate
    if not ioc:
        return "Search for an IOC first."
    prompt = (
        f"You are a senior threat intelligence analyst. Analyse this IOC: {ioc}\n\n"
        f"Provide: 1) Likely threat actor/campaign attribution, "
        f"2) Attack TTPs associated with this indicator, "
        f"3) Business risk and impact assessment, "
        f"4) Concrete defensive actions (block, monitor, hunt queries)."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


@callback(
    Output("ti-ai-output", "children", allow_duplicate=True),
    Input("ti-feed-ai-btn", "n_clicks"),
    State("ti-feed-tabs",   "active_tab"),
    prevent_initial_call=True,
)
def feed_ai(n, tab):
    if not n:
        raise PreventUpdate
    context = {
        "tab-cisa":    "CISA Known Exploited Vulnerabilities",
        "tab-nvd":     "NVD Critical CVEs",
        "tab-urlhaus": "URLhaus malicious URLs",
        "tab-feodo":   "FeodoTracker botnet C2 IPs",
    }.get(tab, "threat intelligence feed")

    # Pull a sample from the feed
    sample = ""
    if tab == "tab-cisa":
        rows = _fetch_cisa_kev()[:5]
        sample = "\n".join(f"{r['cve']} — {r['vendor']} {r['product']}: {r['desc']}" for r in rows)
    elif tab == "tab-nvd":
        rows = _fetch_nvd_recent()[:5]
        sample = "\n".join(f"{r['cve']} (CVSS {r['score']}): {r['desc']}" for r in rows)
    elif tab == "tab-urlhaus":
        rows = _fetch_urlhaus()[:5]
        sample = "\n".join(f"{r['host']} — {r['threat']} ({r['tags']})" for r in rows)
    elif tab == "tab-feodo":
        rows = _fetch_feodotracker()[:5]
        sample = "\n".join(f"{r['ip']}:{r['port']} — {r['malware']} ({r['country']})" for r in rows)

    prompt = (
        f"Analyse this {context} data:\n{sample}\n\n"
        f"Provide: 1) Key trends and patterns, 2) Most critical items requiring immediate action, "
        f"3) Recommended defensive mitigations for a SOC team."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


@callback(
    Output("ti-download", "data"),
    Input("ti-export-json", "n_clicks"),
    Input("ti-export-csv",  "n_clicks"),
    prevent_initial_call=True,
)
def export_ti(json_n, csv_n):
    from dash import ctx
    import csv as csv_mod, io
    if not ctx.triggered_id:
        raise PreventUpdate

    all_data = {
        "cisa_kev":     _fetch_cisa_kev(),
        "nvd_critical": _fetch_nvd_recent(),
        "urlhaus":      _fetch_urlhaus(),
        "feodotracker": _fetch_feodotracker(),
        "exported_at":  datetime.now(timezone.utc).isoformat(),
    }

    if ctx.triggered_id == "ti-export-json":
        return dcc.send_string(json.dumps(all_data, indent=2), "threat_intel.json")
    else:
        buf = io.StringIO()
        w = csv_mod.writer(buf)
        w.writerow(["source", "id", "description", "severity", "date"])
        for r in all_data["cisa_kev"]:
            w.writerow(["CISA KEV", r["cve"], r["desc"], "Critical", r["added"]])
        for r in all_data["nvd_critical"]:
            w.writerow(["NVD", r["cve"], r["desc"], r["severity"], r["published"]])
        for r in all_data["urlhaus"]:
            w.writerow(["URLhaus", r["host"], r["url"], r["threat"], r["added"]])
        for r in all_data["feodotracker"]:
            w.writerow(["Feodo", r["ip"], r["malware"], "Critical", r["added"]])
        return dcc.send_string(buf.getvalue(), "threat_intel.csv")
