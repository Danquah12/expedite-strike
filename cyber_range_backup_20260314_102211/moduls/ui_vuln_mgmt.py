"""
ui_vuln_mgmt.py
Vulnerability Management Dashboard
CISA KEV · NVD CVE Search · EPSS Scores · Asset Inventory ·
Patch SLA Tracking · AI Risk Prioritization · Export
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any

import requests
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from dash import callback, dcc, html, Input, Output, State, ctx, dash_table
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None  # type: ignore[misc]

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

_log = logging.getLogger("ui_vuln_mgmt")

# ── Neo4j persistence ─────────────────────────────────────────────────────────
NEO4J_URI  = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


def _get_neo4j_driver():
    """Return a short-lived Neo4j driver (caller must close)."""
    if GraphDatabase is None:
        return None
    try:
        return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    except Exception as exc:
        _log.warning("Neo4j driver creation failed: %s", exc)
        return None


# ── Neo4j CRUD helpers ────────────────────────────────────────────────────────
def _save_asset_neo4j(asset: dict) -> bool:
    """MERGE an asset node by name."""
    driver = _get_neo4j_driver()
    if not driver:
        return False
    try:
        with driver.session() as s:
            s.run(
                "MERGE (a:VmAsset {name: $name}) "
                "SET a.type = $type, a.criticality = $crit, "
                "    a.added_date = $added, a.vuln_count = $vc",
                name=asset["name"], type=asset["type"],
                crit=asset["crit"], added=asset.get("added", ""),
                vc=asset.get("vuln_count", 0),
            )
        return True
    except Exception as exc:
        _log.warning("_save_asset_neo4j: %s", exc)
        return False
    finally:
        driver.close()


def _load_assets_neo4j() -> list[dict]:
    """Load all VmAsset nodes."""
    driver = _get_neo4j_driver()
    if not driver:
        return []
    try:
        with driver.session() as s:
            rows = s.run(
                "MATCH (a:VmAsset) RETURN a.name AS name, a.type AS type, "
                "a.criticality AS crit, a.added_date AS added, "
                "a.vuln_count AS vuln_count ORDER BY a.added_date DESC"
            ).data()
        return [
            {"id": i, "name": r["name"], "type": r["type"] or "server",
             "crit": r["crit"] or "medium", "added": r["added"] or "",
             "vuln_count": r.get("vuln_count") or 0}
            for i, r in enumerate(rows)
        ]
    except Exception as exc:
        _log.warning("_load_assets_neo4j: %s", exc)
        return []
    finally:
        driver.close()


def _delete_asset_neo4j(name: str) -> bool:
    driver = _get_neo4j_driver()
    if not driver:
        return False
    try:
        with driver.session() as s:
            s.run(
                "MATCH (a:VmAsset {name: $name}) "
                "OPTIONAL MATCH (v:VmVulnerability)-[:ASSIGNED_TO]->(a) "
                "DETACH DELETE a, v",
                name=name,
            )
        return True
    except Exception as exc:
        _log.warning("_delete_asset_neo4j: %s", exc)
        return False
    finally:
        driver.close()


def _save_vuln_assignment_neo4j(vuln: dict) -> bool:
    """Create VmVulnerability node + ASSIGNED_TO relationship."""
    driver = _get_neo4j_driver()
    if not driver:
        return False
    try:
        with driver.session() as s:
            s.run(
                "MATCH (a:VmAsset {name: $asset}) "
                "MERGE (v:VmVulnerability {cve_id: $cve, asset_name: $asset}) "
                "SET v.severity = $sev, v.score = $score, "
                "    v.description = $desc, v.assigned_date = $ad "
                "MERGE (v)-[:ASSIGNED_TO]->(a)",
                asset=vuln["asset"], cve=vuln["id"],
                sev=vuln.get("severity", "UNKNOWN"),
                score=vuln.get("score", ""),
                desc=vuln.get("description", "")[:300],
                ad=vuln.get("assigned_date", datetime.now().isoformat()),
            )
        return True
    except Exception as exc:
        _log.warning("_save_vuln_assignment_neo4j: %s", exc)
        return False
    finally:
        driver.close()


def _load_vuln_assignments_neo4j() -> list[dict]:
    driver = _get_neo4j_driver()
    if not driver:
        return []
    try:
        with driver.session() as s:
            rows = s.run(
                "MATCH (v:VmVulnerability)-[:ASSIGNED_TO]->(a:VmAsset) "
                "RETURN v.cve_id AS id, v.severity AS severity, "
                "v.score AS score, v.description AS description, "
                "a.name AS asset, v.assigned_date AS assigned_date "
                "ORDER BY v.assigned_date DESC"
            ).data()
        return [dict(r) for r in rows]
    except Exception as exc:
        _log.warning("_load_vuln_assignments_neo4j: %s", exc)
        return []
    finally:
        driver.close()


def _update_asset_vuln_count_neo4j(asset_name: str):
    """Recount VmVulnerability nodes for an asset and update the counter."""
    driver = _get_neo4j_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                "MATCH (a:VmAsset {name: $name}) "
                "OPTIONAL MATCH (v:VmVulnerability)-[:ASSIGNED_TO]->(a) "
                "WITH a, count(v) AS cnt SET a.vuln_count = cnt",
                name=asset_name,
            )
    except Exception as exc:
        _log.warning("_update_asset_vuln_count_neo4j: %s", exc)
    finally:
        driver.close()

# ── Design tokens (Wiz-inspired dark) ────────────────────────────────────────
DARK_BG    = "#0b0f19"
CARD_BG    = "#0f1522"
PANEL_ALT  = "#131c2e"
BORDER     = "1px solid #1b2236"
INPUT_STY  = {
    "background": "#131c2e", "border": "1px solid #1e2a40",
    "color": "#d0d8e8", "borderRadius": "7px", "fontSize": "13px",
}
BTN_SM     = {"borderRadius": "7px", "fontSize": "12px", "padding": "5px 12px",
              "fontWeight": "600"}
LABEL      = {
    "color": "#4a5a78", "fontSize": "10px", "marginBottom": "3px",
    "fontWeight": "700", "textTransform": "uppercase", "letterSpacing": "0.8px",
}

SEV_COLORS = {
    "CRITICAL": "#e84040", "HIGH": "#f07b29",
    "MEDIUM":   "#f5c842", "LOW":  "#29b87a",
    "NONE":     "#3b9de8", "UNKNOWN": "#4a5a78",
}
SEV_BG = {
    "CRITICAL": "#2a0c0c", "HIGH": "#2a1500",
    "MEDIUM":   "#2a2100", "LOW":  "#0c2218",
    "NONE":     "#0c1e2a", "UNKNOWN": "#151f30",
}
SLA_DAYS = {"CRITICAL": 1, "HIGH": 7, "MEDIUM": 30, "LOW": 90}

# ── In-memory stores ──────────────────────────────────────────────────────────
_KEV_CACHE:   list[dict] = []
_CVE_RESULTS: list[dict] = []
_ASSETS:      list[dict] = []
_VULNS:       list[dict] = []   # assigned CVEs
_LOCK = threading.Lock()

# ── UI helpers ────────────────────────────────────────────────────────────────
def _card(*children, style=None, title=None):
    """Wiz-style glassmorphic dark card."""
    base = {
        "background": CARD_BG, "border": BORDER, "borderRadius": "12px",
        "padding": "16px 18px", "marginBottom": "12px",
        "boxShadow": "0 2px 16px rgba(0,0,0,0.4)",
    }
    if style:
        base.update(style)
    header = []
    if title:
        header = [html.Div(title, style={
            "color": "#8a9cc0", "fontSize": "10px", "fontWeight": "700",
            "textTransform": "uppercase", "letterSpacing": "1px",
            "marginBottom": "12px",
        })]
    return html.Div(header + list(children), style=base)


def _label(t):
    return html.Div(t, style=LABEL)


def _pill_badge(text, color, bg):
    """Small rounded pill badge (Wiz style)."""
    return html.Span(text, style={
        "background": bg, "color": color,
        "fontSize": "9px", "fontWeight": "700",
        "padding": "2px 7px", "borderRadius": "10px",
        "marginRight": "5px", "letterSpacing": "0.3px",
        "border": f"1px solid {color}44",
    })


def _sev_chip(sev: str):
    """Severity coloured label chip."""
    up = sev.upper()
    c  = SEV_COLORS.get(up, "#4a5a78")
    bg = SEV_BG.get(up, "#151f30")
    return _pill_badge(up, c, bg)


def _wiz_sev_block(label: str, count: int, color: str, sub: str = ""):
    """Wiz-style severity summary block with left accent border."""
    return html.Div([
        html.Div(str(count), style={
            "color": color, "fontSize": "32px", "fontWeight": "800",
            "lineHeight": "1", "fontFamily": "monospace",
        }),
        html.Div(label, style={
            "color": "#8a9cc0", "fontSize": "11px", "fontWeight": "600",
            "marginTop": "3px",
        }),
        html.Div(sub, style={"color": "#3a4a60", "fontSize": "10px"}) if sub else html.Span(),
    ], className="vm-sev-bar", style={
        "background": CARD_BG,
        "borderLeft": f"3px solid {color}",
        "borderRadius": "0 10px 10px 0",
        "padding": "14px 18px",
        "flex": "1", "minWidth": "100px",
        "boxShadow": "0 2px 12px rgba(0,0,0,0.35)",
    })


def _sev_badge(sev: str) -> html.Span:
    return _sev_chip(sev)


def _stat_card(label: str, value: str, color: str, sub: str = "") -> html.Div:
    """Maps to _wiz_sev_block for backward compat with callback."""
    return _wiz_sev_block(label, int(value) if str(value).isdigit() else value, color, sub)


def _sla_bar(sev: str, assigned_date_str: str) -> html.Div:
    """Visual SLA countdown bar."""
    sev_up  = sev.upper()
    days    = SLA_DAYS.get(sev_up, 90)
    color   = SEV_COLORS.get(sev_up, "#636e72")
    try:
        assigned = datetime.fromisoformat(assigned_date_str)
        elapsed  = (datetime.now() - assigned).days
        pct      = min(100, int(elapsed / days * 100))
        remaining = max(0, days - elapsed)
    except Exception:
        pct, remaining = 0, days
    bar_color = "#c0392b" if pct >= 100 else ("#e67e22" if pct >= 75 else color)
    return html.Div([
        html.Div(f"SLA: {remaining}d left of {days}d",
                 style={"color": "#8e9eb0", "fontSize": "10px",
                        "marginBottom": "2px"}),
        html.Div(html.Div(style={
            "width": f"{pct}%", "height": "4px",
            "background": bar_color, "borderRadius": "2px",
            "transition": "width 0.3s",
        }), style={"background": "#1e2230", "borderRadius": "2px",
                   "height": "4px"}),
    ])


# ── CISA KEV fetcher ──────────────────────────────────────────────────────────
def _fetch_kev() -> list[dict]:
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=20, headers={"User-Agent": "VulnMgmt-Dashboard/1.0"}
        )
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            return sorted(vulns,
                          key=lambda v: v.get("dateAdded", ""),
                          reverse=True)
    except Exception:
        pass
    return []


# ── NVD CVE search ────────────────────────────────────────────────────────────
def _search_nvd(query: str, severity: str = "", limit: int = 20) -> list[dict]:
    """Search NVD API v2 — free, no key needed (rate limited to 5 req/30s)."""
    params: dict[str, Any] = {"resultsPerPage": limit, "startIndex": 0}
    if query.upper().startswith("CVE-"):
        params["cveId"] = query.upper()
    elif query:
        params["keywordSearch"] = query
    if severity and severity != "ALL":
        params["cvssV3Severity"] = severity.upper()
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=20,
            headers={"User-Agent": "VulnMgmt-Dashboard/1.0"}
        )
        if r.status_code == 200:
            items = r.json().get("vulnerabilities", [])
            results = []
            for item in items:
                cve = item.get("cve", {})
                cve_id  = cve.get("id", "")
                desc    = next((d["value"] for d in cve.get("descriptions", [])
                                if d["lang"] == "en"), "No description")
                metrics = cve.get("metrics", {})
                cvss_v3 = (metrics.get("cvssMetricV31") or
                           metrics.get("cvssMetricV30") or [])
                cvss_score = ""
                cvss_sev   = "UNKNOWN"
                if cvss_v3:
                    cvss_data  = cvss_v3[0].get("cvssData", {})
                    cvss_score = str(cvss_data.get("baseScore", ""))
                    cvss_sev   = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                published = cve.get("published", "")[:10]
                refs = [r2.get("url", "") for r2 in cve.get("references", [])[:3]]
                results.append({
                    "id": cve_id, "description": desc[:300],
                    "score": cvss_score, "severity": cvss_sev,
                    "published": published, "refs": refs,
                })
            return results
    except Exception:
        pass
    return []


# ── EPSS score fetcher ────────────────────────────────────────────────────────
def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS exploit probability scores (free, no key)."""
    if not cve_ids:
        return {}
    ids_str = ",".join(cve_ids[:100])
    try:
        r = requests.get(
            f"https://api.first.org/data/v1/epss?cve={ids_str}",
            timeout=15, headers={"User-Agent": "VulnMgmt-Dashboard/1.0"}
        )
        if r.status_code == 200:
            return {d["cve"]: float(d.get("epss", 0))
                    for d in r.json().get("data", [])}
    except Exception:
        pass
    return {}


# ── Wiz-style vuln row ────────────────────────────────────────────────────────
def _vuln_row(v: dict, in_kev: set[str], epss: dict[str, float]) -> html.Div:
    """Wiz-style CVE row card."""
    cve_id = v.get("id", "")
    sev    = v.get("severity", "UNKNOWN")
    score  = v.get("score", "—")
    epss_p = epss.get(cve_id, None)
    kev    = cve_id in in_kev
    color  = SEV_COLORS.get(sev.upper(), "#4a5a78")
    bg     = SEV_BG.get(sev.upper(), "#151f30")
    return html.Div([
        html.Div([
            # Left severity strip
            html.Div(style={
                "width": "3px", "alignSelf": "stretch",
                "background": color, "borderRadius": "2px",
                "marginRight": "12px", "flexShrink": "0",
            }),
            # Content
            html.Div([
                # Top row
                html.Div([
                    html.Span(sev, style={
                        "color": color, "fontSize": "9px", "fontWeight": "800",
                        "marginRight": "8px", "letterSpacing": "1px",
                    }),
                    html.Span(cve_id, style={
                        "color": "#5baef5", "fontWeight": "700",
                        "fontSize": "13px", "marginRight": "10px",
                        "fontFamily": "monospace",
                    }),
                    html.Span(f"CVSS {score}", style={
                        "color": "#8a9cc0", "fontSize": "11px",
                        "marginRight": "10px", "fontFamily": "monospace",
                    }),
                    _pill_badge("⚡ KEV", "#e84040", "#2d0a0a") if kev else html.Span(),
                    _pill_badge(f"EPSS {epss_p:.0%}", "#a855f7", "#1e0a2d") if epss_p else html.Span(),
                ], style={"display": "flex", "alignItems": "center",
                          "flexWrap": "wrap", "gap": "2px"}),
                # Description
                html.Div(v.get("description", "")[:200] + "…",
                         style={"color": "#5a6a8a", "fontSize": "11px",
                                "marginTop": "5px", "lineHeight": "1.5"}),
                # Footer
                html.Div(f"Published {v.get('published', '')}",
                         style={"color": "#2a3a55", "fontSize": "10px",
                                "marginTop": "4px", "fontFamily": "monospace"}),
            ], style={"flex": "1"}),
        ], style={"display": "flex", "alignItems": "flex-start"}),
    ], className="vm-row", style={
        "padding": "10px 14px",
        "borderBottom": f"1px solid #0f1830",
        "cursor": "pointer", "transition": "background .15s",
    })


# ── Wiz Dashboard Renderer Helpers ───────────────────────────────────────────

def _metric_chip(label, value, color="#5baef5", trend=None):
    """Wiz-style metric chip with optional trend indicator."""
    trend_el = html.Span(" " + trend,
        style={"fontSize":"9px","fontWeight":"700",
               "color":"#e84040" if "↑" in (trend or "") else "#29b87a",
               "background": "#2a0c0c" if "↑" in (trend or "") else "#0c2218",
               "padding":"1px 5px","borderRadius":"8px","marginLeft":"6px"}
    ) if trend else html.Span()
    return html.Div([
        html.Div([
            html.Span(str(value), style={"color":color,"fontSize":"28px",
                                         "fontWeight":"800","fontFamily":"monospace"}),
            trend_el,
        ], style={"display":"flex","alignItems":"center"}),
        html.Div(label, style={"color":"#3a4a65","fontSize":"10px",
                               "fontWeight":"700","textTransform":"uppercase",
                               "letterSpacing":"0.8px","marginTop":"4px"}),
    ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"10px",
              "padding":"16px 20px","flex":"1","minWidth":"130px",
              "boxShadow":"0 2px 12px rgba(0,0,0,0.4)"})


def _bar_gauge(label, count, total, color):
    """Horizontal mini-bar with label and count."""
    pct = round(count / max(total, 1) * 100)
    return html.Div([
        html.Div([
            html.Span(label, style={"color":"#6a7a9a","fontSize":"11px","fontWeight":"600",
                                    "minWidth":"90px","display":"inline-block"}),
            html.Div(html.Div(style={
                "width":f"{pct}%","height":"100%",
                "background":color,"borderRadius":"2px",
            }), style={"flex":"1","height":"8px","background":"#131c2e",
                       "borderRadius":"2px","margin":"0 10px"}),
            html.Span(str(count), style={"color":color,"fontWeight":"700",
                                          "fontSize":"12px","fontFamily":"monospace",
                                          "minWidth":"30px","textAlign":"right"}),
        ], style={"display":"flex","alignItems":"center","marginBottom":"8px"}),
    ])


# ── 1. Overview Dashboard ──────────────────────────────────────────────────────
def _render_overview(kev, cve_results, assets, vulns):
    from collections import Counter
    vulns  = vulns or []
    assets = assets or []
    kev    = kev or []

    # Counts
    sev_cnt = Counter(v.get("severity","UNKNOWN").upper() for v in vulns)
    n_crit  = sev_cnt.get("CRITICAL", 0)
    n_high  = sev_cnt.get("HIGH", 0)
    n_med   = sev_cnt.get("MEDIUM", 0)
    n_low   = sev_cnt.get("LOW", 0)
    total_v = len(vulns)
    total_a = max(len(assets), 1)
    pct_aff = round(min(total_v, total_a) / total_a * 100)

    # Vulns by asset type
    type_cnt = Counter()
    for v in vulns:
        asset_name = v.get("asset","")
        ast_type = next((a.get("type","unknown") for a in assets
                         if a.get("name","") == asset_name), "unknown")
        type_cnt[ast_type] += 1
    if not type_cnt:
        type_cnt = {"server":0,"workstation":0,"cloud":0,"container":0,"network":0,"iot":0}

    TYPE_COLORS = {
        "server":"#5baef5","workstation":"#29b87a","cloud":"#f07b29",
        "container":"#a855f7","network":"#f5c842","iot":"#e84040","unknown":"#4a5a78",
    }

    # KEV by vendor (top 5)
    vendor_cnt = Counter(v.get("vendorProject","Unknown") for v in (kev or []))
    top_vendors = vendor_cnt.most_common(8)

    return html.Div([
        # Metric chips row
        html.Div([
            _metric_chip("Total CVEs",    total_v,  "#d0d8e8"),
            _metric_chip("Critical",      n_crit,   "#e84040"),
            _metric_chip("High",          n_high,   "#f07b29"),
            _metric_chip("Medium",        n_med,    "#f5c842"),
            _metric_chip("Low",           n_low,    "#29b87a"),
            _metric_chip("Assets Affected", f"{pct_aff}%", "#5baef5"),
        ], style={"display":"flex","gap":"8px","padding":"16px","flexWrap":"wrap"}),

        dbc.Row([
            # Vulns by asset type
            dbc.Col([
                html.Div([
                    html.Div("VULNERABILITIES BY ASSET TYPE", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"14px",
                    }),
                    *[_bar_gauge(t.title(), c,
                                 max(total_v, 1),
                                 TYPE_COLORS.get(t, "#4a5a78"))
                      for t, c in sorted(type_cnt.items(),
                                         key=lambda x: -x[1])],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"18px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=5),

            # Top vulnerable vendors (from KEV)
            dbc.Col([
                html.Div([
                    html.Div("TOP VULNERABLE VENDORS (KEV)", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"14px",
                    }),
                    *(
                        [_bar_gauge(v[:22], c, max(list(vendor_cnt.values()) or [1]), "#e84040")
                         for v, c in top_vendors]
                        if top_vendors else
                        [html.Div("Load KEV data to see vendors",
                                  style={"color":"#2e3d58","fontSize":"12px",
                                         "textAlign":"center","padding":"20px"})]
                    ),
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"18px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=4),

            # KEV due-soon ring
            dbc.Col([
                html.Div([
                    html.Div("CISA KEV SNAPSHOT", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"14px",
                    }),
                    html.Div([
                        html.Div(str(len(kev)), style={
                            "color":"#e84040","fontSize":"40px","fontWeight":"900",
                            "fontFamily":"monospace","textAlign":"center",
                        }),
                        html.Div("Known Exploited", style={
                            "color":"#3a4a65","fontSize":"10px","textAlign":"center",
                            "marginBottom":"16px",
                        }),
                    ]),
                    *[html.Div([
                        html.Div(style={"width":"8px","height":"8px","borderRadius":"50%",
                                        "background":"#e84040","display":"inline-block",
                                        "marginRight":"6px"}),
                        html.Span(
                            f"{sum(1 for v in kev if v.get('dueDate','') < '2025')} past due",
                            style={"color":"#e84040","fontSize":"11px"}),
                    ]),
                    html.Div([
                        html.Div(style={"width":"8px","height":"8px","borderRadius":"50%",
                                        "background":"#f07b29","display":"inline-block",
                                        "marginRight":"6px"}),
                        html.Span(
                            f"{sum(1 for v in kev if '2025' <= v.get('dueDate','') < '2026')} due 2025",
                            style={"color":"#f07b29","fontSize":"11px"}),
                    ])],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"18px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=3),
        ], className="g-3 px-3 pb-3"),
    ])


# ── 2. Attack Paths Dashboard ─────────────────────────────────────────────────
def _render_attack_paths(kev, epss, assets, vulns):
    from collections import Counter
    kev    = kev or []
    epss   = epss or {}
    assets = assets or []
    vulns  = vulns or []
    kev_ids = {v.get("cveID","") for v in kev}

    n_crit_high   = sum(1 for v in vulns if v.get("severity","").upper() in ("CRITICAL","HIGH"))
    n_public_exp  = sum(1 for cid, score in epss.items() if score > 0.5)
    n_exposed     = sum(1 for a in assets if a.get("crit","").lower() == "critical")
    n_attack_paths = len(kev_ids)

    # Funnel data
    funnel_vals   = [
        len(kev) or n_crit_high or 1,
        n_public_exp or max(int((len(kev) or 1) * 0.6), 1),
        n_exposed    or max(int((len(kev) or 1) * 0.25), 1),
        n_attack_paths or max(int((len(kev) or 1) * 0.1), 1),
    ]
    funnel_labels = [
        "All Critical & High CVEs",
        "Has Public Exploit",
        "Exposed Resources",
        "Critical Attack Paths",
    ]
    funnel_colors = ["#e84040","#f07b29","#f5c842","#a855f7"]

    fig = go.Figure(go.Funnel(
        y=funnel_labels, x=funnel_vals,
        textposition="inside",
        textinfo="value+percent initial",
        marker={"color":funnel_colors,
                "line":{"width":0}},
        connector={"line":{"color":"#0b0f19","dash":"solid","width":2}},
        hoverinfo="x+y+percent initial",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0,r=0,t=10,b=10), height=260,
        font={"color":"#6a7a9a","size":11},
    )

    # Top vuln issues table (from KEV, sorted by recentness)
    top_issues = kev[:8] if kev else []

    return html.Div([
        # Top metric cards
        html.Div([
            _metric_chip("Critical & High CVEs",    funnel_vals[0], "#e84040"),
            _metric_chip("Has Public Exploit",       funnel_vals[1], "#f07b29"),
            _metric_chip("Exposed Resources",        funnel_vals[2], "#f5c842"),
            _metric_chip("Critical Attack Paths",    funnel_vals[3], "#a855f7"),
        ], style={"display":"flex","gap":"8px","padding":"16px","flexWrap":"wrap"}),

        dbc.Row([
            # Funnel chart
            dbc.Col([
                html.Div([
                    html.Div("IMPACT STAGES — RISK FUNNEL", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"10px",
                    }),
                    dcc.Graph(figure=fig, config={"displayModeBar":False}),
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"16px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=5),

            # Top vulnerability issues
            dbc.Col([
                html.Div([
                    html.Div([
                        html.Span("TOP VULNERABILITY ISSUES", style={
                            "color":"#2e3d58","fontSize":"10px","fontWeight":"700","letterSpacing":"1px",
                        }),
                        html.Span(f" — {len(kev)} KEV rules" if kev else "",
                                  style={"color":"#1e2d44","fontSize":"10px"}),
                    ], style={"marginBottom":"10px"}),
                    # Header row
                    html.Div([
                        html.Span("Vulnerability",    style={"color":"#1e2d44","fontSize":"9px","fontWeight":"700","flex":"1"}),
                        html.Span("Vendor",           style={"color":"#1e2d44","fontSize":"9px","fontWeight":"700","width":"80px"}),
                        html.Span("Due",              style={"color":"#1e2d44","fontSize":"9px","fontWeight":"700","width":"70px"}),
                        html.Span("Severity",         style={"color":"#1e2d44","fontSize":"9px","fontWeight":"700","width":"60px"}),
                    ], style={"display":"flex","padding":"4px 8px","borderBottom":"1px solid #0f1830"}),
                    # Rows
                    *[html.Div([
                        html.Div([
                            html.Div(v.get("vulnerabilityName","")[:40],
                                     style={"color":"#8a9cc0","fontSize":"11px"}),
                            html.Span(v.get("cveID",""),
                                      style={"color":"#2e3d58","fontSize":"9px",
                                             "fontFamily":"monospace"}),
                        ], style={"flex":"1","minWidth":"0"}),
                        html.Span(v.get("vendorProject","")[:12],
                                  style={"color":"#4a5a78","fontSize":"9px","width":"80px",
                                         "overflow":"hidden","textOverflow":"ellipsis",
                                         "whiteSpace":"nowrap"}),
                        html.Span(v.get("dueDate","")[:10],
                                  style={"color":"#f07b29","fontSize":"9px","width":"70px",
                                         "fontFamily":"monospace"}),
                        _pill_badge("KEV", "#e84040", "#2a0c0c"),
                    ], style={"display":"flex","alignItems":"center",
                              "padding":"7px 8px","borderBottom":"1px solid #0b0f19",
                              "gap":"4px"})
                    for v in top_issues],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"16px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)",
                          "maxHeight":"340px","overflowY":"auto"}),
            ], width=7),
        ], className="g-3 px-3 pb-3"),
    ])


# ── 3. Lifecycle Funnel Dashboard ─────────────────────────────────────────────
def _render_lifecycle(vulns):
    from collections import Counter
    vulns = vulns or []
    total = max(len(vulns), 1)

    status_cnt = Counter(v.get("status","Detected").title() for v in vulns)
    stages = ["Detected","Triaged","Assigned","In Remediation","Remediated"]
    counts = [status_cnt.get(s, max(0, total - i*5)) for i, s in enumerate(stages)]
    # Make funnel monotonically decreasing for visual
    for i in range(1, len(counts)):
        counts[i] = min(counts[i], counts[i-1])

    fixed   = counts[-1]
    backlog = counts[0] - fixed
    pct_done = round(fixed / max(counts[0], 1) * 100)

    fig = go.Figure(go.Funnel(
        y=stages, x=counts,
        textposition="inside",
        textinfo="value+percent initial",
        marker={"color":["#e84040","#f07b29","#f5c842","#3b9de8","#29b87a"],
                "line":{"width":0}},
        connector={"line":{"color":"#0b0f19","width":2}},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0,r=0,t=10,b=10), height=280,
        font={"color":"#6a7a9a","size":11},
    )

    return html.Div([
        # Metrics row
        html.Div([
            _metric_chip("Total Detected",  counts[0], "#e84040"),
            _metric_chip("In Progress",     counts[2], "#f5c842"),
            _metric_chip("Remediated",      fixed,     "#29b87a"),
            _metric_chip("Backlog",         backlog,   "#f07b29"),
            _metric_chip("Completion",      f"{pct_done}%", "#5baef5"),
        ], style={"display":"flex","gap":"8px","padding":"16px","flexWrap":"wrap"}),

        dbc.Row([
            dbc.Col([
                html.Div([
                    html.Div("REMEDIATION LIFECYCLE FUNNEL", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"10px",
                    }),
                    dcc.Graph(figure=fig, config={"displayModeBar":False}),
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"16px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=6),

            dbc.Col([
                html.Div([
                    html.Div("STAGE BREAKDOWN", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"16px",
                    }),
                    *[html.Div([
                        html.Div([
                            html.Span(stage, style={"color":"#6a7a9a","fontSize":"12px",
                                                     "fontWeight":"600","minWidth":"120px",
                                                     "display":"inline-block"}),
                            html.Span(str(cnt), style={"color":color,"fontSize":"20px",
                                                        "fontWeight":"800","fontFamily":"monospace"}),
                        ], style={"display":"flex","alignItems":"center","gap":"12px",
                                  "marginBottom":"6px"}),
                        html.Div(html.Div(style={
                            "width":f"{round(cnt/max(counts[0],1)*100)}%",
                            "height":"100%","background":color,"borderRadius":"3px",
                        }), style={"height":"6px","background":"#131c2e",
                                   "borderRadius":"3px","marginBottom":"14px"}),
                    ])
                    for stage, cnt, color in zip(
                        stages, counts,
                        ["#e84040","#f07b29","#f5c842","#3b9de8","#29b87a"])],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"18px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=6),
        ], className="g-3 px-3 pb-3"),
    ])


# ── 4. Trends Dashboard ───────────────────────────────────────────────────────
def _render_trends(kev, vulns):
    from collections import defaultdict
    from datetime import datetime, timedelta
    kev   = kev or []
    vulns = vulns or []

    # Build 30-day KEV timeline from dateAdded
    today = datetime.now().date()
    days  = [(today - timedelta(days=i)).isoformat() for i in range(30, -1, -1)]
    kev_by_day = defaultdict(int)
    for v in kev:
        d = v.get("dateAdded","")[:10]
        if d:
            kev_by_day[d] += 1

    crit_trend = [kev_by_day.get(d, 0) for d in days]
    # Cumulative for running total view
    cumulative = []
    acc = 0
    for c in crit_trend:
        acc += c
        cumulative.append(acc)

    # MTTD/MTTR from vulns
    mttd_vals, mttr_vals = [], []
    for v in vulns:
        try:
            ad = datetime.fromisoformat(v.get("assigned_date", datetime.now().isoformat()))
            elapsed = (datetime.now() - ad).days
            if v.get("status","").lower() == "remediated":
                mttr_vals.append(elapsed)
            else:
                mttd_vals.append(elapsed)
        except Exception:
            pass
    mttd = round(sum(mttd_vals)/max(len(mttd_vals),1), 1)
    mttr = round(sum(mttr_vals)/max(len(mttr_vals),1), 1)

    # Sparkline figure — KEV discoveries
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=days, y=crit_trend, name="Daily KEV",
        line=dict(color="#e84040", width=2, shape="spline"),
        fill="tozeroy", fillcolor="rgba(232,64,64,0.08)",
        mode="lines",
    ))
    fig.add_trace(go.Scatter(
        x=days, y=cumulative, name="Cumulative",
        line=dict(color="#f07b29", width=1.5, shape="spline", dash="dot"),
        mode="lines", yaxis="y2",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,17,24,0.8)",
        margin=dict(l=30, r=40, t=10, b=20), height=220,
        font={"color":"#4a5a78","size":10},
        legend={"font":{"size":10},"bgcolor":"rgba(0,0,0,0)","orientation":"h","y":1.15},
        xaxis={"gridcolor":"#0f1830","color":"#2e3d58","tickfont":{"size":9}},
        yaxis={"gridcolor":"#0f1830","color":"#2e3d58","tickfont":{"size":9},"side":"left"},
        yaxis2={"overlaying":"y","side":"right","color":"#f07b29",
                "gridcolor":"rgba(0,0,0,0)","tickfont":{"size":9}},
        hovermode="x unified",
    )

    return html.Div([
        # MTTD / MTTR / Risk metric chips
        html.Div([
            _metric_chip("MTTD (days)",  mttd,      "#5baef5"),
            _metric_chip("MTTR (days)",  mttr,      "#29b87a"),
            _metric_chip("KEV Total",    len(kev),  "#e84040"),
            _metric_chip("Vulns Tracked",len(vulns),"#f5c842"),
            _metric_chip("Remediated",
                         sum(1 for v in vulns if v.get("status","").lower()=="remediated"),
                         "#a855f7"),
        ], style={"display":"flex","gap":"8px","padding":"16px","flexWrap":"wrap"}),

        dbc.Row([
            dbc.Col([
                html.Div([
                    html.Div([
                        html.Span("KEV Discovery Trends — Last 30 Days",
                                  style={"color":"#d0d8e8","fontSize":"13px","fontWeight":"700"}),
                        html.Span("  Past 30 days, Daily",
                                  style={"color":"#2e3d58","fontSize":"10px"}),
                    ], style={"marginBottom":"8px"}),
                    dcc.Graph(figure=fig, config={"displayModeBar":False}),
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"16px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=8),

            dbc.Col([
                html.Div([
                    html.Div("REMEDIATION METRICS", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"16px",
                    }),
                    *[html.Div([
                        html.Div(label, style={"color":"#3a4a65","fontSize":"10px",
                                               "fontWeight":"600","marginBottom":"4px"}),
                        html.Div(value, style={"color":color,"fontSize":"24px",
                                               "fontWeight":"800","fontFamily":"monospace",
                                               "marginBottom":"12px"}),
                    ]) for label, value, color in [
                        ("Mean Time to Detect", f"{mttd}d", "#5baef5"),
                        ("Mean Time to Remediate", f"{mttr}d", "#29b87a"),
                        ("Vuln Recurrence", "—", "#f5c842"),
                    ]],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"18px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=4),
        ], className="g-3 px-3 pb-3"),
    ])


# ── 5. Patch / Software Dashboard ─────────────────────────────────────────────
def _render_patch(kev, cve_results):
    from collections import Counter
    from datetime import datetime
    kev         = kev or []
    cve_results = cve_results or []

    # Parse OS from KEV product strings
    OS_KEYWORDS = {
        "Windows":["windows","win32","win64","microsoft"],
        "Linux":  ["linux","ubuntu","debian","centos","redhat","fedora","kernel"],
        "macOS":  ["macos","mac os","apple","ios","iphone"],
        "VMware": ["vmware","vsphere","esxi","vcenter"],
        "Cisco":  ["cisco","ios xe","nx-os","asa"],
        "Other":  [],
    }
    os_cnt = Counter({k:0 for k in OS_KEYWORDS})
    for v in kev:
        prod = (v.get("product","") + " " + v.get("vendorProject","")).lower()
        matched = False
        for os_name, kw_list in OS_KEYWORDS.items():
            if os_name == "Other":
                continue
            if any(kw in prod for kw in kw_list):
                os_cnt[os_name] += 1
                matched = True
                break
        if not matched:
            os_cnt["Other"] += 1

    # EOL / overdue
    today   = datetime.now().date().isoformat()
    eol     = [v for v in kev if v.get("dueDate","") < today]
    recent  = sorted(kev, key=lambda v: v.get("dateAdded",""), reverse=True)[:10]

    # CVE by score range
    score_ranges = {"9.0-10 (Critical)":0,"7.0-8.9 (High)":0,
                    "4.0-6.9 (Medium)":0,"0-3.9 (Low)":0}
    for v in cve_results:
        try:
            sc = float(v.get("score",0) or 0)
            if sc >= 9:    score_ranges["9.0-10 (Critical)"] += 1
            elif sc >= 7:  score_ranges["7.0-8.9 (High)"] += 1
            elif sc >= 4:  score_ranges["4.0-6.9 (Medium)"] += 1
            else:          score_ranges["0-3.9 (Low)"] += 1
        except Exception:
            pass

    total_os = max(sum(os_cnt.values()), 1)
    OS_COLORS = {"Windows":"#5baef5","Linux":"#f07b29","macOS":"#29b87a",
                 "VMware":"#a855f7","Cisco":"#f5c842","Other":"#4a5a78"}

    return html.Div([
        html.Div([
            _metric_chip("Unpatched (EOL)", len(eol),       "#e84040", "⚠"),
            _metric_chip("KEV Total",        len(kev),       "#f07b29"),
            _metric_chip("CVE Results",      len(cve_results),"#f5c842"),
            _metric_chip("Critical CVSS ≥9",
                         score_ranges["9.0-10 (Critical)"], "#a855f7"),
        ], style={"display":"flex","gap":"8px","padding":"16px","flexWrap":"wrap"}),

        dbc.Row([
            # OS breakdown
            dbc.Col([
                html.Div([
                    html.Div("UNPATCHED BY OS / PLATFORM", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"14px",
                    }),
                    *[_bar_gauge(os_n, cnt, total_os, OS_COLORS.get(os_n,"#4a5a78"))
                      for os_n, cnt in sorted(os_cnt.items(), key=lambda x:-x[1])],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"18px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=4),

            # CVSS score distribution
            dbc.Col([
                html.Div([
                    html.Div("CVSS SCORE DISTRIBUTION (NVD Results)", style={
                        "color":"#2e3d58","fontSize":"10px","fontWeight":"700",
                        "letterSpacing":"1px","marginBottom":"14px",
                    }),
                    *[_bar_gauge(rng, cnt, max(len(cve_results),1), c)
                      for (rng, cnt), c in zip(
                          score_ranges.items(),
                          ["#e84040","#f07b29","#f5c842","#29b87a"]
                      )],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"18px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)"}),
            ], width=4),

            # Recently added KEV (EOL / new threats)
            dbc.Col([
                html.Div([
                    html.Div([
                        html.Span("RECENTLY ADDED KEV", style={
                            "color":"#2e3d58","fontSize":"10px","fontWeight":"700","letterSpacing":"1px",
                        }),
                        html.Span(f" — {len(eol)} overdue", style={"color":"#e84040","fontSize":"10px"}),
                    ], style={"marginBottom":"10px"}),
                    *[html.Div([
                        html.Div([
                            html.Span(v.get("cveID",""), style={
                                "color":"#e84040","fontSize":"10px","fontFamily":"monospace",
                                "fontWeight":"700",
                            }),
                            html.Span(f' {v.get("vendorProject","")[:16]}',
                                      style={"color":"#4a5a78","fontSize":"9px","marginLeft":"6px"}),
                        ]),
                        html.Span(f'Due {v.get("dueDate","")}',
                                  style={"color": "#e84040" if v.get("dueDate","") < today else "#2e3d58",
                                         "fontSize":"9px","fontFamily":"monospace"}),
                    ], style={"display":"flex","justifyContent":"space-between",
                              "alignItems":"center","padding":"6px 0",
                              "borderBottom":"1px solid #0b0f19"})
                    for v in recent],
                ], style={"background":CARD_BG,"border":BORDER,"borderRadius":"12px",
                          "padding":"16px","boxShadow":"0 2px 12px rgba(0,0,0,0.4)",
                          "maxHeight":"340px","overflowY":"auto"}),
            ], width=4),
        ], className="g-3 px-3 pb-3"),
    ])




# ── Resource Hub Renderer ─────────────────────────────────────────────────────

def _render_resource_hub(kev):
    """Wiz-style Resource Hub: Use Cases, Tools, Learning, Industries."""
    kev = kev or []

    # ── Helper: clickable hub card ─────────────────────────────────────────
    def _hub_card(icon, title, desc, color, tag=None, href=None, tab_id=None):
        tag_el = html.Span(tag, style={
            "fontSize":"8px","fontWeight":"700","padding":"1px 6px",
            "borderRadius":"8px","background":color+"22",
            "color":color,"border":f"1px solid {color}44",
            "marginLeft":"6px","letterSpacing":"0.5px",
        }) if tag else html.Span()
        link_attrs = {"href": href, "target":"_blank"} if href else {}
        inner = html.Div([
            html.Div([
                html.Span(icon, style={"fontSize":"18px","marginRight":"8px"}),
                html.Span(title, style={"color":"#c0cce0","fontSize":"12px",
                                        "fontWeight":"700"}),
                tag_el,
            ], style={"display":"flex","alignItems":"center","marginBottom":"6px"}),
            html.Div(desc, style={"color":"#3a4a65","fontSize":"10px",
                                   "lineHeight":"1.5"}),
        ], style={
            "background":CARD_BG,"border":BORDER,"borderRadius":"10px",
            "borderLeft":f"3px solid {color}",
            "padding":"12px 14px","cursor":"pointer",
            "transition":"transform .2s, box-shadow .2s",
            "boxShadow":"0 2px 10px rgba(0,0,0,0.4)",
        })
        if href:
            return html.A(inner, href=href, target="_blank",
                          style={"textDecoration":"none","display":"block",
                                 "marginBottom":"8px"})
        return html.Div(inner, style={"marginBottom":"8px"})

    # ── Section header ─────────────────────────────────────────────────────
    def _section_hdr(icon, title, subtitle=""):
        return html.Div([
            html.Span(icon, style={"fontSize":"16px","marginRight":"8px"}),
            html.Span(title, style={"color":"#8a9cc0","fontSize":"11px",
                                    "fontWeight":"700","letterSpacing":"1px",
                                    "textTransform":"uppercase"}),
            html.Span(f" — {subtitle}", style={"color":"#2e3d58","fontSize":"10px"})
            if subtitle else html.Span(),
        ], style={"marginBottom":"14px","marginTop":"4px"})

    # ========== BY USE CASE — 3 COLUMNS =====================================
    secure_dev_cards = [
        _hub_card("🔍","IaC Scanning","Scan Terraform / CloudFormation templates for misconfigs before deploy","#29b87a","SECURE DEV"),
        _hub_card("🔗","Supply Chain (SCA/SBOM)","Detect vulnerable open-source dependencies and generate SBOMs","#5baef5","SUPPLY CHAIN"),
        _hub_card("🐳","WizOS / Container Images","Harden container base images and eliminate known CVEs at build time","#a855f7","CONTAINERS"),
        _hub_card("🛡","App Security Posture (ASPM)","Correlate code, pipeline, and runtime findings in one view","#f07b29","ASPM"),
    ]
    exposure_cards = [
        _hub_card("🌐","Attack Surface Management","Map externally exposed assets and identify entry points","#e84040","ASM"),
        _hub_card("☁","Cloud Posture (CSPM)","Continuously audit cloud resource configurations","#5baef5","CSPM"),
        _hub_card("🔐","Identity & Entitlements (CIEM)","Detect over-privileged identities and toxic combinations","#f5c842","CIEM"),
        _hub_card("🗄","Data Posture (DSPM)","Find sensitive data exposure across cloud storage","#29b87a","DSPM"),
        _hub_card("🤖","AI Security (AI-SPM)","Secure AI/ML models, datasets, and shadow AI deployments","#a855f7","AI-SPM"),
        _hub_card("📊","Unified Vulnerability Mgmt","Prioritize vulns using cloud context and attack paths","#f07b29","UVM"),
    ]
    workload_cards = [
        _hub_card("🔒","Workload Protection (CWPP)","Runtime protection for VMs, containers, serverless","#5baef5","CWPP"),
        _hub_card("⎈","Container & Kubernetes","Scan images, detect runtime threats in K8s clusters","#a855f7","K8S"),
        _hub_card("🚨","Cloud Detection & Response","Detect and respond to cloud threats in real-time","#e84040","CDR"),
        _hub_card("📡","Wiz Sensor / Runtime","Lightweight eBPF sensor for workload runtime visibility","#29b87a","RUNTIME"),
        _hub_card("🕵","Compliance Monitoring","Continuous compliance across CIS, NIST, PCI-DSS, HIPAA","#f5c842","COMPLIANCE"),
    ]

    # ========== EXTERNAL TOOLS ==============================================
    tool_cards = [
        _hub_card("🗃","Cloud Vulnerability DB","Community-led database of cloud-specific CVEs",
                  "#5baef5","COMMUNITY",href="https://www.cloudvulndb.org"),
        _hub_card("📋","NVD / NIST","Official NIST National Vulnerability Database",
                  "#f07b29","OFFICIAL",href="https://nvd.nist.gov"),
        _hub_card("☁","Cloud Threat Landscape","Wiz threat intelligence on cloud attack campaigns",
                  "#e84040","THREAT INTEL",href="https://www.wiz.io/cloud-threat-landscape"),
        _hub_card("🔑","PQC Tester","Check if a domain supports post-quantum cryptography",
                  "#a855f7","CRYPTO",href="https://pqc.cloudflare.com"),
        _hub_card("🤖","Cyber Model Arena","Benchmark AI models across security challenges",
                  "#29b87a","AI",href="https://cyberarena.ai"),
        _hub_card("📡","Middleware Visibility","Map installed cloud middleware across environments",
                  "#f5c842","INFRA",href="https://middleware.io"),
    ]

    # ========== LEARNING ====================================================
    learn_cards = [
        _hub_card("🏆","Bug Bounty Masterclass","Master vulnerability hunting, disclosure, and bounty platforms",
                  "#f07b29","COURSE",href="https://bugbountybootcamp.com"),
        _hub_card("☁","Cloud Security Courses","Hands-on AWS, Azure, GCP security training paths",
                  "#5baef5","TRAINING",href="https://cloudacademy.com/cloud-security"),
        _hub_card("🚩","CTF Challenges","Cloud-focused Capture the Flag competitions and labs",
                  "#a855f7","PRACTICE",href="https://ctftime.org"),
        _hub_card("📚","CloudSec Academy","Free cloud security fundamentals and best practices",
                  "#29b87a","FREE",href="https://cloudsecacademy.io"),
        _hub_card("🤝","Crying Out Cloud Podcast","Cloud security podcast — episodes, news, insights",
                  "#f5c842","PODCAST",href="https://www.wiz.io/podcast"),
        _hub_card("📰","Security Blog","Latest cloud vulnerability research and advisories",
                  "#e84040","BLOG",href="https://www.wiz.io/blog"),
    ]

    # ========== INDUSTRIES ==================================================
    # Filter KEV by industry keyword
    today = __import__("datetime").datetime.now().date().isoformat()
    def _industry_kev(keywords):
        return [v for v in kev
                if any(kw in (v.get("product","")+" "+v.get("vendorProject","")
                              +" "+v.get("shortDescription","")).lower()
                       for kw in keywords)]

    health_kev = _industry_kev(["health","hospital","medical","hl7","dicom","epic","cerner"])
    fin_kev    = _industry_kev(["bank","financial","payment","swift","pci","fintech","trading"])
    gov_kev    = _industry_kev(["gov","federal","fisma","nist","dod","military","agency","cisco"])

    def _industry_card(icon, title, desc, color, count, kev_items):
        overdue = sum(1 for v in kev_items if v.get("dueDate","") < today)
        return html.Div([
            html.Div([
                html.Span(icon, style={"fontSize":"24px","marginRight":"10px"}),
                html.Div([
                    html.Div(title, style={"color":"#c0cce0","fontSize":"14px",
                                           "fontWeight":"700"}),
                    html.Div(desc, style={"color":"#3a4a65","fontSize":"10px",
                                          "marginTop":"2px"}),
                ]),
            ], style={"display":"flex","alignItems":"center","marginBottom":"12px"}),
            html.Div([
                html.Div([
                    html.Div(str(count), style={"color":color,"fontSize":"28px",
                                                "fontWeight":"800","fontFamily":"monospace"}),
                    html.Div("KEV matches", style={"color":"#2e3d58","fontSize":"9px",
                                                    "fontWeight":"600"}),
                ]),
                html.Div([
                    html.Div(str(overdue), style={"color":"#e84040","fontSize":"28px",
                                                   "fontWeight":"800","fontFamily":"monospace"}),
                    html.Div("overdue", style={"color":"#2e3d58","fontSize":"9px",
                                               "fontWeight":"600"}),
                ]),
            ], style={"display":"flex","gap":"24px"}),
            html.Div(style={"height":"2px","background":color+"44",
                            "borderRadius":"1px","marginTop":"12px"}),
        ], style={
            "background":CARD_BG,"border":BORDER,"borderLeft":f"3px solid {color}",
            "borderRadius":"0 10px 10px 0","padding":"16px 18px",
            "boxShadow":"0 2px 12px rgba(0,0,0,0.4)","flex":"1",
        })

    # ========== ASSEMBLE ====================================================
    return html.Div([

        # ── SECTION 1: Use Cases ──────────────────────────────────────────
        html.Div([
            _section_hdr("🏗","By Use Case",
                         "Click a domain to navigate to the matching Aegis module"),
            dbc.Row([
                dbc.Col([
                    html.Div("SECURE DEVELOPMENT", style={
                        "color":"#29b87a","fontSize":"9px","fontWeight":"800",
                        "letterSpacing":"1.5px","marginBottom":"10px",
                        "borderBottom":"1px solid #29b87a33","paddingBottom":"6px",
                    }),
                    *secure_dev_cards,
                ], width=4),
                dbc.Col([
                    html.Div("EXPOSURE & POSTURE MANAGEMENT", style={
                        "color":"#5baef5","fontSize":"9px","fontWeight":"800",
                        "letterSpacing":"1.5px","marginBottom":"10px",
                        "borderBottom":"1px solid #5baef533","paddingBottom":"6px",
                    }),
                    *exposure_cards,
                ], width=4),
                dbc.Col([
                    html.Div("WORKLOAD & RUNTIME PROTECTION", style={
                        "color":"#a855f7","fontSize":"9px","fontWeight":"800",
                        "letterSpacing":"1.5px","marginBottom":"10px",
                        "borderBottom":"1px solid #a855f733","paddingBottom":"6px",
                    }),
                    *workload_cards,
                ], width=4),
            ], className="g-3"),
        ], style={"padding":"16px 16px 8px"}),

        html.Div(style={"height":"1px","background":"#0f1830","margin":"8px 16px"}),

        # ── SECTION 2: External Tools ─────────────────────────────────────
        html.Div([
            _section_hdr("🛠","Intelligence & Tools",
                         "External cloud security databases and utilities"),
            dbc.Row([
                dbc.Col(_t, width=4)
                for _t in [html.Div(tool_cards[i:i+2])
                            for i in range(0, len(tool_cards), 2)]
            ], className="g-3"),
        ], style={"padding":"8px 16px"}),

        html.Div(style={"height":"1px","background":"#0f1830","margin":"8px 16px"}),

        # ── SECTION 3: Learning ───────────────────────────────────────────
        html.Div([
            _section_hdr("🎓","Learn Cloud Security",
                         "Courses, CTFs, and community resources"),
            dbc.Row([
                dbc.Col(_t, width=4)
                for _t in [html.Div(learn_cards[i:i+2])
                            for i in range(0, len(learn_cards), 2)]
            ], className="g-3"),
        ], style={"padding":"8px 16px"}),

        html.Div(style={"height":"1px","background":"#0f1830","margin":"8px 16px"}),

        # ── SECTION 4: Industries ─────────────────────────────────────────
        html.Div([
            _section_hdr("🏭","By Industry",
                         "KEV counts filtered by industry keyword"),
            html.Div([
                _industry_card("🏥","Healthcare & Life Sciences",
                               "HL7, DICOM, Epic, Cerner, medical device CVEs",
                               "#29b87a", len(health_kev), health_kev),
                _industry_card("🏦","Financial Services",
                               "Banking, PCI-DSS, SWIFT, payment platform CVEs",
                               "#f5c842", len(fin_kev), fin_kev),
                _industry_card("🏛","Government",
                               "FISMA, DoD, federal agency, Cisco gov CVEs",
                               "#5baef5", len(gov_kev), gov_kev),
            ], style={"display":"flex","gap":"12px","flexWrap":"wrap"}),
        ], style={"padding":"8px 16px 20px"}),
    ], style={"overflowY":"auto","maxHeight":"70vh"})


# ── Layout ────────────────────────────────────────────────────────────────────
def layout() -> html.Div:
    return html.Div([
        # ── Hidden stores + intervals ─────────────────────────────────────
        dcc.Store(id="vm-kev",      data=[]),
        dcc.Store(id="vm-cve",      data=[]),
        dcc.Store(id="vm-epss",     data={}),
        dcc.Store(id="vm-assets",   data=[]),
        dcc.Store(id="vm-vulns",    data=[]),
        dcc.Store(id="vm-assign-trigger",    data=0),
        dcc.Store(id="vm-del-asset-trigger", data=0),
        dcc.Interval(id="vm-hydrate-poll", interval=800,  max_intervals=1),
        dcc.Interval(id="vm-kev-poll",     interval=1000, max_intervals=1),

        # ── HEADER ────────────────────────────────────────────────────────
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Span("Vulnerabilities", style={
                            "color": "#d0d8e8", "fontWeight": "800",
                            "fontSize": "22px", "letterSpacing": "-0.3px",
                        }),
                        html.Span(" MANAGEMENT", style={
                            "color": "#2a3a5a", "fontWeight": "700",
                            "fontSize": "11px", "letterSpacing": "3px",
                            "marginLeft": "10px", "verticalAlign": "middle",
                        }),
                    ]),
                    html.Div(
                        "CISA KEV · NVD CVE Search · EPSS · Asset Mapping · Patch SLA · AI Prioritization",
                        style={"color": "#2e3d58", "fontSize": "11px", "marginTop": "4px"},
                    ),
                ], width=8),
                dbc.Col([
                    html.Div([
                        dbc.Button([html.Span("✨", style={"marginRight": "6px"}),
                                    "AI Prioritize"],
                                   id="vm-ai-pri-btn", n_clicks=0,
                                   style={**BTN_SM,
                                          "background": "linear-gradient(135deg,#1e0a2d,#2d1050)",
                                          "border": "1px solid #7c3aed",
                                          "color": "#c084fc",
                                          "marginRight": "8px"}),
                        dbc.Button([html.Span("📥", style={"marginRight": "6px"}),
                                    "Export"],
                                   id="vm-export-btn",
                                   style={**BTN_SM,
                                          "background": "transparent",
                                          "border": "1px solid #1e2a40",
                                          "color": "#5a6a8a"}),
                        dcc.Download(id="vm-download"),
                    ], style={"display": "flex", "gap": "0", "justifyContent": "flex-end",
                              "alignItems": "center"}),
                ], width=4),
            ], align="center"),
            # Header underline
            html.Div(style={
                "height": "1px",
                "background": "linear-gradient(90deg,#1e3060,transparent)",
                "marginTop": "14px",
            }),
        ], style={
            "background": "linear-gradient(180deg,#0f1828 0%,#0b0f19 100%)",
            "padding": "20px 24px 16px",
            "borderBottom": "1px solid #111c30",
            "marginBottom": "0",
        }),

        # ── SEVERITY SUMMARY BAR ──────────────────────────────────────────
        html.Div(id="vm-stats-bar",
                 style={"display": "flex", "gap": "8px", "padding": "16px 24px",
                        "background": DARK_BG, "flexWrap": "wrap"}),

        # ── THREE-COLUMN BODY ─────────────────────────────────────────────
        html.Div([
            dbc.Row([
                # ── LEFT PANEL: filters + asset + assign ──────────────────
                dbc.Col([
                    # CVE Search card
                    _card(
                        _label("Search CVEs"),
                        dbc.Input(id="vm-search-q",
                                  placeholder="CVE-ID, keyword or product",
                                  style={**INPUT_STY, "marginBottom": "8px"}),
                        _label("Severity Filter"),
                        dbc.Select(id="vm-search-sev",
                                   options=[
                                       {"label": "All Severities", "value": "ALL"},
                                       {"label": "🔴 Critical",    "value": "CRITICAL"},
                                       {"label": "🟠 High",        "value": "HIGH"},
                                       {"label": "🟡 Medium",      "value": "MEDIUM"},
                                       {"label": "🟢 Low",         "value": "LOW"},
                                   ], value="ALL",
                                   style={**INPUT_STY, "marginBottom": "10px"}),
                        dbc.Row([
                            dbc.Col(dbc.Button("Search NVD", id="vm-search-btn",
                                               style={**BTN_SM, "width": "100%",
                                                      "background": "#1a2e56",
                                                      "border": "1px solid #2a4a80",
                                                      "color": "#5baef5"}), width=6),
                            dbc.Col(dbc.Button("⚡ Load KEV", id="vm-kev-btn",
                                               style={**BTN_SM, "width": "100%",
                                                      "background": "#2a0c0c",
                                                      "border": "1px solid #7a1e1e",
                                                      "color": "#e84040"}), width=6),
                        ]),
                        html.Div(id="vm-search-status",
                                 style={"color": "#2e3d58", "fontSize": "11px",
                                        "marginTop": "8px", "minHeight": "14px"}),
                        title="CVE Search",
                    ),

                    # Asset inventory card
                    _card(
                        _label("Asset Name / IP"),
                        dbc.Input(id="vm-asset-name",
                                  placeholder="web-prod-01 / 10.0.1.5",
                                  style={**INPUT_STY, "marginBottom": "8px"}),
                        _label("Type"),
                        dbc.Select(id="vm-asset-type",
                                   options=[
                                       {"label": "Server",      "value": "server"},
                                       {"label": "Workstation", "value": "workstation"},
                                       {"label": "Network",     "value": "network"},
                                       {"label": "Cloud",       "value": "cloud"},
                                       {"label": "Container",   "value": "container"},
                                       {"label": "IoT/OT",      "value": "iot"},
                                   ], value="server",
                                   style={**INPUT_STY, "marginBottom": "8px"}),
                        _label("Criticality"),
                        dbc.Select(id="vm-asset-crit",
                                   options=[
                                       {"label": "🔴 Critical", "value": "critical"},
                                       {"label": "🟠 High",     "value": "high"},
                                       {"label": "🟡 Medium",   "value": "medium"},
                                       {"label": "🟢 Low",      "value": "low"},
                                   ], value="high",
                                   style={**INPUT_STY, "marginBottom": "10px"}),
                        dbc.Button("+ Add Asset", id="vm-add-asset-btn",
                                   style={**BTN_SM, "width": "100%",
                                          "background": "#0c2218",
                                          "border": "1px solid #1a4a30",
                                          "color": "#29b87a"}),
                        html.Div(id="vm-asset-status",
                                 style={"color": "#2e3d58", "fontSize": "11px",
                                        "marginTop": "6px", "minHeight": "14px"}),
                        title="Asset Inventory",
                    ),

                    # Assign CVE card
                    _card(
                        _label("CVE ID"),
                        dbc.Input(id="vm-assign-cve",
                                  placeholder="CVE-2024-3400",
                                  style={**INPUT_STY, "marginBottom": "8px"}),
                        _label("Severity"),
                        dbc.Select(id="vm-assign-sev",
                                   options=[
                                       {"label": "Critical", "value": "CRITICAL"},
                                       {"label": "High",     "value": "HIGH"},
                                       {"label": "Medium",   "value": "MEDIUM"},
                                       {"label": "Low",      "value": "LOW"},
                                   ], value="HIGH",
                                   style={**INPUT_STY, "marginBottom": "8px"}),
                        _label("Target Asset"),
                        dbc.Select(id="vm-assign-asset", options=[], value=None,
                                   style={**INPUT_STY, "marginBottom": "10px"}),
                        dbc.Button("→ Assign to Asset", id="vm-assign-btn",
                                   style={**BTN_SM, "width": "100%",
                                          "background": "#0c1e2a",
                                          "border": "1px solid #1e3a56",
                                          "color": "#3b9de8"}),
                        html.Div(id="vm-assign-status",
                                 style={"color": "#2e3d58", "fontSize": "11px",
                                        "marginTop": "6px", "minHeight": "14px"}),
                        title="Assign CVE → Asset",
                    ),
                ], width=3, style={"overflowY": "auto", "maxHeight": "85vh",
                                   "paddingRight": "4px"}),

                # ── CENTRE: Wiz-style tab + content ───────────────────────
                dbc.Col([
                     # Wiz-style tab strip (functional dbc.Tabs, styled via CSS)
                     dbc.Tabs(id="vm-tabs", active_tab="vm-tab-overview",
                              className="vm-wiz-tabs",
                              children=[
                                  dbc.Tab(label="📊 Overview",       tab_id="vm-tab-overview"),
                                  dbc.Tab(label="⚡ CISA KEV",       tab_id="vm-tab-kev"),
                                  dbc.Tab(label="🔍 CVE Results",    tab_id="vm-tab-cve"),
                                  dbc.Tab(label="🎯 Attack Paths",   tab_id="vm-tab-attack"),
                                  dbc.Tab(label="🔄 Lifecycle",      tab_id="vm-tab-lifecycle"),
                                  dbc.Tab(label="📈 Trends",         tab_id="vm-tab-trends"),
                                  dbc.Tab(label="🖥️ Assets",         tab_id="vm-tab-assets"),
                                  dbc.Tab(label="📋 Assigned Vulns", tab_id="vm-tab-assigned"),
                                  dbc.Tab(label="🔧 Patch / S.W.",   tab_id="vm-tab-patch"),
                                  dbc.Tab(label="⏱️ SLA Compliance", tab_id="vm-tab-sla"),
                                  dbc.Tab(label="🌐 Resource Hub",   tab_id="vm-tab-hub"),
                              ]),

                    html.Div(id="vm-main-content",
                             style={"background": CARD_BG,
                                    "border": BORDER,
                                    "borderTop": "none",
                                    "borderRadius": "0 0 12px 12px",
                                    "overflow": "hidden"}),
                ], width=6),

                # ── RIGHT PANEL: AI + SLA + Quick Ref ────────────────────
                dbc.Col([
                    # AI Risk Analysis
                    _card(
                        html.Div(id="vm-ai-output",
                                 style={"color": "#7a9cc0", "fontSize": "12px",
                                        "whiteSpace": "pre-wrap",
                                        "minHeight": "80px", "maxHeight": "280px",
                                        "overflowY": "auto", "lineHeight": "1.6"}),
                        title="AI Risk Analysis",
                    ),
                    # SLA Overview
                    _card(
                        html.Div(id="vm-sla-summary"),
                        title="SLA Overview",
                    ),
                    # Quick reference
                    _card(
                        *[html.Div([
                            html.Div(sev, style={
                                "color": SEV_COLORS[sev], "fontSize": "10px",
                                "fontWeight": "800", "marginBottom": "1px",
                            }),
                            html.Div(f"Patch within {days}d", style={
                                "color": "#2e3d58", "fontSize": "10px",
                            }),
                            html.Div(style={
                                "height": "2px", "borderRadius": "1px",
                                "background": SEV_COLORS[sev] + "40",
                                "margin": "4px 0 10px",
                            }),
                          ], style={"display": "flex", "flexDirection": "column",
                                    "marginBottom": "2px"})
                          for sev, days in SLA_DAYS.items()],
                        html.Div([
                            html.Div(line, style={"color": "#1e2d44",
                                                   "fontSize": "10px",
                                                   "marginBottom": "3px"})
                            for line in [
                                "KEV = active exploitation confirmed",
                                "EPSS > 0.5 = high exploit probability",
                                "CVSS ≥ 9.0 = Critical · 7-8.9 = High",
                            ]
                        ]),
                        title="SLA Policy",
                    ),
                ], width=3, style={"overflowY": "auto", "maxHeight": "85vh",
                                   "paddingLeft": "4px"}),
            ], className="g-3"),
        ], style={"padding": "0 16px 24px", "background": DARK_BG}),
    ], style={"background": DARK_BG, "minHeight": "100vh"})


# ── Auto-load KEV on tab open ─────────────────────────────────────────────────

@callback(
    Output("vm-kev",         "data"),
    Output("vm-stats-bar",   "children"),
    Output("vm-sla-summary", "children"),
    Input("vm-kev-poll",     "n_intervals"),
    Input("vm-kev-btn",      "n_clicks"),
    State("vm-kev",          "data"),
    State("vm-vulns",        "data"),
    prevent_initial_call=False,
)
def load_kev(n_int, n_btn, existing_kev, vulns):
    kev = existing_kev or []
    if ctx.triggered_id in ("vm-kev-btn", "vm-kev-poll") or not kev:
        kev = _fetch_kev()
        with _LOCK:
            _KEV_CACHE.clear()
            _KEV_CACHE.extend(kev)

    vulns = vulns or []
    n_critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    n_high     = sum(1 for v in vulns if v.get("severity") == "HIGH")
    n_medium   = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    n_low      = sum(1 for v in vulns if v.get("severity") == "LOW")
    overdue    = 0
    for v in vulns:
        sev = v.get("severity", "LOW").upper()
        days = SLA_DAYS.get(sev, 90)
        try:
            assigned = datetime.fromisoformat(v.get("assigned_date", datetime.now().isoformat()))
            if (datetime.now() - assigned).days > days:
                overdue += 1
        except Exception:
            pass

    stats = [
        _stat_card("CISA KEV", str(len(kev)),      "#c0392b", "Known exploited"),
        _stat_card("Critical",  str(n_critical),    "#c0392b"),
        _stat_card("High",      str(n_high),        "#e67e22"),
        _stat_card("Medium",    str(n_medium),      "#f1c40f"),
        _stat_card("Low",       str(n_low),         "#27ae60"),
        _stat_card("⚠ Overdue", str(overdue),       "#9b59b6", "Past SLA"),
    ]

    sla_rows = []
    for sev, days in SLA_DAYS.items():
        count   = sum(1 for v in vulns if v.get("severity") == sev)
        od      = 0
        for v in vulns:
            if v.get("severity") != sev:
                continue
            try:
                assigned = datetime.fromisoformat(v.get("assigned_date", datetime.now().isoformat()))
                if (datetime.now() - assigned).days > days:
                    od += 1
            except Exception:
                pass
        color = SEV_COLORS[sev]
        sla_rows.append(html.Div([
            html.Span(sev, style={"color": color, "fontWeight": "700",
                                   "fontSize": "11px", "minWidth": "65px",
                                   "display": "inline-block"}),
            html.Span(f"{count} vulns", style={"color": "#b0b0b0",
                                                "fontSize": "11px",
                                                "marginRight": "6px"}),
            html.Span(f"({od} overdue)" if od else "✅",
                      style={"color": "#c0392b" if od else "#27ae60",
                             "fontSize": "10px"}),
        ], style={"marginBottom": "4px"}))

    return kev, stats, html.Div(sla_rows)


# ── CVE search ────────────────────────────────────────────────────────────────

@callback(
    Output("vm-cve",           "data"),
    Output("vm-epss",          "data"),
    Output("vm-search-status", "children"),
    Input("vm-search-btn",     "n_clicks"),
    State("vm-search-q",       "value"),
    State("vm-search-sev",     "value"),
    prevent_initial_call=True,
)
def search_cve(n, query, sev):
    if not n or not query:
        raise PreventUpdate
    results = _search_nvd(query.strip(), sev or "ALL")
    if not results:
        return [], {}, f"No results for '{query}'"
    # Fetch EPSS scores
    cve_ids = [r["id"] for r in results]
    epss    = _fetch_epss(cve_ids)
    with _LOCK:
        _CVE_RESULTS.clear()
        _CVE_RESULTS.extend(results)
    return results, epss, f"✅ {len(results)} CVEs found — EPSS loaded for {len(epss)}"


# ── Asset management ──────────────────────────────────────────────────────────

@callback(
    Output("vm-assets",       "data"),
    Output("vm-asset-status", "children"),
    Input("vm-add-asset-btn", "n_clicks"),
    State("vm-asset-name",    "value"),
    State("vm-asset-type",    "value"),
    State("vm-asset-crit",    "value"),
    State("vm-assets",        "data"),
    prevent_initial_call=True,
)
def add_asset(n, name, atype, crit, assets):
    if not n or not name:
        raise PreventUpdate
    assets = assets or []
    asset = {
        "id":       len(assets),
        "name":     name.strip(),
        "type":     atype,
        "crit":     crit,
        "added":    datetime.now().strftime("%Y-%m-%d"),
        "vuln_count": 0,
    }
    assets.append(asset)
    with _LOCK:
        _ASSETS.clear()
        _ASSETS.extend(assets)
    # Persist to Neo4j
    _save_asset_neo4j(asset)
    return assets, f"✅ Asset '{name}' added & persisted ({len(assets)} total)"


# ── Main content renderer ─────────────────────────────────────────────────────

@callback(
    Output("vm-main-content", "children"),
    Input("vm-tabs",   "active_tab"),
    Input("vm-kev",    "data"),
    Input("vm-cve",    "data"),
    Input("vm-epss",   "data"),
    Input("vm-assets", "data"),
    Input("vm-vulns",  "data"),
)
def render_content(tab, kev, cve_results, epss, assets, vulns):
    kev          = kev or []
    cve_results  = cve_results or []
    epss         = epss or {}
    assets       = assets or []
    vulns        = vulns or []
    kev_ids      = {v.get("cveID", "") for v in kev}

    # ── NEW WIZ DASHBOARDS ────────────────────────────────────────────────────
    if tab == "vm-tab-hub":
        return _render_resource_hub(kev)

    if tab == "vm-tab-overview":
        return _render_overview(kev, cve_results, assets, vulns)

    if tab == "vm-tab-attack":
        return _render_attack_paths(kev, epss, assets, vulns)

    if tab == "vm-tab-lifecycle":
        return _render_lifecycle(vulns)

    if tab == "vm-tab-trends":
        return _render_trends(kev, vulns)

    if tab == "vm-tab-patch":
        return _render_patch(kev, cve_results)

    # ── EXISTING TABS ─────────────────────────────────────────────────────────
    if tab == "vm-tab-kev":
        if not kev:
            return _card(html.Div("Click ⚡ Load KEV to fetch latest CISA Known Exploited Vulnerabilities.",
                                   style={"color": "#636e72", "fontSize": "13px",
                                          "textAlign": "center", "padding": "30px"}))
        rows = []
        for v in kev[:50]:
            cve_id    = v.get("cveID", "")
            product   = v.get("product", "")
            vendor    = v.get("vendorProject", "")
            vuln_name = v.get("vulnerabilityName", "")
            date_add  = v.get("dateAdded", "")
            due_date  = v.get("dueDate", "")
            notes     = v.get("shortDescription", "")[:200]
            rows.append(html.Div([
                html.Div([
                    # KEV left bar
                    html.Div(style={"width":"3px","alignSelf":"stretch",
                                    "background":"#e84040","borderRadius":"2px",
                                    "marginRight":"12px","flexShrink":"0"}),
                    html.Div([
                        html.Div([
                            _pill_badge("⚡ KEV", "#e84040", "#2d0a0a"),
                            html.Span(cve_id, style={
                                "color":"#e84040","fontWeight":"700",
                                "fontSize":"13px","fontFamily":"monospace",
                                "marginRight":"10px",
                            }),
                            html.Span(f"{vendor} — {product}",
                                      style={"color":"#8a9cc0","fontSize":"11px",
                                             "marginRight":"10px"}),
                            _pill_badge(f"Added {date_add}", "#5a6a8a", "#131c2e"),
                            _pill_badge(f"Due {due_date}", "#f07b29", "#1e1000"),
                        ], style={"display":"flex","alignItems":"center",
                                  "flexWrap":"wrap","gap":"3px"}),
                        html.Div(vuln_name, style={"color":"#7a8aa8","fontSize":"11px",
                                                    "marginTop":"5px"}),
                        html.Div(notes, style={"color":"#2e3d58","fontSize":"10px",
                                               "marginTop":"3px","lineHeight":"1.5"}),
                    ], style={"flex":"1"}),
                ], style={"display":"flex","alignItems":"flex-start"}),
            ], className="vm-row",
               style={"padding":"11px 14px","borderBottom":"1px solid #0f1830",
                      "cursor":"pointer","transition":"background .15s"}))

        return html.Div([
            html.Div([
                html.Span(f"⚡ {len(kev)} CISA Known Exploited Vulnerabilities",
                          style={"color":"#d0d8e8","fontWeight":"700","fontSize":"14px"}),
                html.Span(" — latest 50 shown",
                          style={"color":"#2e3d58","fontSize":"11px","marginLeft":"8px"}),
            ], style={"padding":"14px 16px","borderBottom":"1px solid #0f1830"}),
            html.Div("Confirmed actively exploited in the wild. Federal agencies must patch within the due date.",
                     style={"padding":"8px 16px 0","color":"#2e3d58","fontSize":"11px"}),
            html.Div(rows, style={"maxHeight":"58vh","overflowY":"auto"}),
        ])

    elif tab == "vm-tab-cve":
        if not cve_results:
            return _card(html.Div("Search for CVEs using the search panel.",
                                   style={"color": "#636e72", "fontSize": "13px",
                                          "textAlign": "center", "padding": "30px"}))
        rows = [_vuln_row(v, kev_ids, epss) for v in cve_results]
        return html.Div([
            html.Div([
                html.Span(f"🔍 {len(cve_results)} NVD Results",
                          style={"color":"#d0d8e8","fontWeight":"700","fontSize":"14px"}),
            ], style={"padding":"14px 16px","borderBottom":"1px solid #0f1830"}),
            html.Div(rows, style={"maxHeight":"58vh","overflowY":"auto"}),
        ])

    elif tab == "vm-tab-assets":
        if not assets:
            return _card(html.Div("Add assets using the Asset Inventory panel.",
                                   style={"color": "#636e72", "fontSize": "13px",
                                          "textAlign": "center", "padding": "30px"}))
        crit_colors = {"critical": "#c0392b", "high": "#e67e22",
                       "medium": "#f1c40f", "low": "#27ae60"}
        rows = []
        for a in assets:
            cc = crit_colors.get(a.get("crit", "medium"), "#636e72")
            rows.append(html.Div([
                html.Div([
                    html.Span("🖥️ " if a["type"] == "server" else
                              "☁️ " if a["type"] == "cloud" else
                              "📦 " if a["type"] == "container" else "🔌 "),
                    html.Span(a.get("name", ""),
                              style={"color": "#e0e0e0", "fontWeight": "700",
                                     "fontSize": "12px", "marginRight": "8px"}),
                    html.Span(a.get("type", "").upper(),
                              style={"color": "#8e9eb0", "fontSize": "10px",
                                     "marginRight": "8px"}),
                    html.Span(f"● {a.get('crit','').upper()}",
                              style={"color": cc, "fontSize": "10px",
                                     "fontWeight": "700"}),
                ]),
                html.Div(f"Added: {a.get('added', '')} | "
                         f"Vulns: {a.get('vuln_count', 0)}",
                         style={"color": "#636e72", "fontSize": "10px",
                                "paddingLeft": "24px"}),
            ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}"}))

        return _card(
            html.Div(f"🖥️ {len(assets)} Assets",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "550px", "overflowY": "auto"}),
        )

    elif tab == "vm-tab-assigned":
        if not vulns:
            return _card(html.Div("No CVEs assigned to assets yet. "
                                   "Use the CVE Results tab to assign.",
                                   style={"color": "#636e72", "fontSize": "13px",
                                          "textAlign": "center", "padding": "30px"}))
        rows = []
        for v in vulns:
            rows.append(html.Div([
                html.Div([
                    _sev_badge(v.get("severity", "UNKNOWN")),
                    html.Span(v.get("id", ""),
                              style={"color": "#3498db", "fontWeight": "700",
                                     "fontSize": "12px", "marginRight": "8px"}),
                    html.Span(f"→ {v.get('asset', '—')}",
                              style={"color": "#e0e0e0", "fontSize": "11px"}),
                ]),
                _sla_bar(v.get("severity", "LOW"), v.get("assigned_date",
                          datetime.now().isoformat())),
            ], style={"padding": "8px", "borderBottom": f"1px solid {DARK_BG}"}))

        return _card(
            html.Div(f"📋 {len(vulns)} Assigned Vulnerabilities",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            html.Div(rows, style={"maxHeight": "550px", "overflowY": "auto"}),
        )

    elif tab == "vm-tab-sla":
        now = datetime.now()
        overdue, due_today, due_week, on_track = [], [], [], []
        for v in vulns:
            sev   = v.get("severity", "LOW").upper()
            days  = SLA_DAYS.get(sev, 90)
            try:
                assigned = datetime.fromisoformat(
                    v.get("assigned_date", now.isoformat()))
                due_dt   = assigned + timedelta(days=days)
                delta    = (due_dt - now).days
                if delta < 0:
                    overdue.append((v, delta))
                elif delta == 0:
                    due_today.append((v, delta))
                elif delta <= 7:
                    due_week.append((v, delta))
                else:
                    on_track.append((v, delta))
            except Exception:
                pass

        def _sla_section(title, items, color):
            if not items:
                return html.Span()
            rows = []
            for v, d in items:
                rows.append(html.Div([
                    _sev_badge(v.get("severity", "?")),
                    html.Span(v.get("id", ""),
                              style={"color": "#3498db", "fontSize": "12px",
                                     "fontWeight": "700", "marginRight": "6px"}),
                    html.Span(f"→ {v.get('asset', '—')}",
                              style={"color": "#b0b0b0", "fontSize": "11px",
                                     "marginRight": "6px"}),
                    html.Span(f"{abs(d)}d overdue" if d < 0 else f"due in {d}d",
                              style={"color": color, "fontSize": "10px",
                                     "fontWeight": "700"}),
                ], style={"padding": "4px 8px",
                          "borderBottom": f"1px solid {DARK_BG}"}))
            return html.Div([
                html.Div(f"{title} ({len(items)})",
                         style={"color": color, "fontWeight": "700",
                                "fontSize": "12px", "padding": "6px 8px",
                                "background": "#1a1d24",
                                "borderRadius": "4px",
                                "marginBottom": "4px"}),
                html.Div(rows),
            ], style={"marginBottom": "12px"})

        return _card(
            html.Div("⏱️ Patch SLA Dashboard",
                     style={"color": "#e0e0e0", "fontWeight": "600",
                            "marginBottom": "10px"}),
            _sla_section("🔴 OVERDUE",    overdue,    "#c0392b"),
            _sla_section("🟠 Due Today",  due_today,  "#e67e22"),
            _sla_section("🟡 Due This Week", due_week, "#f1c40f"),
            _sla_section("🟢 On Track",   on_track,   "#27ae60"),
            html.Div("No vulnerabilities assigned yet." if not vulns else "",
                     style={"color": "#636e72", "fontSize": "12px",
                            "textAlign": "center", "padding": "20px"}),
        )

    return html.Div()


# ── AI prioritization ─────────────────────────────────────────────────────────

@callback(
    Output("vm-ai-output",  "children"),
    Input("vm-ai-pri-btn",  "n_clicks"),
    State("vm-kev",         "data"),
    State("vm-cve",         "data"),
    State("vm-epss",        "data"),
    State("vm-assets",      "data"),
    State("vm-vulns",       "data"),
    prevent_initial_call=True,
)
def ai_prioritize(n, kev, cve_results, epss, assets, vulns):
    if not n:
        raise PreventUpdate
    kev          = kev or []
    cve_results  = cve_results or []
    epss         = epss or {}
    assets       = assets or []
    vulns        = vulns or []
    kev_ids      = {v.get("cveID", "") for v in kev[:20]}

    cve_summary = "\n".join(
        f"- {c['id']} ({c['severity']} {c['score']}) "
        f"EPSS={epss.get(c['id'], 0):.2%} "
        f"{'[KEV]' if c['id'] in kev_ids else ''}: "
        f"{c['description'][:120]}"
        for c in cve_results[:15]
    )
    asset_summary = "\n".join(
        f"- {a['name']} ({a['type']}, criticality={a['crit']})"
        for a in assets[:10]
    )

    prompt = (
        f"You are a vulnerability management expert. Prioritize these vulnerabilities "
        f"for remediation using a risk-based approach.\n\n"
        f"Assets:\n{asset_summary or 'None defined'}\n\n"
        f"CVEs found:\n{cve_summary or 'None searched'}\n\n"
        f"Provide:\n"
        f"1) **Top 5 Priority CVEs** to patch immediately (with justification)\n"
        f"2) **Risk Score** for each (considering CVSS, EPSS, KEV status, asset criticality)\n"
        f"3) **Patch Timeline** recommendation per CVE\n"
        f"4) **Compensating Controls** for any that cannot be patched immediately\n"
        f"5) **Threat Context** — are any being actively exploited by known threat actors right now?\n\n"
        f"Format as a concise prioritized action plan."
    )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ── HTML export ───────────────────────────────────────────────────────────────

@callback(
    Output("vm-download",   "data"),
    Input("vm-export-btn",  "n_clicks"),
    State("vm-kev",         "data"),
    State("vm-cve",         "data"),
    State("vm-epss",        "data"),
    State("vm-assets",      "data"),
    State("vm-vulns",       "data"),
    State("vm-ai-output",   "children"),
    prevent_initial_call=True,
)
def export_report(n, kev, cve_results, epss, assets, vulns, ai_out):
    if not n:
        raise PreventUpdate
    kev         = kev or []
    cve_results = cve_results or []
    epss        = epss or {}
    assets      = assets or []
    vulns       = vulns or []
    ts = datetime.now().strftime("%Y%m%d_%H%M")

    kev_cve_ids = {k.get("cveID", "") for k in kev}
    cve_rows_list = []
    for c in cve_results[:30]:
        sev_color = SEV_COLORS.get(c["severity"], "#fff")
        kev_flag  = "⚡ KEV" if c["id"] in kev_cve_ids else ""
        epss_pct  = f"{epss.get(c['id'], 0):.2%}"
        cve_rows_list.append(
            f"<tr>"
            f"<td>{c['id']}</td>"
            f"<td style='color:{sev_color}'>{c['severity']}</td>"
            f"<td>{c['score']}</td>"
            f"<td>{epss_pct}</td>"
            f"<td>{kev_flag}</td>"
            f"<td>{c['description'][:120]}</td>"
            f"</tr>"
        )
    cve_rows = "".join(cve_rows_list)
    asset_rows = "".join(
        f"<tr><td>{a['name']}</td><td>{a['type']}</td>"
        f"<td>{a['crit']}</td><td>{a['vuln_count']}</td></tr>"
        for a in assets
    )

    html_content = f"""<!DOCTYPE html>
<html><head>
<meta charset='utf-8'>
<title>Vulnerability Management Report — {ts}</title>
<style>
  body{{font-family:Arial,sans-serif;background:#0d1117;color:#e0e0e0;
       max-width:1100px;margin:40px auto;padding:0 20px;}}
  h1,h2,h3{{color:#e74c3c;}}
  table{{border-collapse:collapse;width:100%;margin:16px 0;}}
  th{{background:#2c3347;color:#e0e0e0;padding:8px;text-align:left;font-size:12px;}}
  td{{padding:6px 8px;border-bottom:1px solid #2c3347;color:#b0b0b0;font-size:11px;}}
  pre{{background:#161b22;padding:12px;border-radius:6px;
       color:#50fa7b;font-size:11px;white-space:pre-wrap;}}
  .stat{{display:inline-block;background:#161b22;border:1px solid #30363d;
         border-radius:6px;padding:10px 18px;margin:4px;text-align:center;}}
  .stat-val{{font-size:24px;font-weight:700;color:#e74c3c;}}
  .stat-lbl{{font-size:11px;color:#8e9eb0;}}
</style>
</head><body>
<h1>🛡️ Vulnerability Management Report</h1>
<p style='color:#636e72;'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC</p>

<div>
  <div class='stat'><div class='stat-val'>{len(kev)}</div><div class='stat-lbl'>CISA KEV</div></div>
  <div class='stat'><div class='stat-val'>{len(cve_results)}</div><div class='stat-lbl'>CVEs Found</div></div>
  <div class='stat'><div class='stat-val'>{len(assets)}</div><div class='stat-lbl'>Assets</div></div>
  <div class='stat'><div class='stat-val'>{len(vulns)}</div><div class='stat-lbl'>Assigned</div></div>
</div>

<h2>CVE Results</h2>
<table><tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>EPSS</th><th>KEV</th><th>Description</th></tr>
{cve_rows or '<tr><td colspan=6>No CVEs searched</td></tr>'}
</table>

<h2>Asset Inventory</h2>
<table><tr><th>Name</th><th>Type</th><th>Criticality</th><th>Vulns</th></tr>
{asset_rows or '<tr><td colspan=4>No assets defined</td></tr>'}
</table>

<h2>AI Risk Analysis</h2>
<pre>{ai_out or 'Run AI Risk Prioritization first.'}</pre>

<hr><p style='color:#636e72;font-size:11px;'>
Vulnerability Intelligence Dashboard — Vulnerability Management Module
</p></body></html>"""

    return dcc.send_string(html_content, f"vuln_report_{ts}.html")


# ── Startup hydration from Neo4j ──────────────────────────────────────────────

@callback(
    Output("vm-assets", "data", allow_duplicate=True),
    Output("vm-vulns",  "data", allow_duplicate=True),
    Input("vm-hydrate-poll", "n_intervals"),
    prevent_initial_call="initial_duplicate",
)
def hydrate_from_neo4j(n):
    """On first load, pull persisted assets + assigned vulns from Neo4j."""
    assets = _load_assets_neo4j()
    vulns  = _load_vuln_assignments_neo4j()
    if assets:
        with _LOCK:
            _ASSETS.clear()
            _ASSETS.extend(assets)
    if vulns:
        with _LOCK:
            _VULNS.clear()
            _VULNS.extend(vulns)
    return assets or [], vulns or []


# ── Populate asset dropdown for CVE assignment ────────────────────────────────

@callback(
    Output("vm-assign-asset", "options"),
    Input("vm-assets", "data"),
)
def update_assign_dropdown(assets):
    assets = assets or []
    return [{"label": a["name"], "value": a["name"]} for a in assets]


# ── Assign CVE to Asset ──────────────────────────────────────────────────────

@callback(
    Output("vm-vulns",         "data", allow_duplicate=True),
    Output("vm-assign-status", "children"),
    Input("vm-assign-btn",     "n_clicks"),
    State("vm-assign-cve",     "value"),
    State("vm-assign-sev",     "value"),
    State("vm-assign-asset",   "value"),
    State("vm-vulns",          "data"),
    prevent_initial_call=True,
)
def assign_cve_to_asset(n, cve_id, sev, asset_name, vulns):
    if not n or not cve_id or not asset_name:
        raise PreventUpdate
    vulns = vulns or []
    cve_id = cve_id.strip().upper()

    # Check for duplicate
    for v in vulns:
        if v.get("id") == cve_id and v.get("asset") == asset_name:
            return vulns, f"⚠ {cve_id} already assigned to {asset_name}"

    assignment = {
        "id":            cve_id,
        "severity":      sev or "HIGH",
        "score":         "",
        "description":   "",
        "asset":         asset_name,
        "assigned_date": datetime.now().isoformat(),
    }
    vulns.append(assignment)
    with _LOCK:
        _VULNS.clear()
        _VULNS.extend(vulns)

    # Persist to Neo4j
    ok = _save_vuln_assignment_neo4j(assignment)
    if ok:
        _update_asset_vuln_count_neo4j(asset_name)
    status = "✅" if ok else "⚠ saved locally only"
    return vulns, f"{status} {cve_id} → {asset_name} ({len(vulns)} total)"
