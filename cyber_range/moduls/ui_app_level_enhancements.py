"""
App-Level Enhancements
=======================
4 features wired directly into the main app:
7.  Real-time Alert System   — toast notifications for new CRITICAL CVEs
8.  AI Response Quality Rater — star ratings stored in session
9.  BloodHound AI Insight    — auto-AI analysis after capture
10. Global Search Bar        — search findings/CVEs from anywhere
"""

import sys
sys.path.insert(0, "/home/kali/.local/lib/python3.13/site-packages")

import os, json, time
from dash import html, dcc, callback, Input, Output, State, no_update, ctx
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

# ─── MODULE-LEVEL STATE ────────────────────────────────────────────────────
_LAST_KNOWN_CRITICAL = [0]      # track count to detect new ones
_RATING_LOG          = []       # [{"ts","source","stars","text_preview"}]

# ═══════════════════════════════════════════════════════════════════════════
# 7. REAL-TIME ALERT SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

def alert_components():
    """Return the dcc.Interval + toast container to inject into app layout."""
    return [
        dcc.Interval(id="alert-poll-interval", interval=30_000, n_intervals=0),
        html.Div(id="alert-toast-container",
                 style={"position":"fixed","top":"70px","right":"20px",
                        "zIndex":"9999","maxWidth":"360px"}),
    ]


@callback(
    Output("alert-toast-container", "children"),
    Input("alert-poll-interval",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_critical_alerts(n):
    try:
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","Adomaa12@"))
        with drv.session() as s:
            row = s.run("""
                MATCH (f:Finding) WHERE f.cve IS NOT NULL
                AND toFloat(coalesce(toString(f.cvss),'0')) >= 9.0
                RETURN count(f) AS n
            """).single()
            top = s.run("""
                MATCH (f:Finding) WHERE f.cve IS NOT NULL
                AND toFloat(coalesce(toString(f.cvss),'0')) >= 9.0
                RETURN f.cve AS cve, toString(f.cvss) AS cvss, coalesce(f.host,'?') AS host
                ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 3
            """).data()
        drv.close()
        current = row["n"] if row else 0
    except Exception:
        return no_update

    prev = _LAST_KNOWN_CRITICAL[0]
    _LAST_KNOWN_CRITICAL[0] = current

    # Only toast if the count increased (new critical detected)
    if current <= prev and n > 0:
        return no_update

    if current == 0:
        return no_update

    top_str = " · ".join(f"{r['cve']} ({r['host']})" for r in top[:2])
    delta   = current - prev if n > 0 else 0
    heading = f"🔴 {delta} New Critical CVE{'s' if delta!=1 else ''}!" if delta > 0 else f"🔴 {current} Critical CVEs Active"

    toast = dbc.Toast([
        html.P(f"Total critical (CVSS≥9): {current}", className="mb-1",
               style={"color":"#ffcccc","fontSize":"12px"}),
        html.P(top_str, className="mb-0",
               style={"color":"#ff8888","fontSize":"11px","fontStyle":"italic"}),
    ],
    header=heading,
    is_open=True,
    dismissable=True,
    duration=12000,
    style={"backgroundColor":"#1a0000","border":"1px solid #ff4444",
           "color":"#fff","fontSize":"13px"},
    header_style={"color":"#ff4444","fontWeight":"bold"},
    )
    return toast


# ═══════════════════════════════════════════════════════════════════════════
# 8. AI RESPONSE QUALITY RATER
# ═══════════════════════════════════════════════════════════════════════════

def rating_widget(source_id: str, label: str = "Rate this response"):
    """Returns a reusable ⭐ rating row for any AI response panel."""
    return html.Div([
        html.Small(label, style={"color":"#888","fontSize":"11px"}),
        dbc.ButtonGroup([
            dbc.Button("★", id={"type":"rating-btn","source":source_id,"stars":str(s)},
                       n_clicks=0, size="sm", outline=True, color="warning",
                       style={"fontSize":"14px","padding":"2px 6px"})
            for s in [1,2,3,4,5]
        ], className="ms-2"),
        html.Span(id={"type":"rating-result","source":source_id},
                  style={"color":"#ffcc00","fontSize":"11px","marginLeft":"8px"}),
    ], style={"marginTop":"6px"})


@callback(
    Output({"type":"rating-result","source":"chatbot-local"}, "children"),
    Input({"type":"rating-btn","source":"chatbot-local","stars":"1"}, "n_clicks"),
    Input({"type":"rating-btn","source":"chatbot-local","stars":"2"}, "n_clicks"),
    Input({"type":"rating-btn","source":"chatbot-local","stars":"3"}, "n_clicks"),
    Input({"type":"rating-btn","source":"chatbot-local","stars":"4"}, "n_clicks"),
    Input({"type":"rating-btn","source":"chatbot-local","stars":"5"}, "n_clicks"),
    prevent_initial_call=True,
)
def rate_local(*args):
    triggered = ctx.triggered_id
    if not triggered: return no_update
    stars = int(triggered.get("stars",0))
    _RATING_LOG.append({"ts":time.strftime("%H:%M:%S"),"source":"Local AI","stars":stars})
    return f"{'★'*stars}{'☆'*(5-stars)}  ({stars}/5 saved)"


# ═══════════════════════════════════════════════════════════════════════════
# 9. BLOODHOUND AI INSIGHT
# ═══════════════════════════════════════════════════════════════════════════

def bloodhound_ai_panel():
    """Card to embed in the BloodHound / Assessment tab."""
    return dbc.Card([
        dbc.CardHeader("🤖 AI Privilege Escalation Analysis",
                       style={"backgroundColor":"#1a0000","color":"#ff6666","fontWeight":"bold"}),
        dbc.CardBody([
            dbc.Button("🔍 Generate AI Insight from Latest Capture",
                       id="bh-ai-btn", color="danger", className="fw-bold w-100 mb-3"),
            dcc.Loading(html.Pre(id="bh-ai-result",
                                 children="Click to analyse the latest BloodHound capture with Claude + ChatGPT.",
                                 style={"fontSize":"12px","color":"#ff8888","whiteSpace":"pre-wrap",
                                        "minHeight":"120px","backgroundColor":"#0d0d0d",
                                        "padding":"10px","border":"1px solid #4a0000",
                                        "borderRadius":"4px","margin":"0"}),
                        color="#ff6666"),
        ]),
    ], style={"border":"1px solid #4a0000","backgroundColor":"#0d0d0d","marginTop":"20px"})


@callback(
    Output("bh-ai-result", "children"),
    Input("bh-ai-btn",     "n_clicks"),
    prevent_initial_call=True,
)
def bh_ai_insight(_):
    # Pull AD/BloodHound data from Neo4j
    try:
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","Adomaa12@"))
        with drv.session() as s:
            # High-value targets
            hvt = s.run("""
                MATCH (c:Computer) WHERE c.unconstraineddelegation=true OR c.enabled=true
                RETURN c.name AS computer, c.unconstraineddelegation AS delegation LIMIT 5
            """).data()
            # Admin paths
            admin = s.run("""
                MATCH p=(u:User)-[:MemberOf*1..3]->(g:Group)-[:AdminTo]->(c:Computer)
                RETURN u.name AS user, g.name AS group_, c.name AS target LIMIT 5
            """).data()
            # Kerberoastable
            kerb = s.run("""
                MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true
                RETURN u.name AS user, u.serviceprincipalnames AS spns LIMIT 5
            """).data()
        drv.close()
        context = (
            f"UNCONSTRAINED DELEGATION COMPUTERS: {json.dumps(hvt)}\n"
            f"ADMIN PATHS: {json.dumps(admin)}\n"
            f"KERBEROASTABLE USERS: {json.dumps(kerb)}"
        )
    except Exception as e:
        context = f"AD data unavailable: {e}"

    prompt = (
        f"You are a red team analyst. Analyse this Active Directory BloodHound data and:\n"
        f"1. Identify the most dangerous privilege escalation path\n"
        f"2. Explain the attack step-by-step\n"
        f"3. Recommend immediate mitigations\n\n"
        f"AD DATA:\n{context}"
    )

    results = ["=== LOCAL AI ==="]
    try:
        from llm_engine import call_llm
        results.append(call_llm(prompt))
    except Exception as e:
        results.append(f"Local AI error: {e}")

    results.append("\n=== CLAUDE ===")
    try:
        import anthropic as _ant
        ac = _ant.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY",""))
        msg = None
        for m in ["claude-sonnet-4-6","claude-sonnet-4-5-20250929","claude-haiku-4-5-20251001"]:
            try:
                msg = ac.messages.create(model=m,max_tokens=500,
                    system="You are a red team AD security analyst.",
                    messages=[{"role":"user","content":prompt}])
                break
            except Exception: continue
        results.append(msg.content[0].text if msg else "No Claude available.")
    except Exception as e:
        results.append(f"Claude error: {e}")

    return "\n\n".join(results)


# ═══════════════════════════════════════════════════════════════════════════
# 10. GLOBAL SEARCH BAR
# ═══════════════════════════════════════════════════════════════════════════

def global_search_components():
    """Returns search input + results dropdown to embed in the navbar."""
    return html.Div([
        dbc.InputGroup([
            dbc.Input(id="global-search-input",
                      placeholder="🔍 Search CVEs, hosts, techniques...",
                      type="text", debounce=True,
                      style={"backgroundColor":"#111","color":"#fff",
                             "border":"1px solid #333","fontSize":"12px",
                             "width":"220px"}),
        ], size="sm"),
        html.Div(id="global-search-results",
                 style={"position":"absolute","top":"36px","left":"0",
                        "zIndex":"9999","width":"320px","backgroundColor":"#111",
                        "border":"1px solid #444","borderRadius":"4px",
                        "maxHeight":"300px","overflowY":"auto"}),
    ], style={"position":"relative","display":"inline-block"})


@callback(
    Output("global-search-results", "children"),
    Input("global-search-input",    "value"),
    prevent_initial_call=True,
)
def do_global_search(query):
    if not query or len(query.strip()) < 2:
        return ""
    q = query.strip()
    try:
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","Adomaa12@"))
        with drv.session() as s:
            rows = s.run("""
                MATCH (f:Finding) WHERE f.cve IS NOT NULL AND
                  (toLower(f.cve) CONTAINS toLower($q) OR
                   toLower(coalesce(f.host,'')) CONTAINS toLower($q) OR
                   toLower(coalesce(f.name,'')) CONTAINS toLower($q))
                RETURN f.cve AS cve, toString(f.cvss) AS cvss,
                       coalesce(f.host,'?') AS host
                ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 8
            """, q=q).data()
        drv.close()
    except Exception as e:
        return html.Div(f"Search error: {e}", style={"color":"#ff4444","padding":"8px","fontSize":"11px"})

    if not rows:
        return html.Div("No results found.", style={"color":"#888","padding":"8px","fontSize":"11px"})

    items = []
    for r in rows:
        cvss_f = float(r["cvss"]) if r["cvss"] and r["cvss"] not in (None,"None") else 0
        col = "#ff4444" if cvss_f>=9 else "#ff8800" if cvss_f>=7 else "#ffcc00"
        items.append(html.Div([
            html.Span(r["cve"], style={"color":col,"fontWeight":"bold","fontSize":"12px"}),
            html.Span(f"  CVSS:{r['cvss']}  {r['host']}",
                      style={"color":"#aaa","fontSize":"11px","marginLeft":"6px"}),
        ], style={"padding":"6px 10px","borderBottom":"1px solid #222",
                  "cursor":"pointer",
                  "transition":"background 0.15s"},
           className="global-search-item"))
    return html.Div(items)
