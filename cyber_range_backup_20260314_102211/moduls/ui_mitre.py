import dash_bootstrap_components as dbc
from dash import html, dcc
import dash_cytoscape as cyto


def generate_mitre_layout():
    """Generates the advanced MITRE ATT&CK Intelligence UI structure."""
    return html.Div(
        [
            # ----------------------------------------------------------
            # HEADER TITLE & DESCRIPTION
            # ----------------------------------------------------------
            html.H2(
                "🧩 Context-Aware MITRE ATT&CK Portal",
                className="text-warning mb-2",
                style={"fontWeight": "bold"}
            ),
            html.P(
                "Map Tactics, Techniques, and Threat Actors directly derived from live Assessment Scans and Vulnerability Feeds inside your environment.",
                className="text-light",
                style={"opacity": "0.85", "fontSize": "18px"}
            ),

            html.Hr(style={"borderColor": "#444"}),

            # ----------------------------------------------------------
            # DYNAMIC FILTERING DROPDOWNS (POPULATED FROM NEO4J)
            # ----------------------------------------------------------
            html.Div(
                [
                    dbc.Row([
                        dbc.Col([
                            html.Label("MITRE Tactics (Enterprise Matrix):", className="fw-bold text-info"),
                            dcc.Dropdown(
                                id="mitre-tactic-dropdown",
                                placeholder="Select an actively targeted Tactic...",
                                className="mb-3 text-dark"
                            )
                        ], width=6),
                        dbc.Col([
                            html.Label("MITRE Techniques (Enterprise Matrix):", className="fw-bold text-info"),
                            dcc.Dropdown(
                                id="mitre-technique-dropdown",
                                placeholder="Select a specific Technique...",
                                className="mb-3 text-dark"
                            )
                        ], width=6)
                    ]),

                    dbc.Row([
                        dbc.Col([
                            dbc.Button(
                                "🔍 Render Attack Chain Graph",
                                id="mitre-load-btn",
                                color="warning",
                                className="mt-3 mb-4 fw-bold",
                                style={"border": "1px solid #ffcc00", "boxShadow": "0px 0px 8px #ffcc00"}
                            ),
                        ])
                    ])
                ]
            ),

            # ----------------------------------------------------------
            # GRAPH TITLE
            # ----------------------------------------------------------
            html.Div(
                id="mitre-graph-dynamic-title",
                className="text-warning mb-3",
                style={"fontSize": "22px", "fontWeight": "bold"},
            ),

            # ----------------------------------------------------------
            # EXPORT BUTTON
            # ----------------------------------------------------------
            html.Div([
                dbc.ButtonGroup([
                    dbc.Button("▶ Start Dance", id="mitre-btn-start", color="success", size="sm"),
                    dbc.Button("⏸ Stop Dance", id="mitre-btn-stop", color="danger", size="sm"),
                    dbc.Button("🔄 Restart", id="mitre-btn-restart", color="warning", size="sm"),
                ], style={"float": "left"}),
                dbc.Button("📸 Export Graph (PNG)", id="mitre-export-png", color="secondary", size="sm", className="mb-2", style={"float": "right"})
            ], style={"width": "100%", "marginBottom": "10px", "display": "inline-block"}),

            # ----------------------------------------------------------
            # CONTEXT-AWARE CYTOSCAPE GRAPH & SIDE PANEL
            # ----------------------------------------------------------
            dbc.Row([
                dbc.Col([
                    dcc.Interval(id="mitre-dance-timer", interval=4000, n_intervals=0, disabled=False),
                    html.Audio(id="mitre-dance-audio", src="https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3", autoPlay=True, loop=True, style={"display": "none"}),
                    cyto.Cytoscape(
                        id="mitre-cytoscape-graph",
                        layout={"name": "cola", "animate": True, "infinite": True, "randomize": False, "refresh": 3, "animationDuration": 3800, "avoidOverlap": True},  # Slow birds-in-flight dance
                        style={
                            "width": "100%",
                            "height": "700px",
                            "backgroundColor": "#0d0d0d",     # Deep dark mode
                            "border": "1px solid #33ccff",    # Neon border
                            "borderRadius": "10px",
                            "boxShadow": "0px 0px 15px rgba(51, 204, 255, 0.2)"
                        },
                        elements=[],
                        stylesheet=[
                            # Base Node styling
                            {
                                "selector": "node",
                                "style": {
                                    "label": "data(label)",
                                    "font-size": "11px",
                                    "color": "white",
                                    "text-outline-color": "#111",
                                    "text-outline-width": 1.5,
                                    "text-valign": "center",
                                    "text-wrap": "wrap",
                                    "text-max-width": "120px"
                                }
                            },
                            
                            # 🔴 Threat Actors (Red/Evil)
                            {
                                "selector": "node[type='ThreatActor']",
                                "style": {
                                    "background-color": "#ff0040", 
                                    "shape": "octagon",
                                    "width": "50px", "height": "50px"
                                }
                            },
                            # 🟠 MITRE Tactic 
                            {
                                "selector": "node[type='Tactic']",
                                "style": {
                                    "background-color": "#ff8c00", 
                                    "shape": "diamond",
                                    "width": "45px", "height": "45px"
                                }
                            },
                            # 🟣 MITRE Technique
                            {
                                "selector": "node[type='Technique']",
                                "style": {
                                    "background-color": "#8e44ad", 
                                    "shape": "rectangle",
                                    "width": "40px", "height": "40px"
                                }
                            },
                            # 🟡 Vulnerabilities (CVEs)
                            {
                                "selector": "node[type='Vulnerability']",
                                "style": {
                                    "background-color": "#f1c40f", 
                                    "shape": "triangle",
                                    "width": "35px", "height": "35px",
                                    "color": "#111",
                                    "text-outline-width": 0 # readable dark text
                                }
                            },
                            # 🟡 Findings (ZAP/Imports)
                            {
                                "selector": "node[type='Finding']",
                                "style": {
                                    "background-color": "#e67e22", 
                                    "shape": "triangle",
                                    "width": "35px", "height": "35px",
                                    "color": "#111",
                                    "text-outline-width": 0 # readable dark text
                                }
                            },
                            # 🔵 Hosts/Assets (Scanned systems)
                            {
                                "selector": "node[type='Host']",
                                "style": {
                                    "background-color": "#3498db", 
                                    "shape": "round-rectangle",
                                    "width": "50px", "height": "30px"
                                }
                            },
                            # 🟢 Services (Running on hosts)
                            {
                                "selector": "node[type='Service']",
                                "style": {
                                    "background-color": "#2ecc71", 
                                    "shape": "ellipse",
                                    "width": "30px", "height": "30px"
                                }
                            },

                            # --- EDGES (Arrows) ---
                            {
                                "selector": "edge",
                                "style": {
                                    "line-color": "#555",
                                    "width": 2,
                                    "target-arrow-shape": "triangle",
                                    "target-arrow-color": "#555",
                                    "curve-style": "bezier",
                                    "label": "data(relation)",
                                    "font-size": "9px",
                                    "color": "#999",
                                    "text-rotation": "autorotate",
                                    "text-background-opacity": 1,
                                    "text-background-color": "#0d0d0d"
                                }
                            },
                            
                            # Specific highlighted edges
                            {
                                "selector": "edge[relation='EXPLOITS']",
                                "style": {"line-color": "#ff0040", "target-arrow-color": "#ff0040", "width": 3}
                            },
                            {
                                "selector": "edge[relation='USES']",
                                "style": {"line-color": "#ff8c00", "target-arrow-color": "#ff8c00"}
                            }
                        ]
                    )
                ], width=8),

                dbc.Col([
                    html.Div(
                        id="mitre-node-details-panel",
                        children=[
                            html.H4("Node Details", className="text-info", style={"borderBottom": "1px solid #444", "paddingBottom": "10px"}),
                            html.P("Select a node in the graph to view context, NVD information, Exploit Databases, and Escalation Paths.", className="text-muted mt-3")
                        ],
                        style={
                            "backgroundColor": "#111", 
                            "border": "1px solid #444", 
                            "borderRadius": "8px", 
                            "padding": "20px", 
                            "height": "700px", 
                            "overflowY": "auto",
                            "color": "#eee"
                        }
                    )
                ], width=4)
            ]),
        ],
        style={"padding": "30px", "backgroundColor": "#1a1a1a", "minHeight": "100vh"}
    )

from dash import Input, Output, State, no_update, callback

def __neo4j_session():
    from neo4j import GraphDatabase
    return GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))

@callback(
    Output("mitre-tactic-dropdown", "options"),
    Input("mitre-tactic-dropdown", "id")
)
def load_detected_tactics(_):
    # Load all Tactics from the enterprise matrix
    query = """
    MATCH (tac:Tactic)
    RETURN DISTINCT tac.id AS id, coalesce(tac.name, tac.label) AS name
    ORDER BY id
    """
    try:
        driver = __neo4j_session()
        with driver.session() as session:
            res = session.run(query).data()
        driver.close()
        return [{"label": f"{r['id']} - {r['name']}", "value": r['id']} for r in res]
    except Exception as e:
        print("[MITRE ERROR]", e)
        return []

@callback(
    Output("mitre-technique-dropdown", "options"),
    Input("mitre-tactic-dropdown", "value"),
    prevent_initial_call=True
)
def load_detected_techniques(tactic_id):
    if not tactic_id:
        return []

    query = """
    MATCH (tech:Technique)-[:PART_OF]->(tac:Tactic {id: $tactic_id})
    RETURN DISTINCT tech.id AS id, coalesce(tech.name, tech.label) AS name
    ORDER BY id
    """
    try:
        driver = __neo4j_session()
        with driver.session() as session:
            res = session.run(query, tactic_id=tactic_id).data()
        driver.close()
        return [{"label": f"{r['id']} - {r['name']}", "value": r['id']} for r in res]
    except:
        return []

@callback(
    Output("mitre-cytoscape-graph", "elements"),
    Output("mitre-graph-dynamic-title", "children"),
    Input("mitre-load-btn", "n_clicks"),
    State("mitre-tactic-dropdown", "value"),
    State("mitre-technique-dropdown", "value"),
    prevent_initial_call=True
)
def render_mitre_graph(n_clicks, tactic_id, technique_id):
    if not tactic_id and not technique_id:
        # Load the macro view of all impacted assets
        query = """
        MATCH p=(h:Host)-[*1..2]->(v)-[:MAPS_TO_TECHNIQUE]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
        WHERE v:Vulnerability OR v:Finding
        OPTIONAL MATCH p2=(tech)<-[:USES]-(actor:ThreatActor)
        RETURN p, p2 LIMIT 150
        """
        title = "Full Environment Attack Surface Chain"
        params = {}

    elif tactic_id and not technique_id:
        query = """
        MATCH ptac=(tac:Tactic {id: $tac_id})
        OPTIONAL MATCH p1=(tech:Technique)-[:PART_OF]->(tac)
        OPTIONAL MATCH p2=(v)-[:MAPS_TO_TECHNIQUE]->(tech) WHERE v:Vulnerability OR v:Finding
        OPTIONAL MATCH p3=(h:Host)-[*1..2]->(v)
        OPTIONAL MATCH p4=(tech)<-[:USES]-(actor:ThreatActor)
        RETURN ptac, p1, p2, p3, p4 LIMIT 150
        """
        title = f"Attack Chains Targeting Tactic: {tactic_id}"
        params = {"tac_id": tactic_id}

    else:
        query = """
        MATCH ptech=(tech:Technique {id: $tech_id})
        OPTIONAL MATCH p1=(tech)-[:PART_OF]->(tac:Tactic)
        OPTIONAL MATCH p2=(v)-[:MAPS_TO_TECHNIQUE]->(tech) WHERE v:Vulnerability OR v:Finding
        OPTIONAL MATCH p3=(h:Host)-[*1..2]->(v)
        OPTIONAL MATCH p4=(tech)<-[:USES]-(actor:ThreatActor)
        RETURN ptech, p1, p2, p3, p4 LIMIT 150
        """
        title = f"Contextual Threat Path for Technique: {technique_id}"
        params = {"tech_id": technique_id}

    elements = []
    added_nodes = set()
    added_edges = set()

    try:
        driver = __neo4j_session()
        with driver.session() as session:
            results = session.run(query, **params)
            for record in results:
                for k in record.keys():
                    path = record[k]
                    if not path:
                        continue
                    
                    # Parse Nodes
                    for node in path.nodes:
                        nid = str(node.id)
                        if nid not in added_nodes:
                            node_type = list(node.labels)[0]
                            label = node.get("name") or node.get("label") or node.get("id") or node.get("ip") or node.get("cve") or "Unknown"
                            
                            elements.append({
                                "data": {
                                    "id": nid,
                                    "label": str(label),
                                    "type": node_type
                                }
                            })
                            added_nodes.add(nid)
                    
                    # Parse Relationships
                    for rel in path.relationships:
                        eid = str(rel.id)
                        if eid not in added_edges:
                            elements.append({
                                "data": {
                                    "id": eid,
                                    "source": str(rel.start_node.id),
                                    "target": str(rel.end_node.id),
                                    "relation": rel.type
                                }
                            })
                            added_edges.add(eid)
        driver.close()
        
    except Exception as e:
        print("[MITRE GRAPH ERROR]", e)
        return [], "Error Generating Graph"

    return elements, title

@callback(
    Output("mitre-cytoscape-graph", "generateImage"),
    Input("mitre-export-png", "n_clicks"),
    prevent_initial_call=True
)
def export_graph_as_png(n_clicks):
    if n_clicks:
        return {"type": "png", "action": "download"}
    return no_update

@callback(
    Output("mitre-node-details-panel", "children"),
    Input("mitre-cytoscape-graph", "tapNodeData"),
    prevent_initial_call=True
)
def display_mitre_node_details(node_data):
    from dash import html
    if not node_data:
        return [
            html.H4("Node Details", className="text-info", style={"borderBottom": "1px solid #444", "paddingBottom": "10px"}),
            html.P("Select a node in the graph to view context, NVD information, Exploit Databases, and Escalation Paths.", className="text-muted mt-3")
        ]

    nid = node_data.get("id")
    ntype = node_data.get("type", "Unknown")
    nlabel = node_data.get("label", "Unknown")
    
    try:
        driver = __neo4j_session()
        with driver.session() as session:
            if ntype in ["Vulnerability", "Finding"]:
                # Grab Node info + Host + Escalation Path
                q = """
                MATCH (v) WHERE id(v) = toInteger($nid) OR v.id = $nid
                OPTIONAL MATCH (h:Host)-[*1..2]->(v)
                OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(tech:Technique)-[:PART_OF]->(tac:Tactic)
                RETURN v, collect(DISTINCT h.host) AS hosts, 
                       collect(DISTINCT tech.id + ' (' + coalesce(tech.name, tech.label) + ') -> ' + tac.id + ' (' + coalesce(tac.name, tac.label) + ')') AS escalation
                """
                res = session.run(q, nid=nid).data()
                if not res:
                    return html.P("Node not found in DB.", className="text-danger")
                    
                data = res[0]["v"]
                hosts = res[0]["hosts"]
                escalation = res[0]["escalation"]
                
                content = [
                    html.H4(f"🛡️ {ntype}: {nlabel}", className="text-danger", style={"borderBottom": "1px solid #555", "paddingBottom": "10px", "marginTop": "10px"}),
                    html.P([html.Strong("Host(s) Affected: ", style={"color": "#33ccff"}), ", ".join([h for h in hosts if h]) or "Unknown"]),
                ]
                
                # NVD & Vuln Info
                desc_str = data.get("description")
                sev_str = data.get("severity") or data.get("priority")
                cve_id = data.get("cve") or data.get("id") or ""
                
                if str(cve_id).startswith("CVE-") and (not desc_str or not sev_str):
                    from cyber_range.services.nvd_live_lookup import fetch_nvd_data
                    nvd = fetch_nvd_data(cve_id)
                    if not desc_str and nvd.get("description"): desc_str = nvd["description"]
                    if not sev_str and nvd.get("severity"): sev_str = nvd["severity"]
                
                desc_str = str(desc_str or "No description available.")
                if len(desc_str) > 500:
                    desc_str = desc_str[:500] + "..."
                
                if str(cve_id).startswith("CVE-"):
                    nvd_link = html.A("View on NVD Database", href=f"https://nvd.nist.gov/vuln/detail/{cve_id}", target="_blank", className="text-info")
                    gh_link = html.A("Search GitHub for Exploits", href=f"https://github.com/search?q={cve_id}+exploit", target="_blank", className="text-info")
                    nist_link = html.A("NIST SP 800-53 Mappings", href=f"https://nvd.nist.gov/vuln/detail/{cve_id}#vulnTechnicalDetailsDiv", target="_blank", className="text-info")
                else:
                    nvd_link = html.Span("NVD: Not a CVE", className="text-muted")
                    gh_link = html.Span("GitHub: No CVE context", className="text-muted")
                    nist_link = html.Span("NIST: Not mapped", className="text-muted")

                content.append(html.P([html.Strong("NVD / Description: ", style={"color": "#33ccff"}), html.Br(), desc_str]))
                
                is_exploitable = data.get("exploitable", False)
                exploit_badge = html.Span("YES (Known Exploits)", className="badge bg-danger") if is_exploitable else html.Span("NO / Unknown", className="badge bg-secondary")
                content.append(html.P([html.Strong("Exploitable: ", style={"color": "#33ccff"}), exploit_badge]))
                content.append(html.P([html.Strong("Severity / CVSS: ", style={"color": "#33ccff"}), str(sev_str or "Not Scored")]))
                
                content.append(html.Ul([
                    html.Li(nvd_link),
                    html.Li(gh_link),
                    html.Li(nist_link)
                ], style={"listStyleType": "square", "paddingLeft": "20px"}))
                
                # Add AI Exploit Generation Button
                content.append(html.Div([
                    dbc.Button("🤖 Generate AI Exploit Analysis", id={"type": "btn-exploit-ai_mitre", "index": nid}, color="danger", size="sm", className="mt-2 text-white fw-bold"),
                    dcc.Loading(
                        html.Div(id={"type": "exploit-ai-result_mitre", "index": nid}, className="mt-3 p-2", style={"backgroundColor": "#0d0d0d", "border": "1px dashed #444", "borderRadius":"5px", "fontSize": "13px", "display": "none"}),
                        type="circle", color="#ff0040"
                    )
                ]))
                
                refs_str = str(data.get("references", "No direct exploits mapped in graph properties."))
                if len(refs_str) > 200:
                    refs_str = refs_str[:200] + "..."
                
                content.append(html.Hr(style={"borderColor": "#444"}))
                content.append(html.H5("🚀 Attack Escalation Path", className="text-warning"))
                content.append(html.P("What this vulnerability leads to:", className="text-muted", style={"fontStyle": "italic"}))
                
                if escalation and escalation[0]:
                    for esc in escalation:
                        if esc:
                            content.append(html.Div(f"➔ {esc}", style={"paddingLeft": "15px", "color": "#ff8c00", "fontWeight": "bold", "marginBottom": "5px"}))
                else:
                    content.append(html.P("No known MITRE escalation paths mapped for this finding.", className="text-muted"))
                    
                content.append(html.Hr(style={"borderColor": "#444"}))
                content.append(html.H5("💡 Why This is Important", className="text-success"))
                content.append(html.P("This vulnerability provides an attacker with a direct foothold into the identified host. From here, the attacker can leverage the listed Techniques to achieve wider organizational compromise, leading to systemic pivoting if left unpatched."))
                
                return content

            elif ntype in ["Technique", "Tactic"]:
                q = """
                MATCH (n) WHERE id(n) = toInteger($nid) OR n.id = $nid
                OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(n) WHERE v:Vulnerability OR v:Finding
                RETURN n, collect(DISTINCT v.cve) AS local_cves
                """
                res = session.run(q, nid=nid).data()
                if not res:
                    return html.P("Node not found.", className="text-danger")
                
                data = res[0]["n"]
                local_cves = [c for c in res[0]["local_cves"] if c]
                desc = str(data.get("description") or "No description provided by MITRE STIX framework.")
                mitre_id = data.get("id", "Unknown")
                
                content = [
                    html.H4(f"🎯 {ntype}: {nlabel}", className="text-warning", style={"borderBottom": "1px solid #555", "paddingBottom": "10px", "marginTop": "10px"}),
                    html.P([html.Strong("MITRE ID: ", style={"color": "#33ccff"}), mitre_id]),
                    html.P([html.Strong("Type: ", style={"color": "#33ccff"}), ntype])
                ]
                
                # Contextual NIST / Environment references
                content.append(html.Hr(style={"borderColor": "#444"}))
                content.append(html.H5("🌐 Environment Intelligence Context", className="text-info"))
                
                if local_cves:
                    content.append(html.P(f"This technique is actively enabled in your environment by {len(local_cves)} mapped CVEs/Findings.", className="text-danger fw-bold"))
                    links = []
                    for cve in local_cves[:5]:
                        links.append(html.Li(html.A(f"NVD: {cve}", href=f"https://nvd.nist.gov/vuln/detail/{cve}", target="_blank", className="text-info")))
                    if len(local_cves) > 5:
                        links.append(html.Li(f"... and {len(local_cves) - 5} more"))
                    content.append(html.Ul(links, style={"listStyleType": "square", "paddingLeft": "20px"}))
                else:
                    content.append(html.P("No active environmental CVEs currently map to this node.", className="text-muted"))
                
                content.append(html.Ul([
                    html.Li(html.A("NIST SP 800-53 Control Mappings", href="https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings", target="_blank", className="text-info")),
                    html.Li(html.A(f"Search GitHub for {mitre_id} scripts", href=f"https://github.com/search?q={mitre_id}+mitre+OR+attack", target="_blank", className="text-info"))
                ], style={"listStyleType": "square", "paddingLeft": "20px"}))
                
                content.append(html.Hr(style={"borderColor": "#444"}))
                content.append(html.H5("💡 Why This is Important", className="text-success"))
                content.append(html.P(desc, style={"maxHeight": "400px", "overflowY": "auto"}))
                
                return content
                
            else:
                return [
                    html.H4(f"🔹 {ntype}: {nlabel}", className="text-primary", style={"borderBottom": "1px solid #555", "paddingBottom": "10px", "marginTop": "10px"}),
                    html.P("Select a Vulnerability or Technique node for deeper escalation context.", className="text-muted")
                ]
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("[MITRE Node Details Error]", e)
        return html.Div(f"Error loading details: {str(e)}", className="text-danger")


# ----------------------------------------------------------------------
# CALLBACK: Continuous Layout "Dancing" Randomization for MITRE
# ----------------------------------------------------------------------
import random
@callback(
    Output("mitre-cytoscape-graph", "layout"),
    Output("mitre-cytoscape-graph", "stylesheet"),
    Input("mitre-dance-timer", "n_intervals"),
    State("mitre-cytoscape-graph", "stylesheet"),
    prevent_initial_call=True
)
def mitre_dance_layout(n, current_style):
    # Bird-like slow glide: long springs, gentle spacing, smooth animation duration matched to timer
    layout = {
        "name": "cola",
        "animate": True,
        "animationDuration": 3800,   # almost fills the 4s interval — silky smooth
        "infinite": True,
        "fit": False,
        "randomize": False,          # no abrupt jumps — let physics drift naturally
        "refresh": 3,                # fewer refreshes = calmer motion
        "avoidOverlap": True,        # nodes glide apart, never crash
        "unconstrainedLayout": True, # free-floating soar
        "edgeLength": random.randint(120, 300),   # long wings — wide spacing
        "nodeSpacing": random.randint(40, 100),
        "padding": random.randint(30, 80)
    }

    # Soft aurora palette — slow colour drift like a sky at dusk
    aurora_colors = ["#33ccff", "#7b2fff", "#00e5ff", "#ff8c00", "#0af0a0", "#ff4db8", "#c8ff00", "#ff6633"]
    new_style = []
    if current_style:
        for s in current_style:
            s_copy = dict(s)
            if "style" in s_copy:
                s_style = dict(s_copy["style"])
                if "background-color" in s_style and s_copy.get("selector") != ":selected":
                    s_style["background-color"] = random.choice(aurora_colors)
                if "line-color" in s_style:
                    s_style["line-color"] = random.choice(aurora_colors)
                s_copy["style"] = s_style
            new_style.append(s_copy)

    return layout, new_style or current_style

# ----------------------------------------------------------------------
# CALLBACK: MITRE Dance Start/Stop/Restart Controls
# ----------------------------------------------------------------------
from dash import ctx
import time

@callback(
    Output("mitre-dance-timer", "disabled"),
    Output("mitre-dance-audio", "src"),
    Input("mitre-btn-start", "n_clicks"),
    Input("mitre-btn-stop", "n_clicks"),
    Input("mitre-btn-restart", "n_clicks"),
    prevent_initial_call=False
)
def mitre_dance_controls(start, stop, restart):
    ctx_id = ctx.triggered_id if ctx.triggered_id else "default"
    if ctx_id == "mitre-btn-stop":
        return True, ""
    elif ctx_id == "mitre-btn-restart":
        return False, f"https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3?t={time.time()}"
    return False, "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3"
