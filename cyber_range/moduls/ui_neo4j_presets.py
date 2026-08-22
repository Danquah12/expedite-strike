from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
# Register extra layouts (cola, cose-bilkent) shipped with dash-cytoscape
try:
    cyto.load_extra_layouts()
except Exception:
    pass

def generate_neo4j_intelligence_layout():
    """Generates the unified 3-column Neo4j Intelligence Portal."""
    return html.Div(
        [
            # ----------------------------------------------------------
            # HEADER TITLE & DESCRIPTION
            # ----------------------------------------------------------
            html.H2(
                "🧠 Neo4j Graph Intelligence & Feeds",
                className="text-info mb-2",
                style={"fontWeight": "bold"}
            ),
            html.P(
                "Aggregated topological graph intelligence overlaid with active vulnerability feeds and dynamic exploit states.",
                className="text-light",
                style={"opacity": "0.85", "fontSize": "18px"}
            ),

            html.Hr(style={"borderColor": "#444"}),

            dbc.Row([
                # ==========================================================
                # COLUMN 1: Control Panel & Filters (Left)
                # ==========================================================
                dbc.Col([
                    html.Div(
                        [
                            html.H4("🎯 Graph Presets", className="text-primary mb-3", style={"borderBottom": "1px solid #333", "paddingBottom": "10px"}),
                            
                            dbc.ListGroup([
                                dbc.ListGroupItem("Show Asset Graph", id="btn-assets", action=True, color="primary", className="fw-bold mb-1", style={"borderRadius": "5px"}),
                                dbc.ListGroupItem("Show Vulnerability Graph", id="btn-vuln", action=True, color="danger", className="fw-bold mb-1", style={"borderRadius": "5px"}),
                                dbc.ListGroupItem("Show Technique → Tactic", id="btn-tech-tac", action=True, color="warning", className="fw-bold mb-1", style={"borderRadius": "5px"}),
                                dbc.ListGroupItem("Show Tech → Subtechniques", id="btn-subtech", action=True, color="dark", className="fw-bold mb-1", style={"borderRadius": "5px"}),
                                dbc.ListGroupItem("Show Attack Paths", id="btn-attack-path", action=True, color="info", className="fw-bold mb-3", style={"borderRadius": "5px"}),
                            ], flush=True),

                            html.H4("🎛️ Feed Filters", className="text-success mt-4 mb-3", style={"borderBottom": "1px solid #333", "paddingBottom": "10px"}),
                            
                            html.Label("Intelligence Source:", className="text-light fw-bold"),
                            dcc.Dropdown(
                                id="import-feed-source",
                                options=[
                                    {"label": "All Sources", "value": ""},
                                ],
                                value="",
                                clearable=False,
                                placeholder="Filter by source",
                                className="mb-3",
                                style={"color": "black"}
                            ),

                            html.Label("Minimum CVSS Threshold:", className="text-light fw-bold mt-2"),
                            dcc.Slider(
                                id="import-feed-confidence",
                                min=0, max=10, step=0.5, value=0,
                                marks={0: "0", 4: "4", 7: "7", 9: "9", 10: "10"},
                                tooltip={"placement": "bottom"},
                                className="mb-4"
                            ),

                            dbc.Row([
                                dbc.Col(dbc.Checklist(
                                    id="import-feed-kev-only",
                                    options=[{"label": "KEV Only", "value": "kev"}],
                                    value=[], switch=True, className="text-danger fw-bold"
                                ), width=6),
                                dbc.Col(dbc.Checklist(
                                    id="import-feed-exploit-only",
                                    options=[{"label": "Exploit Only", "value": "exploit"}],
                                    value=[], switch=True, className="text-warning fw-bold"
                                ), width=6)
                            ]),

                            html.Div([
                                html.H5("Legend", className="text-muted mt-4"),
                                html.Div("🟦 Asset", style={"color": "#4A90E2", "fontSize": "14px"}),
                                html.Div("🔴 Vulnerability", style={"color": "#D0021B", "fontSize": "14px"}),
                                html.Div("🟧 Technique", style={"color": "#F5A623", "fontSize": "14px"}),
                                html.Div("🟨 SubTechnique", style={"color": "#F8E71C", "fontSize": "14px"}),
                                html.Div("🟪 Tactic", style={"color": "#9013FE", "fontSize": "14px"}),
                            ], className="mt-4 p-3 rounded", style={"backgroundColor": "#111", "border": "1px solid #333"})

                        ],
                        style={"backgroundColor": "#1a1a1a", "padding": "20px", "borderRadius": "8px", "border": "1px solid #333"}
                    )
                ], width=2),

                # ==========================================================
                # COLUMN 2: Neo4j Cytoscape Canvas (Center)
                # ==========================================================
                dbc.Col([
                    html.Div(
                        [
                            html.Div([
                                html.H4("🌌 Interactive Topological Canvas", className="text-light mb-0", style={"display": "inline-block"}),
                                dbc.ButtonGroup([
                                    dbc.Button("▶ Start", id="neo4j-btn-start", color="success", size="sm"),
                                    dbc.Button("⏸ Stop", id="neo4j-btn-stop", color="danger", size="sm"),
                                    dbc.Button("🔄 Restart", id="neo4j-btn-restart", color="warning", size="sm"),
                                ], className="float-end")
                            ], style={"borderBottom": "1px solid #333", "paddingBottom": "10px", "marginBottom": "15px"}),
                            html.Div(id="cy-tooltip", style={
                                "position": "absolute", "zIndex": 999, "padding": "6px 10px",
                                "background": "#222", "color": "white", "border": "1px solid #555",
                                "borderRadius": "4px", "display": "none",
                            }),
                            dcc.Interval(id="neo4j-dance-timer", interval=1000, n_intervals=0, disabled=True),
                            html.Audio(id="neo4j-dance-audio", src="https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3", autoPlay=True, loop=True, style={"display": "none"}),
                            cyto.Cytoscape(
                                id="neo4j-preset-graph",
                                style={
                                    "width": "100%", "height": "750px", "backgroundColor": "#080808",
                                    "border": "1px solid #4A90E2", "borderRadius": "8px",
                                    "boxShadow": "0px 0px 15px rgba(74, 144, 226, 0.2)"
                                },
                                layout={"name": "cose", "animate": True, "randomize": True, "refresh": 1},
                                elements=[],
                                stylesheet=[
                                    # ----- GLOBAL NODE STYLE -----
                                    {
                                        "selector": "node",
                                        "style": {
                                            "label": "data(label)",
                                            "font-size": "12px",
                                            "color": "#FFFFFF",
                                            "text-outline-width": 1.5,
                                            "text-outline-color": "#111",
                                            "background-color": "#4A90E2",
                                            "text-valign": "bottom",
                                            "text-margin-y": 5
                                        }
                                    },
                                    # ----- NODE TYPES -----
                                    {
                                        "selector": "[type='Asset']",
                                        "style": {"background-color": "#3498db", "shape": "round-rectangle", "width": "45px", "height": "30px"}
                                    },
                                    {
                                        "selector": "[type='Vulnerability']",
                                        "style": {"background-color": "#e74c3c", "shape": "triangle", "width": "35px", "height": "35px"}
                                    },
                                    {
                                        "selector": "[type='Technique']",
                                        "style": {"background-color": "#e67e22", "shape": "rectangle"}
                                    },
                                    {
                                        "selector": "[type='SubTechnique']",
                                        "style": {"background-color": "#f1c40f", "color": "#000", "text-outline-width": 0}
                                    },
                                    {
                                        "selector": "[type='Tactic']",
                                        "style": {"background-color": "#9b59b6", "shape": "diamond"}
                                    },
                                    # ----- HIGHLIGHTED CVSS SEVERITY -----
                                    {
                                        "selector": "[cvss >= 9.0]",
                                        "style": {"background-color": "#ff0040", "border-width": 3, "border-color": "#fff", "width": "50px", "height": "50px"}
                                    },
                                    {
                                        "selector": "[cvss >= 7.0][cvss < 9.0]",
                                        "style": {"background-color": "#ff4500", "border-width": 2, "border-color": "#fff"}
                                    },
                                    # ----- EDGES -----
                                    {
                                        "selector": "edge",
                                        "style": {
                                            "width": 2, "line-color": "#555", "target-arrow-color": "#555",
                                            "target-arrow-shape": "triangle", "curve-style": "bezier",
                                        }
                                    },
                                    # ----- SELECTED -----
                                    {
                                        "selector": ":selected",
                                        "style": {
                                            "border-width": 4, "border-color": "#33ccff",
                                            "background-color": "#33ccff", "color": "#000",
                                        }
                                    }
                                ]
                            )
                        ],
                        style={"backgroundColor": "#1a1a1a", "padding": "20px", "borderRadius": "8px", "border": "1px solid #333", "minHeight": "820px"}
                    )
                ], width=6),

                # ==========================================================
                # COLUMN 3: Intelligence Data Feed (Right)
                # ==========================================================
                dbc.Col([
                    html.Div(
                        [
                            html.H4("📊 Vulnerability Feed Metadata", className="text-warning mb-3", style={"borderBottom": "1px solid #333", "paddingBottom": "10px"}),
                            html.P("Live data table reflecting current filters and graphical topology limits.", className="text-muted small"),
                            
                            dash_table.DataTable(
                                id="import-feeds-table",
                                columns=[
                                    {"name": "Source", "id": "source", "type": "text"},
                                    {"name": "Feed ID (CVE)", "id": "feed_id", "type": "text", "presentation": "markdown"},
                                    {"name": "CVSS", "id": "cvss", "type": "numeric"},
                                    {"name": "Hosts", "id": "hosts_affected", "type": "text"},
                                ],
                                data=[],
                                page_size=15,
                                sort_action="native",
                                filter_action="native",
                                style_table={"overflowX": "auto", "border": "1px solid #333", "borderRadius": "5px"},
                                style_cell={
                                    "backgroundColor": "#0d0d0d", "color": "#eee", "border": "1px solid #222",
                                    "fontSize": "13px", "padding": "8px", "whiteSpace": "normal", "textAlign": "left"
                                },
                                style_header={
                                    "backgroundColor": "#222", "fontWeight": "bold", "border": "1px solid #444", "color": "#ffcc00"
                                },
                                style_data_conditional=[
                                    {"if": {"filter_query": "{cvss} >= 9"}, "backgroundColor": "#4a0000", "color": "white"},
                                    {"if": {"filter_query": "{cvss} >= 7 && {cvss} < 9"}, "backgroundColor": "#4a2500", "color": "white"},
                                    {"if": {"row_index": "odd"}, "backgroundColor": "#111"}
                                ]
                            ),
                            html.Hr(style={"borderColor": "#333", "marginTop": "30px", "marginBottom": "20px"}),
                            html.H4("🔍 Selected Node Details", className="text-info mb-3", style={"borderBottom": "1px solid #333", "paddingBottom": "10px"}),
                            html.Div(
                                id="neo4j-node-details",
                                children=html.P("Click a node on the canvas to view context, affected hosts, vulnerabilities, and exploitation paths.", className="text-muted small"),
                                style={
                                    "backgroundColor": "#111", "border": "1px solid #222", "borderRadius": "5px", 
                                    "padding": "15px", "color": "#eee", "maxHeight": "400px", "overflowY": "auto"
                                }
                            )
                        ],
                        style={"backgroundColor": "#1a1a1a", "padding": "20px", "borderRadius": "8px", "border": "1px solid #333", "minHeight": "820px"}
                    )
                ], width=4)
            ]),
        ],
        style={"padding": "30px", "backgroundColor": "#0d0d0d", "minHeight": "100vh"}
    )

# ======================================================================
# CALLBACKS: Dashboard Logic & Database Connections
# ======================================================================

from dash import Input, Output, State, callback, ctx, no_update
from dash.exceptions import PreventUpdate
from neo4j.graph import Node, Relationship

def __neo4j_session():
    """Provides an active Neo4j driver connection."""
    from neo4j import GraphDatabase
    return GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))

# ----------------------------------------------------------------------
# HELPER: Construct Cytoscape Elements
# ----------------------------------------------------------------------

def build_cytoscape_node(node: Node):
    """Converts a Neo4j Node into a Cytoscape-compatible node dictionary."""
    data = dict(node)

    # Sanitise values: Cytoscape/Dash only accepts strings, numbers, booleans, None.
    # Nested dicts, lists-of-dicts, and other complex types must be stringified.
    for k, v in list(data.items()):
        if isinstance(v, dict):
            data[k] = str(v)
        elif isinstance(v, (list, tuple)):
            # stringify any list that contains non-primitive items
            if v and isinstance(v[0], dict):
                data[k] = str(v)
        elif not isinstance(v, (str, int, float, bool, type(None))):
            data[k] = str(v)
    
    # Cytoscape requires a unique 'id' field for mapping edges.
    # If the node has its own 'id' property (like MITRE 'id': 'T1066'), 
    # it overwrites the required network topology id. 
    if "id" in data:
        data["mitre_id"] = data.pop("id")
    
    # Cytoscape uses 'source' and 'target' to infer edges. If a node has these, it crashes.
    if "source" in data:
        data["node_source"] = data.pop("source")
    if "target" in data:
        data["node_target"] = data.pop("target")

    # Use exact same schema logic as build_cytoscape_edge
    data["id"] = str(node.element_id if hasattr(node, "element_id") else getattr(node, "id", None))
    data["label"] = str(
        node.get("name")
        or node.get("displayname")
        or node.get("hostname")
        or node.get("host")
        or node.get("cve")
        or node.get("objectid")
        or data.get("mitre_id")
        or "(Unknown)"
    )
    data["type"] = list(node.labels)[0] if node.labels else "Unknown"

    return {"data": data}

def build_cytoscape_edge(rel: Relationship):
    """Converts a Neo4j Relationship into a Cytoscape-compatible edge."""
    # Must use the exact same ID extraction priority as build_cytoscape_node!
    start_id = str(rel.start_node.element_id if hasattr(rel.start_node, "element_id") else getattr(rel.start_node, "id", None))
    end_id   = str(rel.end_node.element_id if hasattr(rel.end_node, "element_id") else getattr(rel.end_node, "id", None))
    edge_id  = str(rel.element_id if hasattr(rel, "element_id") else id(rel))


    return {
        "data": {
            "id": f"{start_id}-{rel.type}-{end_id}-{edge_id}",
            "source": start_id,
            "target": end_id,
            "label": rel.type,
            "type": rel.type,
        }
    }

# ----------------------------------------------------------------------
# CALLBACK: 0) Auto-populate Intelligence Source dropdown from Neo4j
# ----------------------------------------------------------------------

@callback(
    Output("import-feed-source", "options"),
    Input("import-feed-source", "id"),   # fires once on load
)
def _populate_source_dropdown(_):
    """Dynamically populate the Intelligence Source dropdown from Neo4j."""
    options = [{"label": "All Sources", "value": ""}]
    try:
        driver = __neo4j_session()
        with driver.session() as session:
            rows = session.run("""
                MATCH (f:Finding)
                WHERE f.source IS NOT NULL
                RETURN DISTINCT toLower(toString(f.source)) AS src, 
                       toString(f.source) AS original,
                       count(f) AS cnt
                ORDER BY cnt DESC
            """).data()
        driver.close()

        # Pretty-print labels
        LABEL_MAP = {
            "nmap": "Nmap", "nuclei": "Nuclei", "zap": "OWASP ZAP",
            "aegisprobe": "AegisProbe", "burp": "Burp Suite",
            "openvas": "OpenVAS", "nessus": "Nessus",
            "metasploit": "Metasploit", "stig_ckl": "STIG CKL",
            "scap_xccdf": "SCAP / XCCDF",
        }
        seen = set()
        for r in rows:
            src_lower = r["src"]
            if src_lower in seen or not src_lower or src_lower == "none":
                continue
            seen.add(src_lower)
            label = LABEL_MAP.get(src_lower, r["original"] or src_lower.title())
            options.append({
                "label": f"{label}  ({r['cnt']})",
                "value": src_lower,
            })
    except Exception as e:
        print(f"[Source Dropdown] {e}")

    return options

# ----------------------------------------------------------------------
# CALLBACK: 1) The Import Feeds Data Table
# ----------------------------------------------------------------------

@callback(
    Output("import-feeds-table", "data"),
    [
        Input("import-feed-source", "value"),
        Input("import-feed-confidence", "value"),
        Input("import-feed-kev-only", "value"),
        Input("import-feed-exploit-only", "value"),
    ],
)
def update_import_feeds(source, min_cvss, kev_only, exploit_only):
    """Queries live Vulnerability feeds based on Federal dashboard filters."""
    driver = __neo4j_session()

    # Dynamic source matching — dropdown value is already the lowercase source key
    source_list = [source.lower()] if source else []

    # Severity → numeric CVSS mapping for scanners without CVSS scores
    SEV_CVSS = {"Critical": 10.0, "High": 8.0, "Medium": 5.0, "Low": 2.0, "Info": 0.0}

    q = """
    MATCH (a:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(s:Service)
    MATCH (s)-[:HAS_FINDING|HAS_VULN]->(f:Finding)
    WHERE ($use_source = false OR toLower(toString(f.source)) IN $source_list)
      AND ($exploit_only = false OR f.exploitable = true)
      AND ($kev_only = false OR f.in_kev = true)

    WITH
      f.name       AS name,
      f.cve        AS cve,
      f.source     AS source,
      f.severity   AS severity,
      CASE
        WHEN f.cvss IS NOT NULL THEN toFloat(f.cvss)
        WHEN toLower(toString(f.severity)) = 'critical' THEN 10.0
        WHEN toLower(toString(f.severity)) = 'high'     THEN 8.0
        WHEN toLower(toString(f.severity)) = 'medium'   THEN 5.0
        WHEN toLower(toString(f.severity)) = 'low'      THEN 2.0
        ELSE 0.0
      END AS cvss,
      f.exploitable AS exploitable,
      f.in_kev     AS in_kev,
      collect(DISTINCT coalesce(a.host, a.ip, 'Unknown')) AS hosts
    WHERE cvss >= $min_cvss

    RETURN
      source, name, cve, severity, cvss,
      exploitable, in_kev,
      hosts, size(hosts) AS host_count
    ORDER BY cvss DESC
    LIMIT 500
    """

    rows = []
    with driver.session() as session:
        records = session.run(
            q,
            use_source=bool(source_list),
            source_list=[s.lower() for s in source_list],
            min_cvss=min_cvss or 0,
            exploit_only=("exploit" in exploit_only),
            kev_only=("kev" in kev_only),
        )
        for r in records:
            cve = r["cve"] or ""
            name = r["name"] or "Unknown"
            # Show CVE link if available, otherwise show finding name
            if cve and cve.startswith("CVE-"):
                feed_id = f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})"
            else:
                feed_id = name[:60]
            rows.append({
                "source": r["source"] or "unknown",
                "feed_id": feed_id,
                "cvss": r["cvss"],
                "hosts_affected": ", ".join(sorted([h for h in r["hosts"] if h])),
            })

    driver.close()
    return rows

# ----------------------------------------------------------------------
# CALLBACK: 2) The Neo4j Dynamic Canvas
# ----------------------------------------------------------------------

@callback(
    Output("neo4j-preset-graph", "elements"),
    [
        Input("btn-assets",      "n_clicks"),
        Input("btn-vuln",        "n_clicks"),
        Input("btn-tech-tac",    "n_clicks"),
        Input("btn-subtech",     "n_clicks"),
        Input("btn-attack-path", "n_clicks"),
        Input("import-feed-source", "value"),
    ]
)
def load_neo4j_preset_graph(b1, b2, b3, b4, b5, feed_source):
    """Executes preset architectural queries filtered by Intelligence Source."""
    clicked = ctx.triggered_id

    # Dynamic source matching — use the dropdown value directly
    use_source = bool(feed_source)
    source_list = [feed_source.lower()] if use_source else []

    # Build a WHERE clause fragment for source filtering
    src_filter = "AND toLower(toString(f.source)) IN $source_list" if use_source else ""

    # Preset queries — all filtered through Finding.source when a source is selected
    cypher_map = {
        "btn-assets": f"""
            MATCH (a:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_FINDING|HAS_VULN]->(f:Finding)
            WHERE 1=1 {src_filter}
            OPTIONAL MATCH (a)-[r]->(b)
            RETURN a, r, b LIMIT 150
        """,
        "btn-vuln": f"""
            MATCH (s:Service)-[:HAS_FINDING|HAS_VULN]->(f)
            WHERE (f:Finding OR f:Vulnerability) {src_filter}
            OPTIONAL MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(s)
            OPTIONAL MATCH (h)-[r]->(s)
            OPTIONAL MATCH (s)-[r2]->(f)
            RETURN h, r, s, r2, f LIMIT 150
        """,
        "btn-tech-tac": """
            MATCH (t:Technique)
            OPTIONAL MATCH (t)-[r]->(ta:Tactic)
            RETURN t, r, ta LIMIT 120
        """,
        "btn-subtech": """
            MATCH (t:Technique)
            OPTIONAL MATCH (t)-[r]->(s:SubTechnique)
            RETURN t, r, s LIMIT 120
        """,
        "btn-attack-path": f"""
            MATCH (s:Service)-[:HAS_FINDING|HAS_VULN]->(f:Finding)
            WHERE 1=1 {src_filter}
            MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(s)
            OPTIONAL MATCH (f)-[r]->(tgt)
            RETURN h, s, f, r, tgt LIMIT 120
        """,
    }

    # Default query — show findings scoped to source, or everything
    if not clicked or clicked not in cypher_map:
        if use_source:
            cypher = f"""
                MATCH (s:Service)-[:HAS_FINDING|HAS_VULN]->(f:Finding)
                WHERE toLower(toString(f.source)) IN $source_list
                OPTIONAL MATCH (h:Host)-[:RUNS_SERVICE|EXPOSES|HasService]->(s)
                OPTIONAL MATCH (h)-[r1]->(s)
                OPTIONAL MATCH (s)-[r2]->(f)
                RETURN h, r1, s, r2, f LIMIT 150
            """
        else:
            cypher = """
                MATCH (n)
                OPTIONAL MATCH (n)-[r]->(m)
                RETURN n, r, m LIMIT 80
            """
    else:
        cypher = cypher_map[clicked]

    driver = __neo4j_session()
    node_map = {}
    edge_map = {}

    try:
        with driver.session() as session:
            params = {"source_list": source_list} if use_source else {}
            records = list(session.run(cypher, **params))
            for record in records:
                for value in record.values():
                    if value is None:
                        continue
                    if hasattr(value, "nodes") and hasattr(value, "relationships"):
                        # Path object
                        for node in value.nodes:
                            nid = str(node.element_id if hasattr(node, "element_id") else id(node))
                            if nid not in node_map: node_map[nid] = build_cytoscape_node(node)
                        for rel in value.relationships:
                            e_val = build_cytoscape_edge(rel)
                            edge_map[e_val["data"]["id"]] = e_val
                    elif hasattr(value, "start_node") and hasattr(value, "end_node"):
                        # Relationship object
                        e_val = build_cytoscape_edge(value)
                        edge_map[e_val["data"]["id"]] = e_val
                        for node in (value.start_node, value.end_node):
                            nid = str(node.element_id if hasattr(node, "element_id") else id(node))
                            if nid not in node_map: node_map[nid] = build_cytoscape_node(node)
                    elif hasattr(value, "labels"):
                        # Bare node
                        nid = str(value.element_id if hasattr(value, "element_id") else id(value))
                        if nid not in node_map: node_map[nid] = build_cytoscape_node(value)
    except Exception as e:
        print(f"[Neo4j Canvas Error] {e}")
    finally:
        driver.close()

    return list(node_map.values()) + list(edge_map.values())


# ----------------------------------------------------------------------
# CALLBACK: 3) Node Details Panel (Click Handler)
# ----------------------------------------------------------------------

@callback(
    Output("neo4j-node-details", "children"),
    Input("neo4j-preset-graph", "tapNodeData"),
    prevent_initial_call=True
)
def render_neo4j_node_details(node_data):
    if not node_data:
        return html.P("Click a node on the canvas to view context, affected hosts, vulnerabilities, and exploitation paths.", className="text-muted small")

    nid = node_data.get("id")
    ntype = node_data.get("type", "Unknown")
    nlabel = node_data.get("label", "Unknown")
    cve = node_data.get("cve", "")

    try:
        driver = __neo4j_session()
        with driver.session() as session:
            # Universal lookup to get root node properties and its immediate neighbors to derive context
            q = """
            MATCH (n) WHERE id(n) = toInteger($nid) OR n.id = $nid
            OPTIONAL MATCH (h:Host)-[*1..2]->(n)
            OPTIONAL MATCH (n)-[*1..2]->(v:Vulnerability)
            OPTIONAL MATCH (n)-[:MAPS_TO_TECHNIQUE|HAS_SUBTECHNIQUE|PART_OF*1..3]->(tac:Tactic)
            RETURN n, 
                   collect(DISTINCT h.host) AS affected_hosts,
                   collect(DISTINCT v.cve) AS vulnerabilities,
                   collect(DISTINCT tac.name) AS escalation_tactics
            """
            res = session.run(q, nid=nid).data()
            if not res:
                return html.P("Node not found in DB.", className="text-danger")
            
            data = res[0]["n"]
            affected_hosts = [h for h in res[0]["affected_hosts"] if h]
            vulnerabilities = [v for v in res[0]["vulnerabilities"] if v]
            escalation_tactics = [t for t in res[0]["escalation_tactics"] if t]
            
            content = [
                html.H5(f"{ntype}: {nlabel}", className="text-warning", style={"borderBottom": "1px solid #555", "paddingBottom": "8px", "marginTop": "0px"}),
            ]
            
            # Host context
            if ntype == "Host":
                content.append(html.P([html.Strong("Host Identity: ", style={"color": "#33ccff"}), data.get("host") or data.get("ip") or "Unknown"]))
                content.append(html.P([html.Strong("OS / Status: ", style={"color": "#33ccff"}), data.get("os", "Unknown")]))
            else:
                if affected_hosts:
                    content.append(html.P([html.Strong("Hosts Affected: ", style={"color": "#33ccff"}), ", ".join(affected_hosts[:10])]))
                    
            # Vulnerability context
            if ntype in ["Vulnerability", "Finding"]:
                cve_val = data.get("cve") or data.get("id") or "Unknown"
                
                desc = data.get("description")
                sev = data.get("severity")
                if str(cve_val).startswith("CVE-") and (not desc or not sev):
                    from cyber_range.services.nvd_live_lookup import fetch_nvd_data
                    nvd = fetch_nvd_data(cve_val)
                    if not desc and nvd.get("description"): desc = nvd["description"]
                    if not sev and nvd.get("severity"): sev = nvd["severity"]
                
                if str(cve_val).startswith("CVE-"):
                    content.append(html.P([html.Strong("NVD Reference: ", style={"color": "#33ccff"}), html.A(cve_val, href=f"https://nvd.nist.gov/vuln/detail/{cve_val}", target="_blank", className="text-info")]))
                    content.append(html.P([html.Strong("GitHub Exploits: ", style={"color": "#33ccff"}), html.A("Search", href=f"https://github.com/search?q={cve_val}+exploit", target="_blank", className="text-info")]))
                
                is_exploitable = data.get("exploitable", False)
                exploit_badge = html.Span("YES (Known Exploits)", className="badge bg-danger") if is_exploitable else html.Span("NO / Unknown", className="badge bg-secondary")
                content.append(html.P([html.Strong("Exploitable: ", style={"color": "#33ccff"}), exploit_badge]))
                content.append(html.P([html.Strong("Severity: ", style={"color": "#33ccff"}), str(sev or "Unknown")]))
                desc_str = str(desc or "No description provided.")
                content.append(html.P([html.Strong("Exploitation Context: ", style={"color": "#33ccff"}), desc_str[:300] + ("..." if len(desc_str)>300 else "")]))

                # Add AI Exploit Generation Button
                content.append(html.Div([
                    dbc.Button("🤖 Generate AI Exploit Analysis", id={"type": "btn-exploit-ai", "index": nid}, color="danger", size="sm", className="mt-2 text-white fw-bold"),
                    dcc.Loading(
                        html.Div(id={"type": "exploit-ai-result", "index": nid}, className="mt-3 p-2", style={"backgroundColor": "#0d0d0d", "border": "1px dashed #444", "borderRadius":"5px", "fontSize": "13px", "display": "none"}),
                        type="circle", color="#ff0040"
                    )
                ]))

            elif vulnerabilities:
                content.append(html.P([html.Strong("Associated CVEs: ", style={"color": "#33ccff"}), ", ".join(vulnerabilities[:5])]))
                
            # MITRE Context
            if ntype in ["Technique", "SubTechnique", "Tactic"]:
                mitre_id = data.get("id", "Unknown")
                content.append(html.P([html.Strong("MITRE ID: ", style={"color": "#33ccff"}), mitre_id]))
                desc = str(data.get("description") or "No description mapped in graph.")
                content.append(html.P([html.Strong("Description: ", style={"color": "#33ccff"}), desc[:200] + ("..." if len(desc)>200 else "")]))
            
            if escalation_tactics:
                content.append(html.Hr(style={"borderColor": "#444", "margin": "10px 0px"}))
                content.append(html.H6("🔥 Escalation Path Leads To:", className="text-danger"))
                for tac in escalation_tactics:
                    content.append(html.Div(f"➔ {tac}", style={"color": "#ff8c00", "fontWeight": "bold", "fontSize": "13px"}))
                    
            # Fallback for empty contexts
            if not affected_hosts and not vulnerabilities and not escalation_tactics and ntype not in ["Host", "Vulnerability", "Finding", "Technique", "SubTechnique", "Tactic"]:
                content.append(html.P("No definitive attack path contexts tracked for this generic node.", className="text-muted fst-italic"))
                
            return content
            
    except Exception as e:
        print("[Neo4j Presets Details Error]", e)
        return html.Div(f"Error loading node details: {str(e)}", className="text-danger")

# ----------------------------------------------------------------------
# CALLBACK: 4) AI Exploit Steps Generator
# ----------------------------------------------------------------------
from dash import MATCH, dcc
import dash_bootstrap_components as dbc
@callback(
    Output({"type": "exploit-ai-result", "index": MATCH}, "children"),
    Output({"type": "exploit-ai-result", "index": MATCH}, "style"),
    Input({"type": "btn-exploit-ai", "index": MATCH}, "n_clicks"),
    State("neo4j-preset-graph", "tapNodeData"),
    prevent_initial_call=True
)
def generate_ai_exploit_steps(n_clicks, node_data):
    if not n_clicks or not node_data:
        raise PreventUpdate

    from cyber_range.services.exploit_ai import ExploitModeler
    import traceback
    
    try:
        modeler = ExploitModeler()
        res = modeler.analyze_vulnerability(node_data)
        
        style = {"backgroundColor": "#0d0d0d", "border": "1px dashed #ff0040", "borderRadius":"5px", "fontSize": "13px", "display": "block"}
        return dcc.Markdown(res), style
    except Exception as e:
        print(f"[Exploit AI Error] {e}")
        traceback.print_exc()
        style = {"backgroundColor": "#220000", "border": "1px solid red", "borderRadius":"5px", "fontSize": "13px", "display": "block"}
        return f"AI Generation Failed. Make sure OPENAI_API_KEY is properly configured.", style


# ----------------------------------------------------------------------
# CALLBACK: 5) Continuous Layout "Dancing" Randomization
# ----------------------------------------------------------------------
import random
@callback(
    Output("neo4j-preset-graph", "layout"),
    Output("neo4j-preset-graph", "stylesheet"),
    Input("neo4j-dance-timer", "n_intervals"),
    State("neo4j-preset-graph", "stylesheet"),
    prevent_initial_call=True
)
def neo4j_dance_layout(n, current_style):
    # Don't animate if graph is empty — bail out immediately
    import dash
    if not current_style:
        raise PreventUpdate

    layout = {
        "name": "cose",
        "animate": True,
        "fit": False,
        "randomize": True,
        "refresh": 1,
        "nodeRepulsion": random.randint(2000, 8000),
        "gravity": round(random.uniform(0.25, 1.0), 2),
        "nodeOverlap": random.randint(20, 80),
        "idealEdgeLength": random.randint(30, 150),
    }

    neon_colors = ["#FF00FF", "#00FFFF", "#00FF00", "#FFFF00", "#FF0000", "#0000FF", "#33ccff", "#ff8c00"]
    new_style = []
    if current_style:
        for s in current_style:
            s_copy = dict(s)
            if "style" in s_copy:
                s_style = dict(s_copy["style"])
                if "background-color" in s_style and s_copy.get("selector") != ":selected":
                    s_style["background-color"] = random.choice(neon_colors)
                if "line-color" in s_style:
                    s_style["line-color"] = random.choice(neon_colors)
                s_copy["style"] = s_style
            new_style.append(s_copy)

    return layout, new_style or current_style

# ----------------------------------------------------------------------
# CALLBACK: 6) Dance Start/Stop/Restart Controls
# ----------------------------------------------------------------------
from dash import ctx
import time

@callback(
    Output("neo4j-dance-timer", "disabled"),
    Output("neo4j-dance-audio", "src"),
    Input("neo4j-btn-start", "n_clicks"),
    Input("neo4j-btn-stop", "n_clicks"),
    Input("neo4j-btn-restart", "n_clicks"),
    prevent_initial_call=False
)
def neo4j_dance_controls(start, stop, restart):
    ctx_id = ctx.triggered_id if ctx.triggered_id else "default"
    if ctx_id == "neo4j-btn-stop":
        return True, ""
    elif ctx_id == "neo4j-btn-start":
        return False, "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3"
    elif ctx_id == "neo4j-btn-restart":
        return False, f"https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3?t={time.time()}"
    # Default on load: timer stopped
    return True, ""
