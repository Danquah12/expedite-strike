import dash_bootstrap_components as dbc
from dash import html, dash_table
import dash_cytoscape as cyto
import pandas as pd
from neo4j import GraphDatabase

# Configure Neo4j Driver (assuming default values from mitre_loader.py)
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"

def _get_neo4j_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

def generate_threat_actor_layout():
    driver = _get_neo4j_driver()
    try:
        with driver.session() as session:
            # Query the database for top Threat Actors
            result = session.run("""
                MATCH (a:IntrusionSet)
                OPTIONAL MATCH (a)-[:USES]->(t:Technique)
                OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
                RETURN a.name AS `Threat Actor / Group`, 
                       count(DISTINCT t) AS `Mapped Techniques`, 
                       count(DISTINCT v) AS `Exploitable Vulnerabilities`,
                       a.description AS `Description`
                ORDER BY `Exploitable Vulnerabilities` DESC, `Mapped Techniques` DESC
                LIMIT 20
            """).data()
            
            if result:
                df = pd.DataFrame(result)
            else:
                df = pd.DataFrame([{"Threat Actor / Group": "No Data", "Mapped Techniques": 0, "Description": "No Intrusion Sets found in database."}])
    except Exception as e:
        df = pd.DataFrame([{"Threat Actor / Group": "Error", "Mapped Techniques": 0, "Description": str(e)}])
    finally:
        driver.close()

    table = dash_table.DataTable(
        data=df.to_dict("records"),
        columns=[{"name": i, "id": i} for i in df.columns],
        style_table={'overflowX': 'auto', 'backgroundColor': '#2A2A2A', 'color': 'white', 'borderRadius': '10px'},
        style_header={'backgroundColor': '#1E1E1E', 'color': '#E0E0E0', 'fontWeight': 'bold', 'border': '1px solid #444'},
        style_cell={'backgroundColor': '#2A2A2A', 'color': '#E0E0E0', 'textAlign': 'left', 'border': '1px solid #444', 'padding': '10px'},
        style_data={'whiteSpace': 'normal', 'height': 'auto'},
        style_data_conditional=[
            {'if': {'row_index': 'odd'}, 'backgroundColor': '#333333'}
        ],
        page_size=10
    )

    return dbc.Container([
        html.H3("🕵️ Threat Actor Profiling", className="text-danger mb-3"),
        html.P("Analyze known APT groups and their associated TTPs mapped to your architecture.", className="text-light"),
        html.Div(table, className="mt-4 shadow-sm")
    ], fluid=True, className="p-4")

def generate_ttp_correlation_layout():
    driver = _get_neo4j_driver()
    elements = []
    try:
        with driver.session() as session:
            # Get top 5 actors and their techniques — with enriched data
            res = session.run("""
                MATCH (a:IntrusionSet)-[:USES]->(t:Technique)
                OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
                WITH a, count(DISTINCT t) as t_cnt, count(DISTINCT v) as v_cnt 
                ORDER BY v_cnt DESC, t_cnt DESC LIMIT 5
                MATCH (a)-[:USES]->(t:Technique)
                OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
                RETURN a, t, count(DISTINCT v) as vuln_count LIMIT 60
            """).data()
            
            # Build Cytoscape elements with enriched data
            nodes_set = set()
            for row in res:
                actor = row['a']
                tech = row['t']
                a_id = actor.get('id', 'unknown_a')
                t_id = tech.get('id', 'unknown_t')
                a_name = actor.get('name', 'Unknown Actor')
                t_name = tech.get('name', 'Unknown Tech')
                a_desc = actor.get('description', 'No description available.')
                t_desc = tech.get('description', 'No description available.')
                t_mitre = tech.get('stix_id', tech.get('mitre_id', ''))
                vuln_count = row.get('vuln_count', 0)
                
                if a_id not in nodes_set:
                    elements.append({
                        'data': {
                            'id': a_id, 'label': a_name,
                            'node_type': 'actor',
                            'description': a_desc[:300] if a_desc else '',
                            'mitre_id': a_id,
                        },
                        'classes': 'actor'
                    })
                    nodes_set.add(a_id)
                if t_id not in nodes_set:
                    elements.append({
                        'data': {
                            'id': t_id, 'label': t_name,
                            'node_type': 'technique',
                            'description': t_desc[:300] if t_desc else '',
                            'mitre_id': t_mitre or t_id,
                            'vuln_count': vuln_count,
                        },
                        'classes': 'technique'
                    })
                    nodes_set.add(t_id)
                    
                elements.append({'data': {'source': a_id, 'target': t_id}})
    except Exception as e:
        print("[TTP Correl] Error:", e)
    finally:
        driver.close()

    cyto_graph = cyto.Cytoscape(
        id='ttp-correlation-graph',
        elements=elements,
        layout={'name': 'cose', 'animate': True, 'animationDuration': 500},
        style={'width': '100%', 'height': '600px', 'backgroundColor': '#1E1E1E'},
        stylesheet=[
            {'selector': 'node', 'style': {
                'label': 'data(label)', 'color': 'white',
                'text-valign': 'center', 'text-halign': 'center',
                'font-size': '10px', 'text-wrap': 'wrap', 'text-max-width': '80px',
                'border-width': 2, 'border-color': '#333',
                'transition-property': 'border-color, border-width, width, height',
                'transition-duration': '0.2s',
            }},
            {'selector': 'node:active', 'style': {
                'overlay-opacity': 0,
            }},
            {'selector': '.actor', 'style': {
                'background-color': '#d9534f', 'shape': 'hexagon',
                'width': 65, 'height': 65,
                'border-color': '#ff6666',
            }},
            {'selector': '.technique', 'style': {
                'background-color': '#5bc0de',
                'width': 42, 'height': 42,
                'border-color': '#88ddff',
            }},
            {'selector': '.actor:selected', 'style': {
                'border-width': 4, 'border-color': '#ffcc00',
                'background-color': '#ff4444', 'width': 80, 'height': 80,
            }},
            {'selector': '.technique:selected', 'style': {
                'border-width': 4, 'border-color': '#44ff88',
                'background-color': '#44aaff', 'width': 55, 'height': 55,
            }},
            {'selector': 'edge', 'style': {
                'line-color': '#888', 'target-arrow-color': '#888',
                'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
                'opacity': 0.4, 'width': 1.5,
            }},
        ]
    )

    return dbc.Container([
        html.H3("🔗 TTP Correlation Analysis", className="text-info mb-3"),
        html.P("Visual mapping of the Top 5 Threat Actors and their associated Attack Patterns. "
               "Click any node for detailed intelligence.", className="text-light"),
        html.Div(cyto_graph, className="mt-4 shadow-sm border border-secondary rounded"),
        html.Div(id="ttp-click-hint",
                 children="💡 Click any node on the graph above to see detailed threat intelligence.",
                 style={"color":"#666","fontSize":"11px","textAlign":"center",
                        "marginTop":"8px","fontStyle":"italic"}),
    ], fluid=True, className="p-4")

def generate_campaign_attribution_layout():
    driver = _get_neo4j_driver()
    try:
        with driver.session() as session:
            # Query the database for top Campaigns
            result = session.run("""
                MATCH (c:Campaign)
                OPTIONAL MATCH (c)-[:USES]->(t:Technique)
                OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
                RETURN c.name AS `Campaign Name`, 
                       count(DISTINCT t) AS `Mapped Techniques`, 
                       count(DISTINCT v) AS `Exploitable Vulnerabilities`,
                       c.description AS `Description`
                ORDER BY `Exploitable Vulnerabilities` DESC, `Mapped Techniques` DESC
                LIMIT 20
            """).data()
            
            if result:
                df = pd.DataFrame(result)
            else:
                df = pd.DataFrame([{"Campaign Name": "No Data", "Mapped Techniques": 0, "Description": "No Campaigns found in database."}])
    except Exception as e:
        df = pd.DataFrame([{"Campaign Name": "Error", "Mapped Techniques": 0, "Description": str(e)}])
    finally:
        driver.close()

    table = dash_table.DataTable(
        data=df.to_dict("records"),
        columns=[{"name": i, "id": i} for i in df.columns],
        style_table={'overflowX': 'auto', 'backgroundColor': '#2A2A2A', 'color': 'white', 'borderRadius': '10px'},
        style_header={'backgroundColor': '#1E1E1E', 'color': '#E0E0E0', 'fontWeight': 'bold', 'border': '1px solid #444'},
        style_cell={'backgroundColor': '#2A2A2A', 'color': '#E0E0E0', 'textAlign': 'left', 'border': '1px solid #444', 'padding': '10px'},
        style_data={'whiteSpace': 'normal', 'height': 'auto'},
        style_data_conditional=[
            {'if': {'row_index': 'odd'}, 'backgroundColor': '#333333'}
        ],
        page_size=10
    )

    return dbc.Container([
        html.H3("🎯 Campaign Attribution Modeling", className="text-primary mb-3"),
        html.P("Attribute observed activity to known campaigns based on overlapping attack patterns.", className="text-light"),
        html.Div(table, className="mt-4 shadow-sm")
    ], fluid=True, className="p-4")

def generate_detection_gap_layout():
    driver = _get_neo4j_driver()
    try:
        with driver.session() as session:
            # Find Techniques that do NOT have a CourseOfAction mitigating them
            result = session.run("""
                MATCH (t:Technique)
                WHERE NOT (t)<-[:MITIGATES]-(:CourseOfAction)
                OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
                RETURN t.stix_id AS `MITRE ID`, 
                       t.name AS `Technique`, 
                       count(DISTINCT v) AS `Vulnerabilities Exposed`,
                       t.description AS `Description`
                ORDER BY `Vulnerabilities Exposed` DESC
                LIMIT 20
            """).data()
            
            if result:
                df = pd.DataFrame(result)
            else:
                df = pd.DataFrame([{"MITRE ID": "N/A", "Technique": "No Gaps", "Description": "All techniques have known mitigations."}])
    except Exception as e:
        df = pd.DataFrame([{"MITRE ID": "Error", "Technique": "Error", "Description": str(e)}])
    finally:
        driver.close()

    table = dash_table.DataTable(
        data=df.to_dict("records"),
        columns=[{"name": i, "id": i} for i in df.columns],
        style_table={'overflowX': 'auto', 'backgroundColor': '#2A2A2A', 'color': 'white', 'borderRadius': '10px'},
        style_header={'backgroundColor': '#1E1E1E', 'color': '#E0E0E0', 'fontWeight': 'bold', 'border': '1px solid #444'},
        style_cell={'backgroundColor': '#2A2A2A', 'color': '#E0E0E0', 'textAlign': 'left', 'border': '1px solid #444', 'padding': '10px'},
        style_data={'whiteSpace': 'normal', 'height': 'auto'},
        style_data_conditional=[
            {'if': {'row_index': 'odd'}, 'backgroundColor': '#333333'}
        ],
        page_size=10
    )

    return dbc.Container([
        html.H3("🕳️ Detection Gap Mapping", className="text-warning mb-3"),
        html.P("Identify blind spots in your detection engineering coverage based on unmitigated techniques.", className="text-light"),
        html.Div(table, className="mt-4 shadow-sm")
    ], fluid=True, className="p-4")

def generate_control_effectiveness_layout():
    driver = _get_neo4j_driver()
    try:
        with driver.session() as session:
            # Output the top Mitigations (Course of Action)
            result = session.run("""
                MATCH (c:CourseOfAction)-[:MITIGATES]->(t:Technique)
                OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
                RETURN c.name AS `Security Control / Mitigation`, 
                       count(DISTINCT t) AS `Techniques Mitigated`, 
                       count(DISTINCT v) AS `Vulnerabilities Covered`,
                       c.description AS `Description`
                ORDER BY `Vulnerabilities Covered` DESC, `Techniques Mitigated` DESC
                LIMIT 20
            """).data()
            
            if result:
                df = pd.DataFrame(result)
            else:
                df = pd.DataFrame([{"Security Control / Mitigation": "No Data", "Techniques Mitigated": 0, "Description": "No CourseOfActions found."}])
    except Exception as e:
        df = pd.DataFrame([{"Security Control / Mitigation": "Error", "Techniques Mitigated": 0, "Description": str(e)}])
    finally:
        driver.close()

    table = dash_table.DataTable(
        data=df.to_dict("records"),
        columns=[{"name": i, "id": i} for i in df.columns],
        style_table={'overflowX': 'auto', 'backgroundColor': '#2A2A2A', 'color': 'white', 'borderRadius': '10px'},
        style_header={'backgroundColor': '#1E1E1E', 'color': '#E0E0E0', 'fontWeight': 'bold', 'border': '1px solid #444'},
        style_cell={'backgroundColor': '#2A2A2A', 'color': '#E0E0E0', 'textAlign': 'left', 'border': '1px solid #444', 'padding': '10px'},
        style_data={'whiteSpace': 'normal', 'height': 'auto'},
        style_data_conditional=[
            {'if': {'row_index': 'odd'}, 'backgroundColor': '#333333'}
        ],
        page_size=10
    )

    return dbc.Container([
        html.H3("🛡️ Control Effectiveness Mapping", className="text-success mb-3"),
        html.P("Map your implemented security controls against known MITRE ATT&CK techniques to evaluate defensive posture.", className="text-light"),
        html.Div(table, className="mt-4 shadow-sm")
    ], fluid=True, className="p-4")

def generate_d3fend_layout():
    driver = _get_neo4j_driver()
    try:
        with driver.session() as session:
            # Similar to Mitigations but targeting explicit IDs or generic defensive countermeasures mapped in DB
            result = session.run("""
                MATCH (c:CourseOfAction)
                WHERE c.mitre_id IS NOT NULL
                OPTIONAL MATCH (c)-[:MITIGATES]->(t:Technique)
                OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
                RETURN c.mitre_id AS `Countermeasure ID`, 
                       c.name AS `Defensive Artifact`, 
                       count(DISTINCT v) AS `Vulnerabilities Covered`,
                       c.description AS `Implementation Detail`
                ORDER BY `Vulnerabilities Covered` DESC, `Countermeasure ID` ASC
                LIMIT 20
            """).data()
            
            if result:
                df = pd.DataFrame(result)
            else:
                df = pd.DataFrame([{"Countermeasure ID": "N/A", "Defensive Artifact": "No D3FEND Data", "Implementation Detail": "No corresponding MITRE IDs stored."}])
    except Exception as e:
        df = pd.DataFrame([{"Countermeasure ID": "Error", "Defensive Artifact": "Error", "Implementation Detail": str(e)}])
    finally:
        driver.close()

    table = dash_table.DataTable(
        data=df.to_dict("records"),
        columns=[{"name": i, "id": i} for i in df.columns],
        style_table={'overflowX': 'auto', 'backgroundColor': '#2A2A2A', 'color': 'white', 'borderRadius': '10px'},
        style_header={'backgroundColor': '#2C1B4D', 'color': '#E0E0E0', 'fontWeight': 'bold', 'border': '1px solid #444'},
        style_cell={'backgroundColor': '#1E1A29', 'color': '#E0E0E0', 'textAlign': 'left', 'border': '1px solid #444', 'padding': '10px'},
        style_data={'whiteSpace': 'normal', 'height': 'auto'},
        style_data_conditional=[
            {'if': {'row_index': 'odd'}, 'backgroundColor': '#252033'}
        ],
        page_size=10
    )

    return dbc.Container([
        html.H3("🏰 D3FEND Mapping (Defensive Countermeasures)", className="text-primary mb-3"),
        html.P("Map your architecture against the MITRE D3FEND framework to understand countermeasure coverage.", className="text-light"),
        html.Div(table, className="mt-4 shadow-sm border border-secondary rounded")
    ], fluid=True, className="p-4")
