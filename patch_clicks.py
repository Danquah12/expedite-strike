import sys, re

# 1. Update top half of ui_reporting.py 
with open('/Backup/vuln_intel/app/cyber_range/moduls/ui_reporting.py', 'r') as f:
    text = f.read()

# Add IDs to dynamic generated graphs based on method names
text = re.sub(r'dcc\.Graph\(figure=([a-zA-Z0-9_]+)\(\)\)', r"dcc.Graph(id={'type': 'reporting-graph', 'index': '\1'}, figure=\1())", text)

with open('/Backup/vuln_intel/app/cyber_range/moduls/ui_reporting.py', 'w') as f:
    f.write(text)

# 2. Update app.py
with open('/Backup/vuln_intel/app/app.py', 'r') as f:
    app_text = f.read()

modal_html = """        dcc.Location(id="url_refresh", refresh=True),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle("Graph Details & Impact Analysis", id="reporting-details-title", className="text-warning")),
                dbc.ModalBody(id="reporting-details-body", className="text-light"),
                dbc.ModalFooter(
                    dbc.Button("Close", id="close-reporting-modal", className="ms-auto", n_clicks=0, color="secondary")
                ),
            ],
            id="reporting-details-modal",
            is_open=False,
            size="lg",
            centered=True,
            style={"backgroundColor": "#222"}
        ),"""

if "reporting-details-modal" not in app_text:
    app_text = app_text.replace('dcc.Location(id="url_refresh", refresh=True),', modal_html)

callback_code = '''

# =====================================================================
# REPORTING GRAPH CLICK AI HANDLER
# =====================================================================
from dash.dependencies import Input, Output, State, ALL
from dash import callback_context, no_update
import dash_bootstrap_components as dbc
from dash import html, dcc
import json
import os
from openai import OpenAI
from cyber_range.services.neo4j_engine import Neo4jEngine

@callback(
    [Output("reporting-details-modal", "is_open"),
     Output("reporting-details-title", "children"),
     Output("reporting-details-body", "children")],
    [Input({'type': 'reporting-graph', 'index': ALL}, 'clickData'),
     Input('exec-attack-graph', 'tapNodeData'),
     Input('id-attack-tree', 'tapNodeData'),
     Input('lm-attack-graph', 'tapNodeData'),
     Input("close-reporting-modal", "n_clicks")],
    [State("reporting-details-modal", "is_open")],
    prevent_initial_call=True
)
def display_reporting_details(graph_clicks, tap_exec, tap_id, tap_lm, close_clicks, is_open):
    ctx = callback_context
    if not ctx.triggered:
        return no_update, no_update, no_update

    trigger_id_str = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if trigger_id_str == "close-reporting-modal":
        return False, no_update, no_update

    clicked_value = None
    graph_type = "Unknown"
    
    if '{"index":' in trigger_id_str:
        try:
            trigger_id = json.loads(trigger_id_str)
            idx = trigger_id['index']
            
            clicked_data = None
            for data in graph_clicks:
                if data is not None:
                    # In pattern matching with ALL, the list contains the state of all components.
                    # We need to find the one that triggered. Dash Context tells us.
                    # Actually, ctx.triggered gives exact property.
                    pass
            # Just grab it from the specific index using context!
            prop_state = ctx.triggered[0]['value']
            if prop_state and 'points' in prop_state:
                point = prop_state['points'][0]
                clicked_value = point.get('label') or point.get('x') or point.get('text')
                graph_type = f"Chart Region: {idx}"
        except Exception as e:
            print("Err parsing click:", e)
            pass
            
    elif trigger_id_str in ['exec-attack-graph', 'id-attack-tree', 'lm-attack-graph']:
        node_data = tap_exec if trigger_id_str == 'exec-attack-graph' else (tap_id if trigger_id_str == 'id-attack-tree' else tap_lm)
        if node_data:
            clicked_value = node_data.get('label') or node_data.get('id')
            graph_type = f"Network Node ({trigger_id_str})"

    if not clicked_value:
        return no_update, no_update, no_update

    # Safe Neo4j query parameters
    engine = Neo4jEngine()
    
    val_str = str(clicked_value)
    
    res = engine.query(
        "MATCH (n) WHERE toString(n.name) CONTAINS $val OR toString(n.ip) CONTAINS $val OR toString(n.id) CONTAINS $val OR toString(n.label) CONTAINS $val RETURN labels(n)[0] as lbl, properties(n) as props LIMIT 5",
        {"val": val_str}
    )
    
    context_str = f"User clicked on {graph_type} with value: '{val_str}'\\n"
    if res:
        context_str += "Found matching Neo4j Entities:\\n"
        for r in res:
            context_str += f"- Node Type: {r['lbl']}, Properties: {json.dumps(r['props'])}\\n"
    else:
        context_str += "No exact database match. The value might be a category, unmapped variable, or aggregated statistic."

    host_res = engine.query(
        "MATCH (h:Host)-[*1..3]-(n) WHERE toString(n.name) CONTAINS $val OR toString(n.id) CONTAINS $val RETURN DISTINCT h.ip as ip LIMIT 10",
        {"val": val_str}
    )
    if host_res:
        context_str += "\\n\\nDirectly Affected Hosts in Blast Radius:\\n"
        for h in host_res:
            context_str += f"- Host IP: {h['ip']}\\n"

    try:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return True, f"Details: {val_str}", html.P(f"Context:\\n{context_str}\\n\\n[OpenAI API Key Missing]")

        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst. Your job is to explain a graph data point that a user just clicked on. Explain briefly what the context means in a real-world scenario, what it leads to securely, and analyze the affected hosts. Keep it brief, professional, and within 3 paragraphs. Output using markdown."},
                {"role": "user", "content": context_str}
            ]
        )
        ai_analysis = response.choices[0].message.content
        return True, html.Span([html.I(className="fas fa-search"), f" Analysis: {val_str}"]), dcc.Markdown(ai_analysis)
    except Exception as e:
        return True, f"Error Analyzing {val_str}", dcc.Markdown(f"**LLM Error:** {str(e)}\\n\\n**Context:**\\n```\\n{context_str}\\n```")
'''

if "REPORTING GRAPH CLICK AI HANDLER" not in app_text:
    app_text += callback_code

with open('/Backup/vuln_intel/app/app.py', 'w') as f:
    f.write(app_text)

print("Patching complete.")
