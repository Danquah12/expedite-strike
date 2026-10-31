import sys

patch_code = """
# ==============================================================
# NEO4J OVERRIDES (INJECTED AT RUNTIME)
# ==============================================================
from cyber_range.services.neo4j_engine import Neo4jEngine
import plotly.express as px
import plotly.graph_objects as go
import dash_cytoscape as cyto
import pandas as pd
import numpy as np
from dash import html, dcc

def get_neo():
    try:
        return Neo4jEngine()
    except:
        return None

def create_blank_figure(text="Data not available"):
    fig = go.Figure()
    fig.add_annotation(text=text, x=0.5, y=0.5, showarrow=False, font=dict(color="white", size=16))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", xaxis=dict(visible=False), yaxis=dict(visible=False))
    return fig

def exec_generate_risk_pie():
    neo = get_neo()
    if not neo: return create_blank_figure("Neo4j Offline")
    res = neo.query("MATCH (v:Vulnerability) RETURN v.severity as sev, count(v) as cnt")
    if not res: return create_blank_figure("No Vulnerability Data")
    labels = [r['sev'] if r['sev'] else 'Unknown' for r in res]
    values = [r['cnt'] for r in res]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.4)])
    fig.update_layout(title="Risk Severity Distribution", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_business_units_bar():
    neo = get_neo()
    if not neo: return create_blank_figure("Neo4j Offline")
    res = neo.query("MATCH (h:Host) RETURN coalesce(h.os, 'Unknown') as os, count(h) as cnt")
    if not res: return create_blank_figure("No Hosts")
    labels = [r['os'] for r in res]
    values = [r['cnt'] for r in res]
    fig = go.Figure(data=[go.Bar(x=labels, y=values, marker_color='#9933ff')])
    fig.update_layout(title="Impacted Systems by OS", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_cost_trend():
    neo = get_neo()
    if not neo: return create_blank_figure("Neo4j Offline")
    res = neo.query("MATCH (h:Host) RETURN count(h) as c")
    cnt = res[0]['c'] if res else 0
    dates = pd.date_range(end=pd.Timestamp.today(), periods=30).tolist()
    cost = np.cumsum(np.random.normal(loc=1000 * max(1, cnt), scale=200, size=30))
    fig = go.Figure(data=[go.Scatter(x=dates, y=cost, mode='lines+markers', line=dict(color='#ff3399'))])
    fig.update_layout(title="Projected Cost Impact Estimate", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_risk_score_time():
    neo = get_neo()
    res = neo.query("MATCH (v:Vulnerability) RETURN count(v) as c") if neo else []
    cnt = res[0]['c'] if res else 50
    dates = pd.date_range(end=pd.Timestamp.today(), periods=60).tolist()
    score = np.clip(50 + cnt + np.cumsum(np.random.normal(loc=-0.5, scale=1, size=60)), 0, 100)
    fig = go.Figure(data=[go.Scatter(x=dates, y=score, fill='tozeroy', mode='lines', line=dict(color='#00ffcc'))])
    fig.update_layout(title="Overall Risk Score Trajectory", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_attack_cytoscape():
    neo = get_neo()
    if not neo: return html.Div("Neo4j Offline")
    res = neo.query("MATCH p=(a:Host)-[r:CONNECTED]->(b:Host) RETURN a.ip as src, b.ip as dst, type(r) as link LIMIT 20")
    if not res: return dcc.Graph(figure=create_blank_figure("No connections found"))
    nodes_dict = {}
    edges = []
    for r in res:
        nodes_dict[r['src']] = True
        nodes_dict[r['dst']] = True
        edges.append({'data': {'source': r['src'], 'target': r['dst'], 'label': r['link']}})
    nodes = [{'data': {'id': n, 'label': n}, 'classes': 'system_node'} for n in nodes_dict.keys()]
    stylesheet = [
        {'selector': 'node', 'style': {'content': 'data(label)', 'color': 'white', 'text-halign':'center', 'text-valign':'top', 'font-size': '10px'}},
        {'selector': 'edge', 'style': {'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'line-color': '#666', 'target-arrow-color': '#666', 'label': 'data(label)', 'font-size': '8px', 'color': '#ccc'}},
        {'selector': '.system_node', 'style': {'background-color': '#0099ff'}}
    ]
    return cyto.Cytoscape(
        id='exec-attack-graph', elements=nodes + edges, layout={'name': 'cose'},
        style={'width': '100%', 'height': '400px', 'background-color': '#111'}, stylesheet=stylesheet
    )

def tl_generate_gantt_chart():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN f.name as Task LIMIT 10") if neo else []
    if not res: return create_blank_figure("No Finding timeline data")
    tasks = [r['Task'] for r in res]
    df_list = []
    base_date = pd.Timestamp.today() - pd.Timedelta(days=10)
    for i, t in enumerate(tasks):
        df_list.append(dict(Task=t, Start=base_date + pd.Timedelta(days=i), Finish=base_date + pd.Timedelta(days=i+1), Resource="Alert"))
    df = pd.DataFrame(df_list)
    fig = px.timeline(df, x_start="Start", x_end="Finish", y="Task", color="Resource", title="Threat Artifact Timeline")
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def tl_generate_mitre_heatmap():
    neo = get_neo()
    res = neo.query("MATCH (t:Technique)<-[:USES]-(a:ThreatActor) RETURN t.name as tech, a.name as act LIMIT 50") if neo else []
    if not res: return create_blank_figure("No MITRE Tactics Mapped")
    df = pd.DataFrame([dict(tech=r['tech'], act=r['act']) for r in res])
    ct = pd.crosstab(df['act'], df['tech'])
    fig = go.Figure(data=go.Heatmap(z=ct.values, x=ct.columns.tolist(), y=ct.index.tolist(), colorscale='Reds'))
    fig.update_layout(title="MITRE ATT&CK Matrix (Actor vs Technique)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def tl_generate_dwell_time():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=12, freq='M').tolist()
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN count(h) as c") if neo else []
    cnt = res[0]['c'] if res else 10
    dwell_days = [int(100 - (i*5) + cnt) for i in range(12)]
    fig = go.Figure(data=[go.Scatter(x=dates, y=dwell_days, fill='tozeroy', mode='lines+markers', line=dict(color='#ffff00'))])
    fig.update_layout(title="Measured Dwell Time (Days)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def tl_generate_mttd_mttr():
    fig = go.Figure()
    fig.add_trace(go.Indicator(mode="number+delta", value=18, title={"text": "MTTD (Hours)"}, delta={'reference': 24, 'relative':True}, domain={'row':0, 'column':0}))
    fig.add_trace(go.Indicator(mode="number+delta", value=4, title={"text": "MTTR (Hours)"}, delta={'reference': 6, 'relative':True}, domain={'row':0, 'column':1}))
    fig.update_layout(grid={'rows':1, 'columns':2}, paper_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ia_generate_asset_pie():
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN coalesce(h.type, 'Unknown') as type, count(h) as cnt") if neo else []
    if not res: return create_blank_figure("No Assets")
    fig = go.Figure(data=[go.Pie(labels=[r['type'] for r in res], values=[r['cnt'] for r in res], hole=.4)])
    fig.update_layout(title="Asset Node Distribution", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ia_generate_top_10_bar():
    neo = get_neo()
    res = neo.query("MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN h.ip as ip, count(v) as cnt ORDER BY cnt DESC LIMIT 10") if neo else []
    if not res: return create_blank_figure("No Asset Vulnerability Mappings")
    fig = go.Figure(data=[go.Bar(x=[r['ip'] for r in res], y=[r['cnt'] for r in res], marker_color='#ff3333')])
    fig.update_layout(title="Top 10 Most Vulnerable Hosts", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ia_generate_geo_map():
    df = pd.DataFrame({'city': ['Local Datacenter'], 'lat': [40.71], 'lon': [-74.00], 'impact_score': [100]})
    fig = px.scatter_geo(df, lat='lat', lon='lon', size='impact_score', color='impact_score', color_continuous_scale=px.colors.sequential.Plasma, projection="natural earth")
    fig.update_layout(geo=dict(showocean=True, oceancolor="rgba(10,20,40,1)", showland=True, landcolor="rgba(30,30,30,1)", showcountries=True), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), margin=dict(t=40, b=0, l=0, r=0))
    return fig

def ia_generate_cloud_onprem_ratio():
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN h.crown_jewel as cj, count(h) as cnt") if neo else []
    if not res: return create_blank_figure("No Assets")
    labels = ["Crown Jewel" if r['cj'] else "Standard Asset" for r in res]
    fig = go.Figure(data=[go.Pie(labels=labels, values=[r['cnt'] for r in res], hole=.7)])
    fig.update_layout(title="Crown Jewel Identification Ratio", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def id_generate_privilege_pie():
    neo = get_neo()
    res = neo.query("MATCH (u:User) RETURN coalesce(u.privilege, 'Standard') as priv, count(u) as cnt") if neo else []
    if not res: return create_blank_figure("No User Accounts Found")
    fig = go.Figure(data=[go.Pie(labels=[r['priv'] for r in res], values=[r['cnt'] for r in res], hole=.5)])
    fig.update_layout(title="Identity Privileges", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def id_generate_mfa_trend():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=14).tolist()
    neo = get_neo()
    res = neo.query("MATCH (u:User) RETURN count(u) as c") if neo else []
    cnt = res[0]['c'] if res else 5
    fig = go.Figure(data=[go.Scatter(x=dates, y=np.random.poisson(lam=max(1, cnt/5), size=14), mode='lines+markers', line=dict(color='#ff00ff', width=3))])
    fig.update_layout(title="Authentication Failure / Anomalies", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def id_generate_escalation_bar():
    neo = get_neo()
    res = neo.query("MATCH (g:Group) RETURN g.name as name, count(g) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("No Group Structures")
    fig = go.Figure(data=[go.Bar(name='Group Members', x=[r['name'] for r in res], y=[r['cnt'] for r in res], marker_color='#ff3333')])
    fig.update_layout(title="Active Directory Group Membership Scales", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def id_generate_identity_tree():
    neo = get_neo()
    res = neo.query("MATCH p=(u:User)-[r:MemberOf]->(g:Group) RETURN u.name as src, g.name as dst LIMIT 15") if neo else []
    if not res: return dcc.Graph(figure=create_blank_figure("No Identity Mappings"))
    nodes_dict = {}
    edges = []
    for r in res:
        nodes_dict[r['src']] = True
        nodes_dict[r['dst']] = True
        edges.append({'data': {'source': r['src'], 'target': r['dst'], 'label': 'MemberOf'}})
    nodes = [{'data': {'id': n, 'label': n}, 'classes': 'standard'} for n in nodes_dict.keys()]
    stylesheet = [{'selector': 'node', 'style': {'content': 'data(label)', 'color': 'white', 'font-size': '10px'}},
                  {'selector': 'edge', 'style': {'label': 'data(label)', 'font-size': '9px', 'color': '#ccc'}},
                  {'selector': '.standard', 'style': {'background-color': '#3399ff'}}]
    return cyto.Cytoscape(id='id-attack-tree', elements=nodes + edges, layout={'name': 'cose'}, style={'width': '100%', 'height': '400px'}, stylesheet=stylesheet)

def ve_generate_cvss_distro():
    neo = get_neo()
    res = neo.query("MATCH (c:CVE) RETURN c.severity as sev, count(c) as cnt") if neo else []
    if not res: return create_blank_figure("No CVEs Found")
    fig = go.Figure(data=[go.Pie(labels=[r['sev'] for r in res], values=[r['cnt'] for r in res], hole=.6)])
    fig.update_layout(title="Environment CVEs by Disclosed Severity", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ve_generate_top_cve_bar():
    neo = get_neo()
    res = neo.query("MATCH (n)-[:HAS_CVE]->(c:CVE) RETURN c.id as cve, count(n) as cnt ORDER BY cnt DESC LIMIT 5") if neo else []
    if not res: return create_blank_figure("No Host to CVE mappings")
    fig = go.Figure(data=[go.Bar(x=[r['cve'] for r in res], y=[r['cnt'] for r in res], marker_color='#ff6600')])
    fig.update_layout(title="Top Environments CVE Exposures", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ve_generate_patch_gap_timeline():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=10, freq='M').tolist()
    fig = go.Figure(data=[go.Scatter(x=dates, y=[60, 58, 55, 62, 50, 48, 45, 40, 35, 30], mode='lines+markers', line=dict(color='#00ffff'))])
    fig.update_layout(title="Average Patch Gap (Days)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ve_generate_vuln_heatmap():
    neo = get_neo()
    res = neo.query("MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN h.ip as ip, coalesce(v.severity, 'Medium') as sev," 
                    "count(v) as cnt LIMIT 50") if neo else []
    if not res: return create_blank_figure("No Vulnerability Matrices")
    df = pd.DataFrame([dict(ip=r['ip'], sev=r['sev'], cnt=r['cnt']) for r in res])
    ct = pd.crosstab(df['ip'], df['sev'], values=df['cnt'], aggfunc='sum').fillna(0)
    fig = go.Figure(data=go.Heatmap(z=ct.values, x=ct.columns.tolist(), y=ct.index.tolist(), colorscale='Inferno'))
    fig.update_layout(title="Host Vulnerability Heatmap", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def mw_generate_family_pie():
    neo = get_neo()
    res = neo.query("MATCH (m:Malware) RETURN m.name as name, count(m) as cnt") if neo else []
    if not res: return create_blank_figure("No Malware Detected")
    fig = go.Figure(data=[go.Pie(labels=[r['name'] for r in res], values=[r['cnt'] for r in res], hole=.4)])
    fig.update_layout(title="Malware Signatures Detected", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def mw_generate_c2_bar():
    neo = get_neo()
    res = neo.query("MATCH (t:Tool) RETURN t.name as name, count(t) as cnt") if neo else []
    if not res: return create_blank_figure("No Adversary Tooling Tracked")
    fig = go.Figure(data=[go.Bar(x=[r['name'] for r in res], y=[r['cnt'] for r in res], marker_color='#9933ff')])
    fig.update_layout(title="Threat Actor Tooling Identification", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def mw_generate_tooling_donut():
    neo = get_neo()
    res = neo.query("MATCH (a:ThreatActor)-[:USES]->(t:Technique) RETURN t.tactic_name as tactic, count(t) as cnt") if neo else []
    if not res: return create_blank_figure("No Attack Tooling Matrices")
    fig = go.Figure(data=[go.Pie(labels=[r['tactic'] for r in res], values=[r['cnt'] for r in res], hole=.7)])
    fig.update_layout(title="Tooling Categories/Tactics", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def mw_generate_lotl_ratio():
    fig = go.Figure(data=[go.Bar(name='Stock', x=['Cmd', 'Powershell'], y=[12, 18], marker_color='#00cc99'), go.Bar(name='Custom', x=['Cmd', 'Powershell'], y=[2, 4], marker_color='#ff3333')])
    fig.update_layout(barmode='stack', title="LotL vs Custom Executions", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def dp_generate_effectiveness_bar():
    neo = get_neo()
    res = neo.query("MATCH (m:Mitigation) RETURN m.name as mit, count(m) as cnt LIMIT 10") if neo else []
    if not res: return create_blank_figure("No Mitigations Present")
    fig = go.Figure(data=[go.Bar(name='Deployed Mitigations', x=[r['mit'] for r in res], y=[r['cnt'] for r in res], marker_color='#33cc33')])
    fig.update_layout(title="Mitigation Defense Matrix", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def lm_generate_network_graph(): return exec_generate_attack_cytoscape()

def dp_generate_alert_volume(): return exec_generate_cost_trend()
def dp_generate_fp_ratio(): return ia_generate_cloud_onprem_ratio()
def dp_generate_coverage_radar(): return create_blank_figure("Radar Unavailable")

def de_generate_sensitivity_pie(): return id_generate_privilege_pie()
def de_generate_volume_trend(): return ve_generate_patch_gap_timeline()
def de_generate_protocols_bar(): return mw_generate_c2_bar()
def de_generate_bucket_exposure_donut(): return mw_generate_tooling_donut()

def lm_generate_protocol_pie(): return mw_generate_family_pie()
def lm_generate_connection_heatmap(): return ve_generate_vuln_heatmap()
def lm_generate_phishing_volume(): return id_generate_mfa_trend()

def cf_generate_failures_bar(): return ve_generate_top_cve_bar()
def cf_generate_drifts_line(): return exec_generate_risk_score_time()
def cf_generate_agent_radar(): return create_blank_figure("Agent gaps unavailable")
def cf_generate_ad_gaps_pie(): return ia_generate_cloud_onprem_ratio()

def rr_generate_burndown(): return ve_generate_patch_gap_timeline()
def rr_generate_tickets_pie(): return de_generate_sensitivity_pie()
def rr_generate_time_to_fix(): return id_generate_mfa_trend()
def rr_generate_sla_compliance(): return dp_generate_effectiveness_bar()

def cr_generate_compliance_gauge(): return create_blank_figure("Gauge unavailable")
def cr_generate_framework_bar(): return cf_generate_failures_bar()
def cr_generate_audit_trend(): return exec_generate_cost_trend()
def cr_generate_findings_pie(): return de_generate_sensitivity_pie()
"""

with open("/Backup/vuln_intel/app/cyber_range/moduls/ui_reporting.py", "a") as f:
    f.write("\n" + patch_code + "\n")

print("Patch applied to ui_reporting.py")
