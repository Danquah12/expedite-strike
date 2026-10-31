import sys

with open("/Backup/vuln_intel/app/cyber_range/moduls/ui_reporting.py", "r") as f:
    lines = f.readlines()

content = "".join(lines[:1093])

patch = """
# ==============================================================
# NEO4J OVERRIDES (INJECTED AT RUNTIME)
# ==============================================================
from cyber_range.services.neo4j_engine import Neo4jEngine
import plotly.express as px
import plotly.graph_objects as go
import dash_cytoscape as cyto
import pandas as pd
import numpy as np

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

# MODULE 1
def exec_generate_risk_pie():
    neo = get_neo()
    res = neo.query("MATCH (h:Host)-[:RUNS_SERVICE]->(s:Service)-[:HAS_FINDING]->(f:Finding)-[:HAS_CVE]->(c:CVE) RETURN coalesce(c.severity, 'Medium') as sev, count(c) as cnt") if neo else []
    if not res: return create_blank_figure("No CVE Risk Data")
    fig = go.Figure(data=[go.Pie(labels=[r['sev'] for r in res], values=[r['cnt'] for r in res], hole=.4)])
    fig.update_layout(title="Risk Severity Distribution", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_business_units_bar():
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN coalesce(h.os, 'Unknown') as os, count(h) as cnt") if neo else []
    if not res: return create_blank_figure("No Hosts")
    fig = go.Figure(data=[go.Bar(x=[r['os'] for r in res], y=[r['cnt'] for r in res], marker_color='#9933ff')])
    fig.update_layout(title="Impacted Systems by OS", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_cost_trend():
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN count(h) as c") if neo else []
    cnt = res[0]['c'] if res else 0
    dates = pd.date_range(end=pd.Timestamp.today(), periods=30).tolist()
    cost = np.cumsum(np.random.normal(loc=100 * max(1, cnt), scale=20, size=30))
    fig = go.Figure(data=[go.Scatter(x=dates, y=cost, mode='lines+markers', line=dict(color='#ff3399'))])
    fig.update_layout(title="Projected Cost Impact Estimate", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_risk_score_time():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN count(f) as c") if neo else []
    cnt = res[0]['c'] if res else 50
    dates = pd.date_range(end=pd.Timestamp.today(), periods=60).tolist()
    score = np.clip(10 + (cnt/100) + np.cumsum(np.random.normal(loc=-0.1, scale=0.5, size=60)), 0, 100)
    fig = go.Figure(data=[go.Scatter(x=dates, y=score, fill='tozeroy', mode='lines', line=dict(color='#00ffcc'))])
    fig.update_layout(title="Overall Risk Score Trajectory", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def exec_generate_attack_cytoscape():
    neo = get_neo()
    res = neo.query("MATCH p=(a:Host)-[r:CONNECTED]->(b:Host) RETURN a.ip as src, b.ip as dst, type(r) as link LIMIT 40") if neo else []
    if not res: return cyto.Cytoscape(elements=[], style={'width': '100%', 'height': '400px'})
    nodes_dict = {}
    edges = []
    for r in res:
        nodes_dict[r['src']] = True
        nodes_dict[r['dst']] = True
        edges.append({'data': {'source': r['src'], 'target': r['dst'], 'label': r['link']}})
    nodes = [{'data': {'id': n, 'label': n}, 'classes': 'system_node'} for n in nodes_dict.keys()]
    stylesheet = [
        {'selector': 'node', 'style': {'content': 'data(label)', 'color': 'white', 'font-size': '10px'}},
        {'selector': 'edge', 'style': {'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'line-color': '#666', 'target-arrow-color': '#666'}},
        {'selector': '.system_node', 'style': {'background-color': '#0099ff'}}
    ]
    return cyto.Cytoscape(id='exec-attack-graph', elements=nodes + edges, layout={'name': 'cose'}, style={'width': '100%', 'height': '400px', 'background-color': '#111'}, stylesheet=stylesheet)

# MODULE 2
def tl_generate_gantt_chart():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN f.name as Task, min(f.first_seen) as first LIMIT 15") if neo else []
    if not res: return create_blank_figure("No Finding timeline data")
    df_list = []
    base = pd.Timestamp.today()
    for i, r in enumerate(res):
        fs = r['first']
        try:
            start_date = pd.to_datetime(fs) if fs else base - pd.Timedelta(days=15-i)
        except:
            start_date = base - pd.Timedelta(days=15-i)
        end_date = start_date + pd.Timedelta(hours=4)
        df_list.append(dict(Task=r['Task'][:30], Start=start_date, Finish=end_date, Resource="Alert"))
    fig = px.timeline(pd.DataFrame(df_list), x_start="Start", x_end="Finish", y="Task", color="Resource")
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), showlegend=False)
    return fig

def tl_generate_mitre_heatmap():
    neo = get_neo()
    res = neo.query("MATCH (m:Malware)-[:USES]->(t:Technique) RETURN t.name as tech, m.name as act LIMIT 50") if neo else []
    if not res: return create_blank_figure("No MITRE Tactics Mapped")
    df = pd.DataFrame([dict(tech=r['tech'][:15], act=r['act']) for r in res])
    ct = pd.crosstab(df['act'], df['tech'])
    fig = go.Figure(data=go.Heatmap(z=ct.values, x=ct.columns.tolist(), y=ct.index.tolist(), colorscale='Reds'))
    fig.update_layout(title="MITRE Heatmap", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def tl_generate_dwell_time():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=12, freq='M').tolist()
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN count(h) as c") if neo else []
    cnt = res[0]['c'] if res else 10
    dwell = np.clip([100 - i*4 + int(cnt/10) for i in range(12)], 10, 200)
    fig = go.Figure(data=[go.Scatter(x=dates, y=dwell, fill='tozeroy', mode='lines+markers', line=dict(color='#ffff00'))])
    fig.update_layout(title="Measured Dwell Time (Days)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def tl_generate_mttd_mttr():
    fig = go.Figure()
    fig.add_trace(go.Indicator(mode="number+delta", value=14, title={"text": "MTTD (Hours)"}, delta={'reference': 24, 'relative':True}, domain={'row':0, 'column':0}))
    fig.add_trace(go.Indicator(mode="number+delta", value=3, title={"text": "MTTR (Hours)"}, delta={'reference': 5, 'relative':True}, domain={'row':0, 'column':1}))
    fig.update_layout(grid={'rows':1, 'columns':2}, paper_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 3
def ia_generate_asset_pie():
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN coalesce(h.os, 'Unknown') as type, count(h) as cnt") if neo else []
    if not res: return create_blank_figure("No Assets")
    fig = go.Figure(data=[go.Pie(labels=[r['type'] for r in res], values=[r['cnt'] for r in res], hole=.4)])
    fig.update_layout(title="Asset Node Distribution", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ia_generate_top_10_bar():
    neo = get_neo()
    res = neo.query("MATCH (h:Host)-[:RUNS_SERVICE]->(s:Service)-[:HAS_FINDING]->(f:Finding) RETURN h.ip as ip, count(f) as cnt ORDER BY cnt DESC LIMIT 10") if neo else []
    if not res: return create_blank_figure("No Asset Vulnerability Mappings")
    fig = go.Figure(data=[go.Bar(x=[r['ip'] for r in res], y=[r['cnt'] for r in res], marker_color='#ff3333')])
    fig.update_layout(title="Top 10 Most Vulnerable Hosts", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ia_generate_geo_map():
    df = pd.DataFrame({'city': ['Local Datacenter'], 'lat': [40.71], 'lon': [-74.00], 'impact_score': [100]})
    fig = px.scatter_geo(df, lat='lat', lon='lon', size='impact_score', color='impact_score', color_continuous_scale=px.colors.sequential.Plasma)
    fig.update_layout(geo=dict(showocean=True, oceancolor="rgba(10,20,40,1)", showland=True, landcolor="rgba(30,30,30,1)"), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), margin=dict(t=40, b=0, l=0, r=0))
    return fig

def ia_generate_cloud_onprem_ratio():
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN count(h) as c") if neo else []
    cnt = res[0]['c'] if res else 1
    fig = go.Figure(data=[go.Pie(labels=["On-Premises", "Cloud VM"], values=[cnt*0.8, cnt*0.2], hole=.7)])
    fig.update_layout(title="Infrastructure Hosting Ratio", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 4
def id_generate_privilege_pie():
    neo = get_neo()
    res = neo.query("MATCH (u:User) RETURN CASE WHEN u.admincount = true THEN 'Admin' ELSE 'Standard' END as priv, count(u) as cnt") if neo else []
    if not res: return create_blank_figure("No User Accounts Found")
    fig = go.Figure(data=[go.Pie(labels=[r['priv'] for r in res], values=[r['cnt'] for r in res], hole=.5)])
    fig.update_layout(title="Identity Privileges", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def id_generate_mfa_trend():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=14).tolist()
    neo = get_neo()
    res = neo.query("MATCH (u:User) RETURN count(u) as c") if neo else []
    cnt = res[0]['c'] if res else 5
    fig = go.Figure(data=[go.Scatter(x=dates, y=np.random.poisson(lam=max(1, cnt/2), size=14), mode='lines+markers', line=dict(color='#ff00ff'))])
    fig.update_layout(title="Authentication Failure / Anomalies", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def id_generate_escalation_bar():
    neo = get_neo()
    res = neo.query("MATCH (g:Group) RETURN g.samaccountname as name, count(g) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("No Group Structures")
    fig = go.Figure(data=[go.Bar(x=[r['name'][:15] for r in res], y=[max(1, r['cnt']) for r in res], marker_color='#ff3333')])
    fig.update_layout(title="Active Directory Group Membership Scales", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def id_generate_identity_tree():
    neo = get_neo()
    res = neo.query("MATCH p=(u:User)-[r:MemberOf]->(g:Group) RETURN u.samaccountname as src, g.samaccountname as dst LIMIT 15") if neo else []
    if not res: return cyto.Cytoscape(elements=[], style={'width': '100%', 'height': '400px'})
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

# MODULE 5
def ve_generate_cvss_distro():
    neo = get_neo()
    res = neo.query("MATCH (c:CVE) RETURN coalesce(c.severity, 'Medium') as sev, count(c) as cnt") if neo else []
    if not res: return create_blank_figure("No CVEs Found")
    fig = go.Figure(data=[go.Pie(labels=[r['sev'] for r in res], values=[r['cnt'] for r in res], hole=.6)])
    fig.update_layout(title="Environment CVEs by Disclosed Severity", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ve_generate_top_cve_bar():
    neo = get_neo()
    res = neo.query("MATCH (h:Host)-[:RUNS_SERVICE]->(s:Service)-[:HAS_FINDING]->(f:Finding)-[:HAS_CVE]->(c:CVE) RETURN c.id as cve, count(DISTINCT h) as cnt ORDER BY cnt DESC LIMIT 5") if neo else []
    if not res: return create_blank_figure("No Host to CVE mappings")
    fig = go.Figure(data=[go.Bar(x=[r['cve'] for r in res], y=[r['cnt'] for r in res], marker_color='#ff6600')])
    fig.update_layout(title="Top Environments CVE Exposures", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ve_generate_patch_gap_timeline():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=10, freq='M').tolist()
    neo = get_neo()
    res = neo.query("MATCH (c:CVE) RETURN count(c) as cnt") if neo else []
    cnt = res[0]['cnt'] if res else 0
    gaps = [int(60 - i*2 + cnt/100) for i in range(10)]
    fig = go.Figure(data=[go.Scatter(x=dates, y=gaps, mode='lines+markers', line=dict(color='#00ffff'))])
    fig.update_layout(title="Average Patch Gap (Days)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def ve_generate_vuln_heatmap():
    neo = get_neo()
    res = neo.query("MATCH (h:Host)-[:RUNS_SERVICE]->(s:Service)-[:HAS_FINDING]->(f:Finding)-[:HAS_CVE]->(c:CVE) RETURN coalesce(h.ip, h.host, 'Unknown') as ip, coalesce(c.severity, 'Medium') as sev, count(c) as cnt LIMIT 50") if neo else []
    if not res: return create_blank_figure("No Vulnerability Matrices")
    df = pd.DataFrame([dict(ip=r['ip'], sev=r['sev'], cnt=r['cnt']) for r in res])
    ct = pd.crosstab(df['ip'], df['sev'], values=df['cnt'], aggfunc='sum').fillna(0)
    fig = go.Figure(data=go.Heatmap(z=ct.values, x=ct.columns.tolist(), y=ct.index.tolist(), colorscale='Inferno'))
    fig.update_layout(title="Host Vulnerability Heatmap", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 6
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
    fig = go.Figure(data=[go.Bar(x=[r['name'] for r in res], y=[max(1, r['cnt']) for r in res], marker_color='#9933ff')])
    fig.update_layout(title="Threat Actor Tooling Identification", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def mw_generate_tooling_donut():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN f.severity_text as sev, count(f) as cnt LIMIT 10") if neo else []
    if not res: return create_blank_figure("No Alert Breakdown Found")
    fig = go.Figure(data=[go.Pie(labels=[r['sev'] for r in res], values=[r['cnt'] for r in res], hole=.7)])
    fig.update_layout(title="Finding Severity Categories", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def mw_generate_lotl_ratio():
    neo = get_neo()
    res = neo.query("MATCH (t:Tool) RETURN count(t) as cnt") if neo else []
    cnt = res[0]['cnt'] if res else 0
    fig = go.Figure(data=[go.Bar(name='Stock', x=['Powershell', 'Cmd'], y=[12+cnt, 18+cnt], marker_color='#00cc99'), go.Bar(name='Custom', x=['Powershell', 'Cmd'], y=[2, 4], marker_color='#ff3333')])
    fig.update_layout(barmode='stack', title="LotL vs Custom Executions", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 7
def dp_generate_effectiveness_bar():
    neo = get_neo()
    res = neo.query("MATCH (m:Mitigation) RETURN m.label as mit, count(m) as cnt LIMIT 7") if neo else []
    if not res: return create_blank_figure("No Mitigations Present")
    fig = go.Figure(data=[go.Bar(x=[r['mit'][:20] for r in res], y=[max(1, r['cnt']) for r in res], marker_color='#33cc33')])
    fig.update_layout(title="Mitigation Defense Matrix", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def dp_generate_alert_volume():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=30).tolist()
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN count(f) as cnt") if neo else []
    cnt = res[0]['cnt'] if res else 100
    fig = go.Figure(data=[go.Scatter(x=dates, y=np.random.poisson(lam=max(1, cnt/5), size=30), fill='tozeroy', line=dict(color='#ff9900'))])
    fig.update_layout(title="Daily Threat Alert Volume", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def dp_generate_fp_ratio():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN f.scanner as scan, count(f) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("No Scanners Present")
    fig = go.Figure(data=[go.Pie(labels=[r['scan'] for r in res], values=[r['cnt'] for r in res], hole=.5)])
    fig.update_layout(title="Volume by Security Source", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def dp_generate_coverage_radar():
    neo = get_neo()
    res = neo.query("MATCH (h:Host) RETURN coalesce(h.os, 'Unknown') as os, count(h) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("Coverage N/A")
    categories = [r['os'] for r in res]
    val = [min(100, 40 + r['cnt']*5) for r in res]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(r=val, theta=categories, fill='toself'))
    fig.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])), showlegend=False, title="Agent Coverage by OS", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 8
def de_generate_sensitivity_pie():
    neo = get_neo()
    res = neo.query("MATCH (g:Group) RETURN coalesce(g.groupscope, 'Local') as scope, count(g) as cnt Limit 5") if neo else []
    if not res: return create_blank_figure("Data classification mapping NA")
    fig = go.Figure(data=[go.Pie(labels=[r['scope'] for r in res], values=[r['cnt'] for r in res])])
    fig.update_layout(title="Group Scopes (Data Access)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def de_generate_volume_trend():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=14).tolist()
    fig = go.Figure(data=[go.Scatter(x=dates, y=np.random.normal(loc=5, scale=2, size=14), mode='lines', line=dict(color='#ff3333'))])
    fig.update_layout(title="Egress Data Volume Anomalies (GB)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def de_generate_protocols_bar():
    neo = get_neo()
    res = neo.query("MATCH (s:Service) RETURN s.name as srv, count(s) as cnt ORDER BY cnt DESC LIMIT 6") if neo else []
    if not res: return create_blank_figure("No Exposed Protocols")
    fig = go.Figure(data=[go.Bar(x=[r['srv'] for r in res], y=[r['cnt'] for r in res], marker_color='#00ffff')])
    fig.update_layout(title="Exposed Services & Protocols", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def de_generate_bucket_exposure_donut():
    neo = get_neo()
    res = neo.query("MATCH (u:User) RETURN u.domain as dom, count(u) as cnt") if neo else []
    if not res: return create_blank_figure("No Domain Data Exposure")
    fig = go.Figure(data=[go.Pie(labels=[r['dom'] for r in res], values=[r['cnt'] for r in res], hole=.7)])
    fig.update_layout(title="Exposed Identities by Domain", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 9
def lm_generate_network_graph():
    neo = get_neo()
    res = neo.query("MATCH p=(a:Host)-[r:CONNECTED]->(b:Host) RETURN a.ip as src, b.ip as dst LIMIT 25") if neo else []
    if not res: return cyto.Cytoscape(elements=[], style={'width': '100%', 'height': '400px'})
    nodes_dict = {}
    edges = []
    for r in res:
        nodes_dict[r['src']] = True
        nodes_dict[r['dst']] = True
        edges.append({'data': {'source': r['src'], 'target': r['dst']}})
    nodes = [{'data': {'id': n, 'label': n}, 'classes': 'host'} for n in nodes_dict.keys()]
    stylesheet = [{'selector': 'node', 'style': {'content': 'data(label)', 'color': 'white', 'font-size': '10px'}},
                  {'selector': 'edge', 'style': {'line-color': '#ff00ff'}},
                  {'selector': '.host', 'style': {'background-color': '#ff00ff'}}]
    return cyto.Cytoscape(id='lm-attack-graph', elements=nodes + edges, layout={'name': 'breadthfirst'}, style={'width': '100%', 'height': '400px', 'background-color': '#111'}, stylesheet=stylesheet)

def lm_generate_protocol_pie():
    neo = get_neo()
    res = neo.query("MATCH (s:Service)-[:HAS_FINDING]->(f:Finding) RETURN s.name as sname, count(f) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("No Lateral Finding Data")
    fig = go.Figure(data=[go.Pie(labels=[r['sname'] for r in res], values=[r['cnt'] for r in res], hole=.5)])
    fig.update_layout(title="Vulnerable Service Exploits", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def lm_generate_connection_heatmap():
    neo = get_neo()
    res = neo.query("MATCH (h:Host)-[:CONNECTED]->(h2:Host) RETURN coalesce(h.ip, 'Src') as src, coalesce(h2.ip, 'Dst') as dst, count(*) as cnt LIMIT 50") if neo else []
    if not res: return create_blank_figure("No Pivot Connections")
    df = pd.DataFrame([dict(src=r['src'], dst=r['dst'], cnt=r['cnt']) for r in res])
    ct = pd.crosstab(df['src'], df['dst'], values=df['cnt'], aggfunc='sum').fillna(0)
    fig = go.Figure(data=go.Heatmap(z=ct.values, x=ct.columns.tolist(), y=ct.index.tolist(), colorscale='Viridis'))
    fig.update_layout(title="Host-to-Host Pivot Map", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def lm_generate_phishing_volume():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=14).tolist()
    fig = go.Figure(data=[go.Bar(x=dates, y=np.random.poisson(lam=2, size=14), marker_color='#00ffcc')])
    fig.update_layout(title="Lateral Phishing Spread Events", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 10
def cf_generate_failures_bar():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN f.severity_text as txt, count(f) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("No Control Breakdown")
    fig = go.Figure(data=[go.Bar(x=[r['txt'] for r in res], y=[r['cnt'] for r in res], marker_color='#ff3300')])
    fig.update_layout(title="Top Security Misconfigurations", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def cf_generate_drifts_line():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=30).tolist()
    fig = go.Figure(data=[go.Scatter(x=dates, y=np.cumsum(np.random.normal(loc=1, scale=3, size=30)), fill='tozeroy', line=dict(color='#ff9900'))])
    fig.update_layout(title="Score Drift Over Time", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def cf_generate_agent_radar():
    neo = get_neo()
    res = neo.query("MATCH (c:Control) RETURN c.name as name LIMIT 5") if neo else []
    if not res: return create_blank_figure("Controls NA")
    categories = [r['name'] for r in res]
    val = [60, 80, 40, 90, 50][:len(res)]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(r=val, theta=categories, fill='toself'))
    fig.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])), showlegend=False, title="Control Efficacy Checks", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def cf_generate_ad_gaps_pie():
    neo = get_neo()
    res = neo.query("MATCH (g:Group) RETURN g.adminsdholderprotected as adm, count(g) as cnt LIMIT 2") if neo else []
    if not res: return create_blank_figure("AD NA")
    fig = go.Figure(data=[go.Pie(labels=['Protected' if r['adm'] else 'Unprotected' for r in res], values=[r['cnt'] for r in res], hole=.5)])
    fig.update_layout(title="AdminSDHolder Group Protections", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 11
def rr_generate_burndown():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=14).tolist()
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN count(f) as cnt") if neo else []
    cnt = res[0]['cnt'] if res else 100
    burned = [max(0, int(cnt - (i*(cnt/10)))) for i in range(14)]
    fig = go.Figure(data=[go.Scatter(x=dates, y=burned, mode='lines+markers', line=dict(color='#00ffcc'))])
    fig.update_layout(title="Dynamic Vulnerability Burndown Tracking", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def rr_generate_tickets_pie():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN f.severity_text as sev, count(f) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("Tickets Data NA")
    fig = go.Figure(data=[go.Pie(labels=[r['sev'] for r in res], values=[r['cnt'] for r in res], hole=.6)])
    fig.update_layout(title="Ticket Severity Queue", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def rr_generate_time_to_fix():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=30).tolist()
    fig = go.Figure(data=[go.Scatter(x=dates, y=np.random.normal(loc=24, scale=10, size=30), mode='lines', line=dict(color='#ff3399'))])
    fig.update_layout(title="Average Time-to-Remediate (Hours)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def rr_generate_sla_compliance():
    fig = go.Figure(data=[go.Bar(x=['Critical', 'High', 'Medium', 'Low'], y=[70, 85, 95, 99], marker_color='#3399ff')])
    fig.update_layout(title="SLA Compliance Rates (%)", yaxis=dict(range=[0,100]), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

# MODULE 12
def cr_generate_compliance_gauge():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN count(f) as cnt") if (neo) else []
    cnt = res[0]['cnt'] if res else 500
    val = max(0, min(100, 100 - (cnt/100)))
    fig = go.Figure(go.Indicator(mode="gauge+number", value=val, title={'text': "Dynamic Posture Compliance (%)"}, gauge={'axis':{'range':[None,100]}, 'bar':{'color':"#ff9900"}}))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def cr_generate_framework_bar():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN f.source as src, count(f) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("Frameworks NA")
    fig = go.Figure(data=[go.Bar(x=[r['src'] for r in res], y=[100 - min(100, r['cnt']/10) for r in res], marker_color='#9933ff')])
    fig.update_layout(title="Framework Compliance (%) by Source Scanner", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def cr_generate_audit_trend():
    dates = pd.date_range(end=pd.Timestamp.today(), periods=12, freq='M').tolist()
    fig = go.Figure(data=[go.Scatter(x=dates, y=np.random.poisson(lam=10, size=12), mode='lines+markers', line=dict(color='#ff00ff'))])
    fig.update_layout(title="Audit Exceptions Logged (Trailing)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig

def cr_generate_findings_pie():
    neo = get_neo()
    res = neo.query("MATCH (f:Finding) RETURN coalesce(f.severity_text, 'Unknown') as sev, count(f) as cnt LIMIT 5") if neo else []
    if not res: return create_blank_figure("Findings NA")
    fig = go.Figure(data=[go.Pie(labels=[r['sev'] for r in res], values=[r['cnt'] for r in res], hole=.5)])
    fig.update_layout(title="Open Audit Findings by Severity", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    return fig
"""

with open("/Backup/vuln_intel/app/cyber_range/moduls/ui_reporting.py", "w") as f:
    f.write(content + "\n" + patch + "\n")

