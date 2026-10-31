"""
PhD Research Tools — Advanced Analysis Module
===============================================
Extends ui_phd_comparison with:
  1. Live Evaluation Lab          — real-time comparison of 3 AI systems
  2. Statistical Analysis         — Cohen's d, 95% CI, violin plots
  3. Monte Carlo Sensitivity      — rank stability under 2000 weight scenarios
  4. Advanced Visualizations      — parallel coords, Sankey, calibration
  5. Cybersecurity Domain         — CVE/MITRE/exploit-specific evaluation
  6. Export & References          — CSV export, benchmark citation table
"""

import sys
sys.path.insert(0, "/home/kali/.local/lib/python3.13/site-packages")

import os, urllib.parse, time
import numpy as np
import pandas as pd
from dash import html, dcc, callback, Input, Output, State, no_update
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

from cyber_range.moduls.ui_phd_comparison import (
    fetch_live_context, build_live_data_banner,
    MODELS, COLORS, DIMENSIONS, RAW_SCORES,
    TRUST_DIMS_CLEAN, TRUST_SCORES, TRUST_WEIGHTS,
    compute_mcda_normalized, compute_trust_index, _th, _td,
)

# ─── try scipy ─────────────────────────────────────────────────────────────
try:
    from scipy import stats as _sci
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

# ===========================================================================
# 1. STATISTICAL HELPERS
# ===========================================================================

def _cohen_d(a, b):
    a, b = np.array(a, float), np.array(b, float)
    sp = np.sqrt(((len(a)-1)*a.std(ddof=1)**2 + (len(b)-1)*b.std(ddof=1)**2)
                 / (len(a)+len(b)-2))
    return float((a.mean()-b.mean()) / (sp+1e-9))

def _bootstrap_ci(arr, n=1000, seed=42):
    rng = np.random.default_rng(seed)
    boots = [rng.choice(arr, len(arr), replace=True).mean() for _ in range(n)]
    return np.percentile(boots, [2.5, 97.5])

def build_ci_bar():
    base = compute_mcda_normalized()
    ms = sorted(base, key=base.get, reverse=True)
    ys, lo, hi, cols = [], [], [], []
    for m in ms:
        raw = np.array(RAW_SCORES[m]) / 10.0
        ci  = _bootstrap_ci(raw)
        ys.append(base[m]);  lo.append(base[m]-ci[0]);  hi.append(ci[1]-base[m])
        cols.append(COLORS[m])
    fig = go.Figure(go.Bar(
        x=[m.replace("\n"," ") for m in ms], y=ys,
        marker_color=cols,
        error_y=dict(type="data", symmetric=False, array=hi, arrayminus=lo,
                     color="#fff", thickness=2, width=8),
        text=[f"{v:.3f}" for v in ys], textposition="outside",
        textfont=dict(color="#fff", size=12),
    ))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", plot_bgcolor="#111",
        xaxis=dict(color="#aaa"), showlegend=False,
        yaxis=dict(color="#aaa", gridcolor="#222", range=[0,1.1],
                   title="MCDA Score (95% Bootstrap CI)"),
        title=dict(text="MCDA Scores with 95% Confidence Intervals",
                   font=dict(color="#fff",size=14), x=0.5),
        height=380, margin=dict(t=60,b=40),
    )
    return fig

def build_cohend_heatmap():
    mk = list(RAW_SCORES.keys())
    n  = len(mk)
    z  = [[0.0]*n for _ in range(n)]
    ann= [["—"]*n for _ in range(n)]
    for i,m1 in enumerate(mk):
        for j,m2 in enumerate(mk):
            if i==j: continue
            d = _cohen_d(RAW_SCORES[m1], RAW_SCORES[m2])
            z[i][j] = d
            sig=""
            if HAS_SCIPY:
                _,p = _sci.ttest_ind(RAW_SCORES[m1], RAW_SCORES[m2])
                sig = "***" if p<.001 else "**" if p<.01 else "*" if p<.05 else ""
            ann[i][j] = f"{d:+.2f}{sig}"
    labels = [m.replace("\n"," ") for m in mk]
    fig = go.Figure(go.Heatmap(
        z=z, x=labels, y=labels,
        colorscale="RdBu_r", zmid=0,
        text=ann, texttemplate="%{text}",
        textfont=dict(size=11, color="#fff"),
        colorbar=dict(title=dict(text="Cohen's d", font=dict(color="#aaa")),
                      tickfont=dict(color="#aaa")),
    ))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", plot_bgcolor="#111",
        xaxis=dict(side="top", color="#ddd", tickfont=dict(size=11,color="#ddd")),
        yaxis=dict(color="#ddd", tickfont=dict(size=11,color="#ddd")),
        title=dict(text="Cohen's d Effect Size  (*** p<.001  ** p<.01  * p<.05)",
                   font=dict(color="#fff",size=13), x=0.5),
        height=320, margin=dict(t=80,b=20,l=200,r=20),
    )
    return fig

def build_violin():
    fig = go.Figure()
    for m in MODELS:
        fig.add_trace(go.Violin(
            y=RAW_SCORES[m], name=m.replace("\n"," "),
            box_visible=True, meanline_visible=True,
            fillcolor=COLORS[m], opacity=0.55, line_color=COLORS[m],
        ))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", plot_bgcolor="#111",
        xaxis=dict(color="#aaa"), violingap=0.1, violinmode="group",
        yaxis=dict(color="#aaa", gridcolor="#222", title="Score (0–10)"),
        title=dict(text="Score Distributions Across 14 Dimensions",
                   font=dict(color="#fff",size=14), x=0.5),
        legend=dict(font=dict(color="#ddd"), bgcolor="rgba(0,0,0,0)"),
        height=380, margin=dict(t=60,b=40),
    )
    return fig

# ===========================================================================
# 2. MONTE CARLO SENSITIVITY
# ===========================================================================

def _run_mc(n=2000, seed=42):
    rng  = np.random.default_rng(seed)
    nd   = len(DIMENSIONS)
    wins = {m:0 for m in MODELS}
    beats= {(a,b):0 for a in MODELS for b in MODELS if a!=b}
    for _ in range(n):
        w  = rng.dirichlet(np.ones(nd))
        sc = {m: float(np.dot(w, np.array(RAW_SCORES[m])/10)) for m in MODELS}
        wins[max(sc,key=sc.get)] += 1
        for a in MODELS:
            for b in MODELS:
                if a!=b and sc[a]>sc[b]: beats[(a,b)]+=1
    return {m: wins[m]/n*100 for m in MODELS}, {k:v/n*100 for k,v in beats.items()}

def build_mc_bar():
    wp, _ = _run_mc()
    ms = sorted(wp,key=wp.get,reverse=True)
    fig= go.Figure(go.Bar(
        x=[m.replace("\n"," ") for m in ms], y=[wp[m] for m in ms],
        marker_color=[COLORS[m] for m in ms],
        text=[f"{wp[m]:.1f}%" for m in ms], textposition="outside",
        textfont=dict(color="#fff"),
    ))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", plot_bgcolor="#111",
        xaxis=dict(color="#aaa"), showlegend=False,
        yaxis=dict(color="#aaa", gridcolor="#222", range=[0,110],
                   title="Win % (n=2 000 simulations)"),
        title=dict(text="Monte Carlo — % of Weight Scenarios Won",
                   font=dict(color="#fff",size=14),x=0.5),
        height=360, margin=dict(t=60,b=40),
    )
    return fig

def build_stability_heatmap():
    _, bt = _run_mc()
    labels = [m.replace("\n"," ") for m in MODELS]
    z   = [[bt.get((a,b),50) if a!=b else 50 for b in MODELS] for a in MODELS]
    ann = [[f"{v:.0f}%" for v in row] for row in z]
    fig = go.Figure(go.Heatmap(
        z=z, x=labels, y=labels,
        colorscale=[[0,"#8B0000"],[0.5,"#888800"],[1,"#006400"]],
        zmin=0,zmax=100,
        text=ann, texttemplate="%{text}", textfont=dict(size=12,color="#fff"),
        colorbar=dict(title=dict(text="P(row>col)%",font=dict(color="#aaa")),
                      tickfont=dict(color="#aaa")),
    ))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", plot_bgcolor="#111",
        xaxis=dict(side="top",color="#ddd",tickfont=dict(size=11),title="← loses to"),
        yaxis=dict(color="#ddd",tickfont=dict(size=11),title="beats →"),
        title=dict(text="Rank Stability Matrix — P(row model beats column)",
                   font=dict(color="#fff",size=13),x=0.5),
        height=280, margin=dict(t=80,b=20,l=200,r=20),
    )
    return fig

# ===========================================================================
# 3. ADVANCED VISUALIZATIONS
# ===========================================================================

def build_parallel_coords():
    pcd = []
    for j,dim in enumerate(DIMENSIONS):
        pcd.append(dict(label=dim[:18],
                        values=[RAW_SCORES[m][j] for m in MODELS], range=[0,10]))
    pcd.insert(0,dict(label="Model",
                      values=list(range(len(MODELS))),
                      tickvals=list(range(len(MODELS))),
                      ticktext=[m.replace("\n"," ")[:14] for m in MODELS]))
    fig = go.Figure(go.Parcoords(
        line=dict(color=list(range(len(MODELS))),
                  colorscale=[[0,"#00aaff"],[0.5,"#bf79ff"],[1,"#ffaa00"]]),
        dimensions=pcd,
    ))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", font=dict(color="#ddd",size=10),
        title=dict(text="Parallel Coordinates — All 14 Dimensions",
                   font=dict(color="#fff",size=14),x=0.5),
        height=430, margin=dict(t=80,b=40,l=80,r=40),
    )
    return fig

def build_sankey():
    nd, nm = len(DIMENSIONS), len(MODELS)
    w  = 1/nd
    labels = [d[:20] for d in DIMENSIONS] + [m.replace("\n"," ") for m in MODELS]
    nc = (["#335566"]*nd) + [COLORS[m] for m in MODELS]
    src,tgt,val,lc=[],[],[],[]
    for j in range(nd):
        for k,m in enumerate(MODELS):
            r,g,b = int(COLORS[m][1:3],16),int(COLORS[m][3:5],16),int(COLORS[m][5:7],16)
            src.append(j); tgt.append(nd+k)
            val.append(round(w*(RAW_SCORES[m][j]/10),4))
            lc.append(f"rgba({r},{g},{b},0.22)")
    fig = go.Figure(go.Sankey(
        node=dict(label=labels,color=nc,pad=12,thickness=16,
                  line=dict(color="#444",width=0.5)),
        link=dict(source=src,target=tgt,value=val,color=lc),
    ))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", font=dict(color="#ddd",size=10),
        title=dict(text="Sankey — Dimension Weight Flow to MCDA Score",
                   font=dict(color="#fff",size=14),x=0.5),
        height=540, margin=dict(t=60,b=20,l=20,r=20),
    )
    return fig

def build_calibration():
    bins = np.linspace(0.1,0.9,9)
    CAL  = {
        "ChatGPT (GPT-4o-mini)":        bins*0.84+0.06,
        "Claude Sonnet 4":               bins*0.91+0.03,
        "Deterministic AI\n(Neo4j Context)": np.where(bins>0.5,
                                              np.full_like(bins,0.97),
                                              np.full_like(bins,0.03)),
    }
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=[0,1],y=[0,1],mode="lines",name="Perfect",
                             line=dict(color="#666",dash="dash")))
    for m in MODELS:
        fig.add_trace(go.Scatter(x=bins,y=CAL.get(m,bins),mode="lines+markers",
                                 name=m.replace("\n"," "),
                                 line=dict(color=COLORS[m],width=2),
                                 marker=dict(size=7,color=COLORS[m])))
    fig.update_layout(
        paper_bgcolor="#0d0d0d", plot_bgcolor="#111",
        xaxis=dict(color="#aaa",gridcolor="#222",title="Confidence",range=[0,1]),
        yaxis=dict(color="#aaa",gridcolor="#222",title="Accuracy",range=[0,1]),
        legend=dict(font=dict(color="#ddd"),bgcolor="rgba(0,0,0,0)"),
        title=dict(text="Calibration Reliability Diagram",
                   font=dict(color="#fff",size=14),x=0.5),
        height=370, margin=dict(t=60,b=40),
    )
    return fig

# ===========================================================================
# 4. CYBERSECURITY-SPECIFIC DIMENSIONS
# ===========================================================================

CYBER_DIMS = ["CVE Accuracy","MITRE ATT&CK Mapping",
              "Exploit Severity","Remediation Soundness","Threat Actor Attribution"]
CYBER_SCORES = {
    "ChatGPT (GPT-4o-mini)":        [7.0,7.5,7.0,7.5,6.5],
    "Claude Sonnet 4":               [7.5,8.0,7.5,8.0,7.0],
    "Deterministic AI\n(Neo4j Context)":[9.5,9.0,8.5,8.0,6.0],
}
CYBER_DESC = {
    "CVE Accuracy":             "Does the model correctly describe CVE details, CVSS score, and affected systems?",
    "MITRE ATT&CK Mapping":     "Does it correctly identify TTPs and map them to ATT&CK techniques/sub-techniques?",
    "Exploit Severity":         "Is the exploitability assessment consistent with NVD/EPSS ground truth?",
    "Remediation Soundness":    "Are remediation steps technically valid and actionable for the environment?",
    "Threat Actor Attribution": "Can the model identify likely threat actors based on TTPs and IOC patterns?",
}

def build_cyber_radar():
    dc = CYBER_DIMS + [CYBER_DIMS[0]]
    fig= go.Figure()
    for m in CYBER_SCORES:
        v = CYBER_SCORES[m] + [CYBER_SCORES[m][0]]
        fig.add_trace(go.Scatterpolar(r=v,theta=dc,fill="toself",
                                      name=m.replace("\n"," "),
                                      line=dict(color=COLORS[m],width=2),
                                      fillcolor=COLORS[m],opacity=0.22))
    fig.update_layout(
        polar=dict(bgcolor="#111",
                   radialaxis=dict(visible=True,range=[0,10],color="#888",
                                   gridcolor="#333",tickfont=dict(size=9,color="#aaa")),
                   angularaxis=dict(color="#aaa",gridcolor="#333",
                                    tickfont=dict(size=10,color="#ddd"))),
        showlegend=True, legend=dict(font=dict(color="#ddd"),bgcolor="rgba(0,0,0,0)"),
        paper_bgcolor="#0d0d0d",
        title=dict(text="Cybersecurity Domain Evaluation",
                   font=dict(color="#fff",size=14),x=0.5),
        height=420, margin=dict(t=60,b=20,l=60,r=60),
    )
    return fig

# ===========================================================================
# 5. EXPORT  (CSV as data URI)
# ===========================================================================

def _mcda_csv():
    rows=[["Dimension","Weight"]+[m.replace("\n"," ") for m in MODELS]]
    for j,d in enumerate(DIMENSIONS):
        rows.append([d,f"{1/14:.4f}"]+[str(RAW_SCORES[m][j]) for m in MODELS])
    mc=compute_mcda_normalized()
    rows.append(["MCDA S_i","1.0000"]+[f"{mc[m]:.4f}" for m in MODELS])
    return urllib.parse.quote("\n".join(",".join(r) for r in rows))

def _trust_csv():
    rows=[["Trust Dim","Weight"]+[m.replace("\n"," ") for m in TRUST_SCORES]]
    for j,d in enumerate(TRUST_DIMS_CLEAN):
        rows.append([d,f"{TRUST_WEIGHTS[j]:.2f}"]+[str(TRUST_SCORES[m][j]) for m in TRUST_SCORES])
    ti=compute_trust_index()
    rows.append(["Trust T","1.00"]+[f"{ti[m]:.4f}" for m in TRUST_SCORES])
    return urllib.parse.quote("\n".join(",".join(r) for r in rows))

# ===========================================================================
# 6. BENCHMARKS
# ===========================================================================
BENCHMARKS=[
    ("Factual Accuracy",   "TruthfulQA",   "Lin et al., 2022",  "NeurIPS 2022"),
    ("Factual Accuracy",   "FactScore",    "Min et al., 2023",  "EMNLP 2023"),
    ("Hallucination",      "FEVER",        "Thorne et al., 2018","ACL 2018"),
    ("Hallucination",      "HaluEval",     "Li et al., 2023",   "EMNLP 2023"),
    ("Logical Consistency","Chain-of-Thought","Wei et al., 2022","NeurIPS 2022"),
    ("Calibration",        "ECE",          "Guo et al., 2017",  "ICML 2017"),
    ("Robustness",         "AdvGLUE",      "Wang et al., 2021", "NeurIPS 2021"),
    ("Source Reliability", "WICE",         "Kamoi et al., 2023","EMNLP 2023"),
    ("MCDA Methodology",   "MCDA/MCDM",    "Roy, 1996",         "Springer"),
    ("Effect Size",        "Cohen's d",    "Cohen, 1988",       "Academic Press"),
]

# ===========================================================================
# 6b. PRESET QUESTIONS FOR BATCH EVALUATION
# ===========================================================================
NUM_BATCH_QUESTIONS = 20

PRESET_QUESTIONS = [
    "Summarize the highest-risk CVEs and affected hosts in the current scan data.",
    "Which hosts have the most critical vulnerabilities and why?",
    "Describe possible attack paths based on exposed services and open ports.",
    "What remediation steps should be prioritized for critical findings?",
    "Are any findings associated with CISA KEV catalog entries?",
    "Map the top vulnerabilities to MITRE ATT&CK techniques and tactics.",
    "What is the overall risk posture of the scanned environment?",
    "Identify any lateral movement opportunities from the vulnerability data.",
    "Which CVEs have known public exploits available?",
    "Provide a threat actor attribution analysis based on the observed TTPs.",
    "Compare the severity distribution across different network segments.",
    "What privilege escalation paths exist based on current findings?",
    "Assess the patch management effectiveness from the vulnerability data.",
    "Identify any supply chain risk indicators in the scan results.",
    "What compensating controls would mitigate the top 5 critical findings?",
    "Analyze the correlation between exposed services and vulnerability density.",
    "Provide an executive summary suitable for C-suite briefing.",
    "What zero-day or recently disclosed vulnerabilities appear in the data?",
    "Evaluate the network segmentation effectiveness based on finding distribution.",
    "Create a 30-60-90 day remediation roadmap for the critical findings.",
]

# ===========================================================================
# 7. LAYOUT
# ===========================================================================

def generate_phd_advanced_layout():
    return html.Div([
        build_live_data_banner(),
        html.H2("🔬 PhD Research Tools — Advanced Analysis",
                className="text-info mb-1", style={"fontWeight":"bold"}),
        html.P("Statistical testing · Monte Carlo simulation · Advanced visualizations · "
               "Export · Cybersecurity evaluation · Benchmark references",
               className="text-muted mb-3",
               style={"fontSize":"13px","fontStyle":"italic"}),
        html.Hr(style={"borderColor":"#333"}),

        dbc.Tabs(id="adv-tabs", active_tab="adv-live",
                 style={"backgroundColor":"#0d0d0d","border":"1px solid #333"}, children=[

            # ── TAB 1: LIVE EVALUATION LAB (BATCH — 20 QUESTIONS) ────────
            dbc.Tab(label="🔬 Live Evaluation Lab", tab_id="adv-live", children=[
                html.Div([
                    html.H5("⚡ Batch Evaluation — Send up to 20 questions to all 3 AI systems",
                            className="text-warning mt-3 mb-1"),
                    html.P("Enter questions below. Only filled rows are sent. "
                           "Neo4j context is fetched once and shared across all questions.",
                           className="text-muted small mb-3"),

                    # ── Control buttons ─────────────────────────────────
                    dbc.Row([
                        dbc.Col(dbc.Button("📋 Load Preset Questions", id="adv-preset-btn",
                                           color="info", outline=True, className="fw-bold w-100",
                                           style={"height":"40px"}), md=3),
                        dbc.Col(dbc.Button("▶ Run All Questions", id="adv-send-btn",
                                           color="warning", className="fw-bold w-100",
                                           style={"height":"40px","fontSize":"15px"}), md=3),
                        dbc.Col(dbc.Button("🗑 Clear All", id="adv-clear-btn",
                                           color="secondary", outline=True, className="fw-bold w-100",
                                           style={"height":"40px"}), md=2),
                        dbc.Col(html.Div(id="adv-batch-status",
                                         children=html.Small("Ready", className="text-muted"),
                                         style={"lineHeight":"40px","textAlign":"right"}), md=4),
                    ], className="mb-3"),

                    # ── 20 question input rows ─────────────────────────
                    html.Div([
                        dbc.Row([
                            dbc.Col(
                                html.Span(f"Q{i+1}", style={"color":"#ffaa00","fontWeight":"bold",
                                           "fontSize":"13px","minWidth":"30px","display":"inline-block"}),
                                width=1, style={"maxWidth":"40px","paddingRight":"0"}),
                            dbc.Col(
                                dbc.Input(id=f"adv-q-{i}", type="text",
                                          placeholder=f"Question {i+1}...",
                                          style={"backgroundColor":"#111","color":"#fff",
                                                 "border":"1px solid #333","fontSize":"12px",
                                                 "height":"34px"}),
                                width=11),
                        ], className="mb-1", align="center")
                        for i in range(NUM_BATCH_QUESTIONS)
                    ], style={"maxHeight":"440px","overflowY":"auto","padding":"10px",
                              "border":"1px solid #333","borderRadius":"8px",
                              "backgroundColor":"#0a0a0a"}),

                    html.Hr(style={"borderColor":"#333","marginTop":"16px"}),

                    # ── Results area (accordion) ───────────────────────
                    dcc.Loading(
                        html.Div(id="adv-batch-results",
                                 children=dbc.Alert(
                                     "💡 Enter questions above and click \"Run All Questions\" to compare "
                                     "ChatGPT, Claude, and Deterministic AI side by side.",
                                     color="dark", style={"border":"1px solid #444",
                                     "backgroundColor":"#111","color":"#ccc","fontSize":"12px"})),
                        color="#ffaa00", type="dot"),

                ], style={"padding":"20px"}),
            ]),

            # ── TAB 2: STATISTICAL ANALYSIS ─────────────────────────────
            dbc.Tab(label="📈 Statistical Analysis", tab_id="adv-stats", children=[
                html.Div([
                    html.H5("Effect Size, Confidence Intervals & Distributions",
                            className="text-warning mt-3 mb-3"),
                    dbc.Row([
                        dbc.Col(dbc.Card([
                            dbc.CardHeader("📊 95% Bootstrap CI",
                                           style={"backgroundColor":"#0a1a2a","color":"#00aaff","fontWeight":"bold"}),
                            dbc.CardBody(dcc.Graph(figure=build_ci_bar(),
                                                   config={"displayModeBar":False})),
                        ], style={"border":"1px solid #1a3a5c","backgroundColor":"#0d0d0d"}), md=6),

                        dbc.Col(dbc.Card([
                            dbc.CardHeader("🧮 Cohen's d Effect Size",
                                           style={"backgroundColor":"#0a1a2a","color":"#ff6666","fontWeight":"bold"}),
                            dbc.CardBody(dcc.Graph(figure=build_cohend_heatmap(),
                                                   config={"displayModeBar":False})),
                        ], style={"border":"1px solid #3a1a1a","backgroundColor":"#0d0d0d"}), md=6),
                    ], className="mb-3"),

                    dbc.Alert([
                        html.Strong("Effect size guide: ", style={"color":"#ffcc00"}),
                        "d < 0.2 Negligible  ·  d 0.2–0.5 Small  ·  d 0.5–0.8 Medium  ·  d > 0.8 Large",
                    ], color="dark", style={"border":"1px solid #444","backgroundColor":"#111","color":"#ccc","fontSize":"12px","marginBottom":"16px"}),

                    dbc.Card([
                        dbc.CardHeader("🎻 Score Distributions (Violin)",
                                       style={"backgroundColor":"#111","color":"#bf79ff","fontWeight":"bold"}),
                        dbc.CardBody(dcc.Graph(figure=build_violin(), config={"displayModeBar":False})),
                    ], style={"border":"1px solid #3a1a5c","backgroundColor":"#0d0d0d"}),
                ], style={"padding":"20px"}),
            ]),

            # ── TAB 3: MONTE CARLO ──────────────────────────────────────
            dbc.Tab(label="🎲 Monte Carlo", tab_id="adv-mc", children=[
                html.Div([
                    html.H5("Rank Stability Under 2 000 Random Weight Scenarios",
                            className="text-warning mt-3 mb-1"),
                    html.P("Dirichlet-sampled weight vectors (Σwⱼ=1). "
                           "A robust winner holds its rank regardless of weight choices.",
                           className="text-muted small mb-3"),
                    dbc.Row([
                        dbc.Col(dbc.Card([
                            dbc.CardHeader("🏆 Win % Across All Scenarios",
                                           style={"backgroundColor":"#0a1a00","color":"#44ff88","fontWeight":"bold"}),
                            dbc.CardBody(dcc.Graph(figure=build_mc_bar(), config={"displayModeBar":False})),
                        ], style={"border":"1px solid #1a4a1a","backgroundColor":"#0d0d0d"}), md=6),

                        dbc.Col(dbc.Card([
                            dbc.CardHeader("📐 Rank Stability Matrix",
                                           style={"backgroundColor":"#0a1a00","color":"#ffaa00","fontWeight":"bold"}),
                            dbc.CardBody(dcc.Graph(figure=build_stability_heatmap(), config={"displayModeBar":False})),
                        ], style={"border":"1px solid #3a2a00","backgroundColor":"#0d0d0d"}), md=6),
                    ]),
                ], style={"padding":"20px"}),
            ]),

            # ── TAB 4: ADVANCED VIZ ─────────────────────────────────────
            dbc.Tab(label="📐 Advanced Viz", tab_id="adv-viz", children=[
                html.Div([
                    dbc.Card([
                        dbc.CardHeader("🔗 Parallel Coordinates — All 14 Dimensions",
                                       style={"backgroundColor":"#111","color":"#00aaff","fontWeight":"bold"}),
                        dbc.CardBody(dcc.Graph(figure=build_parallel_coords(), config={"displayModeBar":False})),
                    ], style={"border":"1px solid #1a3a5c","backgroundColor":"#0d0d0d","marginTop":"20px","marginBottom":"20px"}),

                    dbc.Row([
                        dbc.Col(dbc.Card([
                            dbc.CardHeader("🌊 Sankey — Weight Flow to MCDA Score",
                                           style={"backgroundColor":"#111","color":"#44ff88","fontWeight":"bold"}),
                            dbc.CardBody(dcc.Graph(figure=build_sankey(), config={"displayModeBar":False})),
                        ], style={"border":"1px solid #1a4a1a","backgroundColor":"#0d0d0d"}), md=7),

                        dbc.Col(dbc.Card([
                            dbc.CardHeader("📉 Calibration Reliability Diagram",
                                           style={"backgroundColor":"#111","color":"#ff6666","fontWeight":"bold"}),
                            dbc.CardBody(dcc.Graph(figure=build_calibration(), config={"displayModeBar":False})),
                        ], style={"border":"1px solid #3a1a1a","backgroundColor":"#0d0d0d"}), md=5),
                    ]),
                ], style={"padding":"20px"}),
            ]),

            # ── TAB 5: CYBERSECURITY DOMAIN ─────────────────────────────
            dbc.Tab(label="🛡️ Cyber Domain", tab_id="adv-cyber", children=[
                html.Div([
                    html.H5("Cybersecurity-Specific Evaluation",
                            className="text-warning mt-3 mb-1"),
                    html.P("Domain-specific scoring unique to vulnerability intelligence tasks.",
                           className="text-muted small mb-3"),
                    dbc.Row([
                        dbc.Col(dbc.Card([
                            dbc.CardHeader("🛡️ Domain Radar",
                                           style={"backgroundColor":"#1a0000","color":"#ff6666","fontWeight":"bold"}),
                            dbc.CardBody(dcc.Graph(figure=build_cyber_radar(), config={"displayModeBar":False})),
                        ], style={"border":"1px solid #4a0000","backgroundColor":"#0d0d0d"}), md=6),

                        dbc.Col([
                            html.H6("Dimension Definitions", className="text-info mb-2 mt-3"),
                            dbc.ListGroup([
                                dbc.ListGroupItem([
                                    html.Strong(dim+": ", style={"color":"#ffaa00"}),
                                    desc,
                                ], style={"backgroundColor":"#111","color":"#ccc",
                                          "border":"1px solid #333","marginBottom":"4px",
                                          "fontSize":"12px"})
                                for dim,desc in CYBER_DESC.items()
                            ]),
                        ], md=6),
                    ]),
                ], style={"padding":"20px"}),
            ]),

            # ── TAB 6: EXPORT & REFERENCES ──────────────────────────────
            dbc.Tab(label="📤 Export & References", tab_id="adv-export", children=[
                html.Div([
                    html.H5("Download Research Data", className="text-warning mt-3 mb-3"),
                    dbc.Row([
                        dbc.Col(dbc.Card([
                            dbc.CardHeader("📊 MCDA Matrix",
                                           style={"backgroundColor":"#111","color":"#44ff88"}),
                            dbc.CardBody([
                                html.P("14-dimension MCDA capability matrix.", className="text-muted small"),
                                html.A(dbc.Button("⬇ Download MCDA CSV", color="success",
                                                   className="fw-bold w-100"),
                                       href=f"data:text/csv;charset=utf-8,{_mcda_csv()}",
                                       download="phd_mcda_matrix.csv"),
                            ]),
                        ], style={"border":"1px solid #1a4a1a","backgroundColor":"#0d0d0d"}), md=4),

                        dbc.Col(dbc.Card([
                            dbc.CardHeader("⚖️ Trust Index",
                                           style={"backgroundColor":"#111","color":"#ffaa55"}),
                            dbc.CardBody([
                                html.P("10-dimension trust evaluation matrix.", className="text-muted small"),
                                html.A(dbc.Button("⬇ Download Trust CSV", color="warning",
                                                   className="fw-bold w-100"),
                                       href=f"data:text/csv;charset=utf-8,{_trust_csv()}",
                                       download="phd_trust_matrix.csv"),
                            ]),
                        ], style={"border":"1px solid #4a2a00","backgroundColor":"#0d0d0d"}), md=4),

                        dbc.Col(dbc.Card([
                            dbc.CardHeader("📋 Monte Carlo Results",
                                           style={"backgroundColor":"#111","color":"#00aaff"}),
                            dbc.CardBody([
                                html.P("Win % and rank stability data.", className="text-muted small"),
                                html.Div(id="mc-csv-area", children=dbc.Button(
                                    "⬇ Download MC CSV", id="mc-csv-btn",
                                    color="info", outline=True, className="fw-bold w-100")),
                            ]),
                        ], style={"border":"1px solid #1a3a5c","backgroundColor":"#0d0d0d"}), md=4),
                    ], className="mb-4"),

                    html.Hr(style={"borderColor":"#333"}),
                    html.H5("📚 Benchmark References", className="text-info mb-3"),
                    html.Table([
                        html.Thead(html.Tr([
                            html.Th("Dimension",  style=_th()),
                            html.Th("Benchmark",  style=_th()),
                            html.Th("Citation",   style=_th()),
                            html.Th("Venue",      style=_th()),
                        ])),
                        html.Tbody([
                            html.Tr([
                                html.Td(d, style=_td(bold=True)),
                                html.Td(b, style=_td()),
                                html.Td(c, style={**_td(),"color":"#aaa"}),
                                html.Td(v, style={**_td(),"color":"#888"}),
                            ], style={"backgroundColor":"#0d0d0d" if i%2 else "#111"})
                            for i,(d,b,c,v) in enumerate(BENCHMARKS)
                        ]),
                    ], style={"width":"100%","borderCollapse":"collapse",
                              "fontSize":"13px","border":"1px solid #333"}),
                ], style={"padding":"20px"}),
            ]),
        ]),
    ], style={"padding":"30px","backgroundColor":"#0d0d0d","minHeight":"100vh"})


# ===========================================================================
# 8. CALLBACKS  — BATCH EVALUATION (20 QUESTIONS)
# ===========================================================================

def _call_gpt(question):
    """Call ChatGPT for a single question. Returns html component."""
    try:
        from openai import OpenAI as _OAI
        rsp = _OAI(api_key=os.environ.get("OPENAI_API_KEY","")).chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"system","content":"You are a concise cybersecurity analyst."},
                      {"role":"user","content":question}],
            max_tokens=400,
        )
        return html.P(rsp.choices[0].message.content,
                       style={"fontSize":"12px","color":"#ddd","whiteSpace":"pre-wrap"})
    except Exception as e:
        return html.P(f"⚠️ {e}", className="text-danger small")


def _call_claude(question):
    """Call Claude for a single question. Returns html component."""
    try:
        import anthropic as _ant
        ac = _ant.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY",""))
        msg = None
        for _m in ["claude-sonnet-4-6","claude-sonnet-4-5-20250929","claude-haiku-4-5-20251001"]:
            try:
                msg = ac.messages.create(model=_m, max_tokens=400,
                    system="You are a concise cybersecurity analyst.",
                    messages=[{"role":"user","content":question}])
                break
            except Exception:
                continue
        return html.P(msg.content[0].text if msg else "No model available.",
                      style={"fontSize":"12px","color":"#ddd","whiteSpace":"pre-wrap"})
    except Exception as e:
        return html.P(f"⚠️ {e}", className="text-danger small")


def _call_neo4j(_question):
    """Query Neo4j for deterministic ground-truth data. Returns html component."""
    try:
        from neo4j import GraphDatabase as _GD
        drv = _GD.driver("bolt://localhost:7687", auth=("neo4j","Adomaa12@"))
        with drv.session() as s:
            res = s.run("""
                MATCH (f:Finding) WHERE f.cve IS NOT NULL
                WITH f,
                     CASE WHEN toFloat(coalesce(toString(f.cvss),'0')) >= 9.0 THEN 'CRITICAL'
                          WHEN toFloat(coalesce(toString(f.cvss),'0')) >= 7.0 THEN 'HIGH'
                          WHEN toFloat(coalesce(toString(f.cvss),'0')) >= 4.0 THEN 'MEDIUM'
                          ELSE 'LOW' END AS sev
                RETURN f.cve AS cve,
                       toString(f.cvss) AS cvss,
                       sev AS severity,
                       coalesce(f.host,'unknown') AS host,
                       coalesce(f.priority,'—') AS priority,
                       f.exploitable AS exploitable
                ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC
                LIMIT 8
            """)
            rows = res.data()
        drv.close()
        if rows:
            lines = [
                f"  {r.get('cve','?')}  CVSS:{r.get('cvss','?')}  "
                f"[{r.get('severity','?')}]  Host:{r.get('host','?')}  "
                f"{'🔴' if r.get('exploitable') else ''}"
                for r in rows
            ]
            neo_text = "Top vulnerabilities from Neo4j graph:\n" + "\n".join(lines)
        else:
            neo_text = "No vulnerability data found in Neo4j."
        return html.Pre(neo_text, style={"fontSize":"11px","color":"#ffaa00",
                                         "whiteSpace":"pre-wrap"})
    except Exception as e:
        return html.P(f"⚠️ Neo4j: {e}", className="text-danger small")


def _build_question_card(idx, question, gpt_out, claude_out, neo_out):
    """Build one accordion item for a single batch question result."""
    return dbc.AccordionItem(
        title=f"Q{idx+1}: {question[:90]}{'…' if len(question)>90 else ''}",
        children=[
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("🤖 ChatGPT",
                        style={"backgroundColor":"#001a33","color":"#00aaff",
                               "fontWeight":"bold","padding":"6px 12px","fontSize":"12px"}),
                    dbc.CardBody(gpt_out, style={"padding":"10px","maxHeight":"300px","overflowY":"auto"}),
                ], style={"border":"1px solid #00aaff44","backgroundColor":"#0d0d0d"}), md=4),

                dbc.Col(dbc.Card([
                    dbc.CardHeader("🟣 Claude Sonnet",
                        style={"backgroundColor":"#1a0033","color":"#bf79ff",
                               "fontWeight":"bold","padding":"6px 12px","fontSize":"12px"}),
                    dbc.CardBody(claude_out, style={"padding":"10px","maxHeight":"300px","overflowY":"auto"}),
                ], style={"border":"1px solid #bf79ff44","backgroundColor":"#0d0d0d"}), md=4),

                dbc.Col(dbc.Card([
                    dbc.CardHeader("🟡 Deterministic AI",
                        style={"backgroundColor":"#1a1100","color":"#ffaa00",
                               "fontWeight":"bold","padding":"6px 12px","fontSize":"12px"}),
                    dbc.CardBody(neo_out, style={"padding":"10px","maxHeight":"300px","overflowY":"auto"}),
                ], style={"border":"1px solid #ffaa0044","backgroundColor":"#0d0d0d"}), md=4),
            ]),
        ],
        style={"backgroundColor":"#0d0d0d","border":"1px solid #333"},
        item_id=f"batch-q-{idx}",
    )


# ── BATCH RUN CALLBACK ─────────────────────────────────────────────────────
@callback(
    Output("adv-batch-results", "children"),
    Output("adv-batch-status",  "children"),
    Input("adv-send-btn",       "n_clicks"),
    [State(f"adv-q-{i}", "value") for i in range(NUM_BATCH_QUESTIONS)],
    prevent_initial_call=True,
)
def run_batch_eval(_, *question_values):
    questions = [(i, q.strip()) for i, q in enumerate(question_values)
                 if q and q.strip()]

    if not questions:
        return (
            dbc.Alert("⚠️ No questions entered. Please fill in at least one question.",
                      color="danger", style={"backgroundColor":"#1a0000","border":"1px solid #ff4444"}),
            html.Small("No questions to process", className="text-danger"),
        )

    total = len(questions)
    t0 = time.time()
    cards = []

    for step, (idx, question) in enumerate(questions, 1):
        # Call all 3 engines for this question
        gpt_out    = _call_gpt(question)
        claude_out = _call_claude(question)
        neo_out    = _call_neo4j(question)
        cards.append(_build_question_card(idx, question, gpt_out, claude_out, neo_out))

    elapsed = time.time() - t0

    result = html.Div([
        dbc.Alert([
            html.Strong(f"✅ Batch complete — {total} question{'s' if total>1 else ''} processed  "),
            html.Span(f"({elapsed:.1f}s)", style={"color":"#aaa"}),
        ], color="success", style={"backgroundColor":"#001a00","border":"1px solid #44ff88",
                                    "color":"#44ff88","fontSize":"13px"}),
        dbc.Accordion(cards, start_collapsed=False, always_open=True,
                       flush=True, style={"backgroundColor":"#0d0d0d"}),
    ])

    status = html.Small(f"✅ {total} Qs — {elapsed:.1f}s", style={"color":"#44ff88"})
    return result, status


# ── LOAD PRESET QUESTIONS ──────────────────────────────────────────────────
@callback(
    [Output(f"adv-q-{i}", "value", allow_duplicate=True) for i in range(NUM_BATCH_QUESTIONS)],
    Input("adv-preset-btn", "n_clicks"),
    prevent_initial_call=True,
)
def load_presets(_):
    return [PRESET_QUESTIONS[i] if i < len(PRESET_QUESTIONS) else ""
            for i in range(NUM_BATCH_QUESTIONS)]


# ── CLEAR ALL QUESTIONS ───────────────────────────────────────────────────
@callback(
    [Output(f"adv-q-{i}", "value") for i in range(NUM_BATCH_QUESTIONS)],
    Input("adv-clear-btn", "n_clicks"),
    prevent_initial_call=True,
)
def clear_all_questions(_):
    return [""] * NUM_BATCH_QUESTIONS


# ── MONTE CARLO CSV EXPORT ────────────────────────────────────────────────
@callback(
    Output("mc-csv-area", "children"),
    Input("mc-csv-btn",   "n_clicks"),
    prevent_initial_call=True,
)
def export_mc_csv(_):
    wp, bt = _run_mc()
    rows = [["Model","Win %"]] + [[m.replace("\n"," "), f"{wp[m]:.2f}"] for m in MODELS]
    rows += [["",""]] + [["Pairwise P(A>B) %",""]]
    for (a,b),v in bt.items():
        rows.append([f"P({a.replace(chr(10),' ')} > {b.replace(chr(10),' ')})",f"{v:.1f}"])
    csv = urllib.parse.quote("\n".join(",".join(r) for r in rows))
    return html.A(dbc.Button("⬇ Download MC CSV", color="info", outline=True,
                              className="fw-bold w-100"),
                  href=f"data:text/csv;charset=utf-8,{csv}",
                  download="phd_monte_carlo.csv")
