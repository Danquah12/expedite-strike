from dash import callback, Input, Output, State, html

from exploit_llm_engine.retrieval.pipeline import retrieve_evidence_by_cve
from exploit_llm_engine.scoring.engine import score_evidence
from exploit_llm_engine.reasoning.lab_sentence_generator import (
    generate_lab_vulnerability_sentence
)
from exploit_llm_engine.reasoning.executive_templates import (
    render_executive_lab_summary_with_hosts
)
from exploit_llm_engine.reasoning.host_aggregator import extract_affected_hosts
from exploit_llm_engine.reasoning.risk_indicators import verdict_to_traffic_light
from exploit_llm_engine.reasoning.technical_appendix import render_technical_appendix
from exploit_llm_engine.reasoning.change_detection import detect_host_changes


@callback(
    Output("risk-indicator", "children"),
    Output("executive-summary", "children"),
    Output("affected-hosts", "children"),
    Output("change-detection", "children"),
    Output("technical-appendix", "children"),
    Input("analyze-button", "n_clicks"),
    State("cve-input", "value"),
    prevent_initial_call=True
)
def analyze_cve(n_clicks, cve_id):
    # ---- Retrieve evidence ----
    evidence = retrieve_evidence_by_cve(cve_id)

    # ---- Score ----
    score_result = score_evidence(evidence)
    verdict = score_result["verdict"]

    # ---- Traffic light ----
    indicator = verdict_to_traffic_light(verdict)
    risk_indicator = html.Div(
        f"{indicator['label']} ({indicator['color']})",
        style={
            "color": indicator["color"].lower(),
            "fontWeight": "bold",
            "fontSize": "18px"
        }
    )

    # ---- Hosts ----
    hosts = extract_affected_hosts(evidence)

    host_list = [html.Li(h) for h in sorted(hosts)]

    # ---- Executive summary ----
    sentence = generate_lab_vulnerability_sentence(evidence)

    executive_summary = render_executive_lab_summary_with_hosts(
        lab_sentence=sentence,
        verdict=verdict,
        confidence=0.5,  # can later be computed deterministically
        hosts=list(hosts)
    )

    # ---- Change detection (placeholder for now) ----
    # Later this will come from persisted snapshots
    changes = detect_host_changes(previous_hosts=set(), current_hosts=hosts)

    change_block = html.Div(
        [
            html.P(f"New hosts: {', '.join(changes['new_hosts']) or 'None'}"),
            html.P(f"Resolved hosts: {', '.join(changes['resolved_hosts']) or 'None'}"),
        ]
    )

    # ---- Technical appendix ----
    appendix = render_technical_appendix(evidence)

    return (
        risk_indicator,
        executive_summary,
        host_list,
        change_block,
        appendix,
    )
