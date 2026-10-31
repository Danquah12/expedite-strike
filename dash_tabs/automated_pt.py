from dash import html, dcc
import dash_bootstrap_components as dbc


def automated_pt_layout():
    return dbc.Container(
        [

            # ==================================================
            # EXISTING PIPELINE EXECUTION SECTION (UNCHANGED)
            # ==================================================
            html.H2(
                "Automated Penetration Testing",
                className="text-warning mb-3",
            ),

            html.P(
                "Executes an automated penetration testing pipeline aligned with "
                "PTES and NIST SP 800-115. The process is non-destructive and operates "
                "in analysis and search-only modes.",
                className="text-muted",
            ),

            dbc.ButtonGroup(
                [
                    dbc.Button(
                        "Check for New Scan Results",
                        id="btn-check-scans",
                        color="primary",
                    ),
                    dbc.Button(
                        "Run Automated Assessment",
                        id="btn-run-assessment",
                        color="danger",
                    ),
                    dbc.Button(
                        "Stop / Cancel Assessment",
                        id="btn-stop-assessment",
                        color="secondary",
                    ),
                ],
                className="mb-4",
            ),

            html.Hr(),

            # ==================================================
            # 🔍 ANALYSIS & DECISION SUPPORT (NEW)
            # ==================================================
            html.H4(
                "Assessment Analysis & Decision Support",
                className="text-info mt-4",
            ),

            html.P(
                "Analyze validated findings from completed scans and "
                "translate technical evidence into actionable risk decisions.",
                className="text-muted mb-3",
            ),

            # ------------------------------
            # CVE Input + Analyze
            # ------------------------------
            dbc.Row(
                [
                    dbc.Col(
                        dcc.Input(
                            id="cve-input",
                            type="text",
                            placeholder="Enter CVE ID (e.g., CVE-2021-41773)",
                            className="form-control",
                        ),
                        md=6,
                    ),
                    dbc.Col(
                        dbc.Button(
                            "Analyze",
                            id="analyze-button",
                            color="success",
                            className="w-100",
                        ),
                        md=2,
                    ),
                ],
                className="mb-4",
            ),

            # ------------------------------
            # Risk Overview
            # ------------------------------
            dbc.Card(
                dbc.CardBody(
                    [
                        html.H5("Risk Overview"),
                        html.Div(id="risk-indicator"),
                        html.Div(id="risk-description", className="text-muted"),
                    ]
                ),
                className="mb-3",
            ),

            # ------------------------------
            # Executive Summary
            # ------------------------------
            dbc.Card(
                dbc.CardBody(
                    [
                        html.H5("Executive Summary"),
                        html.Div(id="executive-summary"),
                        html.Div(id="confidence-statement", className="mt-2"),
                        html.Div(id="scope-statement", className="text-muted"),
                    ]
                ),
                className="mb-3",
            ),

            # ------------------------------
            # Affected Scope
            # ------------------------------
            dbc.Card(
                dbc.CardBody(
                    [
                        html.H5("Affected Lab Scope"),
                        html.Div(id="affected-host-count"),
                        html.Ul(id="affected-hosts"),
                    ]
                ),
                className="mb-3",
            ),

            # ------------------------------
            # Decision Buttons
            # ------------------------------
            dbc.ButtonGroup(
                [
                    dbc.Button(
                        "Can I Exploit This?",
                        id="btn-exploitability",
                        color="warning",
                    ),
                    dbc.Button(
                        "Why Do We Believe This?",
                        id="btn-justification",
                        color="info",
                    ),
                    dbc.Button(
                        "What Changed?",
                        id="btn-what-changed",
                        color="secondary",
                    ),
                ],
                className="mb-3",
            ),

            # ------------------------------
            # Decision Outputs
            # ------------------------------
            dbc.Card(
                dbc.CardBody(
                    html.Div(id="exploitability-explanation")
                ),
                className="mb-2",
            ),

            dbc.Card(
                dbc.CardBody(
                    html.Div(id="justification-explanation")
                ),
                className="mb-2",
            ),

            dbc.Card(
                dbc.CardBody(
                    html.Div(id="what-changed-explanation")
                ),
                className="mb-3",
            ),

            # ------------------------------
            # Technical Appendix
            # ------------------------------
            dbc.Collapse(
                dbc.Card(
                    dbc.CardBody(
                        [
                            html.H5("Technical Appendix"),
                            html.Div(id="technical-appendix"),
                            html.Hr(),
                            html.Pre(
                                id="raw-evidence-viewer",
                                className="small",
                            ),
                        ]
                    )
                ),
                is_open=True,
            ),
        ],
        fluid=True,
    )
