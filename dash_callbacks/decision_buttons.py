from dash import callback, Input, Output


# ======================================================
# NO-OP: "Can I Exploit This?"
# ======================================================
@callback(
    Output("exploitability-explanation", "children"),
    Input("btn-exploitability", "n_clicks"),
    prevent_initial_call=True,
)
def noop_exploitability(n_clicks):
    """
    Placeholder callback.
    Real exploitability explanation will be wired later.
    """

    return (
        "Exploitability analysis is based on validated evidence and "
        "is not yet activated in this view."
    )


# ======================================================
# NO-OP: "Why Do We Believe This?"
# ======================================================
@callback(
    Output("justification-explanation", "children"),
    Input("btn-justification", "n_clicks"),
    prevent_initial_call=True,
)
def noop_justification(n_clicks):
    """
    Placeholder callback.
    Evidence justification logic will be enabled later.
    """

    return (
        "This assessment is supported by lab observations and "
        "authoritative vulnerability sources. "
        "Detailed justification will be available in a future update."
    )


# ======================================================
# NO-OP: "What Changed?"
# ======================================================
@callback(
    Output("what-changed-explanation", "children"),
    Input("btn-what-changed", "n_clicks"),
    prevent_initial_call=True,
)
def noop_what_changed(n_clicks):
    """
    Placeholder callback.
    Change detection summary will be enabled later.
    """

    return (
        "Change tracking across assessments is not yet enabled. "
        "This section will summarize newly affected and resolved systems "
        "once historical snapshots are available."
    )
