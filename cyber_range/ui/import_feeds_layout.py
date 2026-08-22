# cyber_range/ui/import_feeds_layout.py

from dash import html, dcc
import dash_bootstrap_components as dbc
import dash_table


def import_feeds_layout():
    return dbc.Container(
        fluid=True,
        children=[

            # ---------------- HEADER ----------------
            dbc.Row(
                dbc.Col(
                    html.H3("Import Feeds", className="text-light"),
                    width=12
                ),
                className="mb-3"
            ),

            # ---------------- FILTERS ----------------
            dbc.Card(
                dbc.CardBody(
                    dbc.Row([

                        # Source filter
                        dbc.Col(
                            dcc.Dropdown(
                                id="import-feed-source",
                                options=[
                                    {"label": "All Sources", "value": ""},
                                    {"label": "Metasploit", "value": "metasploit"},
                                    {"label": "ExploitPack", "value": "exploitpack"},
                                    {"label": "CVE", "value": "cve"},
                                    {"label": "GitHub Exploit", "value": "githubexploit"},
                                    {"label": "PacketStorm", "value": "packetstorm"},
                                ],
                                value="",
                                placeholder="Filter by source",
                                clearable=False,
                            ),
                            width=3,
                        ),

                        # Confidence slider
                        dbc.Col(
                            dcc.Slider(
                                id="import-feed-confidence",
                                min=0,
                                max=100,
                                step=5,
                                value=0,
                                marks={
                                    0: "0",
                                    40: "40",
                                    60: "60",
                                    80: "80",
                                    100: "100",
                                },
                                tooltip={"placement": "bottom"},
                            ),
                            width=4,
                        ),

                        # KEV only
                        dbc.Col(
                            dbc.Checklist(
                                options=[
                                    {"label": "KEV only", "value": "kev"}
                                ],
                                value=[],
                                id="import-feed-kev-only",
                                switch=True,
                            ),
                            width=2,
                        ),

                        # Exploit only
                        dbc.Col(
                            dbc.Checklist(
                                options=[
                                    {"label": "Exploit only", "value": "exploit"}
                                ],
                                value=[],
                                id="import-feed-exploit-only",
                                switch=True,
                            ),
                            width=2,
                        ),

                    ]),
                ),
                className="mb-3"
            ),

            # ---------------- DATA TABLE ----------------
            dbc.Card(
                dbc.CardBody(
                    dash_table.DataTable(
                        id="import-feeds-table",
                        columns=[
                            {"name": "Source", "id": "source"},
                            {"name": "Feed ID", "id": "feed_id"},
                            {"name": "Confidence", "id": "confidence", "type": "numeric"},
                            {"name": "Exploit", "id": "exploit_available", "type": "boolean"},
                            {"name": "CVSS", "id": "cvss", "type": "numeric"},
                            {"name": "KEV", "id": "in_kev", "type": "boolean"},
                            {"name": "Last Seen", "id": "last_seen"},
                        ],
                        data=[],
                        page_size=15,
                        sort_action="native",
                        filter_action="none",
                        style_table={"overflowX": "auto"},
                        style_cell={
                            "backgroundColor": "#111",
                            "color": "#eee",
                            "border": "1px solid #333",
                            "fontSize": "14px",
                            "padding": "6px",
                        },
                        style_header={
                            "backgroundColor": "#222",
                            "fontWeight": "bold",
                            "border": "1px solid #444",
                        },
                        style_data_conditional=[
                            # High confidence highlight
                            {
                                "if": {
                                    "filter_query": "{confidence} >= 80",
                                    "column_id": "confidence",
                                },
                                "backgroundColor": "#4CAF50",
                                "color": "black",
                            },
                            # KEV highlight
                            {
                                "if": {
                                    "filter_query": "{in_kev} = true",
                                },
                                "backgroundColor": "#7a1f1f",
                            },
                        ],
                    )
                )
            ),
        ],
    )
