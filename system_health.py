import psutil
import pandas as pd
import plotly.express as px
import dash_bootstrap_components as dbc
from dash import html, dcc
from datetime import datetime

def system_health_layout():
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent

    health_df = pd.DataFrame({
        "Metric": ["CPU Usage", "Memory Usage", "Disk Usage"],
        "Value": [cpu, mem, disk]
    })
    fig = px.bar(health_df, x="Metric", y="Value", text="Value", color="Value",
                 color_continuous_scale="inferno")

    return dbc.Container([
        html.H3("🖥️ System Health Overview", className="text-warning mb-3"),
        dcc.Graph(figure=fig),
        html.Div(f"Last updated: {datetime.now()}", style={"textAlign": "center", "color": "#bbb"})
    ])
