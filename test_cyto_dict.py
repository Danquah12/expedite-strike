import dash
from dash import html
import dash_cytoscape as cyto

app = dash.Dash(__name__)

app.layout = html.Div([
    cyto.Cytoscape(
        id={'type': 'my-cyto', 'index': 'test'},
        elements=[
            {'data': {'id': 'one', 'label': 'Node 1'}},
            {'data': {'id': 'two', 'label': 'Node 2'}},
            {'data': {'source': 'one', 'target': 'two'}}
        ],
        style={'width': '100%', 'height': '400px'}
    )
])

if __name__ == '__main__':
    # run for 2 seconds and exit if it works
    import threading, time, os
    def kill():
        time.sleep(2)
        os._exit(0)
    threading.Thread(target=kill).start()
    app.run_server(port=8050)
