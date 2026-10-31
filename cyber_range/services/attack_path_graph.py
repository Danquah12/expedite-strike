"""
Attack Path Graph — Interactive Cytoscape.js Visualization
============================================================
Converts attack path data from the autonomous pentest into an
interactive force-directed graph using dash_cytoscape.

Renders: Initial Access → Exploit → Lateral Movement → Privilege Escalation → Crown Jewels
"""

import logging
from dash import html, dcc, callback, Input, Output, State, no_update
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

logger = logging.getLogger(__name__)

# ── Node styles by type ──────────────────────────────────────────────
GRAPH_STYLESHEET = [
    # Default node
    {
        "selector": "node",
        "style": {
            "label": "data(label)",
            "width": "data(size)",
            "height": "data(size)",
            "background-color": "data(color)",
            "color": "#e2e8f0",
            "font-size": "10px",
            "font-family": "Inter, Segoe UI, sans-serif",
            "font-weight": "500",
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": "8px",
            "text-outline-width": "2px",
            "text-outline-color": "#0a0e1a",
            "border-width": "2px",
            "border-color": "data(border)",
            "transition-property": "background-color, border-color, width, height",
            "transition-duration": "0.25s",
        },
    },
    # Attacker (source) node
    {
        "selector": "node[type='attacker']",
        "style": {
            "shape": "diamond",
            "background-color": "#ef4444",
            "border-color": "#ff6b6b",
        },
    },
    # Target / victim node
    {
        "selector": "node[type='target']",
        "style": {
            "shape": "round-rectangle",
            "background-color": "#3b82f6",
            "border-color": "#60a5fa",
        },
    },
    # Compromised node
    {
        "selector": "node[type='compromised']",
        "style": {
            "shape": "round-rectangle",
            "background-color": "#f59e0b",
            "border-color": "#fbbf24",
        },
    },
    # Crown jewel (domain admin / critical asset)
    {
        "selector": "node[type='crown_jewel']",
        "style": {
            "shape": "star",
            "background-color": "#c9a84c",
            "border-color": "#e6c65a",
            "width": "55px",
            "height": "55px",
        },
    },
    # Domain Controller
    {
        "selector": "node[type='dc']",
        "style": {
            "shape": "hexagon",
            "background-color": "#a78bfa",
            "border-color": "#c4b5fd",
        },
    },
    # Selected node
    {
        "selector": "node:selected",
        "style": {
            "border-width": "4px",
            "border-color": "#c9a84c",
            "background-color": "#c9a84c",
        },
    },
    # Default edge
    {
        "selector": "edge",
        "style": {
            "width": "data(weight)",
            "line-color": "data(color)",
            "target-arrow-color": "data(color)",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "label": "data(label)",
            "font-size": "8px",
            "color": "#94a3b8",
            "font-family": "Inter, sans-serif",
            "text-rotation": "autorotate",
            "text-outline-width": "2px",
            "text-outline-color": "#0a0e1a",
            "opacity": 0.85,
            "transition-property": "opacity, line-color, width",
            "transition-duration": "0.2s",
        },
    },
    # Critical path edge
    {
        "selector": "edge[risk='critical']",
        "style": {
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            "width": "3px",
            "line-style": "solid",
        },
    },
    # High risk edge
    {
        "selector": "edge[risk='high']",
        "style": {
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b",
            "width": "2.5px",
        },
    },
    # Hover edge
    {
        "selector": "edge:selected",
        "style": {
            "line-color": "#c9a84c",
            "target-arrow-color": "#c9a84c",
            "width": "4px",
            "opacity": 1,
        },
    },
]


def _classify_node(name: str, method: str = "", phase: str = "") -> str:
    """Determine node type from name and context."""
    name_lower = name.lower()
    if name_lower in ("xstrike", "aegis", "attacker", "initial"):
        return "attacker"
    if "domain admin" in name_lower or "da" == name_lower or "crown" in name_lower:
        return "crown_jewel"
    if "dc" in name_lower or "domain controller" in name_lower:
        return "dc"
    if phase in ("exploit", "exploited") or "compromised" in name_lower:
        return "compromised"
    return "target"


def _node_color(node_type: str) -> tuple:
    """Return (bg_color, border_color) for node type."""
    colors = {
        "attacker": ("#ef4444", "#ff6b6b"),
        "target": ("#3b82f6", "#60a5fa"),
        "compromised": ("#f59e0b", "#fbbf24"),
        "crown_jewel": ("#c9a84c", "#e6c65a"),
        "dc": ("#a78bfa", "#c4b5fd"),
    }
    return colors.get(node_type, ("#64748b", "#94a3b8"))


def _edge_risk(method: str, risk: str = "") -> str:
    """Classify edge risk level."""
    risk_lower = (risk or "").lower()
    if risk_lower in ("critical",):
        return "critical"
    method_lower = method.lower()
    critical_keywords = ["root", "admin", "dcsync", "golden", "domain admin",
                         "backdoor", "rce", "ntds"]
    if any(k in method_lower for k in critical_keywords):
        return "critical"
    if risk_lower in ("high",) or "shell" in method_lower:
        return "high"
    return "medium"


def build_cytoscape_elements(attack_paths: list) -> list:
    """
    Convert attack_paths from AUTOPENTEST_STATE into Cytoscape elements.

    Each path: {source, target, method, phase, risk?, steps?}
    """
    nodes = {}
    edges = []

    for i, path in enumerate(attack_paths):
        source = path.get("source", "Unknown")
        target = path.get("target", "Unknown")
        method = path.get("method", "")
        phase = path.get("phase", "")
        risk = path.get("risk", "")
        steps = path.get("steps", [])

        # If path has steps (AD security format), build chain
        if steps and isinstance(steps, list) and len(steps) > 1:
            if isinstance(steps[0], dict):
                step_names = [s.get("node", s.get("name", "?")) for s in steps]
            else:
                step_names = steps
            for j, step in enumerate(step_names):
                ntype = _classify_node(step, method, phase)
                if j == 0:
                    ntype = "attacker"
                elif j == len(step_names) - 1:
                    ntype = "crown_jewel"
                color, border = _node_color(ntype)
                nodes[step] = {
                    "data": {
                        "id": step, "label": step, "type": ntype,
                        "color": color, "border": border,
                        "size": "50px" if ntype in ("attacker", "crown_jewel") else "38px",
                    }
                }
                if j > 0:
                    prev = step_names[j - 1]
                    edge_label = method if j == 1 else ""
                    edge_risk = _edge_risk(method, risk)
                    edges.append({
                        "data": {
                            "source": prev, "target": step,
                            "label": edge_label[:30],
                            "weight": 3 if edge_risk == "critical" else 2,
                            "color": "#ef4444" if edge_risk == "critical" else
                                     "#f59e0b" if edge_risk == "high" else "#64748b",
                            "risk": edge_risk,
                        }
                    })
        else:
            # Simple source→target edge
            for name in (source, target):
                if name not in nodes:
                    ntype = _classify_node(name, method, phase)
                    color, border = _node_color(ntype)
                    nodes[name] = {
                        "data": {
                            "id": name, "label": name, "type": ntype,
                            "color": color, "border": border,
                            "size": "45px" if ntype in ("attacker", "crown_jewel") else "35px",
                        }
                    }

            edge_risk = _edge_risk(method, risk)
            edges.append({
                "data": {
                    "source": source, "target": target,
                    "label": method[:35],
                    "weight": 3 if edge_risk == "critical" else 2,
                    "color": "#ef4444" if edge_risk == "critical" else
                             "#f59e0b" if edge_risk == "high" else "#64748b",
                    "risk": edge_risk,
                }
            })

    return list(nodes.values()) + edges


def build_attack_path_graph(attack_paths: list, height: str = "500px") -> html.Div:
    """
    Build the interactive attack path graph component.

    Returns a Dash html.Div containing the Cytoscape graph and legend.
    """
    elements = build_cytoscape_elements(attack_paths)

    if not elements:
        return html.Div(
            html.P("No attack paths discovered yet.",
                   style={"color": "#64748b", "textAlign": "center",
                          "padding": "40px", "fontStyle": "italic"}),
            className="glass-card",
            style={"margin": "12px 0"},
        )

    graph = cyto.Cytoscape(
        id="attack-path-cytoscape",
        elements=elements,
        stylesheet=GRAPH_STYLESHEET,
        layout={
            "name": "breadthfirst",
            "directed": True,
            "spacingFactor": 1.4,
            "avoidOverlap": True,
            "padding": 30,
        },
        style={
            "width": "100%",
            "height": height,
            "backgroundColor": "rgba(10, 14, 26, 0.8)",
            "borderRadius": "12px",
            "border": "1px solid rgba(255, 255, 255, 0.06)",
        },
        responsive=True,
        userZoomingEnabled=True,
        userPanningEnabled=True,
        boxSelectionEnabled=False,
        minZoom=0.3,
        maxZoom=3.0,
    )

    # Legend
    legend_items = [
        ("◆ Attacker", "#ef4444"),
        ("■ Target", "#3b82f6"),
        ("■ Compromised", "#f59e0b"),
        ("★ Crown Jewel", "#c9a84c"),
        ("⬡ Domain Controller", "#a78bfa"),
        ("— Critical Path", "#ef4444"),
        ("— High Risk", "#f59e0b"),
    ]

    legend = html.Div(
        [html.Span(
            label,
            style={
                "color": color, "marginRight": "16px", "fontSize": "11px",
                "fontWeight": "500", "fontFamily": "Inter, sans-serif",
            }
        ) for label, color in legend_items],
        style={
            "display": "flex", "flexWrap": "wrap", "gap": "4px",
            "padding": "10px 16px",
            "background": "rgba(22, 27, 45, 0.6)",
            "borderRadius": "0 0 12px 12px",
            "borderTop": "1px solid rgba(255, 255, 255, 0.04)",
        },
    )

    stats = html.Div(
        [
            html.Span(f"{sum(1 for e in elements if 'source' not in e.get('data', {}))} nodes",
                       style={"color": "#94a3b8", "fontSize": "11px", "marginRight": "12px"}),
            html.Span(f"{sum(1 for e in elements if 'source' in e.get('data', {}))} edges",
                       style={"color": "#94a3b8", "fontSize": "11px", "marginRight": "12px"}),
            html.Span(f"{sum(1 for e in elements if e.get('data', {}).get('risk') == 'critical')} critical paths",
                       style={"color": "#ef4444", "fontSize": "11px", "fontWeight": "600"}),
        ],
        style={
            "display": "flex", "padding": "8px 16px",
            "background": "rgba(22, 27, 45, 0.4)",
        },
    )

    return html.Div([
        html.Div(
            "ATTACK PATH GRAPH",
            style={
                "padding": "12px 16px", "fontSize": "13px", "fontWeight": "600",
                "letterSpacing": "0.08em", "color": "#c9a84c",
                "background": "rgba(22, 27, 45, 0.6)",
                "borderRadius": "12px 12px 0 0",
                "borderBottom": "1px solid rgba(201, 168, 76, 0.15)",
                "fontFamily": "Inter, sans-serif",
            },
        ),
        graph,
        stats,
        legend,
    ], className="glass-card", style={"margin": "12px 0", "borderRadius": "12px", "overflow": "hidden"})
