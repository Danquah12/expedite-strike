import json
import os


class AttackGraphExporter:
    """
    Exports attack graphs to DOT and JSON formats.
    """

    def __init__(self, output_dir="outputs"):
        self.output_dir = output_dir

    def execute(self, context):
        graph = context.attack_graph

        if not graph["nodes"] or not graph["edges"]:
            raise RuntimeError("Attack graph is empty; nothing to export")

        # ✅ Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

        self._export_dot(graph)
        self._export_json(graph)

    def _export_dot(self, graph):
        lines = ["digraph AttackGraph {"]

        for node in graph["nodes"]:
            label = node.replace(":", "\\n")
            lines.append(f'  "{node}" [label="{label}"];')

        for src, dst in graph["edges"]:
            lines.append(f'  "{src}" -> "{dst}";')

        lines.append("}")

        with open(os.path.join(self.output_dir, "attack_graph.dot"), "w") as f:
            f.write("\n".join(lines))

    def _export_json(self, graph):
        export = {
            "nodes": list(graph["nodes"]),
            "edges": [{"from": src, "to": dst} for src, dst in graph["edges"]]
        }

        with open(os.path.join(self.output_dir, "attack_graph.json"), "w") as f:
            json.dump(export, f, indent=2)
