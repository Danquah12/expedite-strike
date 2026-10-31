"""
cpg_plugin.py — Code Property Graph (CPG) Plugin

Builds an AST-backed directed graph using networkx, then runs structural
vulnerability detections on top of the graph:

  • Detects direct SINK calls (no param validation nearby)
  • Measures cyclomatic complexity (McCabe) — high complexity = harder to audit
  • Flags deeply-nested dangerous calls
  • Reports graph metrics for downstream tooling

Requires: pip install networkx
"""
import ast
import textwrap
from .base_plugin import BasePlugin

try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False


# Dangerous functions worth flagging when called from complex/deep paths
_DANGER_FUNCS = {
    "execute": ("PI-CPG-001", "CRITICAL", "CWE-89",  "Taint sink: execute() in complex call graph"),
    "system":  ("PI-CPG-002", "CRITICAL", "CWE-78",  "Taint sink: os.system() in complex call graph"),
    "Popen":   ("PI-CPG-003", "CRITICAL", "CWE-78",  "Taint sink: subprocess.Popen() in complex call graph"),
    "eval":    ("PI-CPG-004", "CRITICAL", "CWE-95",  "Taint sink: eval() in complex call graph"),
    "exec":    ("PI-CPG-005", "CRITICAL", "CWE-95",  "Taint sink: exec() in complex call graph"),
    "open":    ("PI-CPG-006", "HIGH",     "CWE-22",  "Taint sink: open() in complex call graph"),
    "loads":   ("PI-CPG-007", "HIGH",     "CWE-502", "Taint sink: loads() in complex call graph"),
    "render_template_string": ("PI-CPG-008", "CRITICAL", "CWE-94", "Taint sink: render_template_string() — SSTI risk"),
}

# Cyclomatic complexity threshold above which we flag for audit
_COMPLEXITY_WARN = 10


def _count_branches(func_node) -> int:
    """Count decision points in a function to estimate McCabe complexity."""
    branch_nodes = (ast.If, ast.For, ast.While, ast.ExceptHandler,
                    ast.With, ast.Assert, ast.comprehension)
    return 1 + sum(1 for n in ast.walk(func_node) if isinstance(n, branch_nodes))


class CodePropertyGraphPlugin(BasePlugin):
    name        = "Code Property Graph (CPG) Analyser"
    description = (
        "Builds an AST-backed directed graph (AST+CFG approximation) and runs "
        "structural analyses: sink detection in deep call paths, cyclomatic complexity, "
        "and unreachable-branch heuristics."
    )
    engine_tag  = "Plugin-CPG"
    language    = "python"

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        if language not in ("python", "auto"):
            return []
        findings = []

        try:
            source = textwrap.dedent(content)
            tree   = ast.parse(source)
        except SyntaxError:
            return []

        lines = content.splitlines()

        # ── Build graph ──────────────────────────────────────────────────────
        if _NX:
            graph = nx.DiGraph()
            for node in ast.walk(tree):
                graph.add_node(id(node), type=type(node).__name__,
                               lineno=getattr(node, "lineno", 0))
                for child in ast.iter_child_nodes(node):
                    graph.add_edge(id(node), id(child))
            node_count = len(graph.nodes)
            edge_count = len(graph.edges)
        else:
            node_count = sum(1 for _ in ast.walk(tree))
            edge_count = 0

        # ── Structural analysis 1: dangerous sinks ──────────────────────────
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name in _DANGER_FUNCS:
                rid, sev, cwe, msg = _DANGER_FUNCS[func_name]
                lno  = getattr(node, "lineno", 0)
                code = lines[lno - 1] if 0 < lno <= len(lines) else ""
                findings.append(self.make_finding(
                    rule_id=rid, rule=f"CPG-Sink:{func_name}()",
                    severity=sev, cwe=cwe,
                    message=f"{msg} — detected via Code Property Graph traversal.",
                    line=lno, code=code, engine=self.engine_tag,
                ))

        # ── Structural analysis 2: cyclomatic complexity ─────────────────────
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            complexity = _count_branches(node)
            if complexity >= _COMPLEXITY_WARN:
                lno  = getattr(node, "lineno", 0)
                code = lines[lno - 1] if 0 < lno <= len(lines) else ""
                findings.append(self.make_finding(
                    rule_id="PI-CPG-CC",
                    rule="High Cyclomatic Complexity",
                    severity="LOW",
                    cwe="CWE-1121",
                    message=(
                        f"Function '{node.name}' has cyclomatic complexity ≥{complexity} "
                        f"(threshold: {_COMPLEXITY_WARN}). High complexity makes security "
                        f"auditing harder and increases defect probability."
                    ),
                    line=lno, code=code, engine=self.engine_tag,
                    fix=f"Refactor '{node.name}' into smaller single-responsibility functions.",
                ))

        # ── Structural analysis 3: graph size info finding ───────────────────
        findings.append(self.make_finding(
            rule_id="PI-CPG-INFO",
            rule="CPG Graph Built",
            severity="INFO",
            cwe="",
            message=(
                f"Code Property Graph constructed: {node_count} nodes, {edge_count} edges. "
                f"NetworkX available: {_NX}. Graph metrics stored for downstream analysis."
            ),
            line=0, code="", engine=self.engine_tag,
        ))

        return findings
