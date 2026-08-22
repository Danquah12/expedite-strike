"""
interprocedural_taint.py — Interprocedural Taint Tracking Plugin

Extends single-function taint tracking to:
  1. Build a function call graph from the AST
  2. Track tainted return values flowing from callee → caller
  3. Detect taint propagation across function boundaries

Works on Python source only (uses ast module).
"""
import ast
import textwrap
from collections import defaultdict
from .base_plugin import BasePlugin

# Sources that introduce taint
SOURCES = {
    "input", "raw_input",
    # attribute-style: tracked separately
}
ATTR_SOURCES = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "cookies"), ("request", "values"),
    ("request", "headers"), ("req", "body"), ("req", "query"),
    ("sys", "stdin"),
}

# Dangerous sinks
SINKS = {
    "execute":   ("PI-IPT-001", "CRITICAL", "CWE-89",  "Interprocedural taint → SQL execute()"),
    "executemany": ("PI-IPT-002", "CRITICAL", "CWE-89", "Interprocedural taint → SQL executemany()"),
    "system":    ("PI-IPT-003", "CRITICAL", "CWE-78",  "Interprocedural taint → os.system()"),
    "Popen":     ("PI-IPT-004", "CRITICAL", "CWE-78",  "Interprocedural taint → subprocess.Popen()"),
    "eval":      ("PI-IPT-005", "CRITICAL", "CWE-95",  "Interprocedural taint → eval()"),
    "exec":      ("PI-IPT-006", "CRITICAL", "CWE-95",  "Interprocedural taint → exec()"),
    "open":      ("PI-IPT-007", "HIGH",     "CWE-22",  "Interprocedural taint → open()"),
    "render_template_string": ("PI-IPT-008","CRITICAL","CWE-94","Interprocedural taint → SSTI"),
}


def _attr_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_attr_name(node.value)}.{node.attr}"
    return ""


def _is_source_call(node) -> bool:
    """Return True if the call node is a direct source."""
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in SOURCES:
            return True
        if isinstance(fn, ast.Attribute):
            pair = (_attr_name(fn.value), fn.attr)
            if pair in ATTR_SOURCES:
                return True
    return False


def _is_source_attr(node) -> bool:
    """Return True if this is an attribute access like request.args."""
    name = _attr_name(node)
    for obj, attr in ATTR_SOURCES:
        if name == f"{obj}.{attr}" or name.startswith(f"{obj}.{attr}."):
            return True
    return False


class InterproceduralTaintPlugin(BasePlugin):
    name        = "Interprocedural Taint Tracker"
    description = (
        "Tracks tainted data across function boundaries: identifies tainted sources, "
        "propagates through assignments and return values, and flags tainted arguments "
        "reaching dangerous sinks anywhere in the file."
    )
    engine_tag  = "Plugin-IPTaint"
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

        # ── Step 1: collect all function defs ────────────────────────────────
        func_defs: dict[str, ast.FunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_defs[node.name] = node

        # ── Step 2: within each function, find tainted vars + check sinks ───
        # Also track which functions RETURN tainted values
        tainted_funcs: set[str] = set()

        def _analyse_scope(scope_nodes, tainted_vars: set, label: str):
            """Walk a sequence of statements; mutate tainted_vars; return findings."""
            local_findings = []
            for stmt in scope_nodes:
                for node in ast.walk(stmt):
                    # Assignment from source
                    if isinstance(node, ast.Assign):
                        rhs_tainted = False
                        for sub in ast.walk(node.value):
                            if _is_source_call(sub) or _is_source_attr(sub):
                                rhs_tainted = True
                                break
                            if isinstance(sub, ast.Name) and sub.id in tainted_vars:
                                rhs_tainted = True
                                break
                            # Call to a function that returns taint
                            if isinstance(sub, ast.Call):
                                fn_name = ""
                                if isinstance(sub.func, ast.Name):
                                    fn_name = sub.func.id
                                if fn_name in tainted_funcs:
                                    rhs_tainted = True
                                    break
                        if rhs_tainted:
                            for target in node.targets:
                                for n in ast.walk(target):
                                    if isinstance(n, ast.Name):
                                        tainted_vars.add(n.id)

                    # Return of tainted value marks the enclosing function as tainted
                    if isinstance(node, ast.Return) and node.value:
                        for sub in ast.walk(node.value):
                            if isinstance(sub, ast.Name) and sub.id in tainted_vars:
                                tainted_funcs.add(label)

                    # Sink check
                    if isinstance(node, ast.Call):
                        fn = node.func
                        fn_name = (fn.attr if isinstance(fn, ast.Attribute)
                                   else fn.id if isinstance(fn, ast.Name) else "")
                        if fn_name in SINKS:
                            # Check args for taint
                            for arg in node.args:
                                arg_names: set[str] = set()
                                for n in ast.walk(arg):
                                    if isinstance(n, ast.Name):
                                        arg_names.add(n.id)
                                tainted_args = arg_names & tainted_vars
                                if tainted_args or _is_source_call(arg) or _is_source_attr(arg):
                                    lno = getattr(node, "lineno", 0)
                                    code = lines[lno - 1] if 0 < lno <= len(lines) else ""
                                    rid, sev, cwe, msg = SINKS[fn_name]
                                    local_findings.append(self.make_finding(
                                        rule_id=rid,
                                        rule=f"IPTaint:{label}→{fn_name}()",
                                        severity=sev, cwe=cwe,
                                        message=(
                                            f"{msg}. "
                                            f"Tainted variable(s): {sorted(tainted_args) or ['<direct>'}. "
                                            f"Scope: {label}."
                                        ),
                                        line=lno, code=code, engine=self.engine_tag,
                                    ))
            return local_findings

        # Module-level taint
        tainted_module: set[str] = set()
        findings.extend(_analyse_scope(tree.body, tainted_module, "<module>"))

        # Per-function taint (two passes to catch mutual taint)
        for _ in range(2):
            for fname, fnode in func_defs.items():
                local_taint = set(tainted_module)  # module-level taint available
                findings.extend(_analyse_scope(fnode.body, local_taint, fname))

        return findings
