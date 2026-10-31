"""
taint_analysis.py — AST-based Taint Analysis Plugin (Python only)

Performs lightweight inter-statement taint tracking:
  1. Identifies SOURCES (request.args, input(), etc.) → marks variables as tainted
  2. Propagates taint through assignments and string concatenation
  3. Flags any SINK call that receives a tainted argument

This is intentionally conservative (may miss complex flows) but generates
very few false positives compared to naïve pattern matching.
"""
import ast
import textwrap
from .base_plugin import BasePlugin


# ── Source signatures ─────────────────────────────────────────────────────────
SOURCES = {
    # attribute access patterns (obj.attr)
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "values"), ("request", "cookies"),
    ("request", "headers"), ("request", "files"),
    ("req", "body"), ("req", "query"), ("req", "params"),
    # bare function calls
    ("input",),
    ("raw_input",),
    ("sys", "stdin"),
}

# ── Sink signatures ───────────────────────────────────────────────────────────
# Each entry: (obj_or_None, method_or_func, rule_id, severity, cwe, description)
SINKS = [
    (None,         "execute",            "PI-TA-001", "CRITICAL", "CWE-89",
     "Tainted data flows into execute() — SQL injection risk."),
    (None,         "executemany",        "PI-TA-002", "CRITICAL", "CWE-89",
     "Tainted data flows into executemany() — SQL injection risk."),
    ("os",         "system",             "PI-TA-003", "CRITICAL", "CWE-78",
     "Tainted data flows into os.system() — command injection risk."),
    (None,         "Popen",              "PI-TA-004", "CRITICAL", "CWE-78",
     "Tainted data flows into subprocess.Popen() — command injection risk."),
    (None,         "call",               "PI-TA-005", "HIGH",     "CWE-78",
     "Tainted data flows into subprocess.call() — potential command injection."),
    (None,         "run",                "PI-TA-006", "HIGH",     "CWE-78",
     "Tainted data flows into subprocess.run() — potential command injection."),
    (None,         "open",               "PI-TA-007", "HIGH",     "CWE-22",
     "Tainted data flows into open() — potential path traversal."),
    (None,         "eval",               "PI-TA-008", "CRITICAL", "CWE-95",
     "Tainted data flows into eval() — arbitrary code execution."),
    (None,         "exec",               "PI-TA-009", "CRITICAL", "CWE-95",
     "Tainted data flows into exec() — arbitrary code execution."),
    (None,         "render_template_string", "PI-TA-010", "CRITICAL", "CWE-94",
     "Tainted data flows into render_template_string() — SSTI risk."),
    (None,         "loads",              "PI-TA-011", "HIGH",     "CWE-502",
     "Tainted data flows into loads() (pickle/yaml/json) — potential deserialization risk."),
    (None,         "format",             "PI-TA-012", "MEDIUM",   "CWE-134",
     "Tainted data used in str.format() — potential format string injection."),
    (None,         "redirect",           "PI-TA-013", "MEDIUM",   "CWE-601",
     "Tainted data used in redirect() — potential open redirect."),
    (None,         "send_file",          "PI-TA-014", "HIGH",     "CWE-22",
     "Tainted data flows into send_file() — potential path traversal."),
]


def _node_name(node) -> str:
    """Return a best-effort string representation of a Name/Attribute/Call node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_node_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _node_name(node.func)
    return ""


def _is_source(node) -> bool:
    """Return True if *node* is a taint source."""
    name = _node_name(node)
    # attribute access: request.args, request.form …
    for sig in SOURCES:
        if len(sig) == 2:
            if name == f"{sig[0]}.{sig[1]}" or name.startswith(f"{sig[0]}.{sig[1]}."):
                return True
        elif len(sig) == 1:
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == sig[0]:
                    return True
    return False


def _collect_names(node) -> set[str]:
    """Collect all Name ids referenced in *node* (rhs of assignment, call args)."""
    names = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
    return names


def _arg_names(call_node) -> set[str]:
    """Return all variable names used in call args/kwargs."""
    names = set()
    for arg in call_node.args:
        names |= _collect_names(arg)
    for kw in call_node.keywords:
        names |= _collect_names(kw.value)
    return names


class TaintAnalysisPlugin(BasePlugin):
    name        = "AST Taint Analysis"
    description = (
        "Tracks user-controlled data from source to dangerous sink using Python AST. "
        "Covers SQL injection, command injection, path traversal, SSTI, RCE, open redirect."
    )
    engine_tag  = "Plugin-Taint"
    language    = "python"   # AST parsing only makes sense for Python

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        if language not in ("python", "auto"):
            return []

        # Normalise indentation so textwrap.dedent works on snippets
        try:
            tree = ast.parse(content)
        except SyntaxError:
            try:
                tree = ast.parse(textwrap.dedent(content))
            except SyntaxError:
                return []

        findings = []
        # tainted_vars: set of variable names known to carry user input
        tainted_vars: set[str] = set()

        # ── Pass 1: propagate taint forward through statements ───────────────
        for node in ast.walk(tree):
            # Assignment: x = request.args.get(...)   or   x = tainted_var + "..."
            if isinstance(node, ast.Assign):
                for val_node in ast.walk(node.value):
                    if _is_source(val_node):
                        for target in node.targets:
                            for n in ast.walk(target):
                                if isinstance(n, ast.Name):
                                    tainted_vars.add(n.id)
                        break
                # Propagate: if any rhs name is tainted, lhs is tainted too
                rhs_names = _collect_names(node.value)
                if rhs_names & tainted_vars:
                    for target in node.targets:
                        for n in ast.walk(target):
                            if isinstance(n, ast.Name):
                                tainted_vars.add(n.id)

            # AugAssign: x += tainted_var
            elif isinstance(node, ast.AugAssign):
                rhs_names = _collect_names(node.value)
                if rhs_names & tainted_vars:
                    if isinstance(node.target, ast.Name):
                        tainted_vars.add(node.target.id)

        # ── Pass 2: check every Call node against SINKS ──────────────────────
        lines = content.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            func_name = ""
            obj_name  = ""
            if isinstance(func, ast.Attribute):
                func_name = func.attr
                obj_name  = _node_name(func.value)
            elif isinstance(func, ast.Name):
                func_name = func.id

            call_arg_names = _arg_names(node)
            tainted_args   = call_arg_names & tainted_vars

            # Also flag if any argument IS a source directly (no variable assignment)
            for arg in node.args:
                if _is_source(arg):
                    tainted_args.add(_node_name(arg))
            for kw in node.keywords:
                if _is_source(kw.value):
                    tainted_args.add(_node_name(kw.value))

            if not tainted_args:
                continue   # no tainted data reaching this call

            for sink_obj, sink_fn, rid, sev, cwe, msg in SINKS:
                if func_name != sink_fn:
                    continue
                if sink_obj and not obj_name.startswith(sink_obj):
                    continue

                line_no  = getattr(node, "lineno", 0)
                code_snip = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                detail = (
                    f"{msg} Tainted variable(s): {', '.join(sorted(tainted_args))}."
                )
                findings.append(self.make_finding(
                    rule_id=rid,
                    rule=f"Taint→{sink_fn}()",
                    severity=sev,
                    cwe=cwe,
                    message=detail,
                    line=line_no,
                    code=code_snip,
                    fix="",
                    engine=self.engine_tag,
                ))

        return findings
