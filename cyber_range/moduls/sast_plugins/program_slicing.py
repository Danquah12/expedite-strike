"""
program_slicing.py — Program Slicing Plugin

Program slicing extracts only the statements relevant to a particular
variable or sink. A backward slice starting from a sink walks backwards
through the def-use chains to identify every statement that could
contribute a value to the sink.

This implementation:
  1. Identifies sink calls in the AST (execute, system, eval, etc.)
  2. Collects the variable names used as arguments
  3. Walks backward through assignments to build the slice
  4. Reconstructs the slice as readable source lines
  5. Flags the full chain when a source (user input) reaches the sink
"""
import ast
import textwrap
from .base_plugin import BasePlugin

SINKS = {
    "execute", "executemany", "system", "Popen", "call",
    "eval", "exec", "open", "render_template_string", "loads",
}

SOURCES = {
    "input", "raw_input",
}
ATTR_SOURCES = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "cookies"), ("request", "values"),
    ("request", "headers"), ("req", "body"),
}

_SINK_META = {
    "execute":   ("PI-PS-001", "CRITICAL", "CWE-89"),
    "executemany": ("PI-PS-002", "CRITICAL", "CWE-89"),
    "system":    ("PI-PS-003", "CRITICAL", "CWE-78"),
    "Popen":     ("PI-PS-004", "CRITICAL", "CWE-78"),
    "call":      ("PI-PS-005", "HIGH",     "CWE-78"),
    "eval":      ("PI-PS-006", "CRITICAL", "CWE-95"),
    "exec":      ("PI-PS-007", "CRITICAL", "CWE-95"),
    "open":      ("PI-PS-008", "HIGH",     "CWE-22"),
    "render_template_string": ("PI-PS-009", "CRITICAL", "CWE-94"),
    "loads":     ("PI-PS-010", "HIGH",     "CWE-502"),
}


def _attr_name(node) -> str:
    if isinstance(node, ast.Name):      return node.id
    if isinstance(node, ast.Attribute): return f"{_attr_name(node.value)}.{node.attr}"
    return ""


def _is_source_node(node) -> bool:
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in SOURCES:
            return True
        if isinstance(fn, ast.Attribute):
            if (_attr_name(fn.value), fn.attr) in ATTR_SOURCES:
                return True
    a = _attr_name(node)
    for o, attr in ATTR_SOURCES:
        if a == f"{o}.{attr}" or a.startswith(f"{o}.{attr}."):
            return True
    return False


def _used_names(node) -> set:
    """All variable names referenced in node."""
    names = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
    return names


class ProgramSlicingPlugin(BasePlugin):
    name        = "Program Slicer"
    description = (
        "Performs backward program slicing from dangerous sinks. "
        "Reconstructs the chain of statements that contributed user input "
        "to the sink, showing the exact data-flow path."
    )
    engine_tag  = "Plugin-Slice"
    language    = "python"

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        if language not in ("python", "auto"):
            return []
        findings = []
        try:
            tree = ast.parse(textwrap.dedent(content))
        except SyntaxError:
            return []

        src_lines = content.splitlines()

        # ── Collect all assignment statements ─────────────────────────────────
        # {var_name → list of (lineno, node.value)}
        assigns: dict[str, list] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    tname = _attr_name(target)
                    if tname:
                        assigns.setdefault(tname, []).append(
                            (getattr(node, "lineno", 0), node.value)
                        )

        def _backward_slice(var: str, depth: int = 0, visited=None) -> list[str]:
            """Recursively build a backward slice for var up to depth 6."""
            if visited is None: visited = set()
            if depth > 6 or var in visited:
                return []
            visited.add(var)
            result = []
            for lno, val_node in assigns.get(var, []):
                line_txt = src_lines[lno - 1].strip() if 0 < lno <= len(src_lines) else "?"
                result.append(f"L{lno}: {line_txt}")
                # Recurse into rhs names
                for rhs_name in _used_names(val_node):
                    result.extend(_backward_slice(rhs_name, depth + 1, visited))
                # Check if rhs itself is a source
                if _is_source_node(val_node):
                    result.append(f"  └─ SOURCE: {line_txt}")
            return result

        # ── Find sink calls ───────────────────────────────────────────────────
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            fn_name = (fn.attr if isinstance(fn, ast.Attribute)
                       else fn.id if isinstance(fn, ast.Name) else "")
            if fn_name not in SINKS:
                continue

            lno  = getattr(node, "lineno", 0)
            code = src_lines[lno - 1] if 0 < lno <= len(src_lines) else ""

            # Collect arg variable names
            sink_args: set[str] = set()
            touches_source = False
            for arg in node.args:
                sink_args |= _used_names(arg)
                if _is_source_node(arg):
                    touches_source = True

            # Build backward slice for each arg
            full_slice: list[str] = []
            source_reached = touches_source
            for var in sink_args:
                sl = _backward_slice(var)
                if sl:
                    full_slice.append(f"← {var}:")
                    full_slice.extend(f"  {s}" for s in sl)
                    if any("SOURCE" in s for s in sl):
                        source_reached = True

            if not full_slice:
                # No interesting slice — report but as INFO
                full_slice = [f"No taint flows resolved for args: {sorted(sink_args)}"]

            rid, sev, cwe = _SINK_META.get(fn_name, ("PI-PS-X", "MEDIUM", ""))
            severity = sev if source_reached else "INFO"

            findings.append(self.make_finding(
                rule_id=rid,
                rule=f"Slice:{fn_name}()",
                severity=severity,
                cwe=cwe,
                message=(
                    f"Program slice for '{fn_name}()' sink at L{lno}. "
                    f"Source reached: {source_reached}. "
                    f"Data-flow chain:\n" + "\n".join(full_slice[:20])
                ),
                line=lno, code=code, engine=self.engine_tag,
                fix=(
                    "Validate and sanitise all variables in the slice before they reach "
                    f"the '{fn_name}()' sink." if source_reached else ""
                ),
            ))

        return findings
