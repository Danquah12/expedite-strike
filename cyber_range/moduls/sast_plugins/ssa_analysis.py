"""
ssa_analysis.py — SSA-Based Data Flow Analysis Plugin

Static Single Assignment (SSA) form assigns each variable a unique version
at every assignment point and introduces φ-functions at control flow merge
points (e.g., after if/else branches).

This implementation performs a lightweight SSA-like pass:
  1. Version every assignment:  x → x_1, x_2, ...
  2. Track which versions carry taint from user sources
  3. Insert φ-nodes at branch merge points to propagate taint conservatively
  4. Flag sink calls that receive any tainted version

No heavy dependency required — uses ast only.
astor is optional (used for nicer slice display if available).
"""
import ast
import textwrap
from collections import defaultdict
from .base_plugin import BasePlugin

try:
    import astor as _astor
    _ASTOR = True
except ImportError:
    _ASTOR = False

# Sources of taint
SOURCES = {
    "input", "raw_input",
}
ATTR_SOURCES = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "cookies"), ("request", "values"),
    ("request", "headers"), ("req", "body"), ("req", "query"),
}

# Dangerous sinks and their metadata
SINKS = {
    "execute":   ("PI-SSA-001", "CRITICAL", "CWE-89",  "SSA taint → SQL execute()"),
    "executemany": ("PI-SSA-002", "CRITICAL", "CWE-89", "SSA taint → SQL executemany()"),
    "system":    ("PI-SSA-003", "CRITICAL", "CWE-78",  "SSA taint → os.system()"),
    "Popen":     ("PI-SSA-004", "CRITICAL", "CWE-78",  "SSA taint → subprocess.Popen()"),
    "eval":      ("PI-SSA-005", "CRITICAL", "CWE-95",  "SSA taint → eval()"),
    "exec":      ("PI-SSA-006", "CRITICAL", "CWE-95",  "SSA taint → exec()"),
    "open":      ("PI-SSA-007", "HIGH",     "CWE-22",  "SSA taint → open()"),
    "render_template_string": ("PI-SSA-008","CRITICAL","CWE-94","SSA taint → SSTI"),
    "loads":     ("PI-SSA-009", "HIGH",     "CWE-502", "SSA taint → deserialisation"),
}


def _attr_str(node) -> str:
    if isinstance(node, ast.Name):       return node.id
    if isinstance(node, ast.Attribute):  return f"{_attr_str(node.value)}.{node.attr}"
    return ""


def _is_source(node) -> bool:
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in SOURCES:
            return True
        if isinstance(fn, ast.Attribute):
            if (_attr_str(fn.value), fn.attr) in ATTR_SOURCES:
                return True
    if _attr_str(node) in {f"{o}.{a}" for o, a in ATTR_SOURCES}:
        return True
    return False


def _names_in(node) -> set:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class _SSAState:
    """Tracks variable version counters and taint sets."""
    def __init__(self):
        self.counters: dict = defaultdict(int)
        self.versions: dict = {}      # name → current version int
        self.tainted:  set  = set()   # "name_ver" strings

    def new_version(self, name: str) -> str:
        self.counters[name] += 1
        ver = self.counters[name]
        self.versions[name] = ver
        return f"{name}_{ver}"

    def current(self, name: str) -> str:
        return f"{name}_{self.versions.get(name, 0)}"

    def is_tainted(self, name: str) -> bool:
        return self.current(name) in self.tainted

    def mark_tainted(self, name: str):
        self.tainted.add(self.current(name))

    def phi(self, other: "_SSAState"):
        """Merge two branch states conservatively — taint propagates through φ."""
        for k in set(self.counters) | set(other.counters):
            # Take the higher version (either branch may have assigned)
            v1 = self.versions.get(k, 0)
            v2 = other.versions.get(k, 0)
            if v2 > v1:
                self.versions[k] = v2
                self.counters[k] = max(self.counters[k], other.counters[k])
            # If either branch marked the var tainted, post-merge it's tainted
            if other.current(k) in other.tainted:
                self.mark_tainted(k)


class SSAAnalysisPlugin(BasePlugin):
    name        = "SSA Data Flow Analysis"
    description = (
        "Performs Static Single Assignment-based taint tracking. "
        "Each variable assignment gets a unique version; taint propagates through "
        "versions; φ-nodes at branches conservatively merge taint."
    )
    engine_tag  = "Plugin-SSA"
    language    = "python"

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        if language not in ("python", "auto"):
            return []
        findings = []
        try:
            tree = ast.parse(textwrap.dedent(content))
        except SyntaxError:
            return []

        lines    = content.splitlines()
        state    = _SSAState()
        # Track all versioned assignments for report
        version_log: list[str] = []

        def _process_stmts(stmts, st: _SSAState):
            for stmt in stmts:
                _process_node(stmt, st)

        def _process_node(node, st: _SSAState):
            # ── Assignment ───────────────────────────────────────────────────
            if isinstance(node, ast.Assign):
                rhs_tainted = False
                for sub in ast.walk(node.value):
                    if _is_source(sub):
                        rhs_tainted = True
                        break
                    if isinstance(sub, ast.Name) and st.is_tainted(sub.id):
                        rhs_tainted = True
                        break

                for target in node.targets:
                    tname = _attr_str(target)
                    if tname:
                        ver = st.new_version(tname)
                        version_log.append(f"{ver} = <rhs>{'  [TAINTED]' if rhs_tainted else ''}")
                        if rhs_tainted:
                            st.mark_tainted(tname)

            # ── If/Else — φ-node at merge ────────────────────────────────────
            elif isinstance(node, ast.If):
                import copy
                true_state  = copy.deepcopy(st)
                false_state = copy.deepcopy(st)
                _process_stmts(node.body, true_state)
                _process_stmts(node.orelse, false_state)
                # Merge via φ
                st.phi(true_state)
                st.phi(false_state)

            # ── Call — check for tainted args reaching sinks ─────────────────
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                _check_call(node.value, st)

            # ── Recurse into function bodies ─────────────────────────────────
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                import copy
                fn_state = copy.deepcopy(st)
                _process_stmts(node.body, fn_state)

            # Recurse for any embedded nodes
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, (ast.Assign, ast.If, ast.Expr,
                                          ast.FunctionDef, ast.AsyncFunctionDef)):
                    _process_node(child, st)

        def _check_call(call_node, st: _SSAState):
            fn = call_node.func
            fn_name = fn.attr if isinstance(fn, ast.Attribute) else (
                fn.id if isinstance(fn, ast.Name) else ""
            )
            if fn_name not in SINKS:
                return
            # Check args
            tainted_args = []
            for arg in call_node.args:
                for name in _names_in(arg):
                    if st.is_tainted(name):
                        tainted_args.append(f"{name} (ver {st.current(name)})")
                if _is_source(arg):
                    tainted_args.append("<direct source>")
            if tainted_args:
                rid, sev, cwe, msg = SINKS[fn_name]
                lno  = getattr(call_node, "lineno", 0)
                code = lines[lno - 1] if 0 < lno <= len(lines) else ""
                findings.append(self.make_finding(
                    rule_id=rid,
                    rule=f"SSA-Taint→{fn_name}()",
                    severity=sev, cwe=cwe,
                    message=(
                        f"{msg}. "
                        f"Tainted SSA variable(s): {', '.join(tainted_args)}. "
                        f"Version chain: {'; '.join(version_log[-5:])}"
                    ),
                    line=lno, code=code, engine=self.engine_tag,
                ))

        _process_stmts(tree.body, state)
        return findings
