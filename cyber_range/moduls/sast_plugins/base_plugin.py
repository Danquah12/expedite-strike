"""
base_plugin.py — SAST Plugin Base Class
Every plugin inherits from BasePlugin and implements run().
"""
from __future__ import annotations


class BasePlugin:
    """
    Abstract base for all SAST scanner plugins.

    Class attributes to set in every subclass
    ------------------------------------------
    name        : str   — human-readable plugin name shown in UI
    description : str   — one-line description
    engine_tag  : str   — label shown in the 'engine' column  (default: "Plugin")
    language    : str | None — restrict to a specific language, or None for all
    """
    name        : str        = "BasePlugin"
    description : str        = "Base plugin — override run() in subclasses"
    engine_tag  : str        = "Plugin"
    language    : str | None = None      # None = runs on every language

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        """
        Analyse *content* and return a list of finding dicts.

        Each dict must contain:
            id       (str)  — unique rule identifier, e.g. "PI-001"
            rule     (str)  — human-readable rule name
            severity (str)  — one of CRITICAL / HIGH / MEDIUM / LOW / INFO
            cwe      (str)  — e.g. "CWE-89"  (may be empty string)
            message  (str)  — explanation shown in the UI
            line     (int)  — 1-based line number (0 if unknown)
            code     (str)  — the offending line or snippet (≤200 chars)
            engine   (str)  — filled automatically by the runner
            fix      (str)  — optional suggested replacement (may be "")
        """
        return []

    # ── helpers available to all subclasses ─────────────────────────────────

    @staticmethod
    def make_finding(
        rule_id:  str,
        rule:     str,
        severity: str,
        cwe:      str,
        message:  str,
        line:     int,
        code:     str,
        fix:      str = "",
        engine:   str = "Plugin",
    ) -> dict:
        """Convenience constructor — guarantees all required keys are present."""
        return {
            "id":       rule_id,
            "rule":     rule,
            "severity": severity.upper(),
            "cwe":      cwe,
            "message":  message,
            "line":     line,
            "code":     code.strip()[:200],
            "engine":   engine,
            "fix":      fix,
        }
