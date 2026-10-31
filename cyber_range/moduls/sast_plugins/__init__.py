"""
__init__.py — sast_plugins auto-discovery loader
Discovers all BasePlugin subclasses in this package and exposes them via
`load_plugins()`.

Usage (from ui_sast.py):
    from sast_plugins import load_plugins, run_all_plugins
    findings = run_all_plugins(file_path, content, language)
"""
from __future__ import annotations
import importlib
import pkgutil
import pathlib
from typing import List

from .base_plugin import BasePlugin

# ── Auto-discover all modules in this package ──────────────────────────────
_HERE = pathlib.Path(__file__).parent

def _discover_plugin_classes() -> list:
    """Return one instance of every BasePlugin subclass found in this package."""
    classes = []
    for module_info in pkgutil.iter_modules([str(_HERE)]):
        if module_info.name.startswith("_"):
            continue   # skip __init__, base_plugin, private modules
        if module_info.name == "base_plugin":
            continue
        try:
            mod = importlib.import_module(f".{module_info.name}", package=__name__)
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                ):
                    classes.append(obj())
        except Exception as exc:
            # Never let a bad plugin crash the scanner
            import sys
            print(f"[sast_plugins] Failed to load {module_info.name}: {exc}", file=sys.stderr)
    return classes


def load_plugins() -> List[BasePlugin]:
    """Return all auto-discovered plugin instances."""
    return _discover_plugin_classes()


def run_all_plugins(file_path: str, content: str, language: str = "auto") -> List[dict]:
    """
    Execute every plugin and merge findings into a single list.
    Plugins that restrict themselves to a specific language are skipped for others.
    """
    all_findings: list[dict] = []
    for plugin in load_plugins():
        # Skip if the plugin declared a language restriction
        if plugin.language and plugin.language != language:
            continue
        try:
            findings = plugin.run(file_path, content, language)
            # Stamp the engine tag in case the plugin forgot
            for f in findings:
                f.setdefault("engine", plugin.engine_tag)
            all_findings.extend(findings)
        except Exception as exc:
            import sys
            print(f"[sast_plugins] {plugin.name} raised: {exc}", file=sys.stderr)
    return all_findings


__all__ = ["BasePlugin", "load_plugins", "run_all_plugins"]
