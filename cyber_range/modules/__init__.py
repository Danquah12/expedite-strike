"""
Custom Port-Based Exploit Modules

Each module file (port_XX_service.py) provides:
  - MODULE_INFO dict: port, service, name, description, techniques
  - enumerate(target_ip, service_info) → list of exploit dicts
  - exploit(target_ip, port, exploit_info) → result dict

To add a new module:
  1. Create cyber_range/modules/port_<PORT>_<SERVICE>.py
  2. Define MODULE_INFO, enumerate(), and exploit()
  3. The orchestrator will auto-discover and load it
"""

import os
import importlib
import glob

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_loaded_modules = {}  # port_number → module


def load_all_modules():
    """Discover and load all port_*.py modules."""
    global _loaded_modules
    _loaded_modules.clear()
    for fpath in glob.glob(os.path.join(_MODULE_DIR, "port_*.py")):
        mod_name = os.path.basename(fpath).replace(".py", "")
        try:
            mod = importlib.import_module(f"cyber_range.modules.{mod_name}")
            info = getattr(mod, "MODULE_INFO", {})
            port = info.get("port")
            if port:
                _loaded_modules[int(port)] = mod
        except Exception as e:
            print(f"[CustomModules] Failed to load {mod_name}: {e}")
    return _loaded_modules


def get_module_for_port(port):
    """Get the custom module for a given port, or None."""
    if not _loaded_modules:
        load_all_modules()
    return _loaded_modules.get(int(port))


def get_all_modules():
    """Get all loaded modules as {port: module}."""
    if not _loaded_modules:
        load_all_modules()
    return dict(_loaded_modules)
