"""
agent_registry.py
"""

import importlib
import pkgutil
import traceback
import os
from pathlib import Path
from typing import List, Dict, Any

AGENTS: List[Dict[str, Any]] = []


def _discover_agents():
    agents_pkg_path = Path(__file__).parent / "agents"

    print(f"  Looking in: {agents_pkg_path}")
    print(f"  Exists: {agents_pkg_path.exists()}")

    if agents_pkg_path.exists():
        print(f"  Files: {os.listdir(agents_pkg_path)}")
    else:
        print("  ❌ agents/ directory NOT FOUND!")
        return

    init_file = agents_pkg_path / "__init__.py"
    print(f"  __init__.py exists: {init_file.exists()}")

    for finder, module_name, is_pkg in pkgutil.iter_modules(
        [str(agents_pkg_path)]
    ):
        print(f"  → Found module: '{module_name}'")
        try:
            module = importlib.import_module(f"agents.{module_name}")
            agent_def = getattr(module, "AGENT_DEF", None)
            if agent_def and isinstance(agent_def, dict):
                AGENTS.append(agent_def)
                print(
                    f"  ✔ Loaded: {agent_def['name']} "
                    f"(v{agent_def.get('version', '?')})"
                )
            else:
                print(f"  ⚠ No AGENT_DEF in '{module_name}'")
        except Exception as e:
            print(f"  ✘ FAILED '{module_name}': {e}")
            traceback.print_exc()


print("=" * 50)
print("  AGENT DISCOVERY START")
print("=" * 50)
_discover_agents()
print(f"  TOTAL: {len(AGENTS)} agent(s) loaded")
print("=" * 50)
