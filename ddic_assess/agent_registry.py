"""
agent_registry.py
─────────────────
Auto-discovers all agent modules inside the `agents/` package.
Each agent module must expose an AGENT_DEF dict with keys:
    name, description, version, input_key, scan, rules
"""

import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict, Any

AGENTS: List[Dict[str, Any]] = []


def _discover_agents():
    """
    Walk the agents/ package, import each module,
    and collect every AGENT_DEF it exports.
    """
    agents_pkg_path = Path(__file__).parent / "agents"

    for finder, module_name, is_pkg in pkgutil.iter_modules(
        [str(agents_pkg_path)]
    ):
        try:
            module = importlib.import_module(f"agents.{module_name}")
            agent_def = getattr(module, "AGENT_DEF", None)
            if agent_def and isinstance(agent_def, dict):
                AGENTS.append(agent_def)
                print(
                    f"  ✔ Loaded agent: {agent_def['name']} "
                    f"(v{agent_def.get('version', '?')})"
                )
        except Exception as e:
            print(f"  ✘ Failed to load agent '{module_name}': {e}")


print("─── Agent Discovery ───")
_discover_agents()
print(f"─── {len(AGENTS)} agent(s) loaded ───\n")
