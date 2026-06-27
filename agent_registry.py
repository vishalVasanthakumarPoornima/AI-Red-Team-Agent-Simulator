"""Registry-backed discovery for running agent services."""

import json
from pathlib import Path
import urllib.error
import urllib.request


DEFAULT_REGISTRY_PATH = "agent_registry.json"


def load_registry(path=DEFAULT_REGISTRY_PATH):
    registry_path = Path(path)
    if not registry_path.exists():
        return {"agents": []}
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    agents = data.get("agents", [])
    if not isinstance(agents, list):
        raise ValueError("Agent registry must contain an 'agents' list.")
    return {"agents": agents}


def check_agent_health(agent, timeout=5):
    health_url = agent.get("health_url")
    if not health_url:
        return {**agent, "status": "unknown", "error": "Missing health_url."}
    try:
        with urllib.request.urlopen(health_url, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
        return {
            **agent,
            "status": "up" if 200 <= response.status < 300 else "down",
            "http_status": response.status,
            "health_excerpt": body[:300],
        }
    except (OSError, urllib.error.URLError) as exc:
        return {**agent, "status": "down", "error": str(exc)}
