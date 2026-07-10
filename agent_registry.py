"""Registry-backed discovery for running agent services."""

import json
from pathlib import Path
from urllib.parse import urlparse
import urllib.error
import urllib.request


DEFAULT_REGISTRY_PATH = "agent_registry.json"
DEFAULT_DISCOVERY_PORTS = (
    18080,
    18101,
    18102,
    18103,
    18104,
    18105,
    18106,
    18107,
    18108,
    18109,
    18110,
    8000,
    8080,
    5000,
    5001,
)


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


def parse_port_spec(value):
    if not value:
        return list(DEFAULT_DISCOVERY_PORTS)

    ports = []
    seen = set()
    for raw_part in str(value).split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range '{part}'.")
            candidates = range(start, end + 1)
        else:
            candidates = (int(part),)

        for port in candidates:
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: {port}.")
            if port not in seen:
                seen.add(port)
                ports.append(port)
    return ports


def _read_json(url, timeout):
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
        return response.status, json.loads(body)
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
        return None, None


def _registry_ports(registry_path):
    ports = []
    for agent in load_registry(registry_path)["agents"]:
        for url_key in ("health_url", "invoke_url"):
            parsed = urlparse(str(agent.get(url_key) or ""))
            if parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port:
                ports.append(parsed.port)
    return ports


def local_discovery_ports(port_spec=None, registry_path=DEFAULT_REGISTRY_PATH):
    ports = []
    seen = set()
    for port in [*parse_port_spec(port_spec), *_registry_ports(registry_path)]:
        if port not in seen:
            seen.add(port)
            ports.append(port)
    return ports


def discover_local_agents(host="127.0.0.1", ports=None, timeout=0.35):
    discovered = []
    for port in ports or DEFAULT_DISCOVERY_PORTS:
        base_url = f"http://{host}:{port}"
        health_status, health_payload = _read_json(f"{base_url}/health", timeout)
        if health_status is None or not isinstance(health_payload, dict):
            continue

        metadata_status, metadata_payload = _read_json(f"{base_url}/metadata", timeout)
        targets_status, targets_payload = _read_json(f"{base_url}/targets", timeout)
        metadata = metadata_payload if isinstance(metadata_payload, dict) else {}
        targets_payload = targets_payload if isinstance(targets_payload, dict) else {}
        target_names = health_payload.get("targets") or [
            target.get("name")
            for target in targets_payload.get("targets", [])
            if isinstance(target, dict) and target.get("name")
        ]

        name = metadata.get("name") or health_payload.get("agent")
        kind = metadata.get("kind") or "agent-service"
        if target_names:
            name = name or "agent_lab_server"
            kind = "agent-lab"
        if not name:
            name = f"local-agent-{port}"

        discovered.append(
            {
                "name": name,
                "kind": kind,
                "status": "up" if 200 <= health_status < 300 else "down",
                "base_url": base_url,
                "health_url": f"{base_url}/health",
                "metadata_url": f"{base_url}/metadata" if metadata_status else None,
                "invoke_url": f"{base_url}{metadata.get('invoke', '/invoke')}",
                "targets_url": f"{base_url}/targets" if targets_status else None,
                "targets": sorted(target_names or []),
                "http_status": health_status,
                "health": health_payload,
                "metadata": metadata,
            }
        )
    return discovered
