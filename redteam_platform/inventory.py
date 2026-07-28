"""Unified local model, agent, service, listener, and optional Docker inventory."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import psutil

from agent_registry import discover_local_agents, load_registry, local_discovery_ports
from redteam_platform.schemas import (
    Agent,
    Confidence,
    InventoryItem,
    InventorySnapshot,
    LocalModel,
    ScopeClassification,
    Service,
    Status,
    Target,
    TargetType,
)
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings
from scanner.target_loader import discover_targets


class NoRedirectHandler(__import__("urllib.request").request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def stable_id(kind: str, identity: str) -> str:
    digest = hashlib.sha256(f"{kind}:{identity}".encode()).hexdigest()[:16]
    return f"{kind}_{digest}"


def _json_request(url: str, timeout: float = 1.5) -> tuple[int | None, Any, dict[str, str]]:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")
            return response.status, json.loads(body), dict(response.headers)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            return exc.code, None, dict(exc.headers)
        return exc.code, None, dict(exc.headers)
    except (OSError, TimeoutError, json.JSONDecodeError):
        return None, None, {}


def _scope_value(classification: str) -> ScopeClassification:
    try:
        return ScopeClassification(classification)
    except ValueError:
        return ScopeClassification.UNKNOWN


class OllamaInventory:
    def __init__(self, settings: Settings, policy: ScopePolicy):
        self.settings = settings
        self.policy = policy

    @staticmethod
    def _base(endpoint: str) -> str:
        value = endpoint.rstrip("/")
        if value.endswith("/api/generate"):
            value = value[: -len("/api/generate")]
        return value

    def discover(self) -> tuple[list[InventoryItem], list[str]]:
        items: list[InventoryItem] = []
        errors: list[str] = []
        for configured in self.settings.ollama_endpoints:
            base = self._base(configured)
            try:
                decision = self.policy.decide(base, active=False)
            except ScopeDeniedError as exc:
                errors.append(f"Ollama endpoint denied: {exc}")
                continue
            if not decision.allowed:
                errors.append(f"Ollama endpoint denied: {'; '.join(decision.reasons)}")
                continue

            version_status, version_data, _ = _json_request(urljoin(base + "/", "api/version"))
            ps_status, ps_data, _ = _json_request(urljoin(base + "/", "api/ps"))
            tags_status, tags_data, _ = _json_request(urljoin(base + "/", "api/tags"))
            healthy = any(status and 200 <= status < 300 for status in (version_status, ps_status, tags_status))
            items.append(
                InventoryItem(
                    id=stable_id("ollama", base),
                    name="Ollama",
                    type="model_runtime",
                    endpoint=base,
                    status=Status.ACTIVE if healthy else Status.UNAVAILABLE,
                    discovery_source="ollama_api",
                    confidence=Confidence.HIGH if healthy else Confidence.LOW,
                    capabilities=["installed_models", "running_models", "generate"],
                    scope_classification=_scope_value(decision.classification),
                    metadata={"version": (version_data or {}).get("version")},
                    health={
                        "version_status": version_status,
                        "running_status": ps_status,
                        "installed_status": tags_status,
                    },
                )
            )

            running = {
                row.get("name") or row.get("model"): row
                for row in (ps_data or {}).get("models", [])
                if isinstance(row, dict)
            }
            installed = (tags_data or {}).get("models", [])
            for row in installed if isinstance(installed, list) else []:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name") or row.get("model") or "unknown")
                active = running.get(name, {})
                details = row.get("details") or {}
                context_length = active.get("context_length")
                items.append(
                    LocalModel(
                        id=stable_id("model", f"{base}:{name}"),
                        name=name,
                        type="local_model",
                        endpoint=base,
                        status=Status.ACTIVE if active else Status.INACTIVE,
                        discovery_source="ollama_api",
                        confidence=Confidence.HIGH,
                        capabilities=["generate"],
                        scope_classification=_scope_value(decision.classification),
                        metadata={
                            "digest": row.get("digest"),
                            "size_bytes": row.get("size"),
                            "modified_at": row.get("modified_at"),
                            "family": details.get("family"),
                            "format": details.get("format"),
                        },
                        health={},
                        parameter_size=details.get("parameter_size"),
                        quantization=details.get("quantization_level"),
                        context_length=context_length,
                        vram_bytes=active.get("size_vram"),
                        expires_at=active.get("expires_at"),
                        running=bool(active),
                    )
                )
        return items, errors


class ListenerInventory:
    KNOWN_PORTS = {
        11434: "ollama",
        18080: "agent_lab_server",
        18101: "weather_insight_agent",
        18102: "travel_planner_agent",
    }

    @staticmethod
    def discover() -> tuple[list[Service], list[str]]:
        items: list[Service] = []
        errors: list[str] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            return ListenerInventory._fallback(), [f"psutil listener inventory limited: {exc}"]

        for conn in connections:
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            address = conn.laddr.ip
            port = conn.laddr.port
            pid = conn.pid
            process_name = executable = username = None
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    executable = process.exe() or None
                    username = process.username()
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
            loopback = address in {"127.0.0.1", "::1", "localhost"}
            known = ListenerInventory.KNOWN_PORTS.get(port)
            items.append(
                Service(
                    id=stable_id("service", f"{address}:{port}:{pid}"),
                    name=known or process_name or f"listener-{port}",
                    type="listening_service",
                    endpoint=f"tcp://{address}:{port}",
                    status=Status.ACTIVE,
                    discovery_source="psutil",
                    confidence=Confidence.HIGH if known else Confidence.MEDIUM,
                    capabilities=[known] if known else [],
                    scope_classification=(
                        ScopeClassification.LOOPBACK
                        if loopback
                        else ScopeClassification.UNKNOWN
                    ),
                    address=address,
                    port=port,
                    process_id=pid,
                    process_name=process_name,
                    executable=executable,
                    user=username,
                    loopback_only=loopback,
                )
            )
        return items, errors

    @staticmethod
    def _fallback() -> list[Service]:
        system = platform.system()
        if system == "Darwin" and shutil.which("lsof"):
            command = ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]
        elif system == "Linux" and shutil.which("ss"):
            command = ["ss", "-ltnp"]
        else:
            return []
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        items: list[Service] = []
        for index, line in enumerate(result.stdout.splitlines()[1:], start=1):
            items.append(
                Service(
                    id=stable_id("service_fallback", line),
                    name=f"listener-{index}",
                    type="listening_service",
                    status=Status.ACTIVE,
                    discovery_source=f"{system.lower()}_command_fallback",
                    confidence=Confidence.LOW,
                    capabilities=[],
                    metadata={"sanitized_line": " ".join(line.split())[:300]},
                )
            )
        return items


class AgentInventory:
    def __init__(self, settings: Settings, policy: ScopePolicy):
        self.settings = settings
        self.policy = policy

    def discover(self) -> tuple[list[InventoryItem], list[str]]:
        items: list[InventoryItem] = []
        errors: list[str] = []
        for target in discover_targets():
            items.append(
                Target(
                    id=stable_id("python_target", target["path"]),
                    name=target["name"],
                    type="ai_agent",
                    local_path=target["path"],
                    status=Status.READY,
                    discovery_source="redteam_target_marker",
                    confidence=Confidence.HIGH,
                    capabilities=["run_agent", "static_assessment", "adaptive_assessment"],
                    scope_classification=ScopeClassification.LOOPBACK,
                    target_type=TargetType.PYTHON_AGENT,
                    adapter="python",
                    supported_profiles=["passive", "standard", "deep-lab"],
                )
            )

        registry = load_registry()
        for row in registry["agents"]:
            endpoint = row.get("invoke_url") or row.get("health_url")
            decision = None
            if endpoint:
                try:
                    decision = self.policy.decide(endpoint, active=False)
                except ScopeDeniedError as exc:
                    errors.append(f"Registry endpoint denied for {row.get('name')}: {exc}")
            items.append(
                Agent(
                    id=stable_id("registry_agent", str(endpoint or row.get("name"))),
                    name=row.get("name") or "registered-agent",
                    type="ai_agent",
                    endpoint=endpoint,
                    status=Status.UNKNOWN,
                    discovery_source="agent_registry",
                    confidence=Confidence.MEDIUM,
                    capabilities=["health", "invoke"],
                    scope_classification=(
                        _scope_value(decision.classification)
                        if decision
                        else ScopeClassification.BLOCKED
                    ),
                    invoke_endpoint=row.get("invoke_url"),
                    metadata={"kind": row.get("kind"), "description": row.get("description")},
                )
            )

        ports = local_discovery_ports(None)
        for row in discover_local_agents("127.0.0.1", ports=ports, timeout=0.2):
            items.append(
                Agent(
                    id=stable_id("active_agent", row["base_url"]),
                    name=row["name"],
                    type="ai_agent",
                    endpoint=row["base_url"],
                    status=Status.ACTIVE if row["status"] == "up" else Status.UNAVAILABLE,
                    discovery_source="compatible_http_probe",
                    confidence=Confidence.HIGH,
                    capabilities=["health", "metadata", "invoke", *(row.get("targets") or [])],
                    scope_classification=ScopeClassification.LOOPBACK,
                    invoke_endpoint=row.get("invoke_url"),
                    metadata={"kind": row.get("kind"), "targets": row.get("targets") or []},
                    health=row.get("health") or {},
                )
            )
        return items, errors


class DockerInventory:
    @staticmethod
    def discover() -> tuple[list[InventoryItem], list[str]]:
        if shutil.which("docker") is None:
            return [], ["Docker is not installed."]
        command = [
            "docker",
            "ps",
            "--format",
            "{{json .}}",
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [], [f"Docker inventory unavailable: {exc}"]
        if result.returncode != 0:
            return [], ["Docker is installed but not available to the current user."]
        items: list[InventoryItem] = []
        for line in result.stdout.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            identity = row.get("ID") or row.get("Names") or line
            items.append(
                InventoryItem(
                    id=stable_id("container", identity),
                    name=row.get("Names") or identity,
                    type="container",
                    status=Status.ACTIVE,
                    discovery_source="docker_cli",
                    confidence=Confidence.HIGH,
                    capabilities=["container_metadata"],
                    metadata={
                        "image": row.get("Image"),
                        "ports": row.get("Ports"),
                        "state": row.get("State"),
                    },
                )
            )
        return items, []


class InventoryService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.policy = ScopePolicy(settings)

    def refresh(self, include_docker: bool = True) -> InventorySnapshot:
        items: list[InventoryItem] = []
        errors: list[str] = []
        for component in (
            OllamaInventory(self.settings, self.policy),
            AgentInventory(self.settings, self.policy),
        ):
            discovered, component_errors = component.discover()
            items.extend(discovered)
            errors.extend(component_errors)
        listeners, listener_errors = ListenerInventory.discover()
        items.extend(listeners)
        errors.extend(listener_errors)
        if include_docker:
            containers, docker_errors = DockerInventory.discover()
            items.extend(containers)
            errors.extend(docker_errors)
        snapshot = InventorySnapshot(items=items, errors=errors, cached=False)
        self._write_cache(snapshot)
        return snapshot

    def cached(self) -> InventorySnapshot | None:
        path = self.settings.inventory_cache
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["cached"] = True
        return InventorySnapshot.model_validate(payload)

    def _write_cache(self, snapshot: InventorySnapshot) -> None:
        path = self.settings.inventory_cache
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(snapshot.model_dump_json(indent=2) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass

