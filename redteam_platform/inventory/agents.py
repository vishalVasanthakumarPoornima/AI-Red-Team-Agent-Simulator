"""Enrolled Python targets, registry records, and compatible HTTP service discovery."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from agent_registry import load_registry
from redteam_platform.artifacts import sanitize, sanitize_url
from redteam_platform.inventory.http_probe import SafeHTTPProbe
from redteam_platform.inventory.models import (
    AgentDescriptor,
    DiscoveryConfidence,
    DiscoveryError,
    DiscoveryEvidence,
    DiscoverySource,
    HealthState,
    InventoryItem,
    InventoryStatus,
    Listener,
    ServiceEndpoint,
)
from redteam_platform.inventory.platform import (
    normalize_identity_url,
    python_target_id,
    stable_id,
)
from redteam_platform.schemas import ScopeClassification
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings
from scanner.target_loader import discover_targets


def _base_from_route(url: str) -> str:
    parsed = urlsplit(url)
    return normalize_identity_url(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))


class PythonTargetDiscovery:
    def __init__(self, repository_root: str | Path | None = None):
        self.repository_root = (
            Path(repository_root)
            if repository_root
            else Path(__file__).resolve().parents[2]
        )

    def collect(self) -> tuple[list[AgentDescriptor], list[DiscoveryError]]:
        items: list[AgentDescriptor] = []
        errors: list[DiscoveryError] = []
        try:
            targets = discover_targets()
        except (OSError, ValueError) as exc:
            return [], [
                DiscoveryError(
                    source="python_targets",
                    code="target_discovery_failed",
                    message=f"Enrolled target discovery failed: {type(exc).__name__}.",
                )
            ]
        for row in targets:
            path = Path(row["absolute_path"])
            import_status = "loaded"
            contract = None
            metadata: dict[str, Any] = {}
            model_name = None
            deterministic: bool | None = None
            target_errors: list[DiscoveryError] = []
            try:
                spec = importlib.util.spec_from_file_location(
                    f"_inventory_target_{stable_id('module', row['path'])}",
                    path,
                )
                if spec is None or spec.loader is None:
                    raise ImportError("No import loader available.")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if callable(getattr(module, "run_agent", None)):
                    contract = "run_agent(prompt)"
                safe_metadata = getattr(module, "AGENT_METADATA", None)
                if isinstance(safe_metadata, dict):
                    metadata["declared_metadata"] = sanitize(safe_metadata)
                for attribute in ("OLLAMA_MODEL", "MODEL_NAME", "MODEL"):
                    value = getattr(module, attribute, None)
                    if isinstance(value, str) and value:
                        model_name = str(sanitize(value))
                        break
                source_text = path.read_text(encoding="utf-8")
                model_backed = any(
                    marker in source_text
                    for marker in (
                        "generate_with_ollama",
                        "OLLAMA_MODEL",
                        "/api/generate",
                        "ChatOllama",
                    )
                )
                deterministic = not model_backed
            except Exception as exc:  # trusted enrolled module boundary
                import_status = "error"
                target_error = DiscoveryError(
                    source="python_targets",
                    code="target_import_failed",
                    message=f"Enrolled target {row['name']} failed to import: {type(exc).__name__}.",
                    details={"module_path": row["path"]},
                )
                target_errors.append(target_error)
                errors.append(target_error)
            items.append(
                AgentDescriptor(
                    stable_id=python_target_id(row["path"], row["name"]),
                    name=row["name"],
                    item_type="python_target",
                    status=(
                        InventoryStatus.READY
                        if import_status == "loaded" and contract
                        else InventoryStatus.DEGRADED
                    ),
                    endpoint=f"python://{row['name']}",
                    local_path=row["path"],
                    discovery_source=DiscoverySource.TARGET_MARKER,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Module contains the literal REDTEAM_TARGET = True enrollment marker.",
                    capabilities=[contract] if contract else [],
                    health=(
                        HealthState.HEALTHY
                        if import_status == "loaded" and contract
                        else HealthState.DEGRADED
                    ),
                    scope_classification=ScopeClassification.LOOPBACK,
                    metadata=metadata,
                    evidence=[
                        DiscoveryEvidence(
                            source=DiscoverySource.TARGET_MARKER,
                            fact="literal_enrollment_marker",
                            value=True,
                            confidence=DiscoveryConfidence.CONFIRMED,
                        )
                    ],
                    errors=target_errors,
                    agent_kind="python_target",
                    module_path=row["path"],
                    enrolled=True,
                    import_status=import_status,
                    callable_contract=contract,
                    deterministic=deterministic,
                    model_name=model_name,
                )
            )
        return items, errors


class RegistryDiscovery:
    def __init__(
        self,
        settings: Settings,
        policy: ScopePolicy | None = None,
        registry_path: str | Path = "agent_registry.json",
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.registry_path = registry_path

    def collect(self) -> tuple[list[AgentDescriptor], list[DiscoveryError]]:
        try:
            rows = load_registry(self.registry_path)["agents"]
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return [], [
                DiscoveryError(
                    source="agent_registry",
                    code="registry_invalid",
                    message=f"Agent registry could not be loaded: {type(exc).__name__}.",
                )
            ]
        items: list[AgentDescriptor] = []
        errors: list[DiscoveryError] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            endpoint = row.get("health_url") or row.get("invoke_url")
            if not endpoint:
                errors.append(
                    DiscoveryError(
                        source="agent_registry",
                        code="registry_endpoint_missing",
                        message=f"Registry entry {row.get('name', 'unknown')} has no endpoint.",
                    )
                )
                continue
            base = _base_from_route(str(endpoint))
            try:
                decision = self.policy.decide(base, active=False)
            except ScopeDeniedError as exc:
                decision = None
                reason = str(exc)
            else:
                reason = decision.reason
            denied = decision is None or not decision.allowed
            entry_errors: list[DiscoveryError] = []
            if denied:
                error = DiscoveryError(
                    source="agent_registry",
                    code="scope_denied",
                    message=f"Registry endpoint denied: {reason}",
                )
                errors.append(error)
                entry_errors.append(error)
            items.append(
                AgentDescriptor(
                    stable_id=stable_id("registered_agent", base, row.get("name")),
                    name=str(row.get("name") or "registered-agent"),
                    status=(
                        InventoryStatus.UNAVAILABLE
                        if denied
                        else InventoryStatus.INACTIVE
                    ),
                    endpoint=sanitize_url(base),
                    host=decision.evidence.get("hostname") if decision else None,
                    port=decision.evidence.get("port") if decision else None,
                    protocol="http",
                    discovery_source=DiscoverySource.AGENT_REGISTRY,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Entry exists in agent_registry.json.",
                    capabilities=["health", "metadata", "invoke"],
                    health=HealthState.NOT_CHECKED,
                    scope_classification=(
                        decision.classification
                        if decision
                        else ScopeClassification.BLOCKED
                    ),
                    metadata={
                        "kind": str(sanitize(row.get("kind"))),
                        "description": str(sanitize(row.get("description"))),
                        "health_path": urlsplit(str(row.get("health_url") or "")).path,
                    },
                    evidence=[
                        DiscoveryEvidence(
                            source=DiscoverySource.AGENT_REGISTRY,
                            fact="registered",
                            value=True,
                            confidence=DiscoveryConfidence.CONFIRMED,
                        )
                    ],
                    errors=entry_errors,
                    agent_kind=str(row.get("kind") or "registered_http"),
                    registered=True,
                )
            )
        return items, errors


class HTTPAgentDiscovery:
    def __init__(
        self,
        settings: Settings,
        policy: ScopePolicy | None = None,
        probe: SafeHTTPProbe | None = None,
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.probe = probe or SafeHTTPProbe(
            self.policy,
            timeout=min(settings.request_timeout_seconds, 3),
            maximum_bytes=settings.metadata_response_size,
        )

    def collect(
        self,
        listeners: list[Listener],
        registry_items: list[AgentDescriptor],
    ) -> tuple[list[InventoryItem], list[DiscoveryError]]:
        candidates: dict[str, dict[str, Any]] = {}
        for endpoint in self.settings.configured_agent_endpoints:
            base = normalize_identity_url(endpoint)
            candidates[base] = {"configured": True, "registered_ids": []}
        for item in registry_items:
            if item.endpoint and item.scope_classification != ScopeClassification.BLOCKED:
                candidates.setdefault(item.endpoint, {"configured": False, "registered_ids": []})
                candidates[item.endpoint]["registered_ids"].append(item.stable_id)
        known_ports = set(self.settings.known_local_service_ports)
        for listener in listeners:
            if (
                listener.protocol == "tcp"
                and listener.port in known_ports
                and (listener.loopback_only or listener.wildcard_bound)
            ):
                base = f"http://127.0.0.1:{listener.port}"
                candidate = candidates.setdefault(
                    base, {"configured": False, "registered_ids": []}
                )
                candidate["listener_id"] = listener.stable_id

        items: list[InventoryItem] = []
        errors: list[DiscoveryError] = []
        for base in sorted(candidates):
            discovered, endpoint_errors = self._probe_endpoint(
                base, candidates[base]
            )
            items.extend(discovered)
            errors.extend(endpoint_errors)
        return items, errors

    def _probe_endpoint(
        self, base: str, context: dict[str, Any]
    ) -> tuple[list[InventoryItem], list[DiscoveryError]]:
        results = {
            route: self.probe.get_json(base, route)
            for route in self.settings.http_metadata_routes
        }
        any_response = any(result.status_code is not None for result in results.values())
        if not any_response:
            return [], [
                DiscoveryError(
                    source="http_metadata",
                    code="endpoint_unavailable",
                    message=f"Configured metadata endpoint {sanitize_url(base)} is unavailable.",
                )
            ]
        endpoint_errors = [
            DiscoveryError(
                source="http_metadata",
                code=result.error_code,
                message=f"{route}: {result.error}",
                details={"status_code": result.status_code},
            )
            for route, result in results.items()
            if result.error_code and result.error_code != "http_error"
        ]
        protected = any(result.protected for result in results.values())
        valid_payloads = {
            route: result.data
            for route, result in results.items()
            if isinstance(result.data, dict)
        }
        metadata = valid_payloads.get("/metadata", {})
        health = valid_payloads.get("/health", {})
        targets = valid_payloads.get("/targets", {})
        openapi = valid_payloads.get("/openapi.json", {})
        models = valid_payloads.get("/v1/models", {})

        target_names = []
        raw_targets = targets.get("targets") if isinstance(targets, dict) else None
        if isinstance(raw_targets, list):
            target_names = [
                str(row.get("name"))
                for row in raw_targets
                if isinstance(row, dict) and row.get("name")
            ]
        health_targets = health.get("targets") if isinstance(health, dict) else None
        if isinstance(health_targets, list):
            target_names.extend(str(value) for value in health_targets)
        target_names = sorted(set(target_names))

        metadata_name = metadata.get("name") if isinstance(metadata, dict) else None
        health_agent = health.get("agent") if isinstance(health, dict) else None
        metadata_kind = metadata.get("kind") if isinstance(metadata, dict) else None
        metadata_invoke = metadata.get("invoke") if isinstance(metadata, dict) else None
        project_metadata = (
            metadata_kind
            in {
                "ollama-langgraph-agent",
                "agent-service",
                "multi-agent-lab",
            }
            and isinstance(metadata_name, str)
            and isinstance(metadata_invoke, str)
            and metadata_invoke.startswith("/")
        )
        project_agent = bool(project_metadata or health_agent or target_names)
        openai_compatible = isinstance(models.get("data"), list)
        openapi_paths = (
            sorted(str(path) for path in openapi.get("paths", {}))
            if isinstance(openapi.get("paths"), dict)
            else []
        )
        fastapi = bool(openapi_paths)
        if target_names:
            service_kind = "project_multi_agent_lab"
        elif project_agent:
            service_kind = "project_agent_service"
        elif openai_compatible:
            service_kind = "openai_compatible"
        elif fastapi:
            service_kind = "fastapi_application"
        else:
            service_kind = "unknown_http"

        try:
            decision = self.policy.decide(base, active=False)
        except ScopeDeniedError as exc:
            return [], [
                DiscoveryError(
                    source="http_metadata",
                    code="scope_denied",
                    message=str(exc),
                )
            ]
        service_id = stable_id("http_service", base)
        evidence: list[DiscoveryEvidence] = []
        for fact, present in (
            ("project_metadata", project_agent),
            ("multi_agent_targets", bool(target_names)),
            ("openai_models", openai_compatible),
            ("openapi_document", fastapi),
            ("protected_route", protected),
        ):
            if present:
                evidence.append(
                    DiscoveryEvidence(
                        source=(
                            DiscoverySource.OPENAPI
                            if fact == "openapi_document"
                            else DiscoverySource.HTTP_METADATA
                        ),
                        fact=fact,
                        value=True,
                        confidence=DiscoveryConfidence.CONFIRMED,
                    )
                )
        service = ServiceEndpoint(
            stable_id=service_id,
            name=str(metadata_name or health_agent or f"http-service-{decision.evidence.get('port') or ''}").rstrip("-"),
            status=(
                InventoryStatus.PROTECTED
                if protected and not valid_payloads
                else InventoryStatus.ACTIVE
            ),
            endpoint=sanitize_url(base),
            base_url=sanitize_url(base),
            host=decision.evidence.get("hostname"),
            port=decision.evidence.get("port"),
            protocol="http",
            discovery_source=DiscoverySource.HTTP_METADATA,
            discovery_confidence=(
                DiscoveryConfidence.CONFIRMED
                if project_agent
                else DiscoveryConfidence.HIGH
                if openai_compatible
                else DiscoveryConfidence.MEDIUM
                if fastapi or protected
                else DiscoveryConfidence.LOW
            ),
            confidence_reason=(
                "Project-compatible metadata identified an agent service."
                if project_agent
                else "HTTP metadata confirmed a service, but not an AI agent."
            ),
            capabilities=(
                ["health", "metadata", "targets"]
                if project_agent
                else ["models"]
                if openai_compatible
                else ["http"]
            ),
            health=(
                HealthState.PROTECTED
                if protected and not valid_payloads
                else HealthState.HEALTHY
                if valid_payloads
                else HealthState.DEGRADED
            ),
            health_details={
                "statuses": {
                    route: result.status_code
                    for route, result in results.items()
                    if result.status_code is not None
                }
            },
            scope_classification=decision.classification,
            metadata={
                "target_names": target_names,
                "openapi_paths": openapi_paths[:100],
                "configured": bool(context.get("configured")),
            },
            evidence=evidence,
            errors=endpoint_errors,
            related_ids=[
                value
                for value in [
                    context.get("listener_id"),
                    *context.get("registered_ids", []),
                ]
                if value
            ],
            service_kind=service_kind,
            protected=protected,
            observed_routes=[
                route for route, result in results.items() if result.status_code is not None
            ],
            response_statuses={
                route: result.status_code
                for route, result in results.items()
                if result.status_code is not None
            },
        )
        discovered: list[InventoryItem] = [service]
        if project_agent:
            agent_id = stable_id(
                "http_agent",
                base,
                metadata_name or health_agent or ",".join(target_names),
            )
            discovered.append(
                AgentDescriptor(
                    stable_id=agent_id,
                    name=str(metadata_name or health_agent or "agent-lab"),
                    status=InventoryStatus.ACTIVE,
                    endpoint=sanitize_url(base),
                    host=decision.evidence.get("hostname"),
                    port=decision.evidence.get("port"),
                    protocol="http",
                    discovery_source=DiscoverySource.HTTP_METADATA,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Agent-specific health, metadata, or targets evidence was returned.",
                    capabilities=["health", "metadata", *target_names],
                    health=HealthState.HEALTHY,
                    scope_classification=decision.classification,
                    metadata={"target_names": target_names},
                    evidence=evidence,
                    errors=endpoint_errors,
                    related_ids=[service_id, *service.related_ids],
                    agent_kind=service_kind,
                    registered=bool(context.get("registered_ids")),
                    service_endpoint_id=service_id,
                )
            )
        return discovered, endpoint_errors
