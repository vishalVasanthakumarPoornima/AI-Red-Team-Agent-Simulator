"""Deterministic inventory-aware target resolution and scope classification."""

from __future__ import annotations

import hashlib
from urllib.parse import urljoin, urlparse

from redteam_platform.dexter.discovery import DexterDiscoveryService
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import (
    AgentDescriptor,
    InventoryItem,
    InventorySnapshot,
    ItemType,
    OllamaEndpoint,
    OllamaModel,
    ServiceEndpoint,
)
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings
from redteam_platform.targets.models import (
    ResolutionState,
    TargetAuthentication,
    TargetCapability,
    TargetDescriptor,
    TargetInput,
    TargetKind,
    TargetRelationship,
    TargetResolution,
)
from redteam_platform.targets.parser import TargetParser


def _stable_id(kind: TargetKind, identity: str) -> str:
    return f"target_{str(kind)}_{hashlib.sha256(identity.encode()).hexdigest()[:16]}"


class TargetResolver:
    def __init__(
        self,
        settings: Settings,
        *,
        inventory_service: InventoryService | None = None,
        policy: ScopePolicy | None = None,
        parser: TargetParser | None = None,
    ):
        self.settings = settings
        self.inventory_service = inventory_service or InventoryService(settings)
        self.policy = policy or ScopePolicy(settings)
        self.parser = parser or TargetParser()

    def resolve(
        self,
        value: str | TargetInput,
        *,
        kind_hint: TargetKind | str | None = None,
        model_name: str | None = None,
        ports: list[int] | None = None,
        refresh: bool = False,
        snapshot: InventorySnapshot | None = None,
    ) -> TargetResolution:
        authoritative_hint = kind_hint is not None
        target_input = (
            value
            if isinstance(value, TargetInput)
            else self.parser.parse(
                value,
                kind_hint=kind_hint,
                model_name=model_name,
                ports=ports,
            )
        )
        snapshot = snapshot or self.inventory_service.collect(
            include_docker=self.settings.include_docker,
            include_kali=False,
            refresh=refresh,
            force_refresh=refresh,
        )
        candidates: list[TargetDescriptor] = []

        dexter_result = DexterDiscoveryService(
            self.settings,
            inventory_service=self.inventory_service,
            policy=self.policy,
        ).discover(snapshot=snapshot)
        for deployment in dexter_result.deployments:
            target = deployment.target
            if target_input.original in {
                target.stable_id,
                target.deployment_name,
                target.main_endpoint,
            } or (
                target_input.kind_hint == TargetKind.DEXTER
                and target_input.original.startswith("dexter_")
                and target_input.original == target.stable_id
            ):
                candidates.append(self._from_dexter(target))

        for item in snapshot.items:
            if self._matches(target_input, item):
                candidates.append(self._from_inventory(target_input, item))

        for definition in (
            self.settings.generic_targets
            + self.settings.http_agent_definitions
            + self.settings.openai_compatible_endpoints
        ):
            if target_input.original in {
                str(definition.get("id") or ""),
                str(definition.get("name") or ""),
                str(definition.get("endpoint") or ""),
            }:
                candidates.append(self._from_definition(target_input, definition))

        candidates = self._dedupe(candidates)
        if (
            authoritative_hint
            and target_input.kind_hint
            and target_input.kind_hint != TargetKind.UNKNOWN
        ):
            compatible = {
                TargetKind.WEBSITE: {TargetKind.WEBSITE, TargetKind.WEB_APPLICATION},
                TargetKind.WEB_APPLICATION: {TargetKind.WEBSITE, TargetKind.WEB_APPLICATION},
                TargetKind.HOST: {TargetKind.HOST, TargetKind.IP_ADDRESS},
                TargetKind.IP_ADDRESS: {TargetKind.HOST, TargetKind.IP_ADDRESS},
                TargetKind.OLLAMA_ENDPOINT: {
                    TargetKind.OLLAMA_ENDPOINT,
                    TargetKind.OLLAMA_AGENT,
                },
            }.get(target_input.kind_hint, {target_input.kind_hint})
            matching = [
                candidate for candidate in candidates
                if candidate.target_kind in compatible
            ]
            if matching:
                candidates = matching
            elif candidates:
                # An explicit adapter hint is authoritative. Do not silently
                # switch to a specialized or unrelated adapter that happens to
                # share the same endpoint.
                candidates = []
        elif candidates:
            priority = min(self._resolution_priority(candidate) for candidate in candidates)
            candidates = [
                candidate for candidate in candidates
                if self._resolution_priority(candidate) == priority
            ]
        if len(candidates) > 1:
            return TargetResolution(
                input=target_input,
                state=ResolutionState.AMBIGUOUS,
                candidates=candidates,
                explanation="Multiple inventory or configured targets match; use a stable ID.",
            )
        descriptor = candidates[0] if candidates else self._manual(target_input)
        if descriptor is None:
            return TargetResolution(
                input=target_input,
                state=ResolutionState.NOT_FOUND,
                explanation="Target could not be resolved without guessing its kind.",
            )
        decision_target = self._scope_target(descriptor)
        decision = self.policy.decide(decision_target, active=False)
        descriptor.scope_decision = decision
        descriptor.scope_classification = decision.classification
        if not decision.allowed:
            descriptor.errors.append(decision.reason)
            return TargetResolution(
                input=target_input,
                state=ResolutionState.DENIED,
                target=descriptor,
                explanation=decision.reason,
            )
        return TargetResolution(
            input=target_input,
            state=ResolutionState.RESOLVED,
            target=descriptor,
            explanation=descriptor.confidence_reason,
        )

    @staticmethod
    def _matches(target_input: TargetInput, item: InventoryItem) -> bool:
        if target_input.original in {item.stable_id, item.name, item.endpoint}:
            return True
        normalized = target_input.normalized_target or target_input.invocation_route or ""
        if item.endpoint and normalized.rstrip("/") == item.endpoint.rstrip("/"):
            return True
        return False

    def _from_inventory(
        self,
        target_input: TargetInput,
        item: InventoryItem,
    ) -> TargetDescriptor:
        kind = TargetKind.LOCAL_SERVICE
        invocation = None
        health = None
        metadata = None
        openapi = None
        model_name = target_input.model_name
        if isinstance(item, AgentDescriptor):
            if item.item_type == ItemType.PYTHON_TARGET or item.local_path:
                kind = TargetKind.PYTHON_AGENT
            elif item.endpoint:
                kind = TargetKind.HTTP_AGENT
                invocation = urljoin(item.endpoint.rstrip("/") + "/", "invoke")
                health = urljoin(item.endpoint.rstrip("/") + "/", "health")
                metadata = urljoin(item.endpoint.rstrip("/") + "/", "metadata")
            model_name = model_name or item.model_name
        elif isinstance(item, OllamaEndpoint):
            kind = TargetKind.OLLAMA_ENDPOINT
        elif isinstance(item, OllamaModel):
            kind = TargetKind.OLLAMA_ENDPOINT
            model_name = model_name or item.model_name
        elif isinstance(item, ServiceEndpoint):
            if item.service_kind == "openai_compatible":
                kind = TargetKind.OPENAI_COMPATIBLE
                invocation = urljoin(item.endpoint.rstrip("/") + "/", "v1/chat/completions")
            elif item.service_kind in {
                "project_multi_agent_lab",
                "project_agent_service",
            }:
                kind = TargetKind.HTTP_AGENT
                invocation = urljoin(item.endpoint.rstrip("/") + "/", "invoke")
            else:
                kind = TargetKind.LOCAL_SERVICE
            health = urljoin(item.endpoint.rstrip("/") + "/", "health") if item.endpoint else None
            metadata = urljoin(item.endpoint.rstrip("/") + "/", "metadata") if item.endpoint else None
            openapi = urljoin(item.endpoint.rstrip("/") + "/", "openapi.json") if item.endpoint else None
        normalized = (
            f"python://{item.name}"
            if kind == TargetKind.PYTHON_AGENT
            else item.endpoint
            or f"host://{item.host}" + (f":{item.port}" if item.port else "")
        )
        parsed = urlparse(normalized)
        capabilities = self._capabilities(kind, item.capabilities)
        return TargetDescriptor(
            stable_id=item.stable_id,
            display_name=item.name,
            target_kind=kind,
            original_input=target_input.original,
            normalized_target=normalized,
            host=parsed.hostname,
            port=parsed.port or item.port,
            scheme=parsed.scheme,
            base_url=item.endpoint if item.endpoint and item.endpoint.startswith("http") else None,
            local_module_path=item.local_path,
            agent_endpoint=item.endpoint if kind == TargetKind.HTTP_AGENT else None,
            invocation_endpoint=invocation,
            health_endpoint=health,
            metadata_endpoint=metadata,
            openapi_endpoint=openapi,
            model_endpoint=item.endpoint if "ollama" in kind.value else None,
            model_name=model_name,
            discovery_source=str(item.discovery_source),
            discovery_confidence=str(item.discovery_confidence),
            confidence_reason=item.confidence_reason or "Resolved from Phase 2 inventory.",
            capabilities=capabilities,
            related_inventory_ids=sorted({item.stable_id, *item.related_ids}),
            relationships=[
                TargetRelationship(
                    relationship_id="relationship_" + hashlib.sha256(
                        f"{item.stable_id}|related_inventory|{related_id}".encode()
                    ).hexdigest()[:16],
                    relationship_type="related_inventory",
                    source_id=item.stable_id,
                    target_id=related_id,
                    confidence="inventory",
                    reasons=["Preserved from Phase 2 typed inventory correlation."],
                )
                for related_id in sorted(set(item.related_ids))
            ],
            safe_metadata={
                "inventory_type": str(item.item_type),
                "health": str(item.health),
                "process_name": item.process_name,
            },
        )

    def _from_definition(self, target_input, definition) -> TargetDescriptor:
        endpoint = self.parser.normalize(
            str(definition["endpoint"]),
            TargetKind(definition.get("kind", "http_agent")),
        )
        kind = TargetKind(definition.get("kind", "http_agent"))
        parsed = urlparse(endpoint)
        invocation_route = str(definition.get("invocation_route") or "/invoke")
        return TargetDescriptor(
            stable_id=str(definition.get("id") or _stable_id(kind, endpoint)),
            display_name=str(definition.get("name") or parsed.hostname or kind.value),
            target_kind=kind,
            original_input=target_input.original,
            normalized_target=endpoint,
            host=parsed.hostname,
            port=parsed.port,
            scheme=parsed.scheme,
            base_url=endpoint,
            agent_endpoint=endpoint,
            invocation_endpoint=urljoin(endpoint.rstrip("/") + "/", invocation_route.lstrip("/")),
            health_endpoint=urljoin(endpoint.rstrip("/") + "/", str(definition.get("health_route") or "/health").lstrip("/")),
            metadata_endpoint=urljoin(endpoint.rstrip("/") + "/", str(definition.get("metadata_route") or "/metadata").lstrip("/")),
            openapi_endpoint=urljoin(endpoint.rstrip("/") + "/", str(definition.get("openapi_route") or "/openapi.json").lstrip("/")),
            model_name=target_input.model_name or definition.get("model"),
            authentication=TargetAuthentication(
                mode=str(definition.get("authentication_mode") or "none"),
                reference_name=definition.get("authentication_reference"),
                required=str(definition.get("authentication_mode") or "none") != "none",
            ),
            discovery_source="explicit_configuration",
            discovery_confidence="confirmed",
            confidence_reason="Exact configured target definition.",
            capabilities=self._capabilities(kind, definition.get("capabilities") or []),
            safe_metadata={
                "request_field": definition.get("request_field", "prompt"),
                "response_field": definition.get("response_field", "response"),
                "invocation_route": invocation_route,
            },
        )

    def _from_dexter(self, target) -> TargetDescriptor:
        parsed = urlparse(target.main_endpoint)
        return TargetDescriptor(
            stable_id=target.stable_id,
            display_name=target.deployment_name,
            target_kind=TargetKind.DEXTER,
            original_input=target.stable_id,
            normalized_target=target.main_endpoint,
            host=parsed.hostname,
            port=parsed.port,
            scheme=parsed.scheme,
            base_url=target.main_endpoint,
            agent_endpoint=target.main_endpoint,
            invocation_endpoint=target.chat_endpoint,
            health_endpoint=target.health_endpoint,
            metadata_endpoint=target.metadata_endpoint,
            openapi_endpoint=target.openapi_endpoint,
            model_endpoint=target.ollama_endpoint,
            model_name=target.model_name,
            authentication=TargetAuthentication(
                mode=target.authentication_mode,
                reference_name=target.authentication_reference,
                required=target.authentication_mode != "none",
            ),
            discovery_source="dexter_specialized",
            discovery_confidence=target.discovery_confidence,
            confidence_reason="Resolved through the specialized Phase 4 Dexter service.",
            capabilities=[
                TargetCapability(
                    name=capability.name,
                    available=capability.available,
                    source=capability.source,
                    passive=capability.name in {"api", "openapi"},
                    active=capability.name not in {"openapi"},
                    details=capability.details,
                )
                for capability in target.capabilities
            ],
            related_inventory_ids=sorted(
                set(target.listener_ids + target.container_ids)
            ),
            safe_metadata={
                "dexter_deployment_type": target.deployment_type,
                "request_field": "message",
                "response_field": "response",
            },
        )

    def _manual(self, target_input: TargetInput) -> TargetDescriptor | None:
        kind = TargetKind(target_input.kind_hint or TargetKind.UNKNOWN)
        normalized = (
            target_input.normalized_target
            or target_input.invocation_route
            or target_input.original
        )
        if kind == TargetKind.UNKNOWN:
            return None
        if kind == TargetKind.PYTHON_AGENT:
            name = normalized.removeprefix("python://")
            try:
                from redteam_platform.adapters import PythonAgentAdapter

                legacy = PythonAgentAdapter(self.settings).identify(name)
            except Exception:
                return None
            return TargetDescriptor(
                stable_id=legacy.id,
                display_name=legacy.name,
                target_kind=kind,
                original_input=target_input.original,
                normalized_target=legacy.endpoint,
                local_module_path=legacy.local_path,
                discovery_source=legacy.discovery_source,
                discovery_confidence=str(legacy.confidence),
                confidence_reason="Explicit REDTEAM_TARGET enrollment.",
                capabilities=self._capabilities(kind, legacy.capabilities),
                safe_metadata=legacy.metadata,
            )
        parsed = urlparse(normalized)
        if kind == TargetKind.WEBSITE:
            kind = TargetKind.WEB_APPLICATION
        base_url = normalized if parsed.scheme in {"http", "https"} else None
        invocation = None
        health = None
        metadata = None
        openapi = None
        if base_url:
            health = urljoin(base_url.rstrip("/") + "/", "health")
            metadata = urljoin(base_url.rstrip("/") + "/", "metadata")
            openapi = urljoin(base_url.rstrip("/") + "/", "openapi.json")
            if kind == TargetKind.HTTP_AGENT:
                invocation = urljoin(base_url.rstrip("/") + "/", "invoke")
            elif kind == TargetKind.OPENAI_COMPATIBLE:
                invocation = urljoin(base_url.rstrip("/") + "/", "v1/chat/completions")
        return TargetDescriptor(
            stable_id=_stable_id(kind, normalized),
            display_name=parsed.hostname or normalized,
            target_kind=kind,
            original_input=target_input.original,
            normalized_target=normalized,
            host=parsed.hostname,
            port=parsed.port,
            scheme=parsed.scheme,
            base_url=base_url,
            agent_endpoint=base_url if kind == TargetKind.HTTP_AGENT else None,
            invocation_endpoint=invocation,
            health_endpoint=health,
            metadata_endpoint=metadata,
            openapi_endpoint=openapi,
            model_endpoint=normalized if kind == TargetKind.OLLAMA_ENDPOINT else None,
            model_name=target_input.model_name,
            discovery_source="operator_input",
            discovery_confidence="high",
            confidence_reason="Explicit operator input; capabilities remain conservative.",
            capabilities=self._capabilities(kind, []),
            safe_metadata={"ports": target_input.ports},
        )

    @staticmethod
    def _capabilities(kind: TargetKind, observed: list[str]) -> list[TargetCapability]:
        names: dict[TargetKind, list[tuple[str, bool, bool]]] = {
            TargetKind.PYTHON_AGENT: [("invoke", False, True), ("ai_prompts", False, True)],
            TargetKind.HTTP_AGENT: [("metadata", True, False), ("invoke", False, True), ("ai_prompts", False, True)],
            TargetKind.OPENAI_COMPATIBLE: [("models", True, False), ("invoke", False, True)],
            TargetKind.OLLAMA_ENDPOINT: [("models", True, False), ("invoke", False, True)],
            TargetKind.OLLAMA_AGENT: [("models", True, False), ("invoke", False, True), ("ai_prompts", False, True)],
            TargetKind.WEBSITE: [("http", True, True), ("tls", True, False)],
            TargetKind.WEB_APPLICATION: [("http", True, True), ("tls", True, False)],
            TargetKind.HOST: [("socket", False, True), ("service_correlation", True, False)],
            TargetKind.IP_ADDRESS: [("socket", False, True), ("service_correlation", True, False)],
            TargetKind.LOCAL_SERVICE: [("inventory", True, False)],
        }
        result = [
            TargetCapability(
                name=name,
                available=True,
                source="target_kind",
                passive=passive,
                active=active,
            )
            for name, passive, active in names.get(kind, [])
        ]
        for name in observed:
            if not any(item.name == name for item in result):
                result.append(
                    TargetCapability(
                        name=name,
                        available=True,
                        source="inventory",
                        passive=True,
                    )
                )
        return result

    @staticmethod
    def _scope_target(target: TargetDescriptor) -> str:
        if target.target_kind == TargetKind.PYTHON_AGENT:
            return target.normalized_target
        if target.scheme in {"http", "https", "host"}:
            return target.normalized_target
        if target.host:
            rendered = f"[{target.host}]" if ":" in target.host else target.host
            return f"host://{rendered}" + (f":{target.port}" if target.port else "")
        return target.normalized_target

    @staticmethod
    def _dedupe(candidates: list[TargetDescriptor]) -> list[TargetDescriptor]:
        unique: dict[tuple[str, str], TargetDescriptor] = {}
        for candidate in candidates:
            unique[(candidate.stable_id, candidate.target_kind)] = candidate
        return sorted(
            unique.values(),
            key=lambda item: (item.target_kind, item.display_name, item.stable_id),
        )

    @staticmethod
    def _resolution_priority(target: TargetDescriptor) -> int:
        if target.discovery_source == "explicit_configuration":
            return 1
        return {
            TargetKind.DEXTER: 2,
            TargetKind.PYTHON_AGENT: 3,
            TargetKind.HTTP_AGENT: 4,
            TargetKind.OPENAI_COMPATIBLE: 5,
            TargetKind.OLLAMA_AGENT: 6,
            TargetKind.OLLAMA_ENDPOINT: 6,
            TargetKind.WEBSITE: 7,
            TargetKind.WEB_APPLICATION: 7,
            TargetKind.HOST: 8,
            TargetKind.IP_ADDRESS: 8,
            TargetKind.LOCAL_SERVICE: 9,
            TargetKind.UNKNOWN: 10,
        }[TargetKind(target.target_kind)]
