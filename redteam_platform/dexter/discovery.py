"""Deterministic Dexter discovery and Phase 2 inventory correlation."""

from __future__ import annotations

from urllib.parse import urlparse

from redteam_platform.dexter.capabilities import capabilities_for, configured_components
from redteam_platform.dexter.configuration import configured_deployments, endpoint_map
from redteam_platform.dexter.models import (
    DexterComponent,
    DexterComponentStatus,
    DexterComponentType,
    DexterDeployment,
    DexterDeploymentType,
    DexterDiscoveryResult,
    DexterTarget,
)
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import (
    AgentDescriptor,
    DockerContainer,
    InventoryItem,
    InventorySnapshot,
    Listener,
    OllamaModel,
    ServiceEndpoint,
)
from redteam_platform.inventory.platform import stable_id
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


def _contains_dexter(item: InventoryItem) -> bool:
    fields = [
        item.name,
        item.local_path or "",
        str(item.metadata.get("project") or ""),
        str(item.metadata.get("kind") or ""),
        str(item.metadata.get("application") or ""),
    ]
    if isinstance(item, DockerContainer):
        fields.extend([item.image or "", *item.labels.keys(), *item.labels.values()])
    return any("dexter" in value.lower() for value in fields)


def _same_endpoint(item: InventoryItem, endpoint: str) -> bool:
    configured = urlparse(endpoint)
    if item.endpoint:
        observed = urlparse(item.endpoint)
        return (
            observed.hostname == configured.hostname
            and (observed.port or (443 if observed.scheme == "https" else 80))
            == (configured.port or (443 if configured.scheme == "https" else 80))
        )
    return item.host == configured.hostname and item.port == configured.port


def _matches_configuration(item: InventoryItem, configuration) -> bool:
    if _same_endpoint(item, configuration.main_endpoint):
        return True
    main = urlparse(configuration.main_endpoint)
    main_port = main.port or (443 if main.scheme == "https" else 80)
    if (
        item.port
        and item.port in configuration.expected_ports
        and (item.port == main_port or _contains_dexter(item))
    ):
        return True
    if isinstance(item, OllamaModel) and configuration.expected_model:
        return item.model_name == configuration.expected_model
    if isinstance(item, DockerContainer):
        identities = {
            item.name.lower(),
            item.container_id.lower(),
            str(item.image or "").lower(),
        }
        if any(
            configured.lower() in identity
            for configured in configuration.docker_names
            for identity in identities
        ):
            return True
        labels = {f"{key}={value}".lower() for key, value in item.labels.items()}
        if labels.intersection(value.lower() for value in configuration.docker_labels):
            return True
        return any(
            mapping.get("host_port") in configuration.expected_ports
            for mapping in item.port_mappings
        )
    return (
        configuration.name.lower() in item.name.lower()
        and _contains_dexter(item)
    )


def _candidate_endpoint(item: InventoryItem, snapshot: InventorySnapshot) -> str | None:
    if item.endpoint:
        return item.endpoint
    for related_id in item.related_ids:
        related = next(
            (candidate for candidate in snapshot.items if candidate.stable_id == related_id),
            None,
        )
        if related and related.endpoint:
            return related.endpoint
    if isinstance(item, DockerContainer):
        mapping = next(
            (
                row
                for row in item.port_mappings
                if row.get("host_port") and row.get("protocol") == "tcp"
            ),
            None,
        )
        if mapping:
            host = mapping.get("host") or "127.0.0.1"
            if host in {"0.0.0.0", "::", "[::]"}:
                host = "127.0.0.1"
            return f"http://{host}:{mapping['host_port']}"
    return None


class DexterDiscoveryService:
    def __init__(
        self,
        settings: Settings,
        *,
        inventory_service: InventoryService | None = None,
        policy: ScopePolicy | None = None,
    ):
        self.settings = settings
        self.inventory_service = inventory_service or InventoryService(settings)
        self.policy = policy or ScopePolicy(settings)

    def discover(
        self,
        *,
        refresh: bool = False,
        snapshot: InventorySnapshot | None = None,
    ) -> DexterDiscoveryResult:
        if snapshot is None:
            snapshot = self.inventory_service.collect(
                include_docker=self.settings.include_docker,
                include_kali=False,
                refresh=refresh,
                force_refresh=refresh,
            )
        deployments: list[DexterDeployment] = []
        errors: list[str] = []
        configured = configured_deployments(self.settings)
        for configuration in configured:
            try:
                decision = self.policy.decide(configuration.main_endpoint, active=False)
            except ScopeDeniedError as exc:
                errors.append(f"{configuration.name}: {exc}")
                continue
            if not decision.allowed:
                errors.append(f"{configuration.name}: {decision.reason}")
                continue
            related = [
                item
                for item in snapshot.items
                if _matches_configuration(item, configuration)
            ]
            related_ids = {item.stable_id for item in related}
            for item in snapshot.items:
                if item.stable_id in related_ids:
                    related_ids.update(item.related_ids)
                if any(related_id in related_ids for related_id in item.related_ids):
                    related_ids.add(item.stable_id)
            related = [item for item in snapshot.items if item.stable_id in related_ids]
            deployments.append(
                self._deployment(
                    configuration,
                    decision.classification,
                    related,
                    confidence="confirmed",
                    evidence=[f"explicit configuration: {configuration.source}"],
                )
            )

        configured_endpoints = {item.target.main_endpoint for item in deployments}
        automatic = [
            item
            for item in snapshot.items
            if _contains_dexter(item)
            and not any(_same_endpoint(item, endpoint) for endpoint in configured_endpoints)
        ]
        automatic_groups: dict[str, list[InventoryItem]] = {}
        for item in automatic:
            endpoint = _candidate_endpoint(item, snapshot)
            if not endpoint:
                continue
            automatic_groups.setdefault(endpoint, []).append(item)
        ambiguous: list[DexterDeployment] = []
        for endpoint, candidate_items in automatic_groups.items():
            item = candidate_items[0]
            try:
                decision = self.policy.decide(endpoint, active=False)
            except ScopeDeniedError as exc:
                errors.append(f"{item.name}: {exc}")
                continue
            if not decision.allowed:
                errors.append(f"{item.name}: {decision.reason}")
                continue
            from redteam_platform.dexter.models import DexterConfiguration

            configuration = DexterConfiguration(
                name=item.name,
                main_endpoint=endpoint,
                health_route="/health",
                chat_route="/chat",
                metadata_route="/metadata",
                openapi_route="/openapi.json",
                expected_ports=[item.port] if item.port else [],
                source=f"inventory:{item.discovery_source}",
            )
            deployment_type = (
                DexterDeploymentType.PYTHON_TARGET
                if isinstance(item, AgentDescriptor) and item.local_path
                else DexterDeploymentType.DOCKER
                if isinstance(item, DockerContainer)
                else DexterDeploymentType.COMPATIBLE_HTTP
            )
            deployment = self._deployment(
                configuration,
                decision.classification,
                candidate_items,
                confidence="high",
                evidence=[f"project-specific Dexter evidence from {item.discovery_source}"],
                deployment_type=deployment_type,
            )
            deployments.append(deployment)

        deployments.sort(key=lambda row: (row.target.deployment_name.lower(), row.target.stable_id))
        return DexterDiscoveryResult(
            deployments=deployments,
            ambiguous_candidates=ambiguous,
            errors=errors + [error.message for error in snapshot.errors],
            inventory_generated_at=snapshot.generated_at,
        )

    def get(
        self,
        dexter_id: str,
        *,
        refresh: bool = False,
        snapshot: InventorySnapshot | None = None,
    ) -> DexterDeployment:
        result = self.discover(refresh=refresh, snapshot=snapshot)
        matches = [
            item
            for item in result.deployments
            if dexter_id in {item.target.stable_id, item.target.deployment_name}
        ]
        if not matches:
            raise LookupError(f"Dexter deployment not found: {dexter_id}")
        if len(matches) > 1:
            raise LookupError(f"Ambiguous Dexter deployment name; use a stable ID: {dexter_id}")
        return matches[0]

    def _deployment(
        self,
        configuration,
        classification,
        related: list[InventoryItem],
        *,
        confidence: str,
        evidence: list[str],
        deployment_type: DexterDeploymentType = DexterDeploymentType.CONFIGURED_HTTP,
    ) -> DexterDeployment:
        endpoints = endpoint_map(configuration)
        components = configured_components(configuration)
        process_ids = sorted({item.process_id for item in related if item.process_id})
        listener_ids = sorted(
            item.stable_id for item in related if isinstance(item, Listener)
        )
        container_ids = sorted(
            item.container_id for item in related if isinstance(item, DockerContainer)
        )
        inventory_components: list[DexterComponent] = []
        database_services: list[str] = []
        cache_services: list[str] = []
        for item in related:
            if isinstance(item, Listener):
                component_type = DexterComponentType.LISTENER
            elif isinstance(item, DockerContainer):
                component_type = DexterComponentType.CONTAINER
            elif isinstance(item, OllamaModel):
                component_type = DexterComponentType.MODEL
            elif isinstance(item, ServiceEndpoint):
                component_type = DexterComponentType.API
            else:
                process_name = str(item.process_name or item.name).lower()
                if any(marker in process_name for marker in ("postgres", "mysql", "sqlite")):
                    component_type = DexterComponentType.DATABASE
                    if item.endpoint:
                        database_services.append(item.endpoint)
                elif any(marker in process_name for marker in ("redis", "memcached")):
                    component_type = DexterComponentType.CACHE
                    if item.endpoint:
                        cache_services.append(item.endpoint)
                else:
                    component_type = DexterComponentType.PROCESS
            inventory_components.append(
                DexterComponent(
                    stable_id=f"dexter_{item.stable_id}",
                    name=item.name,
                    component_type=component_type,
                    status=(
                        DexterComponentStatus.READY
                        if str(item.status) in {"active", "ready", "running", "available"}
                        else DexterComponentStatus.UNKNOWN
                    ),
                    endpoint=item.endpoint,
                    related_inventory_ids=[item.stable_id],
                    evidence=[
                        f"{item.discovery_source}: {item.confidence_reason or item.discovery_confidence}"
                    ],
                )
            )
        components.extend(inventory_components)
        target_id = stable_id(
            "dexter",
            f"{configuration.name}|{configuration.main_endpoint}",
        )
        if deployment_type == DexterDeploymentType.CONFIGURED_HTTP:
            if any(isinstance(item, DockerContainer) for item in related):
                deployment_type = DexterDeploymentType.DOCKER
            elif any(
                isinstance(item, AgentDescriptor) and item.local_path
                for item in related
            ):
                deployment_type = DexterDeploymentType.PYTHON_TARGET
            elif len(process_ids) > 1:
                deployment_type = DexterDeploymentType.MULTI_PROCESS
            elif any(
                isinstance(item, ServiceEndpoint)
                and (
                    item.service_kind == "fastapi_application"
                    or str(item.metadata.get("framework") or "").lower()
                    == "fastapi"
                )
                for item in related
            ):
                deployment_type = DexterDeploymentType.FASTAPI
            elif str(classification) == "lab":
                deployment_type = DexterDeploymentType.PRIVATE_LAB
        target = DexterTarget(
            stable_id=target_id,
            deployment_name=configuration.name,
            deployment_type=deployment_type,
            main_endpoint=configuration.main_endpoint,
            health_endpoint=endpoints["health"],
            chat_endpoint=endpoints["chat"],
            metadata_endpoint=endpoints["metadata"],
            openapi_endpoint=endpoints["openapi"],
            authentication_mode=configuration.authentication_mode,
            authentication_reference=configuration.authentication_reference,
            process_ids=process_ids,
            listener_ids=listener_ids,
            container_ids=container_ids,
            ollama_endpoint=configuration.ollama_endpoint,
            model_name=configuration.expected_model,
            tool_service_endpoints=configuration.tool_endpoints,
            memory_service=configuration.memory_endpoint,
            vector_store=configuration.vector_endpoint,
            retrieval_service=configuration.retrieval_endpoint,
            voice_services=configuration.voice_endpoints,
            database_services=sorted(set(database_services)),
            cache_services=sorted(set(cache_services)),
            scope_classification=classification,
            discovery_confidence=confidence,
            discovery_evidence=evidence,
            capabilities=capabilities_for(configuration, components),
            components=components,
            configuration=configuration,
        )
        return DexterDeployment(
            target=target,
            inventory_item_ids=sorted(
                {item.stable_id for item in related}
            ),
        )
