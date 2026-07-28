"""Versioned typed models for passive inventory and cache persistence."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, SerializeAsAny, field_validator

from redteam_platform.schemas import ScopeClassification, VersionedModel, utc_now


class ItemType(StrEnum):
    LISTENER = "listener"
    PROCESS = "process"
    SERVICE = "service"
    AGENT = "agent"
    PYTHON_TARGET = "python_target"
    OLLAMA_ENDPOINT = "ollama_endpoint"
    OLLAMA_MODEL = "ollama_model"
    DOCKER_CONTAINER = "docker_container"
    KALI_READINESS = "kali_readiness"
    TOOL = "tool"
    UNKNOWN = "unknown"


class InventoryStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PROTECTED = "protected"
    READY = "ready"
    DEGRADED = "degraded"
    INSTALLED = "installed"
    RUNNING = "running"
    STOPPED = "stopped"
    NOT_CONFIGURED = "not_configured"
    ERROR = "error"
    UNKNOWN = "unknown"


class DiscoverySource(StrEnum):
    CONFIGURATION = "configuration"
    OLLAMA_API = "ollama_api"
    PSUTIL = "psutil"
    LSOF = "lsof"
    SS = "ss"
    TARGET_MARKER = "target_marker"
    AGENT_REGISTRY = "agent_registry"
    HTTP_METADATA = "http_metadata"
    OPENAPI = "openapi"
    DOCKER_CLI = "docker_cli"
    KALI_SSH = "kali_ssh"
    CORRELATION = "correlation"
    CACHE = "cache"
    PLATFORM = "platform"


class DiscoveryConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    PROTECTED = "protected"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"
    UNKNOWN = "unknown"


class ToolState(StrEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"
    UNKNOWN = "unknown"


class AdapterState(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    SKIPPED = "skipped"


class RefreshMode(StrEnum):
    FRESH = "fresh"
    CACHE_PREFERRED = "cache_preferred"
    CACHED_ONLY = "cached_only"
    FORCE_REFRESH = "force_refresh"


class DiscoveryEvidence(VersionedModel):
    source: DiscoverySource
    fact: str
    value: str | int | float | bool | None = None
    confidence: DiscoveryConfidence = DiscoveryConfidence.UNKNOWN
    collected_at: datetime = Field(default_factory=utc_now)


class DiscoveryError(VersionedModel):
    source: str
    code: str
    message: str
    fatal: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=utc_now)


class ProcessInfo(VersionedModel):
    stable_id: str
    process_id: int | None = None
    process_name: str | None = None
    executable: str | None = None
    process_user: str | None = None
    command_summary: str | None = None
    access_denied: bool = False
    errors: list[DiscoveryError] = Field(default_factory=list)


class InventoryItem(VersionedModel):
    stable_id: str
    name: str
    item_type: ItemType
    status: InventoryStatus = InventoryStatus.UNKNOWN
    endpoint: str | None = None
    local_path: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = None
    process_id: int | None = None
    process_name: str | None = None
    executable: str | None = None
    process_user: str | None = None
    discovery_source: DiscoverySource
    discovery_confidence: DiscoveryConfidence = DiscoveryConfidence.UNKNOWN
    confidence_reason: str = ""
    capabilities: list[str] = Field(default_factory=list)
    health: HealthState = HealthState.NOT_CHECKED
    health_details: dict[str, Any] = Field(default_factory=dict)
    scope_classification: ScopeClassification = ScopeClassification.UNKNOWN
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[DiscoveryEvidence] = Field(default_factory=list)
    errors: list[DiscoveryError] = Field(default_factory=list)
    stale: bool = False
    related_ids: list[str] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return self.stable_id

    @property
    def type(self) -> str:
        return self.item_type.value if isinstance(self.item_type, ItemType) else str(self.item_type)

    @property
    def confidence(self) -> str:
        value = self.discovery_confidence
        return value.value if isinstance(value, DiscoveryConfidence) else str(value)


class Listener(InventoryItem):
    item_type: ItemType = ItemType.LISTENER
    address: str
    transport: str
    listen_state: str | None = None
    loopback_only: bool = False
    wildcard_bound: bool = False
    reachability: str = "unknown"
    address_family: str = "unknown"
    network_namespace: str | None = None
    process: ProcessInfo | None = None
    possible_container_id: str | None = None


class ServiceEndpoint(InventoryItem):
    item_type: ItemType = ItemType.SERVICE
    base_url: str
    service_kind: str = "unknown_http"
    protected: bool = False
    observed_routes: list[str] = Field(default_factory=list)
    response_statuses: dict[str, int] = Field(default_factory=dict)


class AgentDescriptor(InventoryItem):
    item_type: ItemType = ItemType.AGENT
    agent_kind: str = "unknown"
    module_path: str | None = None
    enrolled: bool = False
    import_status: str = "not_applicable"
    callable_contract: str | None = None
    deterministic: bool | None = None
    model_name: str | None = None
    registered: bool = False
    service_endpoint_id: str | None = None


class OllamaEndpoint(InventoryItem):
    item_type: ItemType = ItemType.OLLAMA_ENDPOINT
    base_url: str
    version: str | None = None
    latency_seconds: float | None = None
    installed_model_count: int = 0
    running_model_count: int = 0


class OllamaModel(InventoryItem):
    item_type: ItemType = ItemType.OLLAMA_MODEL
    endpoint_id: str
    model_name: str
    installed: bool = False
    running: bool = False
    size_bytes: int | None = None
    parameter_size: str | None = None
    quantization: str | None = None
    context_length: int | None = None
    digest: str | None = None
    modified_at: datetime | None = None
    loaded_size_bytes: int | None = None
    vram_bytes: int | None = None
    expires_at: datetime | None = None


class DockerContainer(InventoryItem):
    item_type: ItemType = ItemType.DOCKER_CONTAINER
    container_id: str
    image: str | None = None
    container_status: str | None = None
    port_mappings: list[dict[str, Any]] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    container_health: str | None = None


class ToolAvailability(VersionedModel):
    name: str
    state: ToolState
    version: str | None = None
    evidence: str = ""


class KaliReadiness(InventoryItem):
    item_type: ItemType = ItemType.KALI_READINESS
    configured: bool = False
    ssh_alias: str | None = None
    ssh_state: ToolState = ToolState.NOT_CHECKED
    reachable: bool | None = None
    os_identity: str | None = None
    reverse_tunnel_capability: bool | None = None
    tools: list[ToolAvailability] = Field(default_factory=list)
    live_check_performed: bool = False


class CorrelationRecord(VersionedModel):
    correlation_id: str
    logical_name: str
    item_ids: list[str]
    confidence: DiscoveryConfidence
    reasons: list[str]


class AdapterRun(VersionedModel):
    adapter: str
    state: AdapterState
    duration_seconds: float = Field(ge=0)
    item_count: int = Field(ge=0)
    errors: list[DiscoveryError] = Field(default_factory=list)


class InventorySummary(VersionedModel):
    installed_ollama_models: int = 0
    running_ollama_models: int = 0
    enrolled_python_targets: int = 0
    active_compatible_agents: int = 0
    generic_listening_services: int = 0
    wildcard_bound_services: int = 0
    docker_status: str = "not_requested"
    kali_status: str = "not_requested"
    error_count: int = 0
    stale: bool = False


class InventoryCacheMetadata(VersionedModel):
    generated_at: datetime
    expires_at: datetime
    source_host_id: str
    refresh_mode: RefreshMode
    cache_path: str
    stale: bool = False


ITEM_MODEL_MAP: dict[ItemType, type[InventoryItem]] = {
    ItemType.LISTENER: Listener,
    ItemType.SERVICE: ServiceEndpoint,
    ItemType.AGENT: AgentDescriptor,
    ItemType.PYTHON_TARGET: AgentDescriptor,
    ItemType.OLLAMA_ENDPOINT: OllamaEndpoint,
    ItemType.OLLAMA_MODEL: OllamaModel,
    ItemType.DOCKER_CONTAINER: DockerContainer,
    ItemType.KALI_READINESS: KaliReadiness,
}


class InventorySnapshot(VersionedModel):
    generated_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    source_host_id: str = ""
    refresh_mode: RefreshMode = RefreshMode.FRESH
    items: list[SerializeAsAny[InventoryItem]] = Field(default_factory=list)
    correlations: list[CorrelationRecord] = Field(default_factory=list)
    adapter_runs: list[AdapterRun] = Field(default_factory=list)
    errors: list[DiscoveryError] = Field(default_factory=list)
    summary: InventorySummary = Field(default_factory=InventorySummary)
    cached: bool = False
    stale: bool = False
    cache_metadata: InventoryCacheMetadata | None = None

    @field_validator("items", mode="before")
    @classmethod
    def restore_item_types(cls, values: Any) -> Any:
        if not isinstance(values, list):
            return values
        restored: list[InventoryItem] = []
        for value in values:
            if isinstance(value, InventoryItem):
                restored.append(value)
                continue
            if not isinstance(value, dict):
                restored.append(value)
                continue
            try:
                item_type = ItemType(value.get("item_type", "unknown"))
            except ValueError:
                item_type = ItemType.UNKNOWN
            model = ITEM_MODEL_MAP.get(item_type, InventoryItem)
            restored.append(model.model_validate(value))
        return restored
