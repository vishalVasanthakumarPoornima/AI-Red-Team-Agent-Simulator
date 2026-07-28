"""Versioned typed models for Dexter discovery and deterministic assessment."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field

from redteam_platform.schemas import (
    AssessmentBudget,
    ScopeClassification,
    VersionedModel,
    new_id,
    utc_now,
)


class DexterDeploymentType(StrEnum):
    CONFIGURED_HTTP = "configured_http"
    PYTHON_TARGET = "python_target"
    FASTAPI = "fastapi"
    COMPATIBLE_HTTP = "compatible_http"
    DOCKER = "docker"
    MULTI_PROCESS = "multi_process"
    PRIVATE_LAB = "private_lab"


class DexterComponentType(StrEnum):
    API = "api"
    PROCESS = "process"
    LISTENER = "listener"
    CONTAINER = "container"
    OLLAMA = "ollama"
    MODEL = "model"
    TOOL = "tool"
    MEMORY = "memory"
    VECTOR = "vector"
    RETRIEVAL = "retrieval"
    VOICE = "voice"
    DATABASE = "database"
    CACHE = "cache"
    KALI = "kali"
    REPORTS = "reports"


class DexterComponentStatus(StrEnum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    PROTECTED = "protected"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN = "unknown"


class DexterProfile(StrEnum):
    PASSIVE = "passive"
    STANDARD = "standard"
    DEEP_LAB = "deep-lab"


class DexterStepMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


class DexterStepStatus(StrEnum):
    PLANNED = "planned"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"


class DexterProbeStatus(StrEnum):
    PASS = "PASS"
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INFORMATIONAL = "INFORMATIONAL"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    COVERAGE_ERROR = "COVERAGE_ERROR"


class DexterFindingStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INFORMATIONAL = "INFORMATIONAL"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    COVERAGE_ERROR = "COVERAGE_ERROR"


class DexterConfiguration(VersionedModel):
    name: str = "Dexter"
    main_endpoint: str
    health_route: str = "/status"
    chat_route: str = "/chat"
    metadata_route: str = "/metadata"
    openapi_route: str = "/openapi.json"
    authentication_mode: str = "none"
    authentication_reference: str | None = None
    ollama_endpoint: str | None = None
    expected_model: str | None = None
    tool_endpoints: list[str] = Field(default_factory=list)
    memory_endpoint: str | None = None
    vector_endpoint: str | None = None
    retrieval_endpoint: str | None = None
    voice_endpoints: list[str] = Field(default_factory=list)
    docker_names: list[str] = Field(default_factory=list)
    docker_labels: list[str] = Field(default_factory=list)
    expected_ports: list[int] = Field(default_factory=list)
    requires_kali_tunnel: bool = False
    kali_remote_port: int = Field(default=18000, ge=1024, le=65535)
    allowed_profiles: list[DexterProfile] = Field(
        default_factory=lambda: list(DexterProfile)
    )
    disposable_memory_namespace: bool = False
    source: str = "configuration"


class DexterEndpoint(VersionedModel):
    name: str
    url: str
    purpose: str
    scope_classification: ScopeClassification = ScopeClassification.UNKNOWN
    protected: bool = False


class DexterCapability(VersionedModel):
    name: str
    available: bool
    source: str
    details: dict[str, Any] = Field(default_factory=dict)


class DexterComponent(VersionedModel):
    stable_id: str
    name: str
    component_type: DexterComponentType
    status: DexterComponentStatus = DexterComponentStatus.UNKNOWN
    endpoint: str | None = None
    related_inventory_ids: list[str] = Field(default_factory=list)
    required: bool = False
    evidence: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DexterTarget(VersionedModel):
    stable_id: str
    deployment_name: str
    deployment_type: DexterDeploymentType
    main_endpoint: str
    health_endpoint: str
    chat_endpoint: str
    metadata_endpoint: str
    openapi_endpoint: str
    authentication_mode: str = "none"
    authentication_reference: str | None = None
    process_ids: list[int] = Field(default_factory=list)
    listener_ids: list[str] = Field(default_factory=list)
    container_ids: list[str] = Field(default_factory=list)
    ollama_endpoint: str | None = None
    model_name: str | None = None
    tool_service_endpoints: list[str] = Field(default_factory=list)
    memory_service: str | None = None
    vector_store: str | None = None
    retrieval_service: str | None = None
    voice_services: list[str] = Field(default_factory=list)
    database_services: list[str] = Field(default_factory=list)
    cache_services: list[str] = Field(default_factory=list)
    scope_classification: ScopeClassification
    discovery_confidence: str
    discovery_evidence: list[str] = Field(default_factory=list)
    health: DexterComponentStatus = DexterComponentStatus.UNKNOWN
    capabilities: list[DexterCapability] = Field(default_factory=list)
    components: list[DexterComponent] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    configuration: DexterConfiguration


class DexterDeployment(VersionedModel):
    target: DexterTarget
    inventory_item_ids: list[str] = Field(default_factory=list)


class DexterDiscoveryResult(VersionedModel):
    generated_at: datetime = Field(default_factory=utc_now)
    deployments: list[DexterDeployment] = Field(default_factory=list)
    ambiguous_candidates: list[DexterDeployment] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    inventory_generated_at: datetime | None = None


class DexterHealth(VersionedModel):
    target_id: str
    overall: DexterComponentStatus
    components: list[DexterComponent] = Field(default_factory=list)
    available_coverage: list[str] = Field(default_factory=list)
    unavailable_coverage: list[str] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=utc_now)


class DexterAssessmentProfile(VersionedModel):
    profile: DexterProfile
    description: str
    active: bool
    allow_kali: bool
    request_budget: int
    timeout_seconds: int
    requires_final_confirmation: bool = True


class DexterAssessmentStep(VersionedModel):
    step_id: str
    phase: str
    name: str
    category: str
    mode: DexterStepMode
    required_capability: str | None = None
    expected_operations: list[str] = Field(default_factory=list)
    maximum_requests: int = Field(ge=0)
    timeout_seconds: int = Field(ge=1)
    required_authorization: bool
    required_tool: str | None = None
    scope_target: str
    skip_conditions: list[str] = Field(default_factory=list)
    evidence_type: str


class DexterAssessmentPlan(VersionedModel):
    plan_id: str = Field(default_factory=lambda: new_id("dexter_plan"))
    target_id: str
    profile: DexterProfile
    scope_targets: list[str]
    steps: list[DexterAssessmentStep]
    budget: AssessmentBudget
    deterministic: bool = True
    hidden_steps_allowed: bool = False
    created_at: datetime = Field(default_factory=utc_now)


class DexterProbe(VersionedModel):
    probe_id: str
    version: str = "1.0"
    category: str
    name: str
    method: str
    route: str
    payload: dict[str, Any] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    expected_boundary: str
    synthetic_canary: str | None = None
    maximum_response_bytes: int = 262_144
    timeout_seconds: int = 10


class DexterEvidenceRecord(VersionedModel):
    evidence_id: str = Field(default_factory=lambda: new_id("dexter_evidence"))
    probe_id: str
    component_id: str
    kind: str
    summary: str
    content: str = ""
    sha256: str | None = None
    collected_at: datetime = Field(default_factory=utc_now)


class DexterProbeResult(VersionedModel):
    probe_id: str
    step_id: str
    target_id: str
    component_id: str
    status: DexterProbeStatus
    http_status: int | None = None
    evaluation_rule: str
    evaluator_version: str = "1.0"
    evidence: list[DexterEvidenceRecord] = Field(default_factory=list)
    error: str | None = None
    duration_seconds: float = Field(ge=0)


class DexterFinding(VersionedModel):
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    status: DexterFindingStatus
    affected_component: str
    target_stable_id: str
    probe_id: str
    evidence_references: list[str] = Field(default_factory=list)
    reproduction_summary: str
    technical_impact: str
    business_impact: str
    root_cause: str
    remediation: str
    evaluator_version: str
    standards: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    retest_guidance: str


class DexterCoverageCategory(VersionedModel):
    category: str
    planned_steps: int = 0
    completed_steps: int = 0
    skipped_steps: int = 0
    failed_steps: int = 0
    unavailable_steps: int = 0
    coverage_percentage: float = Field(ge=0, le=100)
    limitations: list[str] = Field(default_factory=list)
    evidence_count: int = 0


class DexterCoverage(VersionedModel):
    target_id: str
    categories: list[DexterCoverageCategory]
    overall_percentage: float = Field(ge=0, le=100)
    complete: bool


class DexterKaliPlan(VersionedModel):
    target_id: str
    enabled: bool
    ssh_alias: str | None = None
    tools: list[str] = Field(default_factory=list)
    exact_host: str
    exact_ports: list[int] = Field(default_factory=list)
    requires_tunnel: bool = False
    skip_reason: str | None = None


class DexterAssessmentSummary(VersionedModel):
    run_id: str
    target_id: str
    profile: DexterProfile
    status: str
    started_at: datetime
    ended_at: datetime
    completed_steps: int
    skipped_steps: int
    failed_steps: int
    unavailable_steps: int
    finding_count: int
    error_count: int
    coverage_percentage: float = Field(ge=0, le=100)
    coverage_complete: bool
    stop_reason: str
    artifact_paths: dict[str, str] = Field(default_factory=dict)
