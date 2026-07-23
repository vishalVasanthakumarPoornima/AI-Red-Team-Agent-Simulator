"""Versioned domain schemas shared by CLI, API, assessment, and reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def new_run_id() -> str:
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    return f"run_{stamp}_{uuid4().hex[:16]}"


class VersionedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)
    schema_version: str = SCHEMA_VERSION


class TargetType(StrEnum):
    PYTHON_AGENT = "python_agent"
    HTTP_AGENT = "http_agent"
    OPENAI_AGENT = "openai_agent"
    OLLAMA_AGENT = "ollama_agent"
    HOST = "host"
    WEB = "web"
    DEXTER = "dexter"


class Status(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScopeClassification(StrEnum):
    LOOPBACK = "loopback"
    LAB = "lab"
    PRIVATE_DENIED = "private_denied"
    PUBLIC = "public"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class AssessmentProfile(StrEnum):
    PASSIVE = "passive"
    STANDARD = "standard"
    DEEP_LAB = "deep-lab"


class ResultStatus(StrEnum):
    PASS = "PASS"
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INFORMATIONAL = "INFORMATIONAL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNPARSED = "UNPARSED"
    DENIED = "DENIED"
    CANCELLED = "CANCELLED"


class InventoryItem(VersionedModel):
    id: str
    name: str
    type: str
    endpoint: str | None = None
    local_path: str | None = None
    status: Status = Status.UNKNOWN
    discovery_source: str
    confidence: Confidence
    capabilities: list[str] = Field(default_factory=list)
    last_seen: datetime = Field(default_factory=utc_now)
    scope_classification: ScopeClassification = ScopeClassification.UNKNOWN
    metadata: dict[str, Any] = Field(default_factory=dict)
    health: dict[str, Any] = Field(default_factory=dict)


class Target(InventoryItem):
    target_type: TargetType
    adapter: str
    supported_profiles: list[AssessmentProfile] = Field(default_factory=list)


class Agent(InventoryItem):
    model_id: str | None = None
    invoke_endpoint: str | None = None


class Service(InventoryItem):
    address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str = "tcp"
    process_id: int | None = None
    process_name: str | None = None
    executable: str | None = None
    user: str | None = None
    loopback_only: bool = False
    containerized: bool | None = None


class LocalModel(InventoryItem):
    provider: str = "ollama"
    parameter_size: str | None = None
    quantization: str | None = None
    context_length: int | None = None
    vram_bytes: int | None = None
    expires_at: datetime | None = None
    running: bool = False


class AuthorizationDecision(VersionedModel):
    allowed: bool
    normalized_target: str
    classification: ScopeClassification
    resolved_addresses: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    policy_id: str = "default-loopback-policy"
    reason: str = ""
    policy_rule: str = "default-deny"
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def populate_compatibility_fields(self) -> "AuthorizationDecision":
        if not self.reason:
            self.reason = "; ".join(self.reasons) or (
                "Target allowed by policy." if self.allowed else "Target denied by policy."
            )
        if not self.evidence:
            self.evidence = {"resolved_addresses": list(self.resolved_addresses)}
        return self


class AuthorizationRequest(VersionedModel):
    target: str
    requested_profile: AssessmentProfile = AssessmentProfile.STANDARD
    human_authorization_statement: str = Field(min_length=12, max_length=2000)
    source: Literal["human-cli", "human-api", "human-config"]
    public_mode: bool = False
    confirmed_interactively: bool = False


class AuthorizationRecord(VersionedModel):
    id: str = Field(default_factory=lambda: new_id("auth"))
    run_id: str = Field(default_factory=new_run_id)
    target: str = ""
    normalized_target: str = ""
    requested_profile: AssessmentProfile | None = None
    scope_classification: ScopeClassification | None = None
    human_authorization_statement: str = ""
    policy_decision: AuthorizationDecision | None = None
    timestamp: datetime | None = None
    decision: AuthorizationDecision
    statement: str
    source: Literal["human-cli", "human-api", "human-config"]
    profile: AssessmentProfile
    public_mode: bool = False
    confirmed_interactively: bool = False
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def populate_persisted_fields(self) -> "AuthorizationRecord":
        self.target = self.target or self.decision.normalized_target
        self.normalized_target = self.normalized_target or self.decision.normalized_target
        self.requested_profile = self.requested_profile or self.profile
        self.scope_classification = self.scope_classification or self.decision.classification
        self.human_authorization_statement = self.human_authorization_statement or self.statement
        self.policy_decision = self.policy_decision or self.decision
        self.timestamp = self.timestamp or self.created_at
        return self


class AssessmentBudget(VersionedModel):
    max_rounds: int = Field(default=8, ge=1, le=50)
    max_probes: int = Field(default=100, ge=1, le=1000)
    max_model_calls: int = Field(default=24, ge=0, le=500)
    max_duration_seconds: int = Field(default=1200, ge=1, le=86400)
    no_new_evidence_rounds: int = Field(default=2, ge=1, le=20)
    duplicate_threshold: int = Field(default=3, ge=1, le=20)


class AssessmentRequest(VersionedModel):
    target: Target
    profile: AssessmentProfile = AssessmentProfile.STANDARD
    authorization: AuthorizationRecord
    categories: list[str] = Field(default_factory=list)
    budget: AssessmentBudget = Field(default_factory=AssessmentBudget)
    planner_model: str | None = None
    requested_by: str = "local-user"
    requested_at: datetime = Field(default_factory=utc_now)


class AssessmentPlan(VersionedModel):
    id: str = Field(default_factory=lambda: new_id("plan"))
    request: AssessmentRequest
    phases: list[str]
    registered_actions: list[str]
    tool_requirements: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class Probe(VersionedModel):
    id: str = Field(default_factory=lambda: new_id("probe"))
    category: str
    template_id: str
    target_id: str
    prompt: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    round_number: int = Field(default=1, ge=1)
    source: Literal["deterministic", "model", "operator"] = "deterministic"


class ToolInvocation(VersionedModel):
    id: str = Field(default_factory=lambda: new_id("tool"))
    action: str
    adapter: str
    target_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utc_now)


class ToolResult(VersionedModel):
    invocation_id: str
    status: ResultStatus
    exit_code: int | None = None
    started_at: datetime
    ended_at: datetime = Field(default_factory=utc_now)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class InvocationOutcome(VersionedModel):
    probe_id: str
    target_id: str
    status: ResultStatus
    response_excerpt: str = ""
    evaluation: dict[str, Any] = Field(default_factory=dict)
    transport: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    started_at: datetime
    ended_at: datetime = Field(default_factory=utc_now)


class Evidence(VersionedModel):
    id: str = Field(default_factory=lambda: new_id("evidence"))
    kind: str
    summary: str
    content: str = ""
    source: str
    collected_at: datetime = Field(default_factory=utc_now)
    sha256: str | None = None


class Finding(VersionedModel):
    id: str
    title: str
    category: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    confidence: float = Field(ge=0, le=1)
    status: ResultStatus
    affected_target: str
    evidence: list[Evidence] = Field(default_factory=list)
    reproduction: list[str] = Field(default_factory=list)
    impact: str
    root_cause: str
    remediation: str
    standards: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utc_now)
    source: str


class AssessmentEvent(VersionedModel):
    sequence: int = Field(ge=1)
    timestamp: datetime = Field(default_factory=utc_now)
    phase: str
    action: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class CoverageState(VersionedModel):
    categories_attempted: list[str] = Field(default_factory=list)
    categories_completed: list[str] = Field(default_factory=list)
    unique_probe_fingerprints: list[str] = Field(default_factory=list)
    findings_by_category: dict[str, int] = Field(default_factory=dict)


class RunSummary(VersionedModel):
    run_id: str
    status: ResultStatus
    target_id: str
    profile: AssessmentProfile
    started_at: datetime
    ended_at: datetime
    rounds: int = 0
    probes: int = 0
    model_calls: int = 0
    finding_counts: dict[str, int] = Field(default_factory=dict)
    coverage: CoverageState = Field(default_factory=CoverageState)
    errors: list[str] = Field(default_factory=list)
    stop_reason: str


class ArtifactRecord(VersionedModel):
    path: str
    sha256: str
    bytes: int = Field(ge=0)
    media_type: str


class RunManifest(VersionedModel):
    run_id: str
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    status: str = "created"
    stop_reason: str = "not started"
    tools: list[str] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)
    scope: str = ""
    authorization_id: str | None = None
    errors: list[str] = Field(default_factory=list)
    artifacts: list[ArtifactRecord] = Field(default_factory=list)


# Compatibility aliases retained while dictionary-based and earlier typed callers migrate.
ArtifactEntry = ArtifactRecord
ArtifactManifest = RunManifest


def schema_from_legacy(model_type: type[VersionedModel], payload: dict[str, Any]) -> VersionedModel:
    """Validate an existing dictionary using a shared schema and default version."""
    return model_type.model_validate({"schema_version": SCHEMA_VERSION, **payload})


def schema_to_legacy(model: VersionedModel, *, include_version: bool = False) -> dict[str, Any]:
    """Return a JSON-compatible dictionary for incremental legacy integration."""
    payload = model.model_dump(mode="json")
    if not include_version:
        payload.pop("schema_version", None)
    return payload


class ReportMetadata(VersionedModel):
    run_id: str
    title: str
    generated_at: datetime = Field(default_factory=utc_now)
    target_name: str
    scope: str
    authorization_id: str
    tool_versions: dict[str, str] = Field(default_factory=dict)
    models_used: list[str] = Field(default_factory=list)
    formats: list[str] = Field(default_factory=lambda: ["markdown", "html", "json"])
    limitations: list[str] = Field(default_factory=list)


class InventorySnapshot(VersionedModel):
    generated_at: datetime = Field(default_factory=utc_now)
    items: list[InventoryItem] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    cached: bool = False


class ModelBenchmarkResult(VersionedModel):
    model: str
    available: bool
    structured_output_validity: float = 0
    category_coverage: float = 0
    probe_diversity: float = 0
    duplicate_rate: float = 0
    policy_compliance: float = 0
    unsupported_tool_requests: int = 0
    finding_yield: int = 0
    false_positives: int = 0
    latency_seconds: float | None = None
    memory_bytes: int | None = None
    context_length: int | None = None
    notes: list[str] = Field(default_factory=list)
