"""Versioned models for Phase 5 unified targets."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field

from redteam_platform.schemas import (
    AssessmentProfile,
    AuthorizationDecision,
    ScopeClassification,
    VersionedModel,
    utc_now,
)


class TargetKind(StrEnum):
    PYTHON_AGENT = "python_agent"
    HTTP_AGENT = "http_agent"
    OPENAI_COMPATIBLE = "openai_compatible"
    OLLAMA_ENDPOINT = "ollama_endpoint"
    OLLAMA_AGENT = "ollama_agent"
    DEXTER = "dexter"
    HOST = "host"
    IP_ADDRESS = "ip_address"
    WEBSITE = "website"
    WEB_APPLICATION = "web_application"
    LOCAL_SERVICE = "local_service"
    UNKNOWN = "unknown"


class TargetState(StrEnum):
    READY = "ready"
    DEGRADED = "degraded"
    PROTECTED = "protected"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ResolutionState(StrEnum):
    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    DENIED = "denied"
    NOT_FOUND = "not_found"


class TargetInput(VersionedModel):
    original: str
    kind_hint: TargetKind | None = None
    normalized_target: str | None = None
    model_name: str | None = None
    invocation_route: str | None = None
    ports: list[int] = Field(default_factory=list)


class TargetEndpoint(VersionedModel):
    name: str
    url: str
    purpose: str
    passive: bool = True
    protected: bool = False


class TargetCapability(VersionedModel):
    name: str
    available: bool
    source: str
    passive: bool = False
    active: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class TargetAuthentication(VersionedModel):
    mode: str = "none"
    reference_name: str | None = None
    required: bool = False
    state: TargetState = TargetState.UNKNOWN


class TargetRelationship(VersionedModel):
    relationship_id: str
    relationship_type: str
    source_id: str
    target_id: str
    confidence: str
    reasons: list[str] = Field(default_factory=list)


class TargetDescriptor(VersionedModel):
    stable_id: str
    display_name: str
    target_kind: TargetKind
    original_input: str
    normalized_target: str
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    scheme: str | None = None
    base_url: str | None = None
    local_module_path: str | None = None
    agent_endpoint: str | None = None
    invocation_endpoint: str | None = None
    health_endpoint: str | None = None
    metadata_endpoint: str | None = None
    openapi_endpoint: str | None = None
    model_endpoint: str | None = None
    model_name: str | None = None
    authentication: TargetAuthentication = Field(default_factory=TargetAuthentication)
    scope_classification: ScopeClassification = ScopeClassification.UNKNOWN
    scope_decision: AuthorizationDecision | None = None
    discovery_source: str
    discovery_confidence: str
    confidence_reason: str
    capabilities: list[TargetCapability] = Field(default_factory=list)
    related_inventory_ids: list[str] = Field(default_factory=list)
    relationships: list[TargetRelationship] = Field(default_factory=list)
    health: TargetState = TargetState.UNKNOWN
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    errors: list[str] = Field(default_factory=list)
    safe_metadata: dict[str, Any] = Field(default_factory=dict)


class TargetDiscoveryResult(VersionedModel):
    targets: list[TargetDescriptor] = Field(default_factory=list)
    ambiguous_candidates: list[TargetDescriptor] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)


class TargetHealth(VersionedModel):
    target_id: str
    overall: TargetState
    observations: dict[str, Any] = Field(default_factory=dict)
    available_capabilities: list[str] = Field(default_factory=list)
    unavailable_capabilities: list[str] = Field(default_factory=list)
    protected_capabilities: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=utc_now)


class TargetResolution(VersionedModel):
    input: TargetInput
    state: ResolutionState
    target: TargetDescriptor | None = None
    candidates: list[TargetDescriptor] = Field(default_factory=list)
    explanation: str


class TargetSelection(VersionedModel):
    target_id: str
    selected_kind: TargetKind
    profile: AssessmentProfile
    ports: list[int] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    include_kali: bool = False
    public_mode: bool = False


class AdapterMetadata(VersionedModel):
    adapter_name: str
    supported_kinds: list[TargetKind]
    supported_profiles: list[AssessmentProfile]
    passive_capabilities: list[str] = Field(default_factory=list)
    active_capabilities: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    authentication_requirements: list[str] = Field(default_factory=list)
    maximum_requests: int = 0
    timeout_seconds: int = 0
    cleanup_required: bool = False
