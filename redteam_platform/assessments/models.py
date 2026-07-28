"""Versioned models for deterministic multi-target assessments."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field

from redteam_platform.schemas import AssessmentBudget, AssessmentProfile, VersionedModel, utc_now
from redteam_platform.targets.models import TargetKind


class StepMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


class StepState(StrEnum):
    PLANNED = "planned"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    PROTECTED = "protected"
    CANCELLED = "cancelled"


class ResultState(StrEnum):
    PASS = "PASS"
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INFORMATIONAL = "INFORMATIONAL"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    COVERAGE_ERROR = "COVERAGE_ERROR"
    PROTECTED = "PROTECTED"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"
    CANCELLED = "CANCELLED"


class AssessmentPhase(VersionedModel):
    phase_id: str
    name: str
    order: int = Field(ge=1)
    description: str


class ProbeDefinition(VersionedModel):
    probe_id: str
    version: str = "1.0"
    category: str
    name: str
    target_kinds: list[TargetKind]
    mode: StepMode
    request_count: int = Field(ge=0, le=10)
    timeout_seconds: int = Field(ge=1, le=60)
    required_tool: str
    expected_evidence: str
    evaluation_rule: str
    safety_constraints: list[str]
    operation: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    synthetic_canary: str | None = None


class AssessmentStep(VersionedModel):
    step_id: str
    phase_id: str
    name: str
    category: str
    mode: StepMode
    expected_operations: list[str]
    maximum_requests: int = Field(ge=0)
    timeout_seconds: int = Field(ge=1)
    required_capability: str | None = None
    required_tool: str | None = None
    scope_target: str
    authorization_required: bool
    skip_conditions: list[str] = Field(default_factory=list)
    evidence_type: str
    cleanup_required: bool = False
    probe: ProbeDefinition | None = None


class AssessmentPlan(VersionedModel):
    plan_id: str
    target_id: str
    target_kind: TargetKind
    profile: AssessmentProfile
    scope_targets: list[str]
    authorization_required: bool
    phases: list[AssessmentPhase]
    steps: list[AssessmentStep]
    budget: AssessmentBudget
    port_allowlist: list[int] = Field(default_factory=list)
    deterministic: bool = True
    hidden_steps_allowed: bool = False
    created_at: datetime = Field(default_factory=utc_now)


class ToolRequest(VersionedModel):
    request_id: str
    tool: str
    operation: str
    target_id: str
    scope_target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(ge=1, le=60)
    maximum_output_bytes: int = Field(default=262_144, ge=1024, le=5_000_000)


class ToolResult(VersionedModel):
    request_id: str
    tool: str
    status: ResultState
    started_at: datetime
    ended_at: datetime = Field(default_factory=utc_now)
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    evidence_content: str = ""


class EvidenceRecord(VersionedModel):
    evidence_id: str
    probe_id: str
    target_id: str
    kind: str
    summary: str
    content: str
    sha256: str
    collected_at: datetime = Field(default_factory=utc_now)


class ProbeResult(VersionedModel):
    probe_id: str
    step_id: str
    target_id: str
    status: ResultState
    evaluation_rule: str
    evaluator_version: str
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    error: str | None = None
    duration_seconds: float = Field(ge=0)


class Finding(VersionedModel):
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    status: ResultState
    target_stable_id: str
    affected_component: str
    probe_id: str
    evidence_references: list[str] = Field(default_factory=list)
    reproduction_summary: str
    technical_impact: str
    business_impact: str
    root_cause: str
    remediation: str
    evaluator_version: str
    standards_mappings: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    retest_guidance: str


class CoverageCategory(VersionedModel):
    category: str
    planned_steps: int = 0
    completed_steps: int = 0
    skipped_steps: int = 0
    failed_steps: int = 0
    unavailable_steps: int = 0
    protected_steps: int = 0
    evidence_count: int = 0
    coverage_percentage: float = Field(ge=0, le=100)
    limitations: list[str] = Field(default_factory=list)


class CoverageSummary(VersionedModel):
    target_id: str
    categories: list[CoverageCategory]
    overall_percentage: float = Field(ge=0, le=100)
    complete: bool


class AssessmentSummary(VersionedModel):
    run_id: str
    target_id: str
    target_kind: TargetKind
    profile: AssessmentProfile
    status: str
    started_at: datetime
    ended_at: datetime
    completed_steps: int
    skipped_steps: int
    failed_steps: int
    unavailable_steps: int
    protected_steps: int
    finding_count: int
    error_count: int
    coverage_percentage: float
    coverage_complete: bool
    stop_reason: str
    artifact_paths: dict[str, str] = Field(default_factory=dict)
