"""Typed canonical models consumed by every Phase 7 renderer."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from redteam_platform.schemas import VersionedModel, utc_now


REPORT_SCHEMA_VERSION = "7.0"


class ReportModel(VersionedModel):
    schema_version: str = REPORT_SCHEMA_VERSION


class ReportMode(StrEnum):
    INTERNAL = "internal"
    SAFE_SHARE = "safe_share"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class FindingStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INFORMATIONAL = "informational"
    ACCEPTED_RISK = "accepted_risk"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    NOT_RETESTED = "not_retested"


class CoverageState(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    FINDING = "finding"
    NOT_TESTED = "not_tested"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


class Branding(ReportModel):
    organization_name: str = "Security Assessment"
    project_name: str = "AI Red Team Agent Simulator"
    report_title: str = "Enterprise AI Security Assessment"
    assessment_owner: str = "Authorized assessment team"
    classification_label: str = "Internal"
    logo_path: str | None = None
    footer_text: str = "Authorized, bounded security-assessment evidence"
    accent_theme: str = "navy"
    contact: str | None = None
    report_version: str = "1.0"


class AuthorizationSummary(ReportModel):
    authorization_id: str | None = None
    statement_present: bool = False
    allowed: bool | None = None
    scope: str = ""
    scope_classification: str = "unknown"
    source: str | None = None


class TargetSummary(ReportModel):
    target_id: str
    name: str
    target_type: str = "unknown"
    endpoint: str | None = None
    reachable: bool | None = None
    components: list[dict[str, Any]] = Field(default_factory=list)


class InventorySummary(ReportModel):
    item_count: int = 0
    ready: int = 0
    degraded: int = 0
    unavailable: int = 0
    items: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class KaliSummary(ReportModel):
    configured: bool = False
    reachable: bool | None = None
    used: bool = False
    checks_completed: int = 0
    checks_skipped: int = 0
    tools_available: list[str] = Field(default_factory=list)
    tools_unavailable: list[str] = Field(default_factory=list)
    tunnel_used: bool = False


class ProbeStatistics(ReportModel):
    planned: int = 0
    completed: int = 0
    passed: int = 0
    failed: int = 0
    findings: int = 0
    skipped: int = 0
    unsupported: int = 0
    errors: int = 0
    timeouts: int = 0


class AdaptiveStatistics(ReportModel):
    mode: str = "off"
    rounds_completed: int = 0
    model_calls: int = 0
    proposals_accepted: int = 0
    proposals_rejected: int = 0
    duplicate_proposals: int = 0
    novelty_scores: list[float] = Field(default_factory=list)


class StandardsMapping(ReportModel):
    standard: str
    version: str
    identifier: str
    title: str
    rationale: str
    source_category: str
    certification_claim: bool = False


class RiskInputs(ReportModel):
    technical_severity: Severity
    confidence: FindingConfidence
    exploitability: Literal["low", "medium", "high", "unknown"] = "unknown"
    exposure: Literal["local", "restricted", "network", "public", "unknown"] = "unknown"
    required_privileges: Literal["none", "low", "high", "unknown"] = "unknown"
    user_interaction: Literal["none", "required", "unknown"] = "unknown"
    business_impact: Literal["low", "medium", "high", "unknown"] = "unknown"
    data_sensitivity: Literal["low", "medium", "high", "unknown"] = "unknown"
    control_effectiveness: Literal["none", "partial", "effective", "unknown"] = "unknown"


class RiskRating(ReportModel):
    rating: Severity
    ordinal: int = Field(ge=0, le=4)
    rationale: str
    inputs: RiskInputs
    cvss_vector: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    official_cvss: bool = False

    @model_validator(mode="after")
    def reject_partial_cvss(self) -> "RiskRating":
        if (self.cvss_vector is None) != (self.cvss_score is None):
            raise ValueError("CVSS vector and score must be supplied together")
        return self


class EvidenceReference(ReportModel):
    evidence_id: str
    evidence_type: str = "text"
    source_probe: str | None = None
    source_tool: str | None = None
    relative_artifact_path: str | None = None
    content_hash: str | None = None
    timestamp: datetime | None = None
    sanitized: bool = True
    truncated: bool = False
    mime_type: str = "text/plain"
    size: int | None = Field(default=None, ge=0)
    description: str = ""
    excerpt: str | None = None


class RetestEntry(ReportModel):
    prior_run_id: str
    current_run_id: str
    outcome: Literal["resolved", "persistent", "changed", "not_retested"]
    observed_at: datetime = Field(default_factory=utc_now)
    notes: str = ""


class CanonicalFinding(ReportModel):
    finding_id: str
    fingerprint: str
    title: str
    category: str
    severity: Severity
    confidence: FindingConfidence
    status: FindingStatus
    affected_target: str
    affected_component: str = ""
    affected_endpoint: str | None = None
    description: str = ""
    technical_details: str = ""
    evidence_summary: str = ""
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    impact: str = ""
    likelihood: str = "unknown"
    preconditions: list[str] = Field(default_factory=list)
    reproduction_guidance: str = ""
    safe_validation_steps: list[str] = Field(default_factory=list)
    remediation: str = ""
    verification_guidance: str = ""
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    source_probe_ids: list[str] = Field(default_factory=list)
    source_tool_ids: list[str] = Field(default_factory=list)
    standards_mappings: list[StandardsMapping] = Field(default_factory=list)
    risk: RiskRating
    retest_history: list[RetestEntry] = Field(default_factory=list)
    suppressed: bool = False
    suppression_reason: str | None = None
    false_positive_rationale: str | None = None

    @model_validator(mode="after")
    def require_false_positive_reason(self) -> "CanonicalFinding":
        if self.status == FindingStatus.FALSE_POSITIVE and not self.false_positive_rationale:
            raise ValueError("False-positive findings require a rationale")
        return self


class CoverageCategory(ReportModel):
    category: str
    state: CoverageState
    planned: int = 0
    completed: int = 0
    passed: int = 0
    failed: int = 0
    findings: int = 0
    skipped: int = 0
    unsupported: int = 0
    unavailable: int = 0
    errors: int = 0
    timeouts: int = 0
    percentage: float = Field(default=0, ge=0, le=100)
    exclusions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class CoverageSummary(ReportModel):
    overall_percentage: float = Field(default=0, ge=0, le=100)
    categories: list[CoverageCategory] = Field(default_factory=list)
    denominator: int = 0
    denominator_explanation: str = (
        "All planned in-scope probes except explicit unsupported exclusions; skipped, "
        "unavailable, error, and timeout outcomes remain uncompleted and are never passes."
    )
    exclusions: list[str] = Field(default_factory=list)


class RemediationItem(ReportModel):
    priority: Literal["immediate", "near_term", "long_term"]
    title: str
    rationale: str
    finding_fingerprints: list[str] = Field(default_factory=list)
    verification: str = ""


class ArtifactIntegrity(ReportModel):
    status: Literal["ok", "warning", "failed", "unavailable"] = "unavailable"
    files_checked: int = 0
    hashes_verified: int = 0
    missing: list[str] = Field(default_factory=list)
    modified: list[str] = Field(default_factory=list)
    invalid_paths: list[str] = Field(default_factory=list)
    report_hashes: dict[str, str] = Field(default_factory=dict)


class ReportingWarning(ReportModel):
    code: str
    message: str
    recovery_command: str | None = None


class CanonicalReport(ReportModel):
    report_id: str
    run_id: str
    generated_at: datetime = Field(default_factory=utc_now)
    mode: ReportMode = ReportMode.INTERNAL
    branding: Branding = Field(default_factory=Branding)
    assessment_started_at: datetime | None = None
    assessment_completed_at: datetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    assessment_status: str = "unknown"
    profile: str = "unknown"
    adaptive_mode: str = "off"
    target: TargetSummary
    authorization: AuthorizationSummary = Field(default_factory=AuthorizationSummary)
    purpose: str = "Authorized, bounded security assessment"
    methodology: list[str] = Field(default_factory=list)
    environment: dict[str, Any] = Field(default_factory=dict)
    inventory: InventorySummary = Field(default_factory=InventorySummary)
    kali: KaliSummary = Field(default_factory=KaliSummary)
    assessment_plan: dict[str, Any] = Field(default_factory=dict)
    probe_statistics: ProbeStatistics = Field(default_factory=ProbeStatistics)
    adaptive_statistics: AdaptiveStatistics = Field(default_factory=AdaptiveStatistics)
    findings: list[CanonicalFinding] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    coverage: CoverageSummary = Field(default_factory=CoverageSummary)
    errors: list[str] = Field(default_factory=list)
    timeouts: list[str] = Field(default_factory=list)
    unavailable_capabilities: list[str] = Field(default_factory=list)
    skipped_tests: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommendations: list[RemediationItem] = Field(default_factory=list)
    retest_status: str = "not_retested"
    integrity: ArtifactIntegrity = Field(default_factory=ArtifactIntegrity)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    model_roles: dict[str, str] = Field(default_factory=dict)
    stop_reason: str = ""
    appendices: dict[str, Any] = Field(default_factory=dict)
    executive_summary: list[str] = Field(default_factory=list)
    reporting_warnings: list[ReportingWarning] = Field(default_factory=list)


class FindingDelta(ReportModel):
    fingerprint: str
    old: CanonicalFinding | None = None
    new: CanonicalFinding | None = None
    changes: list[str] = Field(default_factory=list)


class ReportComparison(ReportModel):
    old_run_id: str
    new_run_id: str
    new_findings: list[FindingDelta] = Field(default_factory=list)
    resolved_findings: list[FindingDelta] = Field(default_factory=list)
    persistent_findings: list[FindingDelta] = Field(default_factory=list)
    changed_findings: list[FindingDelta] = Field(default_factory=list)
    coverage_change: float = 0
    new_unavailable_areas: list[str] = Field(default_factory=list)
    removed_unavailable_areas: list[str] = Field(default_factory=list)
    probe_count_change: int = 0
    duration_change_seconds: float | None = None
    error_count_change: int = 0
    timeout_count_change: int = 0
