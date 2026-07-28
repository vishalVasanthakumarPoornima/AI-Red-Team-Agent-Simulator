"""Versioned models for adaptive planning, execution, and benchmarking."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from redteam_platform.schemas import AssessmentProfile, VersionedModel, utc_now


class AdaptiveMode(StrEnum):
    OFF = "off"
    GUIDED = "guided"
    ADAPTIVE = "adaptive"
    COMPARATIVE = "comparative"


class ModelRole(StrEnum):
    PLANNER = "planner"
    MUTATOR = "mutator"
    SUMMARIZER = "summarizer"
    REVIEWER = "reviewer"


class ProviderKind(StrEnum):
    DETERMINISTIC = "deterministic"
    OLLAMA = "ollama"
    MOCK = "mock"


class ProposalType(StrEnum):
    REGISTERED_PROBE = "registered_probe"
    STOP_RECOMMENDATION = "stop_recommendation"


class RejectionReason(StrEnum):
    INVALID_SCHEMA = "invalid_schema"
    UNKNOWN_TEMPLATE = "unknown_template"
    UNSUPPORTED_CATEGORY = "unsupported_category"
    UNSUPPORTED_TARGET = "unsupported_target"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    SCOPE_CHANGE = "scope_change"
    AUTHORIZATION_CHANGE = "authorization_change"
    UNREGISTERED_OPERATION = "unregistered_operation"
    UNREGISTERED_TOOL = "unregistered_tool"
    UNSAFE_MUTATION = "unsafe_mutation"
    DUPLICATE = "duplicate"
    BUDGET_EXHAUSTED = "budget_exhausted"
    MISSING_HYPOTHESIS = "missing_hypothesis"
    EVIDENCE_NOT_FOUND = "evidence_not_found"
    PROMPT_TOO_LONG = "prompt_too_long"
    MODEL_OVERRIDE_ATTEMPT = "model_override_attempt"


class StopReason(StrEnum):
    NOT_STARTED = "not_started"
    MODE_OFF = "mode_off"
    COMPLETED = "completed"
    COVERAGE_SATURATED = "coverage_saturated"
    NO_NOVELTY = "no_novelty"
    DUPLICATE_RATE = "duplicate_rate"
    MAX_ROUNDS = "max_rounds"
    TOTAL_PROBE_BUDGET = "total_probe_budget"
    MODEL_CALL_BUDGET = "model_call_budget"
    DURATION_BUDGET = "duration_budget"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TARGET_UNAVAILABLE = "target_unavailable"
    CANCELLED = "cancelled"
    MANUAL_STOP = "manual_stop"
    POLICY_REFUSAL = "policy_refusal"
    ERROR = "error"


class NoveltyLevel(StrEnum):
    NOVEL = "novel"
    USEFUL_VARIANT = "useful_variant"
    COSMETIC = "cosmetic"
    NEAR_DUPLICATE = "near_duplicate"
    EXACT_DUPLICATE = "exact_duplicate"


class HypothesisStatus(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    EXHAUSTED = "exhausted"


class BenchmarkOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    TIMEOUT = "timeout"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


class RecommendationLevel(StrEnum):
    RECOMMENDED = "recommended"
    SUITABLE = "suitable"
    LIMITED = "limited"
    NOT_RECOMMENDED = "not_recommended"
    UNAVAILABLE = "unavailable"


class AdaptiveBudget(VersionedModel):
    max_rounds: int = Field(default=8, ge=1, le=32)
    max_total_probes: int = Field(default=100, ge=1, le=500)
    max_probes_per_round: int = Field(default=15, ge=1, le=50)
    max_model_calls: int = Field(default=25, ge=0, le=200)
    max_duration_seconds: int = Field(default=1200, ge=1, le=7200)
    no_novelty_rounds: int = Field(default=2, ge=1, le=8)
    duplicate_rate_threshold: float = Field(default=0.5, ge=0, le=1)


class AdaptiveConfiguration(VersionedModel):
    configuration_version: str = "1.0"
    target_id: str
    target_kind: str
    normalized_target: str
    profile: AssessmentProfile = AssessmentProfile.STANDARD
    mode: AdaptiveMode = AdaptiveMode.OFF
    selected_categories: list[str] = Field(default_factory=list)
    role_models: dict[str, str] = Field(default_factory=dict)
    fallback_model: str | None = None
    allow_fallback: bool = False
    provider: ProviderKind = ProviderKind.DETERMINISTIC
    provider_endpoint: str | None = None
    budget: AdaptiveBudget = Field(default_factory=AdaptiveBudget)
    prompt_max_characters: int = Field(default=4000, ge=256, le=20000)
    provider_timeout_seconds: float = Field(default=30, gt=0, le=180)
    provider_retries: int = Field(default=1, ge=0, le=3)
    provider_repairs: int = Field(default=1, ge=0, le=2)
    deterministic_fallback: bool = True
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def enforce_mode_profile(self):
        if self.profile == AssessmentProfile.PASSIVE and self.mode != AdaptiveMode.OFF:
            raise ValueError("Passive profile cannot enable active adaptive assessment.")
        if self.mode == AdaptiveMode.ADAPTIVE and self.provider == ProviderKind.DETERMINISTIC:
            raise ValueError("Adaptive mode requires an explicitly selected model provider.")
        if self.mode == AdaptiveMode.COMPARATIVE and len(set(self.role_models.values())) < 2:
            raise ValueError("Comparative mode requires at least two explicitly selected models.")
        return self


class ModelCapability(VersionedModel):
    role: ModelRole
    supported: bool
    reason: str


class AdaptiveModelCandidate(VersionedModel):
    model: str
    provider: ProviderKind
    endpoint: str | None = None
    installed: bool = False
    running: bool = False
    digest: str | None = None
    size_bytes: int | None = None
    quantization: str | None = None
    context_length: int | None = None
    capabilities: list[ModelCapability] = Field(default_factory=list)
    reliability: float | None = Field(default=None, ge=0, le=1)
    median_latency_seconds: float | None = Field(default=None, ge=0)
    policy_eligible: bool = False
    notes: list[str] = Field(default_factory=list)


class ModelRoleAssignment(VersionedModel):
    role: ModelRole
    model: str
    provider: ProviderKind
    fallback: bool = False
    reason: str


class ProviderResponse(VersionedModel):
    provider: ProviderKind
    model: str
    role: ModelRole
    available: bool
    valid: bool
    raw_response: str = ""
    parsed: dict[str, Any] | list[Any] | None = None
    error: str | None = None
    latency_seconds: float = Field(default=0, ge=0)
    input_characters: int = Field(default=0, ge=0)
    output_characters: int = Field(default=0, ge=0)
    repair_attempts: int = Field(default=0, ge=0)


class CoverageGap(VersionedModel):
    category: str
    reason: str
    existing_evidence_ids: list[str] = Field(default_factory=list)
    registered_template_ids: list[str] = Field(default_factory=list)
    priority: int = Field(default=50, ge=0, le=100)


class AdaptiveHypothesis(VersionedModel):
    hypothesis_id: str
    statement: str
    category: str
    evidence_ids: list[str] = Field(default_factory=list)
    capability_names: list[str] = Field(default_factory=list)
    coverage_gap: str
    template_ids: list[str]
    status: HypothesisStatus = HypothesisStatus.OPEN
    source: str = "deterministic"
    confidence: float = Field(default=0.5, ge=0, le=1)


class ProbeProposal(VersionedModel):
    proposal_id: str
    proposal_type: ProposalType = ProposalType.REGISTERED_PROBE
    hypothesis_id: str
    template_id: str
    category: str
    target_id: str
    prompt: str
    rationale: str
    expected_coverage: list[str] = Field(default_factory=list)
    requested_operation: str = "invoke"
    requested_tool: str | None = None
    requested_scope_target: str | None = None
    requested_auth_reference: str | None = None
    requested_ports: list[int] = Field(default_factory=list)
    requested_paths: list[str] = Field(default_factory=list)
    request_count: int = Field(default=1, ge=0, le=10)
    priority: int = Field(default=50, ge=0, le=100)
    recommend_stop: bool = False
    model_commentary: str = ""


class ProbeMutation(VersionedModel):
    mutation_id: str
    template_id: str
    category: str
    original_prompt: str
    mutated_prompt: str
    mutation_types: list[str] = Field(default_factory=list)
    lineage: list[str] = Field(default_factory=list)
    normalized_prompt_hash: str


class ValidatedAdaptiveProbe(VersionedModel):
    validation_id: str
    proposal: ProbeProposal
    mutation: ProbeMutation
    required_tool: str
    operation: str
    evaluation_rule: str
    target_kinds: list[str]
    standards_mappings: list[str] = Field(default_factory=list)
    validated_at: datetime = Field(default_factory=utc_now)


class ProbeRejection(VersionedModel):
    proposal_id: str
    reason: RejectionReason
    detail: str
    round_number: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)


class AdaptiveObservation(VersionedModel):
    probe_id: str
    template_id: str
    hypothesis_id: str
    category: str
    status: str
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    error: str | None = None
    duration_seconds: float = Field(default=0, ge=0)


class EvidenceDelta(VersionedModel):
    new_evidence_ids: list[str] = Field(default_factory=list)
    new_finding_ids: list[str] = Field(default_factory=list)
    status_changed: bool = False


class CoverageDelta(VersionedModel):
    categories_added: list[str] = Field(default_factory=list)
    gaps_closed: list[str] = Field(default_factory=list)
    percentage_delta: float = 0


class NoveltyAssessment(VersionedModel):
    proposal_id: str
    level: NoveltyLevel
    score: float = Field(ge=0, le=1)
    normalized_prompt_hash: str
    nearest_probe_id: str | None = None
    similarity: float = Field(default=0, ge=0, le=1)
    useful_evidence_delta: bool = False
    useful_coverage_delta: bool = False
    explanation: str


class DuplicateAssessment(VersionedModel):
    exact_duplicates: int = Field(default=0, ge=0)
    near_duplicates: int = Field(default=0, ge=0)
    cosmetic_variants: int = Field(default=0, ge=0)
    total_proposals: int = Field(default=0, ge=0)
    duplicate_rate: float = Field(default=0, ge=0, le=1)


class AdaptiveDecision(VersionedModel):
    round_number: int
    selected_proposal_ids: list[str] = Field(default_factory=list)
    rejected_proposal_ids: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)


class StopDecision(VersionedModel):
    stop: bool
    reason: StopReason
    detail: str
    deterministic: bool = True
    model_recommended: bool = False
    decided_at: datetime = Field(default_factory=utc_now)


class AdaptiveRound(VersionedModel):
    round_number: int = Field(ge=1)
    started_at: datetime = Field(default_factory=utc_now)
    ended_at: datetime | None = None
    planning_context_hash: str
    hypotheses: list[AdaptiveHypothesis] = Field(default_factory=list)
    proposals: list[ProbeProposal] = Field(default_factory=list)
    validated_probes: list[ValidatedAdaptiveProbe] = Field(default_factory=list)
    rejections: list[ProbeRejection] = Field(default_factory=list)
    observations: list[AdaptiveObservation] = Field(default_factory=list)
    novelty: list[NoveltyAssessment] = Field(default_factory=list)
    decision: AdaptiveDecision
    stop_decision: StopDecision | None = None
    model_calls: int = Field(default=0, ge=0)


class AdaptiveRunState(VersionedModel):
    run_id: str
    target_id: str
    mode: AdaptiveMode
    status: str = "created"
    current_round: int = Field(default=0, ge=0)
    total_probes: int = Field(default=0, ge=0)
    total_model_calls: int = Field(default=0, ge=0)
    consecutive_no_novelty_rounds: int = Field(default=0, ge=0)
    duplicate_proposals: int = Field(default=0, ge=0)
    total_proposals: int = Field(default=0, ge=0)
    observed_prompt_hashes: list[str] = Field(default_factory=list)
    observed_template_ids: list[str] = Field(default_factory=list)
    completed_categories: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    stop_decision: StopDecision = Field(
        default_factory=lambda: StopDecision(
            stop=False, reason=StopReason.NOT_STARTED, detail="Adaptive execution has not started."
        )
    )


class AdaptiveSummary(VersionedModel):
    run_id: str
    mode: AdaptiveMode
    status: str
    rounds: int
    probes: int
    model_calls: int
    accepted_proposals: int
    rejected_proposals: int
    novel_proposals: int
    duplicate_rate: float
    categories_covered: list[str] = Field(default_factory=list)
    stop_reason: StopReason
    limitations: list[str] = Field(default_factory=list)


class BenchmarkCase(VersionedModel):
    case_id: str
    name: str
    role: ModelRole
    category: str
    prompt: str
    expected: dict[str, Any]
    tags: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=15, gt=0, le=60)


class BenchmarkCaseResult(VersionedModel):
    case_id: str
    model: str
    outcome: BenchmarkOutcome
    valid_schema: bool = False
    policy_compliant: bool = False
    correct_decision: bool = False
    duplicate_detected: bool | None = None
    redaction_safe: bool = True
    latency_seconds: float = Field(default=0, ge=0)
    repair_attempts: int = Field(default=0, ge=0)
    error: str | None = None


class BenchmarkMetrics(VersionedModel):
    model: str
    cases_total: int = Field(ge=0)
    cases_completed: int = Field(ge=0)
    availability_rate: float = Field(ge=0, le=1)
    structured_output_validity: float = Field(ge=0, le=1)
    policy_compliance: float = Field(ge=0, le=1)
    correct_decision_rate: float = Field(ge=0, le=1)
    unsupported_template_rejection: float = Field(ge=0, le=1)
    scope_override_rejection: float = Field(ge=0, le=1)
    auth_override_rejection: float = Field(ge=0, le=1)
    shell_request_rejection: float = Field(ge=0, le=1)
    duplicate_detection: float = Field(ge=0, le=1)
    useful_hypothesis_rate: float = Field(ge=0, le=1)
    proposal_diversity: float = Field(ge=0, le=1)
    evidence_grounding: float = Field(ge=0, le=1)
    coverage_gap_planning: float = Field(ge=0, le=1)
    stop_decision_accuracy: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)
    timeout_rate: float = Field(ge=0, le=1)
    provider_error_rate: float = Field(ge=0, le=1)
    long_context_validity: float = Field(ge=0, le=1)
    redaction_safety: float = Field(ge=0, le=1)
    repair_rate: float = Field(ge=0, le=1)
    median_latency_seconds: float = Field(ge=0)
    p95_latency_seconds: float = Field(ge=0)
    consistency_rate: float = Field(ge=0, le=1)
    deterministic_replay_rate: float = Field(ge=0, le=1)
    weighted_score: float = Field(ge=0, le=100)
    weights: dict[str, float]


class ModelRecommendation(VersionedModel):
    model: str
    role: ModelRole
    level: RecommendationLevel
    score: float = Field(ge=0, le=100)
    evidence: list[str]
    limitations: list[str] = Field(default_factory=list)


class BenchmarkReport(VersionedModel):
    benchmark_id: str
    dataset_version: str
    created_at: datetime = Field(default_factory=utc_now)
    models: list[str]
    case_results: list[BenchmarkCaseResult]
    metrics: list[BenchmarkMetrics]
    recommendations: list[ModelRecommendation]
    configuration: dict[str, Any]
