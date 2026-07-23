"""Safe planner benchmarking with no target invocation or arbitrary commands."""

from __future__ import annotations

import time

from redteam_platform.adaptive import LocalModelPlanner, PROBE_TEMPLATES, probe_fingerprint
from redteam_platform.schemas import (
    AssessmentProfile,
    AssessmentRequest,
    AuthorizationDecision,
    AuthorizationRecord,
    CoverageState,
    ModelBenchmarkResult,
    ScopeClassification,
    Target,
    TargetType,
)


def benchmark_model(model: str) -> ModelBenchmarkResult:
    target = Target(
        id="benchmark_target",
        name="Synthetic planner benchmark",
        type="synthetic",
        endpoint="python://benchmark",
        status="ready",
        discovery_source="benchmark_fixture",
        confidence="high",
        capabilities=["planner_only"],
        scope_classification=ScopeClassification.LOOPBACK,
        target_type=TargetType.PYTHON_AGENT,
        adapter="python",
        supported_profiles=[AssessmentProfile.PASSIVE],
    )
    decision = AuthorizationDecision(
        allowed=True,
        normalized_target="python://benchmark",
        classification=ScopeClassification.LOOPBACK,
        reasons=["Synthetic planner benchmark; no target invocation."],
    )
    request = AssessmentRequest(
        target=target,
        profile=AssessmentProfile.PASSIVE,
        authorization=AuthorizationRecord(
            decision=decision,
            statement="Human-authorized local planner benchmark only.",
            source="human-cli",
            profile=AssessmentProfile.PASSIVE,
        ),
        categories=list(PROBE_TEMPLATES),
        planner_model=model,
    )
    started = time.monotonic()
    planner = LocalModelPlanner(model)
    probes = planner.propose(request, CoverageState(), 1)
    latency = time.monotonic() - started
    fingerprints = {probe_fingerprint(probe) for probe in probes}
    categories = {probe.template_id for probe in probes}
    valid = bool(probes) and all(probe.template_id in PROBE_TEMPLATES for probe in probes)
    return ModelBenchmarkResult(
        model=model,
        available=bool(probes),
        structured_output_validity=1.0 if valid else 0.0,
        category_coverage=len(categories) / len(PROBE_TEMPLATES),
        probe_diversity=len(fingerprints) / len(probes) if probes else 0.0,
        duplicate_rate=1 - (len(fingerprints) / len(probes)) if probes else 0.0,
        policy_compliance=1.0 if valid else 0.0,
        unsupported_tool_requests=0,
        latency_seconds=latency,
        notes=[
            "Planner-only benchmark: no probes were executed against a target.",
            "Unavailable or invalid model output scores zero rather than falling back silently.",
        ],
    )

