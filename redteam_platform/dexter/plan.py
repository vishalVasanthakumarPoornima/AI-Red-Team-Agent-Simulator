"""Deterministic Dexter assessment profiles and visible plan builder."""

from __future__ import annotations

from redteam_platform.dexter.models import (
    DexterAssessmentPlan,
    DexterAssessmentProfile,
    DexterAssessmentStep,
    DexterHealth,
    DexterProfile,
    DexterStepMode,
    DexterTarget,
)
from redteam_platform.schemas import AssessmentBudget, ScopeClassification


PROFILES = {
    DexterProfile.PASSIVE: DexterAssessmentProfile(
        profile=DexterProfile.PASSIVE,
        description="Read-only inventory, readiness, metadata, OpenAPI, and exposure observations.",
        active=False,
        allow_kali=False,
        request_budget=12,
        timeout_seconds=120,
    ),
    DexterProfile.STANDARD: DexterAssessmentProfile(
        profile=DexterProfile.STANDARD,
        description="Bounded deterministic AI, API, tool, memory, retrieval, and service checks.",
        active=True,
        allow_kali=True,
        request_budget=36,
        timeout_seconds=300,
    ),
    DexterProfile.DEEP_LAB: DexterAssessmentProfile(
        profile=DexterProfile.DEEP_LAB,
        description="Expanded deterministic probes for an explicitly authorized loopback/private lab.",
        active=True,
        allow_kali=True,
        request_budget=80,
        timeout_seconds=600,
    ),
}


class DexterPlanService:
    def profile(self, profile: DexterProfile | str) -> DexterAssessmentProfile:
        return PROFILES[DexterProfile(profile)]

    def build(
        self,
        target: DexterTarget,
        readiness: DexterHealth,
        *,
        profile: DexterProfile | str,
        include_kali: bool = False,
    ) -> DexterAssessmentPlan:
        selected = DexterProfile(profile)
        if selected not in target.configuration.allowed_profiles:
            raise ValueError(f"Profile {selected} is not enabled for this Dexter deployment.")
        if selected == DexterProfile.DEEP_LAB and target.scope_classification not in {
            ScopeClassification.LOOPBACK,
            ScopeClassification.LAB,
        }:
            raise ValueError("Deep-lab is restricted to loopback or configured private lab scope.")
        profile_model = PROFILES[selected]
        steps: list[DexterAssessmentStep] = []

        def add(
            phase: str,
            name: str,
            category: str,
            mode: DexterStepMode,
            operations: list[str],
            requests: int,
            evidence: str,
            *,
            capability: str | None = None,
            tool: str | None = None,
            scope: str | None = None,
            skip: list[str] | None = None,
        ) -> None:
            steps.append(
                DexterAssessmentStep(
                    step_id=f"DEX-{len(steps) + 1:03d}",
                    phase=phase,
                    name=name,
                    category=category,
                    mode=mode,
                    required_capability=capability,
                    expected_operations=operations,
                    maximum_requests=requests,
                    timeout_seconds=min(profile_model.timeout_seconds, 30),
                    required_authorization=mode == DexterStepMode.ACTIVE,
                    required_tool=tool,
                    scope_target=scope or target.main_endpoint,
                    skip_conditions=skip or [],
                    evidence_type=evidence,
                )
            )

        add("preflight", "Authorization and scope preflight", "deployment_discovery", DexterStepMode.PASSIVE, ["revalidate exact scope"], 0, "policy")
        add("inventory", "Attach passive inventory", "deployment_discovery", DexterStepMode.PASSIVE, ["read Phase 2 inventory"], 0, "inventory")
        add("readiness", "Record Dexter readiness", "service_exposure", DexterStepMode.PASSIVE, ["GET configured health routes"], 2, "readiness")
        add("api", "Analyze API metadata and OpenAPI", "api_surface", DexterStepMode.PASSIVE, ["GET metadata", "GET OpenAPI", "observe headers"], 3, "http")
        add("services", "Review service boundaries", "service_exposure", DexterStepMode.PASSIVE, ["correlate listeners and components"], 0, "inventory")
        if selected != DexterProfile.PASSIVE:
            multiplier = 2 if selected == DexterProfile.DEEP_LAB else 1
            add("api", "Bounded API input validation", "error_handling", DexterStepMode.ACTIVE, ["OPTIONS", "POST conservative malformed JSON", "POST missing/unexpected fields"], 5 * multiplier, "http", capability="api")
            add("ai", "Deterministic AI boundary probes", "prompt_security", DexterStepMode.ACTIVE, ["POST synthetic prompts to configured chat route"], 8 * multiplier, "response", capability="chat", scope=target.chat_endpoint)
            add("tools", "Tool-boundary probes", "tool_security", DexterStepMode.ACTIVE, ["request fake/dry-run tool behavior", "verify approval and argument rejection"], 4 * multiplier, "response", capability="tools", skip=["tool capability unavailable"])
            add("memory", "Synthetic memory isolation probes", "memory", DexterStepMode.ACTIVE, ["use unique synthetic marker", "read-only fallback without disposable namespace"], 4 * multiplier, "response", capability="memory", skip=["memory capability unavailable"])
            add("retrieval", "Retrieval-boundary probes", "retrieval", DexterStepMode.ACTIVE, ["inject local synthetic document marker", "verify instruction separation"], 3 * multiplier, "response", capability="retrieval", skip=["retrieval capability unavailable"])
            add("rate_limit", "Bounded rate-limit observation", "rate_limiting", DexterStepMode.ACTIVE, ["send at most three sequential fixture requests", "observe headers"], 3, "http")
            if include_kali:
                add("kali", "Optional deterministic Kali verification", "kali_network_checks", DexterStepMode.ACTIVE, ["verify exact service and safe HTTP metadata"], 3, "kali", tool="registered-kali-adapter", skip=["Kali unavailable", "tunnel unavailable"])
        add("evaluation", "Normalize and deduplicate findings", "reporting", DexterStepMode.PASSIVE, ["apply versioned deterministic evaluators"], 0, "finding")
        add("artifacts", "Finalize artifacts and reports", "reporting", DexterStepMode.PASSIVE, ["write coverage", "hash manifest", "write Markdown and JSON"], 0, "artifact")
        total_requests = sum(step.maximum_requests for step in steps)
        if total_requests > profile_model.request_budget:
            # The plan is authoritative; budgets are expanded only to the fixed
            # profile ceiling, never by a target or model.
            total_requests = profile_model.request_budget
        budget = AssessmentBudget(
            max_rounds=1,
            max_probes=max(1, profile_model.request_budget),
            max_model_calls=0,
            max_duration_seconds=profile_model.timeout_seconds,
        )
        return DexterAssessmentPlan(
            target_id=target.stable_id,
            profile=selected,
            scope_targets=sorted(
                {
                    step.scope_target
                    for step in steps
                    if step.scope_target
                }
            ),
            steps=steps,
            budget=budget,
        )
