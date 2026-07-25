"""Explicit model-role assignment and evidence-based candidate selection."""

from __future__ import annotations

from redteam_platform.adaptive_engine.models import (
    AdaptiveConfiguration,
    AdaptiveModelCandidate,
    ModelRole,
    ModelRoleAssignment,
)


ROLE_ORDER = (
    ModelRole.PLANNER,
    ModelRole.MUTATOR,
    ModelRole.SUMMARIZER,
    ModelRole.REVIEWER,
)


def assign_roles(
    configuration: AdaptiveConfiguration,
    candidates: list[AdaptiveModelCandidate],
) -> list[ModelRoleAssignment]:
    by_name = {candidate.model: candidate for candidate in candidates}
    assignments: list[ModelRoleAssignment] = []
    for role in ROLE_ORDER:
        requested = configuration.role_models.get(str(role))
        fallback = False
        if not requested and configuration.allow_fallback:
            requested = configuration.fallback_model
            fallback = bool(requested)
        if not requested:
            continue
        candidate = by_name.get(requested)
        if candidate is None or not candidate.installed or not candidate.policy_eligible:
            raise LookupError(
                f"Configured {role} model {requested!r} is not installed and policy-eligible."
            )
        assignments.append(
            ModelRoleAssignment(
                role=role,
                model=requested,
                provider=candidate.provider,
                fallback=fallback,
                reason=(
                    "Explicit fallback was enabled by the human configuration."
                    if fallback
                    else "Explicit human role selection."
                ),
            )
        )
    return assignments


def ranked_candidates(
    candidates: list[AdaptiveModelCandidate],
    *,
    role: ModelRole,
) -> list[AdaptiveModelCandidate]:
    def key(candidate: AdaptiveModelCandidate):
        supported = any(
            capability.role == role and capability.supported
            for capability in candidate.capabilities
        )
        return (
            supported,
            candidate.policy_eligible,
            candidate.running,
            candidate.reliability or 0,
            -(candidate.median_latency_seconds or 9999),
            -(candidate.size_bytes or 0),
        )

    return sorted(candidates, key=key, reverse=True)
