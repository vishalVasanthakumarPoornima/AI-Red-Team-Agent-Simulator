"""Deterministic stopping policy; model recommendations are non-authoritative."""

from __future__ import annotations

from datetime import datetime, timezone

from redteam_platform.adaptive_engine.models import (
    AdaptiveConfiguration,
    AdaptiveRunState,
    StopDecision,
    StopReason,
)


def stopping_decision(
    state: AdaptiveRunState,
    configuration: AdaptiveConfiguration,
    *,
    deadline: float,
    cancelled: bool = False,
    manual_stop: bool = False,
    provider_available: bool = True,
    target_available: bool = True,
    model_recommended: bool = False,
) -> StopDecision:
    budget = configuration.budget
    checks = (
        (cancelled, StopReason.CANCELLED, "Cancellation was requested."),
        (manual_stop, StopReason.MANUAL_STOP, "A persisted human stop request was observed."),
        (not target_available, StopReason.TARGET_UNAVAILABLE, "Target adapter is unavailable."),
        (
            configuration.mode in {"adaptive", "comparative"} and not provider_available,
            StopReason.PROVIDER_UNAVAILABLE,
            "The explicitly selected adaptive provider is unavailable.",
        ),
        (state.current_round >= budget.max_rounds, StopReason.MAX_ROUNDS, "Maximum adaptive rounds reached."),
        (
            state.total_probes >= budget.max_total_probes,
            StopReason.TOTAL_PROBE_BUDGET,
            "Total adaptive probe budget exhausted.",
        ),
        (
            state.total_model_calls >= budget.max_model_calls
            and configuration.mode in {"adaptive", "comparative"},
            StopReason.MODEL_CALL_BUDGET,
            "Model-call budget exhausted.",
        ),
        (
            datetime.now(timezone.utc).timestamp() >= deadline,
            StopReason.DURATION_BUDGET,
            "Adaptive duration budget exhausted.",
        ),
        (
            state.consecutive_no_novelty_rounds >= budget.no_novelty_rounds,
            StopReason.NO_NOVELTY,
            "No useful novelty was observed for the configured number of rounds.",
        ),
        (
            state.total_proposals >= 2
            and state.duplicate_proposals / state.total_proposals
            >= budget.duplicate_rate_threshold,
            StopReason.DUPLICATE_RATE,
            "Duplicate proposal rate reached the configured threshold.",
        ),
        (
            bool(configuration.selected_categories)
            and set(configuration.selected_categories).issubset(state.completed_categories),
            StopReason.COVERAGE_SATURATED,
            "All configured adaptive categories have deterministic observations.",
        ),
        (
            model_recommended and not (
                set(configuration.selected_categories) - set(state.completed_categories)
            ),
            StopReason.COMPLETED,
            "Model stop recommendation agreed with deterministic coverage state.",
        ),
    )
    for stop, reason, detail in checks:
        if stop:
            return StopDecision(
                stop=True,
                reason=reason,
                detail=detail,
                model_recommended=model_recommended,
            )
    return StopDecision(
        stop=False,
        reason=StopReason.NOT_STARTED,
        detail="Budgets, novelty, coverage, provider, and target checks permit another round.",
        model_recommended=model_recommended,
    )
