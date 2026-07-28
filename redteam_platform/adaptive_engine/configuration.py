"""Validated construction of adaptive settings from profile and CLI policy."""

from __future__ import annotations

from redteam_platform.adaptive_engine.models import (
    AdaptiveBudget,
    AdaptiveConfiguration,
    AdaptiveMode,
    ProviderKind,
)
from redteam_platform.schemas import AssessmentProfile
from redteam_platform.settings import Settings
from redteam_platform.targets.models import TargetDescriptor


ADAPTIVE_TARGET_KINDS = {
    "python_agent",
    "http_agent",
    "openai_compatible",
    "ollama_endpoint",
    "ollama_agent",
    "dexter",
}


def build_adaptive_configuration(
    settings: Settings,
    target: TargetDescriptor,
    *,
    mode: AdaptiveMode | str = AdaptiveMode.GUIDED,
    profile: AssessmentProfile | str = AssessmentProfile.STANDARD,
    role_models: dict[str, str] | None = None,
    fallback_model: str | None = None,
    allow_fallback: bool = False,
    budget_overrides: dict[str, int | float] | None = None,
) -> AdaptiveConfiguration:
    selected_mode = AdaptiveMode(mode)
    selected_profile = AssessmentProfile(profile)
    kind = str(target.target_kind)
    if selected_mode != AdaptiveMode.OFF and kind not in ADAPTIVE_TARGET_KINDS:
        raise ValueError(
            f"Adaptive assessment is unavailable for {kind}; generic host and web targets remain deterministic."
        )
    if selected_profile == AssessmentProfile.PASSIVE and selected_mode != AdaptiveMode.OFF:
        raise ValueError("Passive profile cannot run active adaptive probes.")
    values = {
        "max_rounds": settings.adaptive_max_rounds,
        "max_total_probes": settings.adaptive_max_total_probes,
        "max_probes_per_round": settings.adaptive_max_probes_per_round,
        "max_model_calls": settings.adaptive_max_model_calls,
        "max_duration_seconds": settings.adaptive_max_duration_seconds,
        "no_novelty_rounds": settings.adaptive_no_novelty_rounds,
        "duplicate_rate_threshold": settings.adaptive_duplicate_rate_threshold,
    }
    if selected_profile == AssessmentProfile.STANDARD:
        values.update(
            max_rounds=min(values["max_rounds"], 4),
            max_total_probes=min(values["max_total_probes"], 40),
            max_probes_per_round=min(values["max_probes_per_round"], 8),
            max_model_calls=min(values["max_model_calls"], 12),
            max_duration_seconds=min(values["max_duration_seconds"], 600),
        )
    values.update(budget_overrides or {})
    roles = dict(role_models or {})
    provider = ProviderKind.OLLAMA if roles else ProviderKind.DETERMINISTIC
    return AdaptiveConfiguration(
        target_id=target.stable_id,
        target_kind=kind,
        normalized_target=target.normalized_target,
        profile=selected_profile,
        mode=selected_mode,
        selected_categories=settings.adaptive_categories,
        role_models=roles,
        fallback_model=fallback_model,
        allow_fallback=allow_fallback,
        provider=provider,
        provider_endpoint=(
            settings.ollama_endpoints[0]
            if provider == ProviderKind.OLLAMA and settings.ollama_endpoints
            else None
        ),
        budget=AdaptiveBudget(**values),
        prompt_max_characters=settings.adaptive_prompt_max_characters,
        provider_timeout_seconds=settings.adaptive_provider_timeout_seconds,
        provider_retries=settings.adaptive_provider_retries,
        provider_repairs=settings.adaptive_provider_repairs,
        deterministic_fallback=settings.adaptive_deterministic_fallback,
    )
