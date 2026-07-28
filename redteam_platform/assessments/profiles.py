"""Standard deterministic profile definitions."""

from redteam_platform.assessments.models import StepMode
from redteam_platform.schemas import AssessmentBudget, AssessmentProfile, VersionedModel


class ProfileDefinition(VersionedModel):
    profile: AssessmentProfile
    description: str
    active: bool
    allow_kali: bool
    budget: AssessmentBudget


PROFILES = {
    AssessmentProfile.PASSIVE: ProfileDefinition(
        profile=AssessmentProfile.PASSIVE,
        description="Read-only inventory, metadata, health, headers, TLS, and configuration evidence.",
        active=False,
        allow_kali=False,
        budget=AssessmentBudget(max_rounds=1, max_probes=12, max_model_calls=0, max_duration_seconds=120),
    ),
    AssessmentProfile.STANDARD: ProfileDefinition(
        profile=AssessmentProfile.STANDARD,
        description="Bounded deterministic AI, API, web, host, and service checks.",
        active=True,
        allow_kali=True,
        budget=AssessmentBudget(max_rounds=1, max_probes=40, max_model_calls=0, max_duration_seconds=300),
    ),
    AssessmentProfile.DEEP_LAB: ProfileDefinition(
        profile=AssessmentProfile.DEEP_LAB,
        description="Expanded fixed checks for an explicitly authorized loopback/private lab.",
        active=True,
        allow_kali=True,
        budget=AssessmentBudget(max_rounds=1, max_probes=80, max_model_calls=0, max_duration_seconds=600),
    ),
}

__all__ = ["PROFILES", "ProfileDefinition", "StepMode"]
