"""Transparent qualitative risk calculation without false precision."""

from redteam_platform.reporting.models import (
    FindingConfidence,
    RiskInputs,
    RiskRating,
    Severity,
)
from redteam_platform.reporting.severity import severity_rank


def calculate_risk(inputs: RiskInputs) -> RiskRating:
    base = severity_rank(inputs.technical_severity)
    confidence_penalty = {
        FindingConfidence.CONFIRMED: 0,
        FindingConfidence.HIGH: 0,
        FindingConfidence.MEDIUM: 1,
        FindingConfidence.LOW: 1,
        FindingConfidence.UNVERIFIED: 2,
    }[inputs.confidence]
    exposure_adjustment = 1 if inputs.exposure == "public" else 0
    impact_adjustment = 1 if inputs.business_impact == "high" else 0
    control_adjustment = -1 if inputs.control_effectiveness == "effective" else 0
    ordinal = max(0, min(4, base - confidence_penalty + exposure_adjustment + impact_adjustment + control_adjustment))
    rating = {
        4: Severity.CRITICAL,
        3: Severity.HIGH,
        2: Severity.MEDIUM,
        1: Severity.LOW,
        0: Severity.INFORMATIONAL,
    }[ordinal]
    return RiskRating(
        rating=rating,
        ordinal=ordinal,
        inputs=inputs,
        rationale=(
            "Qualitative ordinal rating derived from the displayed severity, confidence, "
            "exposure, business-impact, and control-effectiveness inputs; it is not CVSS."
        ),
    )
