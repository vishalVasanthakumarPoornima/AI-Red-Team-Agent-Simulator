"""Deterministic finding confidence handling."""

from redteam_platform.reporting.models import FindingConfidence


def normalize_confidence(value: object, status: object = "") -> FindingConfidence:
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric >= 0.95:
            return FindingConfidence.CONFIRMED
        if numeric >= 0.75:
            return FindingConfidence.HIGH
        if numeric >= 0.5:
            return FindingConfidence.MEDIUM
        if numeric > 0:
            return FindingConfidence.LOW
        return FindingConfidence.UNVERIFIED
    text = str(value or "").strip().lower()
    if text in {item.value for item in FindingConfidence}:
        return FindingConfidence(text)
    if str(status).upper() == "CONFIRMED":
        return FindingConfidence.CONFIRMED
    if str(status).upper() == "LIKELY":
        return FindingConfidence.MEDIUM
    return FindingConfidence.UNVERIFIED
