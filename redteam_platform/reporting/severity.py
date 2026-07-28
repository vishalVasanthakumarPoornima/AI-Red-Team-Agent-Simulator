"""Deterministic severity normalization and ordering."""

from redteam_platform.reporting.models import Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


def normalize_severity(value: object) -> Severity:
    text = str(value or "informational").strip().lower()
    aliases = {"info": "informational", "error": "informational", "unknown": "informational"}
    try:
        return Severity(aliases.get(text, text))
    except ValueError:
        return Severity.INFORMATIONAL


def severity_rank(value: Severity | str) -> int:
    return SEVERITY_ORDER[normalize_severity(value)]
