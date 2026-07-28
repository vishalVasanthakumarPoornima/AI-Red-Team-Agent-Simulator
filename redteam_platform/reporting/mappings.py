"""Versioned, category-based security-standard mappings."""

from redteam_platform.reporting.models import StandardsMapping

MAPPING_VERSION = "2026.1"

_CATEGORY_MAPPINGS: dict[str, tuple[tuple[str, str, str, str], ...]] = {
    "prompt_injection": (
        ("OWASP LLM Top 10", "2025", "LLM01", "Prompt Injection"),
        ("MITRE ATLAS", "2026", "AML.T0051", "LLM Prompt Injection"),
    ),
    "prompt_disclosure": (
        ("OWASP LLM Top 10", "2025", "LLM07", "System Prompt Leakage"),
        ("CWE", "4.16", "CWE-200", "Exposure of Sensitive Information"),
    ),
    "synthetic_secret": (
        ("OWASP LLM Top 10", "2025", "LLM02", "Sensitive Information Disclosure"),
        ("CWE", "4.16", "CWE-200", "Exposure of Sensitive Information"),
    ),
    "missing_security_headers": (
        ("OWASP Web Top 10", "2021", "A05", "Security Misconfiguration"),
        ("CWE", "4.16", "CWE-693", "Protection Mechanism Failure"),
    ),
    "authentication": (
        ("OWASP API Top 10", "2023", "API2", "Broken Authentication"),
    ),
    "authorization": (
        ("OWASP API Top 10", "2023", "API1", "Broken Object Level Authorization"),
    ),
    "tool_security": (
        ("OWASP LLM Top 10", "2025", "LLM06", "Excessive Agency"),
    ),
}


def mappings_for_category(category: str) -> list[StandardsMapping]:
    normalized = str(category).strip().lower()
    return [
        StandardsMapping(
            standard=standard,
            version=version,
            identifier=identifier,
            title=title,
            rationale=f"Structured finding category '{normalized}' maps to {identifier}.",
            source_category=normalized,
        )
        for standard, version, identifier, title in _CATEGORY_MAPPINGS.get(normalized, ())
    ]


def remediation_for_structured_finding(
    category: str,
    root_cause: str,
    existing: str,
) -> str:
    """Refine generic guidance from structured category/root-cause evidence."""
    normalized = str(category).strip().lower()
    cause = str(root_cause).strip().lower()
    if normalized == "service_exposure" and "security header" in cause and "omitted" in cause:
        return (
            "Add recommended HTTP security headers at the service boundary and "
            "verify them with the same registered header probe."
        )
    if normalized in {"prompt_security", "prompt_injection", "synthetic_secret"} and any(
        marker in cause for marker in ("synthetic", "isolation", "reflected", "context")
    ):
        return (
            "Strengthen prompt and context isolation, prevent prohibited synthetic "
            "content from crossing sessions, and add a deterministic regression probe."
        )
    if normalized in {"api_surface", "service_exposure"} and any(
        marker in cause for marker in ("metadata", "unauthenticated", "health")
    ):
        return (
            "Reduce unauthenticated operational metadata to the minimum readiness "
            "signal and protect detailed settings behind authorization."
        )
    return existing
