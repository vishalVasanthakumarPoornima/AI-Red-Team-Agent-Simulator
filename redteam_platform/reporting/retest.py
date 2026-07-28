"""Retest classification that never equates skipped coverage with resolution."""

from redteam_platform.reporting.comparison import compare_reports
from redteam_platform.reporting.models import CanonicalReport, ReportComparison


def classify_retest(old: CanonicalReport, new: CanonicalReport) -> ReportComparison:
    comparison = compare_reports(old, new)
    skipped_categories = {
        item.category
        for item in new.coverage.categories
        if item.state in {"skipped", "not_tested", "unavailable", "error", "timeout"}
    }
    retained = []
    for delta in comparison.resolved_findings:
        if delta.old and delta.old.category in skipped_categories:
            delta.changes.append("not_retested")
            retained.append(delta)
    comparison.resolved_findings = [
        item for item in comparison.resolved_findings if item not in retained
    ]
    comparison.persistent_findings.extend(retained)
    return comparison
