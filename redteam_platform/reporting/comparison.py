"""Stable-fingerprint report comparison."""

from redteam_platform.reporting.models import CanonicalReport, FindingDelta, ReportComparison


def compare_reports(old: CanonicalReport, new: CanonicalReport) -> ReportComparison:
    old_findings = {item.fingerprint: item for item in old.findings}
    new_findings = {item.fingerprint: item for item in new.findings}
    result = ReportComparison(
        old_run_id=old.run_id,
        new_run_id=new.run_id,
        coverage_change=round(
            new.coverage.overall_percentage - old.coverage.overall_percentage, 3
        ),
        new_unavailable_areas=sorted(
            set(new.unavailable_capabilities) - set(old.unavailable_capabilities)
        ),
        removed_unavailable_areas=sorted(
            set(old.unavailable_capabilities) - set(new.unavailable_capabilities)
        ),
        probe_count_change=new.probe_statistics.completed - old.probe_statistics.completed,
        duration_change_seconds=(
            None
            if old.duration_seconds is None or new.duration_seconds is None
            else round(new.duration_seconds - old.duration_seconds, 3)
        ),
        error_count_change=len(new.errors) - len(old.errors),
        timeout_count_change=len(new.timeouts) - len(old.timeouts),
    )
    for fingerprint in sorted(new_findings.keys() - old_findings.keys()):
        result.new_findings.append(FindingDelta(fingerprint=fingerprint, new=new_findings[fingerprint]))
    for fingerprint in sorted(old_findings.keys() - new_findings.keys()):
        result.resolved_findings.append(
            FindingDelta(fingerprint=fingerprint, old=old_findings[fingerprint])
        )
    for fingerprint in sorted(old_findings.keys() & new_findings.keys()):
        previous = old_findings[fingerprint]
        current = new_findings[fingerprint]
        changes: list[str] = []
        if previous.severity != current.severity:
            changes.append("severity")
        if previous.confidence != current.confidence:
            changes.append("confidence")
        if previous.affected_component != current.affected_component:
            changes.append("affected_component")
        delta = FindingDelta(
            fingerprint=fingerprint, old=previous, new=current, changes=changes
        )
        (result.changed_findings if changes else result.persistent_findings).append(delta)
    return result
