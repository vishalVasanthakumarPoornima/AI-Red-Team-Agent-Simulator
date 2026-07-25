"""Coverage accounting that never treats missing evidence as a pass."""

from __future__ import annotations

from collections import defaultdict

from redteam_platform.assessments.models import (
    AssessmentPlan,
    CoverageCategory,
    CoverageSummary,
    ProbeResult,
    ResultState,
)


def build_coverage(plan: AssessmentPlan, results: list[ProbeResult]) -> CoverageSummary:
    by_probe = {item.probe_id: item for item in results}
    grouped: dict[str, list] = defaultdict(list)
    for step in plan.steps:
        if step.probe:
            grouped[step.category].append(step)
    categories: list[CoverageCategory] = []
    for category, steps in sorted(grouped.items()):
        counts = defaultdict(int)
        limitations: list[str] = []
        evidence_count = 0
        for step in steps:
            result = by_probe.get(step.probe.probe_id)
            if result is None:
                counts["skipped"] += 1
                limitations.append(f"{step.probe.probe_id}: no result")
                continue
            evidence_count += len(result.evidence)
            if result.status in {
                ResultState.PASS,
                ResultState.CONFIRMED,
                ResultState.LIKELY,
                ResultState.INFORMATIONAL,
            }:
                counts["completed"] += 1
            elif result.status == ResultState.PROTECTED:
                counts["protected"] += 1
                limitations.append(f"{result.probe_id}: protected")
            elif result.status in {ResultState.UNAVAILABLE, ResultState.TIMEOUT}:
                counts["unavailable"] += 1
                limitations.append(f"{result.probe_id}: {str(result.status).lower()}")
            else:
                counts["failed"] += 1
                limitations.append(f"{result.probe_id}: {str(result.status).lower()}")
        planned = len(steps)
        percentage = round((counts["completed"] / planned * 100) if planned else 0, 2)
        categories.append(
            CoverageCategory(
                category=category,
                planned_steps=planned,
                completed_steps=counts["completed"],
                skipped_steps=counts["skipped"],
                failed_steps=counts["failed"],
                unavailable_steps=counts["unavailable"],
                protected_steps=counts["protected"],
                evidence_count=evidence_count,
                coverage_percentage=percentage,
                limitations=sorted(set(limitations)),
            )
        )
    planned_total = sum(item.planned_steps for item in categories)
    completed_total = sum(item.completed_steps for item in categories)
    overall = round((completed_total / planned_total * 100) if planned_total else 100, 2)
    complete = bool(categories) and overall == 100 and all(not item.limitations for item in categories)
    return CoverageSummary(
        target_id=plan.target_id,
        categories=categories,
        overall_percentage=overall,
        complete=complete,
    )
