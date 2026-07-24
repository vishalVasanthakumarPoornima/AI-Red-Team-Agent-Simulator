"""Dexter coverage accounting that never treats unavailable work as secure."""

from __future__ import annotations

from collections import defaultdict

from redteam_platform.dexter.models import (
    DexterAssessmentPlan,
    DexterCoverage,
    DexterCoverageCategory,
    DexterProbeResult,
    DexterStepStatus,
)


def build_coverage(
    plan: DexterAssessmentPlan,
    step_status: dict[str, DexterStepStatus],
    results: list[DexterProbeResult],
) -> DexterCoverage:
    counters: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "planned": 0,
            "completed": 0,
            "skipped": 0,
            "failed": 0,
            "unavailable": 0,
            "evidence": 0,
        }
    )
    limitations: dict[str, list[str]] = defaultdict(list)
    category_by_step = {step.step_id: step.category for step in plan.steps}
    for step in plan.steps:
        row = counters[step.category]
        row["planned"] += 1
        status = step_status.get(step.step_id, DexterStepStatus.PLANNED)
        if status == DexterStepStatus.COMPLETED:
            row["completed"] += 1
        elif status == DexterStepStatus.SKIPPED:
            row["skipped"] += 1
            limitations[step.category].append(f"{step.name} was skipped.")
        elif status in {DexterStepStatus.FAILED, DexterStepStatus.CANCELLED}:
            row["failed"] += 1
            limitations[step.category].append(f"{step.name} did not complete.")
        elif status == DexterStepStatus.UNAVAILABLE:
            row["unavailable"] += 1
            limitations[step.category].append(f"{step.name} was unavailable.")
    for result in results:
        category = category_by_step.get(result.step_id)
        if category:
            counters[category]["evidence"] += len(result.evidence)
    categories: list[DexterCoverageCategory] = []
    total_planned = total_completed = 0
    for category in sorted(counters):
        row = counters[category]
        percentage = (
            100.0 * row["completed"] / row["planned"]
            if row["planned"]
            else 0.0
        )
        total_planned += row["planned"]
        total_completed += row["completed"]
        categories.append(
            DexterCoverageCategory(
                category=category,
                planned_steps=row["planned"],
                completed_steps=row["completed"],
                skipped_steps=row["skipped"],
                failed_steps=row["failed"],
                unavailable_steps=row["unavailable"],
                coverage_percentage=percentage,
                limitations=limitations[category],
                evidence_count=row["evidence"],
            )
        )
    overall = 100.0 * total_completed / total_planned if total_planned else 0.0
    return DexterCoverage(
        target_id=plan.target_id,
        categories=categories,
        overall_percentage=overall,
        complete=all(
            item.coverage_percentage == 100
            and not item.limitations
            for item in categories
        ),
    )
