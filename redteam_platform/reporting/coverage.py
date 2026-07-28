"""Truthful coverage aggregation."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from redteam_platform.reporting.models import (
    CoverageCategory,
    CoverageState,
    CoverageSummary,
)


def category_from_counts(category: str, counts: dict[str, Any]) -> CoverageCategory:
    values = {
        key: max(0, int(counts.get(key, 0) or 0))
        for key in (
            "planned", "completed", "passed", "failed", "findings", "skipped",
            "unsupported", "unavailable", "errors", "timeouts",
        )
    }
    eligible = max(0, values["planned"] - values["unsupported"])
    successful = min(values["passed"], eligible)
    percentage = round((values["completed"] / eligible) * 100, 3) if eligible else 0
    if values["timeouts"]:
        state = CoverageState.TIMEOUT
    elif values["errors"]:
        state = CoverageState.ERROR
    elif values["unavailable"] and not values["completed"]:
        state = CoverageState.UNAVAILABLE
    elif values["skipped"] and not values["completed"]:
        state = CoverageState.SKIPPED
    elif values["findings"] or values["failed"]:
        state = CoverageState.FINDING
    elif successful and values["completed"]:
        state = CoverageState.PASSED
    elif values["completed"]:
        state = CoverageState.FAILED
    else:
        state = CoverageState.NOT_TESTED
    return CoverageCategory(
        category=category,
        state=state,
        percentage=min(100, percentage),
        **values,
        limitations=list(counts.get("limitations") or []),
        exclusions=list(counts.get("exclusions") or []),
    )


def summarize_coverage(categories: list[CoverageCategory]) -> CoverageSummary:
    denominator = sum(
        max(0, item.planned - item.unsupported)
        for item in categories
    )
    completed = sum(
        min(
            item.completed,
            max(0, item.planned - item.unsupported),
        )
        for item in categories
    )
    overall = round((completed / denominator) * 100, 3) if denominator else 0
    exclusions = sorted(
        {
            exclusion
            for item in categories
            for exclusion in item.exclusions + item.limitations
        }
    )
    return CoverageSummary(
        overall_percentage=overall,
        categories=categories,
        denominator=denominator,
        exclusions=exclusions,
    )


def normalize_legacy_coverage(payload: dict[str, Any], results: list[dict[str, Any]]) -> CoverageSummary:
    categories_payload = payload.get("categories")
    if isinstance(categories_payload, list):
        categories: list[CoverageCategory] = []
        for item in categories_payload:
            if not isinstance(item, dict):
                continue
            counts = {
                "planned": item.get("planned_steps", item.get("planned", 0)),
                "completed": item.get("completed_steps", item.get("completed", 0)),
                "skipped": item.get("skipped_steps", item.get("skipped", 0)),
                "failed": item.get("failed_steps", item.get("failed", 0)),
                "unavailable": item.get("unavailable_steps", item.get("unavailable", 0)),
                "errors": item.get("error_steps", item.get("errors", 0)),
                "timeouts": item.get("timeout_steps", item.get("timeouts", 0)),
                "findings": item.get("finding_count", item.get("findings", 0)),
                "passed": item.get("passed_steps", item.get("passed", 0)),
                "limitations": item.get("limitations") or [],
            }
            if not counts["passed"]:
                counts["passed"] = max(
                    0,
                    int(counts["completed"] or 0)
                    - int(counts["failed"] or 0)
                    - int(counts["errors"] or 0)
                    - int(counts["timeouts"] or 0)
                    - int(counts["findings"] or 0),
                )
            categories.append(category_from_counts(str(item.get("category") or "unknown"), counts))
        return summarize_coverage(categories)

    grouped: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for result in results:
        category = str(result.get("category") or result.get("probe_id") or "unknown")
        status = str(result.get("status") or "").upper()
        counts = grouped[category]
        counts["planned"] += 1
        if status in {"PASS", "CONFIRMED", "LIKELY", "INFORMATIONAL"}:
            counts["completed"] += 1
        if status == "PASS":
            counts["passed"] += 1
        elif status in {"CONFIRMED", "LIKELY"}:
            counts["findings"] += 1
        elif status in {"ERROR", "COVERAGE_ERROR"}:
            counts["errors"] += 1
        elif status == "TIMEOUT":
            counts["timeouts"] += 1
        elif status in {"UNAVAILABLE", "PROTECTED"}:
            counts["unavailable"] += 1
        elif status in {"SKIPPED", "NOT_APPLICABLE"}:
            counts["skipped"] += 1
        elif status:
            counts["failed"] += 1
    return summarize_coverage(
        [category_from_counts(category, counts) for category, counts in sorted(grouped.items())]
    )
