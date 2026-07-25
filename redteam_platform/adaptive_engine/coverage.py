"""Adaptive coverage deltas computed from observed categories."""

from redteam_platform.adaptive_engine.models import CoverageDelta


def coverage_delta(
    *,
    before: set[str],
    after: set[str],
    configured_categories: list[str],
) -> CoverageDelta:
    added = sorted(after - before)
    denominator = max(1, len(set(configured_categories)))
    return CoverageDelta(
        categories_added=added,
        gaps_closed=added,
        percentage_delta=round(100 * len(added) / denominator, 2),
    )
