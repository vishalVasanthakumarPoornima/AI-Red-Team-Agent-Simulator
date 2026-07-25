"""Evidence-grounded deterministic hypotheses for adaptive planning."""

from __future__ import annotations

import hashlib

from redteam_platform.adaptive_engine.models import AdaptiveHypothesis, CoverageGap
from redteam_platform.adaptive_engine.templates import AdaptiveTemplateRegistry
from redteam_platform.targets.models import TargetDescriptor


class HypothesisBuilder:
    def __init__(self, registry: AdaptiveTemplateRegistry):
        self.registry = registry

    def coverage_gaps(
        self,
        target: TargetDescriptor,
        *,
        categories: list[str],
        completed_categories: list[str] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> list[CoverageGap]:
        completed = set(completed_categories or [])
        known_evidence = list(evidence_ids or [])
        gaps: list[CoverageGap] = []
        for category in categories:
            if category in completed:
                continue
            templates = [
                item.template_id
                for item in self.registry.list(
                    target_kind=target.target_kind, categories=[category]
                )
            ]
            if not templates:
                continue
            gaps.append(
                CoverageGap(
                    category=category,
                    reason=f"No completed adaptive observation exists for {category}.",
                    existing_evidence_ids=known_evidence[:20],
                    registered_template_ids=templates,
                    priority=max(1, 100 - len(gaps) * 5),
                )
            )
        return gaps

    def build(
        self,
        target: TargetDescriptor,
        gaps: list[CoverageGap],
        *,
        available_evidence_ids: set[str] | None = None,
    ) -> list[AdaptiveHypothesis]:
        known = available_evidence_ids or set()
        hypotheses: list[AdaptiveHypothesis] = []
        capabilities = {
            capability.name
            for capability in target.capabilities
            if capability.available and capability.active
        }
        if not capabilities:
            capabilities = {"invoke"}
        for gap in gaps:
            evidence = [item for item in gap.existing_evidence_ids if item in known]
            identity = "|".join(
                [target.stable_id, gap.category, *gap.registered_template_ids]
            )
            hypotheses.append(
                AdaptiveHypothesis(
                    hypothesis_id="hyp_" + hashlib.sha256(identity.encode()).hexdigest()[:16],
                    statement=(
                        f"A registered {gap.category} probe may add deterministic "
                        "evidence for the current coverage gap."
                    ),
                    category=gap.category,
                    evidence_ids=evidence,
                    capability_names=sorted(capabilities),
                    coverage_gap=gap.reason,
                    template_ids=gap.registered_template_ids,
                    source="deterministic",
                    confidence=0.6 if evidence else 0.45,
                )
            )
        return hypotheses
