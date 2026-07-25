"""Deterministic duplicate and useful-novelty assessment without embeddings."""

from __future__ import annotations

from redteam_platform.adaptive_engine.models import (
    CoverageDelta,
    EvidenceDelta,
    NoveltyAssessment,
    NoveltyLevel,
    ValidatedAdaptiveProbe,
)
from redteam_platform.adaptive_engine.mutations import word_similarity


class NoveltyEvaluator:
    def before_execution(
        self,
        probe: ValidatedAdaptiveProbe,
        *,
        prior: list[ValidatedAdaptiveProbe],
    ) -> NoveltyAssessment:
        nearest = None
        similarity = 0.0
        for existing in prior:
            score = word_similarity(
                probe.mutation.mutated_prompt, existing.mutation.mutated_prompt
            )
            if (
                probe.mutation.normalized_prompt_hash
                == existing.mutation.normalized_prompt_hash
            ):
                score = 1.0
            if score > similarity:
                similarity = score
                nearest = existing
        if similarity == 1:
            level = NoveltyLevel.EXACT_DUPLICATE
        elif similarity >= 0.9:
            level = NoveltyLevel.NEAR_DUPLICATE
        elif similarity >= 0.75 and nearest and nearest.proposal.category == probe.proposal.category:
            level = NoveltyLevel.COSMETIC
        elif nearest and nearest.proposal.template_id == probe.proposal.template_id:
            level = NoveltyLevel.USEFUL_VARIANT
        else:
            level = NoveltyLevel.NOVEL
        score = {
            NoveltyLevel.EXACT_DUPLICATE: 0,
            NoveltyLevel.NEAR_DUPLICATE: 0.1,
            NoveltyLevel.COSMETIC: 0.25,
            NoveltyLevel.USEFUL_VARIANT: 0.65,
            NoveltyLevel.NOVEL: 1,
        }[level]
        return NoveltyAssessment(
            proposal_id=probe.proposal.proposal_id,
            level=level,
            score=score,
            normalized_prompt_hash=probe.mutation.normalized_prompt_hash,
            nearest_probe_id=nearest.proposal.proposal_id if nearest else None,
            similarity=similarity,
            explanation=f"{level} from normalized hash, template lineage, and word similarity.",
        )

    @staticmethod
    def after_execution(
        assessment: NoveltyAssessment,
        evidence_delta: EvidenceDelta,
        coverage_delta: CoverageDelta,
    ) -> NoveltyAssessment:
        useful_evidence = bool(
            evidence_delta.new_evidence_ids
            or evidence_delta.new_finding_ids
            or evidence_delta.status_changed
        )
        useful_coverage = bool(
            coverage_delta.categories_added
            or coverage_delta.gaps_closed
            or coverage_delta.percentage_delta > 0
        )
        update = {
            "useful_evidence_delta": useful_evidence,
            "useful_coverage_delta": useful_coverage,
        }
        if assessment.level in {
            NoveltyLevel.COSMETIC,
            NoveltyLevel.NEAR_DUPLICATE,
        } and (useful_evidence or useful_coverage):
            update.update(
                level=NoveltyLevel.USEFUL_VARIANT,
                score=max(assessment.score, 0.6),
                explanation=assessment.explanation + " Deterministic outcome added useful evidence or coverage.",
            )
        return assessment.model_copy(update=update)
