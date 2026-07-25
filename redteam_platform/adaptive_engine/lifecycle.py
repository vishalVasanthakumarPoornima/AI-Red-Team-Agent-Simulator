"""Round lifecycle with persistence, cancellation, resume-safe counters, and budgets."""

from __future__ import annotations

from datetime import datetime, timezone

from redteam_platform.adaptive_engine.artifacts import AdaptiveArtifactStore
from redteam_platform.adaptive_engine.coverage import coverage_delta
from redteam_platform.adaptive_engine.executor import AdaptiveProbeExecutor
from redteam_platform.adaptive_engine.hypotheses import HypothesisBuilder
from redteam_platform.adaptive_engine.models import (
    AdaptiveConfiguration,
    AdaptiveDecision,
    AdaptiveRound,
    AdaptiveRunState,
    AdaptiveSummary,
    EvidenceDelta,
    ModelRoleAssignment,
    NoveltyLevel,
    StopDecision,
    StopReason,
)
from redteam_platform.adaptive_engine.novelty import NoveltyEvaluator
from redteam_platform.adaptive_engine.planner import (
    AdaptivePlanner,
    minimized_planning_context,
)
from redteam_platform.adaptive_engine.stopping import stopping_decision
from redteam_platform.adaptive_engine.templates import AdaptiveTemplateRegistry
from redteam_platform.adaptive_engine.validator import ProposalValidator
from redteam_platform.schemas import AssessmentEvent, AuthorizationRecord, utc_now
from redteam_platform.targets.models import TargetDescriptor


class AdaptiveLifecycle:
    def __init__(
        self,
        *,
        registry: AdaptiveTemplateRegistry,
        planner: AdaptivePlanner,
        executor: AdaptiveProbeExecutor,
        store: AdaptiveArtifactStore,
    ):
        self.registry = registry
        self.planner = planner
        self.executor = executor
        self.store = store
        self.hypotheses = HypothesisBuilder(registry)
        self.validator = ProposalValidator(registry)
        self.novelty = NoveltyEvaluator()

    def run(
        self,
        *,
        target: TargetDescriptor,
        authorization: AuthorizationRecord,
        configuration: AdaptiveConfiguration,
        assignments: list[ModelRoleAssignment],
        state: AdaptiveRunState,
        existing_evidence_ids: set[str] | None = None,
    ) -> dict:
        rounds: list[AdaptiveRound] = [
            AdaptiveRound.model_validate(item)
            for item in self.store.read_json("adaptive_rounds.json", [])
        ]
        all_hypotheses = [
            item
            for round_record in rounds
            for item in round_record.hypotheses
        ]
        all_rejections = [
            item
            for round_record in rounds
            for item in round_record.rejections
        ]
        all_novelty = [
            item
            for round_record in rounds
            for item in round_record.novelty
        ]
        validated_history = [
            item
            for round_record in rounds
            for item in round_record.validated_probes
        ]
        provider_responses = self.store.read_json("provider_responses.json", [])
        evidence_ids = set(existing_evidence_ids or set())
        deadline = (
            state.started_at.timestamp() + configuration.budget.max_duration_seconds
        )
        planner_assignment = next(
            (item for item in assignments if item.role == "planner"), None
        )
        model = planner_assignment.model if planner_assignment else None
        state.status = "running"
        state.stop_decision = StopDecision(
            stop=False,
            reason=StopReason.NOT_STARTED,
            detail="Adaptive execution is running.",
        )
        self._persist(
            target,
            configuration,
            assignments,
            state,
            rounds,
            all_hypotheses,
            all_rejections,
            all_novelty,
            provider_responses,
        )
        self._event(
            "adaptive",
            "adaptive_lifecycle_started",
            "running",
            {"mode": str(configuration.mode), "target_id": target.stable_id},
        )
        try:
            while True:
                manual_stop = (self.store.run_dir / "adaptive-stop-request.json").is_file()
                decision = stopping_decision(
                    state,
                    configuration,
                    deadline=deadline,
                    manual_stop=manual_stop,
                    provider_available=(
                        configuration.mode in {"off", "guided"}
                        or bool(planner_assignment)
                        or configuration.deterministic_fallback
                    ),
                )
                if decision.stop:
                    state.stop_decision = decision
                    self._event(
                        "adaptive",
                        "stop_condition",
                        "completed",
                        {"reason": str(decision.reason)},
                    )
                    break
                round_number = state.current_round + 1
                self._event(
                    "adaptive",
                    "adaptive_round_started",
                    "running",
                    {"round": round_number},
                )
                gaps = self.hypotheses.coverage_gaps(
                    target,
                    categories=configuration.selected_categories,
                    completed_categories=state.completed_categories,
                    evidence_ids=sorted(evidence_ids),
                )
                current_hypotheses = self.hypotheses.build(
                    target, gaps, available_evidence_ids=evidence_ids
                )
                context, context_hash = minimized_planning_context(
                    target,
                    configuration,
                    current_hypotheses,
                    completed_categories=state.completed_categories,
                    observed_hashes=state.observed_prompt_hashes,
                    round_number=round_number,
                )
                remaining = min(
                    configuration.budget.max_probes_per_round,
                    configuration.budget.max_total_probes - state.total_probes,
                )
                planner_output, provider_response = self.planner.plan(
                    target,
                    configuration,
                    current_hypotheses,
                    model=model,
                    context=context,
                    limit=remaining,
                )
                if provider_response:
                    provider_responses.append(provider_response.model_dump(mode="json"))
                    state.total_model_calls += 1 + provider_response.repair_attempts
                accepted = []
                rejected = []
                novelty_rows = []
                for proposal in planner_output.proposals:
                    state.total_proposals += 1
                    validated, rejection = self.validator.validate(
                        proposal,
                        configuration=configuration,
                        target=target,
                        hypothesis_ids={
                            item.hypothesis_id for item in current_hypotheses
                        },
                        evidence_ids=evidence_ids,
                        seen_hashes=set(state.observed_prompt_hashes),
                        round_number=round_number,
                    )
                    if rejection:
                        rejected.append(rejection)
                        self._event(
                            "adaptive",
                            "proposal_rejected",
                            "rejected",
                            {
                                "proposal_id": rejection.proposal_id,
                                "reason": rejection.reason,
                                "round": round_number,
                            },
                        )
                        if rejection.reason == "duplicate":
                            state.duplicate_proposals += 1
                        continue
                    novelty = self.novelty.before_execution(
                        validated, prior=validated_history
                    )
                    if novelty.level in {
                        NoveltyLevel.EXACT_DUPLICATE,
                        NoveltyLevel.NEAR_DUPLICATE,
                        NoveltyLevel.COSMETIC,
                    }:
                        state.duplicate_proposals += 1
                    accepted.append(validated)
                    novelty_rows.append(novelty)
                    self._event(
                        "adaptive",
                        "proposal_accepted",
                        "accepted",
                        {
                            "proposal_id": validated.proposal.proposal_id,
                            "template_id": validated.proposal.template_id,
                            "round": round_number,
                        },
                    )
                round_record = AdaptiveRound(
                    round_number=round_number,
                    planning_context_hash=context_hash,
                    hypotheses=current_hypotheses,
                    proposals=planner_output.proposals,
                    validated_probes=accepted,
                    rejections=rejected,
                    novelty=novelty_rows,
                    decision=AdaptiveDecision(
                        round_number=round_number,
                        selected_proposal_ids=[
                            item.proposal.proposal_id for item in accepted
                        ],
                        rejected_proposal_ids=[
                            item.proposal_id for item in rejected
                        ],
                        rationale=[
                            "Every selected proposal passed schema, template, capability, scope, budget, mutation, and duplicate validation."
                        ],
                    ),
                    model_calls=1 if provider_response else 0,
                )
                useful = False
                categories_before = set(state.completed_categories)
                for index, validated in enumerate(accepted, 1):
                    if state.total_probes >= configuration.budget.max_total_probes:
                        break
                    self._event(
                        "adaptive",
                        "adaptive_probe_started",
                        "running",
                        {
                            "template_id": validated.proposal.template_id,
                            "round": round_number,
                        },
                    )
                    observation, evidence, probe_result, findings = self.executor.execute(
                        validated,
                        target=target,
                        authorization=authorization,
                        round_number=round_number,
                        index=index,
                    )
                    evidence_ids.add(evidence.evidence_id)
                    self.store.write_text(
                        f"evidence/{evidence.evidence_id}.txt", evidence.content
                    )
                    round_record.observations.append(observation)
                    state.total_probes += 1
                    state.observed_prompt_hashes.append(
                        validated.mutation.normalized_prompt_hash
                    )
                    state.observed_template_ids.append(
                        validated.proposal.template_id
                    )
                    if observation.status not in {"COVERAGE_ERROR", "UNAVAILABLE", "TIMEOUT"}:
                        state.completed_categories.append(observation.category)
                    category_after = set(state.completed_categories)
                    delta = coverage_delta(
                        before=categories_before,
                        after=category_after,
                        configured_categories=configuration.selected_categories,
                    )
                    evidence_delta = EvidenceDelta(
                        new_evidence_ids=observation.evidence_ids,
                        new_finding_ids=observation.finding_ids,
                        status_changed=True,
                    )
                    row_index = accepted.index(validated)
                    round_record.novelty[row_index] = self.novelty.after_execution(
                        round_record.novelty[row_index], evidence_delta, delta
                    )
                    useful = useful or bool(
                        evidence_delta.new_finding_ids or delta.categories_added
                    )
                    validated_history.append(validated)
                    categories_before = category_after
                    self.store.append_jsonl(
                        "adaptive_probe_results.jsonl", probe_result
                    )
                    for finding in findings:
                        self.store.append_jsonl(
                            "adaptive_findings.jsonl", finding
                        )
                        self._event(
                            "adaptive",
                            "finding_created",
                            "completed",
                            {
                                "finding_id": finding.finding_id,
                                "severity": str(finding.severity),
                                "category": finding.category,
                            },
                        )
                    self._event(
                        "adaptive",
                        "adaptive_probe_completed",
                        str(observation.status),
                        {
                            "probe_id": observation.probe_id,
                            "category": observation.category,
                            "round": round_number,
                        },
                    )
                state.completed_categories = sorted(set(state.completed_categories))
                state.current_round = round_number
                state.consecutive_no_novelty_rounds = (
                    0 if useful else state.consecutive_no_novelty_rounds + 1
                )
                round_record.ended_at = utc_now()
                round_record.stop_decision = stopping_decision(
                    state,
                    configuration,
                    deadline=deadline,
                    model_recommended=planner_output.recommend_stop,
                )
                rounds.append(round_record)
                all_hypotheses.extend(current_hypotheses)
                all_rejections.extend(rejected)
                all_novelty.extend(round_record.novelty)
                state.updated_at = utc_now()
                self._persist(
                    target,
                    configuration,
                    assignments,
                    state,
                    rounds,
                    all_hypotheses,
                    all_rejections,
                    all_novelty,
                    provider_responses,
                )
                self._event(
                    "adaptive",
                    "coverage_updated",
                    "completed",
                    {
                        "round": round_number,
                        "categories_covered": len(state.completed_categories),
                        "probes_completed": state.total_probes,
                    },
                )
                if round_record.stop_decision.stop:
                    state.stop_decision = round_record.stop_decision
                    self._event(
                        "adaptive",
                        "stop_condition",
                        "completed",
                        {"reason": str(round_record.stop_decision.reason)},
                    )
                    break
            state.status = (
                "cancelled"
                if state.stop_decision.reason in {"cancelled", "manual_stop"}
                else "complete"
            )
        except KeyboardInterrupt:
            state.status = "cancelled"
            state.stop_decision = StopDecision(
                stop=True,
                reason=StopReason.CANCELLED,
                detail="Operator interruption was persisted.",
            )
            raise
        except Exception as exc:
            state.status = "failed"
            state.stop_decision = StopDecision(
                stop=True,
                reason=StopReason.ERROR,
                detail=f"{type(exc).__name__}: adaptive lifecycle failed",
            )
            raise
        finally:
            state.updated_at = utc_now()
            summary = self._summary(state, rounds)
            self._persist(
                target,
                configuration,
                assignments,
                state,
                rounds,
                all_hypotheses,
                all_rejections,
                all_novelty,
                provider_responses,
                summary=summary,
            )
            self._event(
                "reporting",
                "adaptive_report_finalized",
                state.status,
                {
                    "rounds": state.current_round,
                    "probes": state.total_probes,
                    "stop_reason": str(state.stop_decision.reason),
                },
            )
        return {
            "state": state,
            "summary": summary,
            "rounds": rounds,
            "hypotheses": all_hypotheses,
            "rejections": all_rejections,
            "novelty": all_novelty,
        }

    def _summary(self, state, rounds):
        all_novelty = [item for row in rounds for item in row.novelty]
        accepted = sum(len(row.validated_probes) for row in rounds)
        rejected = sum(len(row.rejections) for row in rounds)
        return AdaptiveSummary(
            run_id=state.run_id,
            mode=state.mode,
            status=state.status,
            rounds=state.current_round,
            probes=state.total_probes,
            model_calls=state.total_model_calls,
            accepted_proposals=accepted,
            rejected_proposals=rejected,
            novel_proposals=sum(
                item.level in {"novel", "useful_variant"} for item in all_novelty
            ),
            duplicate_rate=(
                state.duplicate_proposals / state.total_proposals
                if state.total_proposals
                else 0
            ),
            categories_covered=state.completed_categories,
            stop_reason=state.stop_decision.reason,
            limitations=[
                "Model output was treated as untrusted proposals.",
                "Findings were determined only by the Phase 5 deterministic evaluator.",
                "No embeddings, external model downloads, shell execution, or scope expansion were used.",
            ],
        )

    def _persist(
        self,
        target,
        configuration,
        assignments,
        state,
        rounds,
        hypotheses,
        rejections,
        novelty,
        provider_responses,
        *,
        summary=None,
    ):
        self.store.write_json("adaptive_configuration.json", configuration)
        self.store.write_json("model_roles.json", assignments)
        self.store.write_json("adaptive_state.json", state)
        self.store.write_json("hypotheses.json", hypotheses)
        self.store.write_json("adaptive_rounds.json", rounds)
        self.store.write_json("proposal_rejections.json", rejections)
        self.store.write_json("novelty.json", novelty)
        self.store.write_json("stop_decision.json", state.stop_decision)
        self.store.write_json("provider_responses.json", provider_responses)
        if rounds:
            self.store.write_json(
                f"adaptive/round-{rounds[-1].round_number:02d}/round.json",
                rounds[-1],
            )
        if summary:
            self.store.write_json("adaptive_summary.json", summary)

    def _event(self, phase: str, action: str, status: str, details: dict) -> None:
        path = self.store.run_dir / "events.jsonl"
        sequence = 1
        if path.is_file():
            with path.open("r", encoding="utf-8") as handle:
                sequence += sum(1 for line in handle if line.strip())
        self.store.append_jsonl(
            "events.jsonl",
            AssessmentEvent(
                sequence=sequence,
                phase=phase,
                action=action,
                status=status,
                details=details,
            ),
        )
