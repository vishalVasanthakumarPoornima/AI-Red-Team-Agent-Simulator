"""Strict proposal validation against immutable human and registry boundaries."""

from __future__ import annotations

from redteam_platform.adaptive_engine.models import (
    AdaptiveConfiguration,
    ProbeProposal,
    ProbeRejection,
    RejectionReason,
    ValidatedAdaptiveProbe,
)
from redteam_platform.adaptive_engine.mutations import build_mutation, unsafe_mutation_reason
from redteam_platform.adaptive_engine.templates import AdaptiveTemplateRegistry
from redteam_platform.schemas import new_id
from redteam_platform.targets.models import TargetDescriptor, TargetKind


class ProposalValidator:
    def __init__(self, registry: AdaptiveTemplateRegistry):
        self.registry = registry

    def validate(
        self,
        proposal: ProbeProposal,
        *,
        configuration: AdaptiveConfiguration,
        target: TargetDescriptor,
        hypothesis_ids: set[str],
        evidence_ids: set[str] | None = None,
        seen_hashes: set[str] | None = None,
        round_number: int = 0,
    ) -> tuple[ValidatedAdaptiveProbe | None, ProbeRejection | None]:
        def reject(reason: RejectionReason, detail: str):
            return None, ProbeRejection(
                proposal_id=proposal.proposal_id,
                reason=reason,
                detail=detail,
                round_number=round_number,
            )

        if proposal.target_id != target.stable_id:
            return reject(RejectionReason.SCOPE_CHANGE, "Proposal changed the stable target identity.")
        if (
            proposal.requested_scope_target
            and proposal.requested_scope_target != target.normalized_target
        ):
            return reject(RejectionReason.SCOPE_CHANGE, "Proposal requested a different destination.")
        if proposal.requested_auth_reference or proposal.requested_ports or proposal.requested_paths:
            return reject(
                RejectionReason.MODEL_OVERRIDE_ATTEMPT,
                "Models cannot change authorization, ports, or target paths.",
            )
        if proposal.hypothesis_id not in hypothesis_ids:
            return reject(RejectionReason.MISSING_HYPOTHESIS, "Proposal is not linked to a current hypothesis.")
        template = self.registry.get(proposal.template_id)
        if template is None:
            return reject(RejectionReason.UNKNOWN_TEMPLATE, "Proposal selected an unregistered template.")
        if proposal.category != template.category:
            return reject(RejectionReason.UNSUPPORTED_CATEGORY, "Proposal changed the template category.")
        if proposal.category not in configuration.selected_categories:
            return reject(RejectionReason.UNSUPPORTED_CATEGORY, "Category is outside configured adaptive coverage.")
        if TargetKind(target.target_kind) not in template.target_kinds:
            return reject(RejectionReason.UNSUPPORTED_TARGET, "Template does not support this target adapter.")
        if proposal.requested_operation != template.operation:
            return reject(RejectionReason.UNREGISTERED_OPERATION, "Proposal changed the registered operation.")
        expected_tool = "python" if target.target_kind == TargetKind.PYTHON_AGENT else "http"
        if proposal.requested_tool and proposal.requested_tool != expected_tool:
            return reject(RejectionReason.UNREGISTERED_TOOL, "Proposal requested an unregistered tool.")
        if proposal.request_count > template.request_count:
            return reject(RejectionReason.BUDGET_EXHAUSTED, "Proposal exceeds the template request bound.")
        if len(proposal.prompt) > min(template.prompt_max_characters, configuration.prompt_max_characters):
            return reject(RejectionReason.PROMPT_TOO_LONG, "Proposed prompt exceeds the configured bound.")
        if configuration.mode == "guided" and proposal.prompt != template.base_prompt:
            return reject(RejectionReason.UNSAFE_MUTATION, "Guided mode permits template selection but not mutation.")
        unsafe = unsafe_mutation_reason(template.base_prompt, proposal.prompt)
        if unsafe:
            return reject(RejectionReason.UNSAFE_MUTATION, unsafe)
        mutation = build_mutation(
            template_id=template.template_id,
            category=template.category,
            original_prompt=template.base_prompt,
            mutated_prompt=proposal.prompt,
            mutation_types=[] if proposal.prompt == template.base_prompt else ["model_text"],
        )
        if mutation.normalized_prompt_hash in (seen_hashes or set()):
            return reject(RejectionReason.DUPLICATE, "Normalized prompt was already executed.")
        return (
            ValidatedAdaptiveProbe(
                validation_id=new_id("validation"),
                proposal=proposal,
                mutation=mutation,
                required_tool=expected_tool,
                operation=template.operation,
                evaluation_rule=template.evaluation_rule,
                target_kinds=[str(item) for item in template.target_kinds],
                standards_mappings=template.standards_mappings,
            ),
            None,
        )
