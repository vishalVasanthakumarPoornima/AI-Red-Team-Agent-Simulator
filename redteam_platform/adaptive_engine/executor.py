"""Execution bridge from validated adaptive probes to Phase 5 tools/evaluator."""

from __future__ import annotations

from redteam_platform.adaptive_engine.models import (
    AdaptiveObservation,
    ValidatedAdaptiveProbe,
)
from redteam_platform.adaptive_engine.templates import AdaptiveTemplateRegistry
from redteam_platform.assessments.evaluation import DeterministicEvaluator
from redteam_platform.assessments.evidence import evidence_from_result
from redteam_platform.assessments.models import ResultState, ToolRequest, ToolResult
from redteam_platform.assessments.service import UnifiedAssessmentService
from redteam_platform.schemas import AuthorizationRecord, utc_now
from redteam_platform.targets.models import TargetDescriptor


class AdaptiveProbeExecutor:
    def __init__(
        self,
        service: UnifiedAssessmentService,
        registry: AdaptiveTemplateRegistry,
    ):
        self.service = service
        self.registry = registry
        self.evaluator = DeterministicEvaluator()

    def execute(
        self,
        validated: ValidatedAdaptiveProbe,
        *,
        target: TargetDescriptor,
        authorization: AuthorizationRecord,
        round_number: int,
        index: int,
    ):
        template = self.registry.require(validated.proposal.template_id)
        prompt = validated.mutation.mutated_prompt
        phase5_probe = template.phase5_probe(
            prompt=prompt,
            target_kind=target.target_kind,
            probe_id=f"ADAPT-{round_number:02d}-{index:03d}-{template.template_id}",
        )
        operation = "invoke"
        scope_target = target.normalized_target
        parameters = {
            "prompt": prompt,
            "category": template.category,
        }
        if validated.required_tool == "http":
            operation = "POST"
            scope_target, payload = self.service._http_invocation(target, prompt)
            parameters = {"url": scope_target, "payload": payload}
        request = ToolRequest(
            request_id=f"adaptive-{round_number:02d}-{index:03d}",
            tool=validated.required_tool,
            operation=operation,
            target_id=target.stable_id,
            scope_target=scope_target,
            parameters=parameters,
            timeout_seconds=10,
            maximum_output_bytes=self.service.settings.maximum_response_bytes,
        )
        tool = self.service.tools.get(validated.required_tool)
        if tool is None:
            result = ToolResult(
                request_id=request.request_id,
                tool=validated.required_tool,
                status=ResultState.UNAVAILABLE,
                started_at=utc_now(),
                error="Registered Phase 5 tool is unavailable.",
            )
        else:
            try:
                result = tool.execute(request, target, authorization)
            except Exception as exc:
                result = ToolResult(
                    request_id=request.request_id,
                    tool=validated.required_tool,
                    status=ResultState.COVERAGE_ERROR,
                    started_at=utc_now(),
                    error=f"{type(exc).__name__}: adaptive target invocation failed",
                )
        if validated.required_tool == "http":
            result = self.service._normalize_ai_response(target, result)
        evidence = evidence_from_result(phase5_probe, target.stable_id, result)
        probe_result, findings = self.evaluator.evaluate(
            phase5_probe,
            target,
            result,
            evidence,
            step_id=f"adaptive-round-{round_number}",
        )
        observation = AdaptiveObservation(
            probe_id=phase5_probe.probe_id,
            template_id=template.template_id,
            hypothesis_id=validated.proposal.hypothesis_id,
            category=template.category,
            status=str(probe_result.status),
            evidence_ids=[evidence.evidence_id],
            finding_ids=[finding.finding_id for finding in findings],
            error=probe_result.error,
            duration_seconds=probe_result.duration_seconds,
        )
        return observation, evidence, probe_result, findings
