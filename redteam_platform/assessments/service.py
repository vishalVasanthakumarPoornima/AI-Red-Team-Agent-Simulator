"""Unified target resolution, deterministic execution, and run lifecycle."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Callable

from redteam_platform.artifacts import RunArtifacts
from redteam_platform.assessments.coverage import build_coverage
from redteam_platform.assessments.evaluation import DeterministicEvaluator, deduplicate_findings
from redteam_platform.assessments.evidence import evidence_from_result
from redteam_platform.assessments.models import (
    AssessmentPlan,
    AssessmentSummary,
    ProbeResult,
    ResultState,
    StepMode,
    ToolRequest,
    ToolResult,
)
from redteam_platform.assessments.planner import DeterministicAssessmentPlanner
from redteam_platform.assessments.reporting import markdown_report, report_payload
from redteam_platform.assessments.tools import (
    HTTPTool,
    InventoryEvidenceTool,
    KaliTool,
    PythonTargetTool,
    SocketTool,
    TLSTool,
)
from redteam_platform.inventory import InventoryService
from redteam_platform.schemas import (
    AssessmentEvent,
    AssessmentProfile,
    CoverageState,
    ResultStatus,
    RunSummary,
    utc_now,
)
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings, sanitized_settings
from redteam_platform.targets.models import (
    ResolutionState,
    TargetDescriptor,
    TargetHealth,
    TargetKind,
    TargetResolution,
    TargetState,
)
from redteam_platform.targets.parser import TargetParser
from redteam_platform.targets.registry import TargetAdapterRegistry
from redteam_platform.targets.resolver import TargetResolver


ProgressCallback = Callable[[dict], None]


class UnifiedAssessmentService:
    def __init__(
        self,
        settings: Settings,
        *,
        inventory_service: InventoryService | None = None,
        resolver: TargetResolver | None = None,
        tools: dict | None = None,
    ):
        self.settings = settings
        self.policy = ScopePolicy(settings)
        self.inventory_service = inventory_service or InventoryService(settings)
        self.parser = TargetParser()
        self.resolver = resolver or TargetResolver(
            settings,
            inventory_service=self.inventory_service,
            policy=self.policy,
            parser=self.parser,
        )
        self.registry = TargetAdapterRegistry()
        self.planner = DeterministicAssessmentPlanner(settings)
        self.evaluator = DeterministicEvaluator()
        self.tools = tools or {
            "python": PythonTargetTool(settings, policy=self.policy),
            "http": HTTPTool(settings, policy=self.policy),
            "inventory": InventoryEvidenceTool(),
            "kali": KaliTool(settings, policy=self.policy),
            "socket": SocketTool(settings, policy=self.policy),
            "tls": TLSTool(settings, policy=self.policy),
        }
        self._cancel_events: dict[str, threading.Event] = {}

    def parse(self, value: str, **kwargs):
        return self.parser.parse(value, **kwargs)

    def resolve(self, value: str, **kwargs) -> TargetResolution:
        return self.resolver.resolve(value, **kwargs)

    def require_target(self, value: str, **kwargs) -> TargetDescriptor:
        resolution = self.resolve(value, **kwargs)
        if resolution.state == ResolutionState.DENIED:
            raise ScopeDeniedError(resolution.explanation)
        if resolution.state != ResolutionState.RESOLVED or not resolution.target:
            raise LookupError(resolution.explanation)
        self.registry.resolve(resolution.target)
        return resolution.target

    def health(self, value: str | TargetDescriptor, **kwargs) -> TargetHealth:
        target = value if isinstance(value, TargetDescriptor) else self.require_target(value, **kwargs)
        available = [item.name for item in target.capabilities if item.available]
        unavailable = [item.name for item in target.capabilities if not item.available]
        protected = [
            item.name for item in target.capabilities
            if target.authentication.required and item.active
        ]
        overall = target.health
        if overall == TargetState.UNKNOWN:
            if protected and not [name for name in available if name not in protected]:
                overall = TargetState.PROTECTED
            elif target.errors:
                overall = TargetState.DEGRADED
            else:
                overall = TargetState.READY
        return TargetHealth(
            target_id=target.stable_id,
            overall=overall,
            observations={
                "network_probe_performed": False,
                "reason": "Health is derived from inventory and declared capabilities; assessment probes collect live evidence.",
            },
            available_capabilities=sorted(set(available) - set(protected)),
            unavailable_capabilities=sorted(set(unavailable)),
            protected_capabilities=sorted(set(protected)),
            errors=target.errors,
        )

    def plan(
        self,
        value: str,
        *,
        profile: AssessmentProfile | str = AssessmentProfile.PASSIVE,
        kind_hint: TargetKind | str | None = None,
        model_name: str | None = None,
        ports: list[int] | None = None,
        paths: list[str] | None = None,
        include_kali: bool = False,
        refresh: bool = False,
    ) -> tuple[TargetDescriptor, TargetHealth, AssessmentPlan]:
        target = self.require_target(
            value,
            kind_hint=kind_hint,
            model_name=model_name,
            ports=ports,
            refresh=refresh,
        )
        health = self.health(target)
        plan = self.planner.build(
            target,
            profile=profile,
            ports=ports,
            paths=paths,
            include_kali=include_kali,
        )
        return target, health, plan

    def run(
        self,
        value: str,
        *,
        authorization: str,
        profile: AssessmentProfile | str = AssessmentProfile.STANDARD,
        kind_hint: TargetKind | str | None = None,
        model_name: str | None = None,
        ports: list[int] | None = None,
        paths: list[str] | None = None,
        include_kali: bool = False,
        public_mode: bool = False,
        interactive_confirmation: bool = False,
        source: str = "human-cli",
        progress_callback: ProgressCallback | None = None,
    ) -> dict:
        selected_profile = AssessmentProfile(profile)
        if len(str(authorization or "").strip()) < 12:
            raise ScopeDeniedError("A human authorization statement of at least 12 characters is required.")
        target, health, plan = self.plan(
            value,
            profile=selected_profile,
            kind_hint=kind_hint,
            model_name=model_name,
            ports=ports,
            paths=paths,
            include_kali=include_kali,
        )
        if target.target_kind == TargetKind.DEXTER:
            raise LookupError(
                "Dexter remains routed through the specialized Phase 4 assessment service."
            )
        if selected_profile == AssessmentProfile.DEEP_LAB and not interactive_confirmation:
            raise ScopeDeniedError("Deep-lab requires explicit final interactive confirmation.")
        record = self.policy.authorize(
            target.normalized_target,
            statement=authorization,
            source=source,
            profile=selected_profile,
            public_mode=public_mode,
            interactive_confirmation=interactive_confirmation,
        )
        self.policy.require_record(target.normalized_target, record)
        for scope_target in plan.scope_targets:
            decision = self.policy.decide(
                scope_target,
                active=any(
                    step.scope_target == scope_target and step.mode == StepMode.ACTIVE
                    for step in plan.steps
                ),
                authorization_statement=record.statement,
                public_mode=record.public_mode,
                interactive_confirmation=record.confirmed_interactively,
            )
            if not decision.allowed:
                raise ScopeDeniedError(decision.reason)
        artifacts = RunArtifacts(self.settings.report_root, run_id=record.run_id)
        cancel_event = threading.Event()
        self._cancel_events[artifacts.run_id] = cancel_event
        started = utc_now()
        results: list[ProbeResult] = []
        findings = []
        errors: list[str] = []
        snapshot = self.inventory_service.collect(
            include_kali=False,
            refresh=False,
        )
        sequence = 0

        def event(phase, action, status, details=None):
            nonlocal sequence
            sequence += 1
            event_details = {
                "run_id": artifacts.run_id,
                "target_id": target.stable_id,
                "profile": str(selected_profile),
                "elapsed_seconds": round(
                    max(0.0, (utc_now() - started).total_seconds()), 3
                ),
                "finding_count": len(findings),
                **(details or {}),
            }
            entry = AssessmentEvent(
                sequence=sequence,
                phase=phase,
                action=action,
                status=status,
                details=event_details,
            )
            artifacts.append_event(entry)
            if progress_callback:
                progress_callback(entry.model_dump(mode="json"))

        try:
            artifacts.write_json("target.json", target)
            artifacts.write_inventory(snapshot)
            artifacts.write_json("health.json", health)
            artifacts.write_json("assessment_plan.json", plan)
            artifacts.write_authorization(record)
            artifacts.write_json("config_snapshot.json", sanitized_settings(self.settings))
            event("preflight", "authorization", "completed", {"plan_id": plan.plan_id})
            deadline = started.timestamp() + plan.budget.max_duration_seconds
            probe_steps = [step for step in plan.steps if step.probe]
            for index, step in enumerate(probe_steps, 1):
                if cancel_event.is_set():
                    event("assessment", step.step_id, "cancelled")
                    break
                if datetime.now(timezone.utc).timestamp() >= deadline:
                    errors.append("Assessment duration budget exhausted.")
                    event("assessment", step.step_id, "timeout")
                    break
                request = self._tool_request(step, target, index)
                tool = self.tools.get(request.tool)
                if not tool:
                    tool_result = ToolResult(
                        request_id=request.request_id,
                        tool=request.tool,
                        status=ResultState.UNAVAILABLE,
                        started_at=utc_now(),
                        error=f"Registered tool {request.tool} is unavailable.",
                    )
                else:
                    try:
                        tool_result = tool.execute(request, target, record)
                    except Exception as exc:
                        tool_result = ToolResult(
                            request_id=request.request_id,
                            tool=request.tool,
                            status=ResultState.COVERAGE_ERROR,
                            started_at=utc_now(),
                            error=f"{type(exc).__name__}: {exc}",
                        )
                if (
                    step.probe.operation == "invoke"
                    and step.probe.required_tool == "http"
                ):
                    tool_result = self._normalize_ai_response(target, tool_result)
                evidence = evidence_from_result(step.probe, target.stable_id, tool_result)
                artifacts.write_evidence(evidence.evidence_id, evidence.content)
                probe_result, produced = self.evaluator.evaluate(
                    step.probe, target, tool_result, evidence, step_id=step.step_id
                )
                results.append(probe_result)
                findings.extend(produced)
                event(
                    "assessment",
                    step.step_id,
                    str(probe_result.status),
                    {
                        "current_step": step.name,
                        "completed": index,
                        "planned": len(probe_steps),
                        "requests_used": index,
                        "request_budget": plan.budget.max_probes,
                    },
                )
            findings = deduplicate_findings(findings)
            coverage = build_coverage(plan, results)
            ended = utc_now()
            stopped = (
                "cancelled" if cancel_event.is_set()
                else "completed" if coverage.complete
                else "completed with incomplete coverage"
            )
            summary = AssessmentSummary(
                run_id=artifacts.run_id,
                target_id=target.stable_id,
                target_kind=target.target_kind,
                profile=selected_profile,
                status="cancelled" if cancel_event.is_set() else ("complete" if coverage.complete else "partial"),
                started_at=started,
                ended_at=ended,
                completed_steps=sum(item.completed_steps for item in coverage.categories),
                skipped_steps=sum(item.skipped_steps for item in coverage.categories),
                failed_steps=sum(item.failed_steps for item in coverage.categories),
                unavailable_steps=sum(item.unavailable_steps for item in coverage.categories),
                protected_steps=sum(item.protected_steps for item in coverage.categories),
                finding_count=len(findings),
                error_count=len(errors),
                coverage_percentage=coverage.overall_percentage,
                coverage_complete=coverage.complete,
                stop_reason=stopped,
            )
            summary.artifact_paths = {
                "run": str(artifacts.run_dir),
                "report_markdown": str(artifacts.run_dir / "report.md"),
                "report_json": str(artifacts.run_dir / "report.json"),
                "manifest": str(artifacts.run_dir / "manifest.json"),
            }
            artifacts.write_json("probe_results.json", results)
            artifacts.write_json("findings.json", findings)
            artifacts.write_json("coverage.json", coverage)
            artifacts.write_json("summary.json", summary)
            payload = report_payload(target, health, plan, results, findings, coverage, summary)
            artifacts.write_json("report.json", payload)
            artifacts._write_text(
                "report.md",
                markdown_report(target, health, plan, results, findings, coverage, summary),
            )
            event("reporting", "finalize", "completed")
            legacy_summary = RunSummary(
                run_id=artifacts.run_id,
                status=(
                    ResultStatus.CANCELLED
                    if cancel_event.is_set()
                    else ResultStatus.ERROR
                    if errors
                    else ResultStatus.INFORMATIONAL
                    if not coverage.complete
                    else ResultStatus.PASS
                ),
                target_id=target.stable_id,
                profile=selected_profile,
                started_at=started,
                ended_at=ended,
                rounds=1,
                probes=len(results),
                finding_counts=self._finding_counts(findings),
                coverage=CoverageState(
                    categories_attempted=sorted({item.category for item in plan.steps if item.probe}),
                    categories_completed=sorted({
                        item.category for item in coverage.categories
                        if item.coverage_percentage == 100
                    }),
                    unique_probe_fingerprints=[
                        hashlib.sha256(item.probe_id.encode()).hexdigest()
                        for item in results
                    ],
                    findings_by_category=self._finding_categories(findings),
                ),
                errors=errors,
                stop_reason=stopped,
            )
            artifacts.build_manifest(
                summary=legacy_summary,
                authorization=record,
                tools=sorted({step.required_tool for step in plan.steps if step.required_tool}),
                models=[target.model_name] if target.model_name else [],
                errors=errors,
            )
            from redteam_platform.reporting.service import generate_automatic_reports

            generate_automatic_reports(self.settings.report_root, artifacts.run_id)
            artifacts.build_manifest(
                summary=legacy_summary,
                authorization=record,
                tools=sorted({step.required_tool for step in plan.steps if step.required_tool}),
                models=[target.model_name] if target.model_name else [],
                errors=errors,
            )
            return {
                "target": target,
                "health": health,
                "plan": plan,
                "summary": summary,
                "findings": findings,
                "coverage": coverage,
                "results": results,
                "artifacts": summary.artifact_paths,
            }
        except KeyboardInterrupt:
            cancel_event.set()
            findings = deduplicate_findings(findings)
            coverage = build_coverage(plan, results)
            ended = utc_now()
            summary = AssessmentSummary(
                run_id=artifacts.run_id,
                target_id=target.stable_id,
                target_kind=target.target_kind,
                profile=selected_profile,
                status="cancelled",
                started_at=started,
                ended_at=ended,
                completed_steps=sum(item.completed_steps for item in coverage.categories),
                skipped_steps=sum(item.skipped_steps for item in coverage.categories),
                failed_steps=sum(item.failed_steps for item in coverage.categories),
                unavailable_steps=sum(item.unavailable_steps for item in coverage.categories),
                protected_steps=sum(item.protected_steps for item in coverage.categories),
                finding_count=len(findings),
                error_count=0,
                coverage_percentage=coverage.overall_percentage,
                coverage_complete=False,
                stop_reason="operator interruption",
                artifact_paths={
                    "run": str(artifacts.run_dir),
                    "report_markdown": str(artifacts.run_dir / "report.md"),
                    "report_json": str(artifacts.run_dir / "report.json"),
                    "manifest": str(artifacts.run_dir / "manifest.json"),
                },
            )
            artifacts.write_json("probe_results.json", results)
            artifacts.write_json("findings.json", findings)
            artifacts.write_json("coverage.json", coverage)
            artifacts.write_json("summary.json", summary)
            artifacts.write_json(
                "report.json",
                report_payload(target, health, plan, results, findings, coverage, summary),
            )
            artifacts._write_text(
                "report.md",
                markdown_report(target, health, plan, results, findings, coverage, summary),
            )
            cancelled_summary = RunSummary(
                run_id=artifacts.run_id,
                status=ResultStatus.CANCELLED,
                target_id=target.stable_id,
                profile=selected_profile,
                started_at=started,
                ended_at=ended,
                rounds=1,
                probes=len(results),
                finding_counts=self._finding_counts(findings),
                errors=[],
                stop_reason="operator interruption",
            )
            artifacts.build_manifest(
                summary=cancelled_summary,
                authorization=record,
                tools=sorted({step.required_tool for step in plan.steps if step.required_tool}),
                models=[target.model_name] if target.model_name else [],
            )
            raise
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            artifacts.write_json("errors.json", errors)
            artifacts.build_manifest(
                authorization=record,
                tools=sorted(self.tools),
                errors=errors,
            )
            raise
        finally:
            for tool in self.tools.values():
                tool.cleanup()
            self._cancel_events.pop(artifacts.run_id, None)

    def cancel(self, run_id: str) -> bool:
        event = self._cancel_events.get(run_id)
        if not event:
            return False
        event.set()
        return True

    def _tool_request(self, step, target, index):
        probe = step.probe
        parameters = dict(probe.parameters)
        operation = probe.operation
        scope_target = str(parameters.get("url") or step.scope_target)
        if operation == "invoke" and probe.required_tool == "http":
            operation = "POST"
            scope_target, payload = self._http_invocation(target, parameters["prompt"])
            parameters = {"url": scope_target, "payload": payload}
        if probe.required_tool == "socket":
            parameters["approved_by_plan"] = int(parameters["port"]) in step.probe.parameters.values()
        return ToolRequest(
            request_id=f"{step.step_id.lower()}-{index:03d}",
            tool=probe.required_tool,
            operation=operation,
            target_id=target.stable_id,
            scope_target=scope_target,
            parameters=parameters,
            timeout_seconds=min(probe.timeout_seconds, 60),
            maximum_output_bytes=self.settings.maximum_response_bytes,
        )

    def _http_invocation(self, target, prompt):
        endpoint = target.invocation_endpoint or target.base_url or target.normalized_target
        if target.target_kind == TargetKind.OPENAI_COMPATIBLE:
            if not target.model_name:
                raise ValueError("OpenAI-compatible targets require --model.")
            return endpoint, {
                "model": target.model_name,
                "messages": [{"role": "user", "content": prompt}],
            }
        if target.target_kind in {TargetKind.OLLAMA_ENDPOINT, TargetKind.OLLAMA_AGENT}:
            model = target.model_name or self.settings.default_ollama_model
            if not model:
                raise ValueError("Ollama targets require --model or default_ollama_model.")
            configured = target.invocation_endpoint
            base = (target.model_endpoint or target.base_url or target.normalized_target).rstrip("/")
            endpoint = configured or base + "/api/generate"
            if endpoint.rstrip("/").endswith("/api/chat"):
                return endpoint, {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                }
            return endpoint, {"model": model, "prompt": prompt, "stream": False}
        field = str(target.safe_metadata.get("request_field") or "prompt")
        return endpoint, {field: prompt}

    @staticmethod
    def _normalize_ai_response(target, result: ToolResult) -> ToolResult:
        if result.status in {
            ResultState.PROTECTED,
            ResultState.TIMEOUT,
            ResultState.UNAVAILABLE,
            ResultState.COVERAGE_ERROR,
            ResultState.CANCELLED,
        }:
            return result
        body = result.data.get("body")
        try:
            payload = json.loads(body) if isinstance(body, str) else body
        except (TypeError, ValueError):
            result.status = ResultState.COVERAGE_ERROR
            result.error = "AI invocation returned invalid JSON."
            return result
        try:
            if target.target_kind == TargetKind.OPENAI_COMPATIBLE:
                response = payload["choices"][0]["message"]["content"]
            elif target.target_kind in {
                TargetKind.OLLAMA_ENDPOINT,
                TargetKind.OLLAMA_AGENT,
            }:
                response = payload.get("response")
                if response is None:
                    response = payload["message"]["content"]
            else:
                response = payload
                for part in str(
                    target.safe_metadata.get("response_field") or "response"
                ).split("."):
                    response = response[part]
            if not isinstance(response, str):
                raise TypeError
        except (KeyError, IndexError, TypeError, AttributeError):
            result.status = ResultState.COVERAGE_ERROR
            result.error = "AI invocation response did not match the configured response schema."
            return result
        result.data["response"] = response
        return result

    @staticmethod
    def _finding_counts(findings):
        counts = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @staticmethod
    def _finding_categories(findings):
        counts = {}
        for finding in findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return counts
