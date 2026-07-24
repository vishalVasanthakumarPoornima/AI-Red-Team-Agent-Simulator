"""Authorized deterministic Dexter assessment orchestration."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from redteam_platform.artifacts import RunArtifacts
from redteam_platform.dexter.adapter import DexterHTTPExecutor
from redteam_platform.dexter.coverage import build_coverage
from redteam_platform.dexter.evaluation import deduplicate_findings, evaluate_probe
from redteam_platform.dexter.kali import DexterKaliService
from redteam_platform.dexter.models import (
    DexterAssessmentPlan,
    DexterAssessmentSummary,
    DexterComponentStatus,
    DexterComponentType,
    DexterFinding,
    DexterProfile,
    DexterProbe,
    DexterProbeResult,
    DexterProbeStatus,
    DexterStepMode,
    DexterStepStatus,
    DexterTarget,
)
from redteam_platform.dexter.probes import (
    ai_probes,
    api_probes,
    memory_probes,
    retrieval_probes,
    service_probes,
    tool_probes,
)
from redteam_platform.dexter.reporting import DexterReporter
from redteam_platform.dexter.readiness import DexterReadinessService
from redteam_platform.inventory import InventoryService
from redteam_platform.schemas import (
    AssessmentEvent,
    AssessmentProfile,
    CoverageState,
    ResultStatus,
    RunSummary,
)
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


class DexterAssessmentService:
    def __init__(
        self,
        settings: Settings,
        *,
        policy: ScopePolicy | None = None,
        inventory_service: InventoryService | None = None,
        readiness_service: DexterReadinessService | None = None,
        http_executor: DexterHTTPExecutor | None = None,
        kali_service: DexterKaliService | None = None,
        reporter: DexterReporter | None = None,
        clock: Callable[[], datetime] | None = None,
        id_generator: Callable[[], str] | None = None,
        artifacts_factory: Callable[..., RunArtifacts] | None = None,
        cancel_event: threading.Event | None = None,
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.inventory_service = inventory_service or InventoryService(settings)
        self.readiness_service = readiness_service or DexterReadinessService(
            settings,
            policy=self.policy,
            inventory_service=self.inventory_service,
        )
        self.http_executor = http_executor or DexterHTTPExecutor(
            settings, policy=self.policy
        )
        self.kali_service = kali_service or DexterKaliService(
            settings, policy=self.policy
        )
        self.reporter = reporter or DexterReporter()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.id_generator = id_generator or (lambda: uuid4().hex)
        self.artifacts_factory = artifacts_factory or RunArtifacts
        self.cancel_event = cancel_event or threading.Event()

    def assess(
        self,
        target: DexterTarget,
        plan: DexterAssessmentPlan,
        *,
        authorization_statement: str,
        confirmed: bool,
        interactive_confirmation: bool,
        include_kali: bool = False,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> tuple[DexterAssessmentSummary, list[DexterFinding], dict[str, str]]:
        if plan.target_id != target.stable_id:
            raise ValueError("Dexter plan target does not match the selected deployment.")
        if len(str(authorization_statement or "").strip()) < 12:
            raise ScopeDeniedError("A human authorization statement is required.")
        if plan.profile != DexterProfile.PASSIVE and not confirmed:
            raise ScopeDeniedError("Final assessment confirmation is required.")
        if plan.profile == DexterProfile.DEEP_LAB and not interactive_confirmation:
            raise ScopeDeniedError("Deep-lab requires a real interactive confirmation.")
        primary = self.policy.authorize(
            target.main_endpoint,
            statement=authorization_statement,
            source="human-cli",
            profile=AssessmentProfile(str(plan.profile)),
            public_mode=False,
            interactive_confirmation=interactive_confirmation,
        )
        # Validate the complete visible plan before creating the run directory.
        for scope_target in plan.scope_targets:
            decision = self.policy.decide(
                scope_target,
                active=any(
                    step.mode == DexterStepMode.ACTIVE
                    and step.scope_target == scope_target
                    for step in plan.steps
                ),
                authorization_statement=authorization_statement,
                public_mode=False,
                interactive_confirmation=interactive_confirmation,
            )
            if not decision.allowed:
                raise ScopeDeniedError(decision.reason)

        inventory = self.inventory_service.cached() or self.inventory_service.collect(
            include_kali=False,
            refresh=True,
        )
        readiness = self.readiness_service.check(target, live=True)
        artifacts = self.artifacts_factory(
            self.settings.report_root,
            run_id=primary.run_id,
        )
        started = self.clock()
        sequence = 0
        events: list[AssessmentEvent] = []
        errors: list[str] = []
        results: list[DexterProbeResult] = []
        findings: list[DexterFinding] = []
        step_status: dict[str, DexterStepStatus] = {}
        tools: dict[str, Any] = {
            "http": "httpx",
            "detector": "dexter-rules-1.0",
            "kali": "not requested",
        }

        def emit(phase: str, action: str, status: str, details: dict | None = None):
            nonlocal sequence
            sequence += 1
            event = AssessmentEvent(
                sequence=sequence,
                phase=phase,
                action=action,
                status=status,
                details=details or {},
            )
            events.append(event)
            artifacts.append_event(event)
            if progress_callback:
                progress_callback(
                    {
                        "phase": phase,
                        "step": action,
                        "elapsed_seconds": round(
                            max(0.0, (self.clock() - started).total_seconds()),
                            3,
                        ),
                        "completed_steps": sum(
                            value == DexterStepStatus.COMPLETED
                            for value in step_status.values()
                        ),
                        "total_steps": len(plan.steps),
                        "finding_count": len(findings),
                        "error_count": len(errors),
                        "skipped_count": sum(
                            value
                            in {
                                DexterStepStatus.SKIPPED,
                                DexterStepStatus.UNAVAILABLE,
                            }
                            for value in step_status.values()
                        ),
                    }
                )

        artifacts.write_authorization(primary)
        artifacts.write_inventory(inventory)
        artifacts.write_json("dexter_target.json", target)
        artifacts.write_json("dexter_readiness.json", readiness)
        artifacts.write_json("assessment_plan.json", plan)
        emit("preflight", "run_created_after_confirmation", "ok")
        deadline = time.monotonic() + plan.budget.max_duration_seconds
        probes_used = 0
        stop_reason = "deterministic plan completed"
        status = "complete"
        try:
            capability_map = {
                capability.name: capability.available
                for capability in target.capabilities
            }
            unavailable_states = {
                DexterComponentStatus.UNAVAILABLE,
                DexterComponentStatus.NOT_CONFIGURED,
                DexterComponentStatus.PROTECTED,
            }
            required_api = next(
                (
                    component
                    for component in readiness.components
                    if component.component_type == DexterComponentType.API
                    and component.required
                ),
                None,
            )
            api_status = required_api.status if required_api else None
            if api_status in unavailable_states:
                for capability in ("api", "chat", "tools", "memory", "retrieval"):
                    capability_map[capability] = False
            for component_type, capabilities in {
                DexterComponentType.TOOL: ("tools",),
                DexterComponentType.MEMORY: ("memory",),
            }.items():
                component_statuses = [
                    component.status
                    for component in readiness.components
                    if component.component_type == component_type
                ]
                if component_statuses and all(
                    status in unavailable_states for status in component_statuses
                ):
                    for capability in capabilities:
                        capability_map[capability] = False
            retrieval_statuses = [
                component.status
                for component in readiness.components
                if component.component_type
                in {
                    DexterComponentType.VECTOR,
                    DexterComponentType.RETRIEVAL,
                }
            ]
            if retrieval_statuses and all(
                status in unavailable_states for status in retrieval_statuses
            ):
                capability_map["retrieval"] = False
            canary = (
                f"DX-CANARY-{artifacts.run_id[-8:]}-"
                f"{self.id_generator()[:8]}"
            )
            for step in plan.steps:
                if self.cancel_event.is_set():
                    step_status[step.step_id] = DexterStepStatus.CANCELLED
                    status = "cancelled"
                    stop_reason = "user cancellation"
                    emit(step.phase, step.name, "cancelled")
                    break
                if time.monotonic() >= deadline:
                    step_status[step.step_id] = DexterStepStatus.FAILED
                    status = "partial"
                    stop_reason = "maximum duration reached"
                    errors.append(stop_reason)
                    emit(step.phase, step.name, "timeout")
                    break
                if (
                    step.required_capability
                    and not capability_map.get(step.required_capability, False)
                ):
                    step_status[step.step_id] = DexterStepStatus.UNAVAILABLE
                    errors.append(
                        f"{step.step_id}: capability {step.required_capability} unavailable"
                    )
                    emit(step.phase, step.name, "unavailable")
                    continue
                emit(step.phase, step.name, "running")
                probes = self._probes_for(step, target, canary)
                if step.phase == "kali":
                    kali_plan = self.kali_service.plan(target, enabled=include_kali)
                    artifacts.write_json("dexter_kali_plan.json", kali_plan)
                    kali_results = self.kali_service.execute(target, kali_plan, primary)
                    tools["kali"] = kali_results
                    if any(item.get("status") == "complete" for item in kali_results):
                        step_status[step.step_id] = DexterStepStatus.COMPLETED
                    else:
                        step_status[step.step_id] = DexterStepStatus.UNAVAILABLE
                        errors.append("Kali coverage unavailable.")
                    emit(step.phase, step.name, step_status[step.step_id])
                    continue
                if not probes:
                    step_status[step.step_id] = DexterStepStatus.COMPLETED
                    emit(step.phase, step.name, "completed")
                    continue
                step_failed = False
                for probe in probes[: step.maximum_requests]:
                    if probes_used >= plan.budget.max_probes:
                        errors.append("Probe budget reached.")
                        step_failed = True
                        break
                    raw = self.http_executor.execute(
                        target, probe, primary, step_id=step.step_id
                    )
                    probes_used += 1
                    evaluated, finding = evaluate_probe(target, probe, raw)
                    results.append(evaluated)
                    for evidence in evaluated.evidence:
                        artifacts.write_evidence(evidence.evidence_id, evidence.content)
                    if evaluated.status == DexterProbeStatus.COVERAGE_ERROR:
                        errors.append(
                            evaluated.error or f"{probe.probe_id}: coverage error"
                        )
                        step_failed = True
                    if finding:
                        findings.append(finding)
                step_status[step.step_id] = (
                    DexterStepStatus.FAILED
                    if step_failed
                    else DexterStepStatus.COMPLETED
                )
                emit(step.phase, step.name, step_status[step.step_id])
        except ScopeDeniedError:
            status = "denied"
            stop_reason = "scope policy denial"
            errors.append(stop_reason)
            emit("policy", "scope_denied", "denied")
        except KeyboardInterrupt:
            self.cancel_event.set()
            status = "cancelled"
            stop_reason = "keyboard interruption"
            errors.append(stop_reason)
            emit("stop", "keyboard_interrupt", "cancelled")
        except Exception as exc:
            status = "partial"
            stop_reason = f"assessment error: {type(exc).__name__}"
            errors.append(f"{type(exc).__name__}: {exc}")
            emit("execute", "assessment_error", "error", {"type": type(exc).__name__})

        findings = deduplicate_findings(findings)
        coverage = build_coverage(plan, step_status, results)
        if errors and status == "complete":
            status = "partial"
            stop_reason = "completed with unavailable or failed coverage"
        ended = self.clock()
        summary = DexterAssessmentSummary(
            run_id=artifacts.run_id,
            target_id=target.stable_id,
            profile=plan.profile,
            status=status,
            started_at=started,
            ended_at=ended,
            completed_steps=sum(
                value == DexterStepStatus.COMPLETED
                for value in step_status.values()
            ),
            skipped_steps=sum(
                value == DexterStepStatus.SKIPPED for value in step_status.values()
            ),
            failed_steps=sum(
                value in {DexterStepStatus.FAILED, DexterStepStatus.CANCELLED}
                for value in step_status.values()
            ),
            unavailable_steps=sum(
                value == DexterStepStatus.UNAVAILABLE
                for value in step_status.values()
            ),
            finding_count=len(findings),
            error_count=len(errors),
            coverage_percentage=coverage.overall_percentage,
            coverage_complete=coverage.complete,
            stop_reason=stop_reason,
        )
        artifacts.write_json("probe_results.json", results)
        artifacts.write_json("findings.json", findings)
        artifacts.write_json("coverage.json", coverage)
        artifacts.write_json("dexter_summary.json", summary)
        base_summary = RunSummary(
            run_id=artifacts.run_id,
            status=(
                ResultStatus.CANCELLED
                if status == "cancelled"
                else ResultStatus.DENIED
                if status == "denied"
                else ResultStatus.ERROR
                if status == "partial"
                else ResultStatus.CONFIRMED
                if findings
                else ResultStatus.PASS
            ),
            target_id=target.stable_id,
            profile=AssessmentProfile(str(plan.profile)),
            started_at=started,
            ended_at=ended,
            rounds=1,
            probes=len(results),
            model_calls=0,
            finding_counts={
                severity: sum(
                    finding.severity == severity for finding in findings
                )
                for severity in ("Critical", "High", "Medium", "Low", "Informational")
            },
            coverage=CoverageState(
                categories_attempted=[
                    category.category for category in coverage.categories
                ],
                categories_completed=[
                    category.category
                    for category in coverage.categories
                    if category.coverage_percentage == 100
                ],
            ),
            errors=errors,
            stop_reason=stop_reason,
        )
        artifacts.write_summary(base_summary)
        try:
            reports = self.reporter.write(
                artifacts,
                target=target,
                readiness=readiness,
                plan=plan,
                authorization=primary,
                results=results,
                findings=findings,
                coverage=coverage,
                summary=summary,
                tools=tools,
                errors=errors,
            )
        except Exception as exc:
            report_error = f"Report failure: {type(exc).__name__}: {exc}"
            errors.append(report_error)
            summary.status = "partial"
            summary.error_count = len(errors)
            summary.stop_reason = "assessment completed but report generation failed"
            base_summary.status = ResultStatus.ERROR
            base_summary.errors = errors
            base_summary.stop_reason = summary.stop_reason
            artifacts.write_summary(base_summary)
            artifacts.write_json("dexter_summary.json", summary)
            emit("reporting", "report_generation", "error", {"type": type(exc).__name__})
            reports = {"run_directory": str(artifacts.run_dir)}
        summary.artifact_paths = {
            **reports,
            "run_directory": str(artifacts.run_dir),
        }
        artifacts.write_json("dexter_summary.json", summary)
        artifacts.build_manifest(
            summary=base_summary,
            authorization=primary,
            tools=["httpx", "dexter-rules-1.0"]
            + (["kali"] if include_kali else []),
            models=[target.model_name] if target.model_name else [],
            errors=errors,
        )
        return summary, findings, reports

    @staticmethod
    def _probes_for(step, target, canary) -> list[DexterProbe]:
        if step.phase == "readiness":
            return service_probes(target)
        if step.phase == "api" and step.mode == DexterStepMode.PASSIVE:
            return api_probes(target)[:3]
        if step.phase == "api":
            return api_probes(target)[3:]
        if step.phase == "ai":
            return ai_probes(target.chat_endpoint, canary)
        if step.phase == "tools":
            return tool_probes(target.chat_endpoint)
        if step.phase == "memory":
            return memory_probes(
                target.chat_endpoint,
                canary,
                disposable=target.configuration.disposable_memory_namespace,
            )
        if step.phase == "retrieval":
            return retrieval_probes(target.chat_endpoint, canary)
        if step.phase == "rate_limit":
            base = service_probes(target)[0]
            return [
                base.model_copy(update={"probe_id": f"DX-RATE-{index:03d}"})
                for index in range(1, 4)
            ]
        return []
