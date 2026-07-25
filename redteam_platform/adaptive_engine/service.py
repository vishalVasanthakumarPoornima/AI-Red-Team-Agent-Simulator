"""Public Phase 6 adaptive service layered on Phase 5/Dexter runs."""

from __future__ import annotations

import json
from pathlib import Path

from redteam_platform.adaptive_engine.artifacts import AdaptiveArtifactStore
from redteam_platform.adaptive_engine.configuration import (
    ADAPTIVE_TARGET_KINDS,
    build_adaptive_configuration,
)
from redteam_platform.adaptive_engine.executor import AdaptiveProbeExecutor
from redteam_platform.adaptive_engine.hypotheses import HypothesisBuilder
from redteam_platform.adaptive_engine.lifecycle import AdaptiveLifecycle
from redteam_platform.adaptive_engine.models import (
    AdaptiveConfiguration,
    AdaptiveMode,
    AdaptiveRunState,
    ModelRole,
    ModelRoleAssignment,
    ProviderKind,
    StopDecision,
    StopReason,
)
from redteam_platform.adaptive_engine.planner import (
    AdaptivePlanner,
    minimized_planning_context,
)
from redteam_platform.adaptive_engine.providers import (
    DeterministicProvider,
    OllamaStructuredProvider,
)
from redteam_platform.adaptive_engine.roles import assign_roles
from redteam_platform.adaptive_engine.templates import DEFAULT_TEMPLATE_REGISTRY
from redteam_platform.artifacts import sanitize
from redteam_platform.assessments.service import UnifiedAssessmentService
from redteam_platform.schemas import AssessmentProfile, AuthorizationRecord, utc_now
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings
from redteam_platform.targets.models import TargetDescriptor, TargetKind


class AdaptiveAssessmentService:
    def __init__(
        self,
        settings: Settings,
        *,
        unified: UnifiedAssessmentService | None = None,
        provider=None,
    ):
        self.settings = settings
        self.policy = ScopePolicy(settings)
        self.unified = unified or UnifiedAssessmentService(settings)
        self.registry = DEFAULT_TEMPLATE_REGISTRY
        self.ollama = provider or OllamaStructuredProvider(settings)

    def status(self) -> dict:
        return {
            "available": True,
            "default_mode": self.settings.adaptive_default_mode,
            "modes": [str(item) for item in AdaptiveMode],
            "supported_target_kinds": sorted(ADAPTIVE_TARGET_KINDS),
            "registered_templates": len(self.registry.list()),
            "default_budget": {
                "max_rounds": self.settings.adaptive_max_rounds,
                "max_total_probes": self.settings.adaptive_max_total_probes,
                "max_probes_per_round": self.settings.adaptive_max_probes_per_round,
                "max_model_calls": self.settings.adaptive_max_model_calls,
                "max_duration_seconds": self.settings.adaptive_max_duration_seconds,
                "no_novelty_rounds": self.settings.adaptive_no_novelty_rounds,
                "duplicate_rate_threshold": self.settings.adaptive_duplicate_rate_threshold,
            },
            "policy": {
                "model_output_untrusted": True,
                "deterministic_evaluator_authoritative": True,
                "scope_expansion_allowed": False,
                "model_downloads_allowed": False,
                "shell_execution_allowed": False,
                "passive_profile_adaptive": False,
                "deep_lab_interactive_confirmation_required": True,
            },
        }

    def models(self, *, live: bool = False):
        return self.ollama.candidates(live=live)

    def plan(
        self,
        value: str,
        *,
        mode: AdaptiveMode | str = AdaptiveMode.GUIDED,
        profile: AssessmentProfile | str = AssessmentProfile.STANDARD,
        kind_hint: TargetKind | str | None = None,
        target_model: str | None = None,
        role_models: dict[str, str] | None = None,
        fallback_model: str | None = None,
        allow_fallback: bool = False,
        budget_overrides: dict | None = None,
        include_kali: bool = False,
    ) -> dict:
        target = self.unified.require_target(
            value,
            kind_hint=kind_hint,
            model_name=target_model,
        )
        configuration = build_adaptive_configuration(
            self.settings,
            target,
            mode=mode,
            profile=profile,
            role_models=role_models,
            fallback_model=fallback_model,
            allow_fallback=allow_fallback,
            budget_overrides=budget_overrides,
        )
        gaps = HypothesisBuilder(self.registry).coverage_gaps(
            target,
            categories=configuration.selected_categories,
        )
        hypotheses = HypothesisBuilder(self.registry).build(target, gaps)
        context, context_hash = minimized_planning_context(
            target,
            configuration,
            hypotheses,
            completed_categories=[],
            observed_hashes=[],
            round_number=1,
        )
        planner = AdaptivePlanner(self.registry, DeterministicProvider())
        output = planner.deterministic(
            target,
            configuration,
            hypotheses,
            limit=configuration.budget.max_probes_per_round,
        )
        payload = {
            "target": target,
            "configuration": configuration,
            "hypotheses": hypotheses,
            "proposals": output.proposals,
            "planning_context_hash": context_hash,
            "planning_context": context,
            "execution": {
                "creates_run": False,
                "authorization_required": True,
                "human_confirmation_required": profile != AssessmentProfile.PASSIVE,
                "model_output_executes_directly": False,
            },
        }
        if target.target_kind == TargetKind.DEXTER:
            from redteam_platform.dexter.discovery import DexterDiscoveryService
            from redteam_platform.dexter.models import DexterProfile
            from redteam_platform.dexter.plan import DexterPlanService
            from redteam_platform.dexter.readiness import DexterReadinessService

            dexter_target = DexterDiscoveryService(self.settings).get(
                target.stable_id, refresh=False
            ).target
            readiness = DexterReadinessService(self.settings).check(
                dexter_target, live=True
            )
            baseline_plan = DexterPlanService().build(
                dexter_target,
                readiness,
                profile=DexterProfile(str(profile)),
                include_kali=include_kali,
            )
            payload["baseline_plan"] = baseline_plan
            payload["safety_review"] = {
                "exact_target": dexter_target.stable_id,
                "exact_urls": sorted(
                    {
                        dexter_target.main_endpoint,
                        dexter_target.health_endpoint,
                        dexter_target.chat_endpoint,
                        dexter_target.openapi_endpoint,
                    }
                ),
                "exact_ports": sorted(
                    {
                        port
                        for port in (
                            target.port,
                            11434 if dexter_target.ollama_endpoint else None,
                        )
                        if port is not None
                    }
                ),
                "kali_requested": include_kali,
                "kali_tunnel_endpoint": (
                    f"http://127.0.0.1:{dexter_target.configuration.kali_remote_port}"
                    if include_kali
                    and dexter_target.configuration.requires_kali_tunnel
                    else None
                ),
                "registered_probe_ids": [
                    proposal.template_id for proposal in output.proposals
                ],
                "registered_kali_adapter_ids": (
                    ["registered-reverse-tunnel", "nmap", "whatweb", "curl"]
                    if include_kali
                    else []
                ),
                "scope_classification": str(dexter_target.scope_classification),
                "authorization_required": True,
                "cleanup_behavior": (
                    "The owned SSH reverse-tunnel process is terminated in a finally block."
                    if include_kali
                    else "No Kali tunnel is created."
                ),
                "model_selected_destinations": False,
                "arbitrary_shell_allowed": False,
            }
        return payload

    def run(
        self,
        value: str,
        *,
        authorization: str,
        mode: AdaptiveMode | str = AdaptiveMode.GUIDED,
        profile: AssessmentProfile | str = AssessmentProfile.STANDARD,
        kind_hint: TargetKind | str | None = None,
        target_model: str | None = None,
        role_models: dict[str, str] | None = None,
        fallback_model: str | None = None,
        allow_fallback: bool = False,
        budget_overrides: dict | None = None,
        public_mode: bool = False,
        interactive_confirmation: bool = False,
        include_kali: bool = False,
    ) -> dict:
        if len(str(authorization or "").strip()) < 12:
            raise ScopeDeniedError(
                "A human authorization statement of at least 12 characters is required."
            )
        target = self.unified.require_target(
            value,
            kind_hint=kind_hint,
            model_name=target_model,
        )
        configuration = build_adaptive_configuration(
            self.settings,
            target,
            mode=mode,
            profile=profile,
            role_models=role_models,
            fallback_model=fallback_model,
            allow_fallback=allow_fallback,
            budget_overrides=budget_overrides,
        )
        if configuration.profile == AssessmentProfile.DEEP_LAB and not interactive_confirmation:
            raise ScopeDeniedError(
                "Adaptive deep-lab requires a real interactive confirmation."
            )
        candidates = (
            self.models(live=True)
            if configuration.provider == ProviderKind.OLLAMA
            else []
        )
        assignments = assign_roles(configuration, candidates)
        baseline = self._baseline(
            value,
            target=target,
            authorization=authorization,
            profile=AssessmentProfile(profile),
            kind_hint=kind_hint,
            target_model=target_model,
            public_mode=public_mode,
            interactive_confirmation=interactive_confirmation,
            include_kali=include_kali,
        )
        run_id = baseline["summary"].run_id
        store = AdaptiveArtifactStore(self.settings.report_root, run_id)
        record = AuthorizationRecord.model_validate(
            store.read_json("authorization.json")
        )
        self.policy.require_record(target.normalized_target, record)
        store.write_json("adaptive_target_descriptor.json", target)
        provider = (
            self.ollama
            if configuration.provider == ProviderKind.OLLAMA
            else DeterministicProvider()
        )
        state = AdaptiveRunState(
            run_id=run_id,
            target_id=target.stable_id,
            mode=configuration.mode,
        )
        lifecycle = AdaptiveLifecycle(
            registry=self.registry,
            planner=AdaptivePlanner(self.registry, provider),
            executor=AdaptiveProbeExecutor(self.unified, self.registry),
            store=store,
        )
        evidence_ids = {
            path.stem
            for path in (store.run_dir / "evidence").glob("evidence_*.txt")
        }
        result = lifecycle.run(
            target=target,
            authorization=record,
            configuration=configuration,
            assignments=assignments,
            state=state,
            existing_evidence_ids=evidence_ids,
        )
        self._extend_report(store, result["summary"])
        store.rebuild_manifest(
            status=result["state"].status,
            stop_reason=str(result["state"].stop_decision.reason),
            models=[assignment.model for assignment in assignments],
        )
        result["baseline"] = baseline
        result["artifacts"] = {
            "run": str(store.run_dir),
            "adaptive_configuration": str(store.run_dir / "adaptive_configuration.json"),
            "adaptive_state": str(store.run_dir / "adaptive_state.json"),
            "adaptive_rounds": str(store.run_dir / "adaptive_rounds.json"),
            "adaptive_summary": str(store.run_dir / "adaptive_summary.json"),
            "manifest": str(store.run_dir / "manifest.json"),
        }
        return result

    def resume(
        self,
        run_id: str,
        *,
        authorization: str,
    ) -> dict:
        if len(str(authorization or "").strip()) < 12:
            raise ScopeDeniedError("Resume requires a fresh human authorization statement.")
        store = AdaptiveArtifactStore(self.settings.report_root, run_id)
        integrity = store.verify_existing_manifest()
        if integrity:
            raise ValueError(
                "Resume refused because manifest integrity failed: "
                + ", ".join(integrity[:5])
            )
        configuration = AdaptiveConfiguration.model_validate(
            store.read_json("adaptive_configuration.json")
        )
        target = TargetDescriptor.model_validate(
            store.read_json("adaptive_target_descriptor.json")
        )
        if target.stable_id != configuration.target_id:
            raise ValueError("Resume refused because target identity changed.")
        resolution = self.unified.resolve(
            target.original_input,
            kind_hint=target.target_kind,
            model_name=target.model_name,
        )
        if not resolution.target or resolution.target.stable_id != target.stable_id:
            raise LookupError("Resume refused because the target adapter identity changed.")
        if resolution.target.normalized_target != configuration.normalized_target:
            raise ScopeDeniedError("Resume refused because normalized scope changed.")
        record = self.policy.authorize(
            target.normalized_target,
            statement=authorization,
            source="human-cli",
            profile=AssessmentProfile(configuration.profile),
            public_mode=False,
            interactive_confirmation=False,
        )
        record.run_id = run_id
        self.policy.require_record(target.normalized_target, record)
        store.write_json("authorization-resume.json", record)
        candidates = (
            self.models(live=True)
            if configuration.provider == ProviderKind.OLLAMA
            else []
        )
        assignments = assign_roles(configuration, candidates)
        state = AdaptiveRunState.model_validate(
            store.read_json("adaptive_state.json")
        )
        stop_marker = store.run_dir / "adaptive-stop-request.json"
        if stop_marker.is_file():
            stop_marker.unlink()
        state.status = "resuming"
        state.stop_decision = StopDecision(
            stop=False,
            reason=StopReason.NOT_STARTED,
            detail="Explicit resume accepted after integrity, target, scope, model, and authorization checks.",
        )
        provider = (
            self.ollama
            if configuration.provider == ProviderKind.OLLAMA
            else DeterministicProvider()
        )
        lifecycle = AdaptiveLifecycle(
            registry=self.registry,
            planner=AdaptivePlanner(self.registry, provider),
            executor=AdaptiveProbeExecutor(self.unified, self.registry),
            store=store,
        )
        result = lifecycle.run(
            target=target,
            authorization=record,
            configuration=configuration,
            assignments=assignments,
            state=state,
            existing_evidence_ids={
                path.stem
                for path in (store.run_dir / "evidence").glob("evidence_*.txt")
            },
        )
        self._extend_report(store, result["summary"])
        store.rebuild_manifest(
            status=result["state"].status,
            stop_reason=str(result["state"].stop_decision.reason),
            models=[assignment.model for assignment in assignments],
        )
        result["artifacts"] = {"run": str(store.run_dir)}
        return result

    def stop(self, run_id: str) -> dict:
        store = AdaptiveArtifactStore(self.settings.report_root, run_id)
        state_payload = store.read_json("adaptive_state.json")
        if not state_payload:
            raise LookupError(f"Run {run_id} has no adaptive state.")
        state = AdaptiveRunState.model_validate(state_payload)
        if state.status in {"complete", "failed", "cancelled"}:
            return {
                "run_id": run_id,
                "requested": False,
                "reason": f"Adaptive run is already {state.status}.",
            }
        store.write_json(
            "adaptive-stop-request.json",
            {
                "run_id": run_id,
                "requested_at": utc_now(),
                "source": "human-cli",
            },
        )
        return {
            "run_id": run_id,
            "requested": True,
            "reason": "The lifecycle will persist a manual-stop decision at its next boundary.",
        }

    def _baseline(
        self,
        value,
        *,
        target,
        authorization,
        profile,
        kind_hint,
        target_model,
        public_mode,
        interactive_confirmation,
        include_kali,
    ):
        if target.target_kind != TargetKind.DEXTER:
            return self.unified.run(
                value,
                authorization=authorization,
                profile=profile,
                kind_hint=kind_hint,
                model_name=target_model,
                public_mode=public_mode,
                interactive_confirmation=interactive_confirmation,
            )
        from redteam_platform.dexter.assessment import DexterAssessmentService
        from redteam_platform.dexter.discovery import DexterDiscoveryService
        from redteam_platform.dexter.models import DexterProfile
        from redteam_platform.dexter.plan import DexterPlanService
        from redteam_platform.dexter.readiness import DexterReadinessService

        dexter_target = DexterDiscoveryService(self.settings).get(
            target.stable_id, refresh=False
        ).target
        readiness = DexterReadinessService(self.settings).check(
            dexter_target, live=True
        )
        plan = DexterPlanService().build(
            dexter_target,
            readiness,
            profile=DexterProfile(str(profile)),
            include_kali=include_kali,
        )
        summary, findings, reports = DexterAssessmentService(self.settings).assess(
            dexter_target,
            plan,
            authorization_statement=authorization,
            confirmed=True,
            interactive_confirmation=interactive_confirmation,
            include_kali=include_kali,
        )
        return {
            "target": dexter_target,
            "health": readiness,
            "plan": plan,
            "summary": summary,
            "findings": findings,
            "artifacts": reports,
        }

    @staticmethod
    def _extend_report(store: AdaptiveArtifactStore, summary) -> None:
        markdown_path = store.run_dir / "report.md"
        if markdown_path.is_file():
            original = markdown_path.read_text(encoding="utf-8")
            marker = "\n## Adaptive assessment\n"
            if marker in original:
                original = original.split(marker, 1)[0].rstrip() + "\n"
            section = (
                marker
                + f"\n- Mode: `{summary.mode}`\n"
                + f"- Status: `{summary.status}`\n"
                + f"- Rounds: {summary.rounds}\n"
                + f"- Adaptive probes: {summary.probes}\n"
                + f"- Model calls: {summary.model_calls}\n"
                + f"- Stop reason: `{summary.stop_reason}`\n"
                + f"- Categories covered: {', '.join(summary.categories_covered) or 'none'}\n"
                + "\nModel output was untrusted; deterministic validators and evaluators remained authoritative.\n"
            )
            store.write_text("report.md", original + section)
        report_json = store.read_json("report.json", {})
        if isinstance(report_json, dict):
            report_json["adaptive"] = summary.model_dump(mode="json")
            store.write_json("report.json", report_json)
