"""Capability-aware deterministic common plan builder."""

from __future__ import annotations

import hashlib

from redteam_platform.assessments.models import (
    AssessmentPhase,
    AssessmentPlan,
    AssessmentStep,
    StepMode,
)
from redteam_platform.assessments.probes import probes_for
from redteam_platform.assessments.profiles import PROFILES
from redteam_platform.schemas import AssessmentBudget, AssessmentProfile, ScopeClassification
from redteam_platform.settings import Settings
from redteam_platform.targets.models import TargetDescriptor, TargetKind


PHASES = [
    AssessmentPhase(phase_id="preflight", name="Preflight", order=1, description="Scope and authorization boundary."),
    AssessmentPhase(phase_id="discovery", name="Discovery", order=2, description="Inventory, relationships, and health."),
    AssessmentPhase(phase_id="assessment", name="Assessment", order=3, description="Registered bounded probes."),
    AssessmentPhase(phase_id="evaluation", name="Evaluation", order=4, description="Deterministic finding evaluation."),
    AssessmentPhase(phase_id="reporting", name="Reporting", order=5, description="Coverage, artifacts, and reports."),
]


class DeterministicAssessmentPlanner:
    def __init__(self, settings: Settings):
        self.settings = settings

    def build(
        self,
        target: TargetDescriptor,
        *,
        profile: AssessmentProfile | str,
        ports: list[int] | None = None,
        paths: list[str] | None = None,
        include_kali: bool = False,
        context=None,
    ) -> AssessmentPlan:
        selected = AssessmentProfile(profile)
        if selected == AssessmentProfile.DEEP_LAB and target.scope_classification not in {
            ScopeClassification.LOOPBACK,
            ScopeClassification.LAB,
        }:
            raise ValueError("Deep-lab is restricted to loopback or configured lab scope.")
        port_allowlist = self._ports(ports)
        path_allowlist = list(paths or self.settings.web_path_allowlist)
        profile_definition = PROFILES[selected]
        configured_budget = self.settings.profile_budgets.get(str(selected), {})
        maximum_probes = min(
            int(configured_budget.get("max_probes", profile_definition.budget.max_probes)),
            (
                self.settings.assessment_maximum_requests * 2
                if selected == AssessmentProfile.DEEP_LAB
                else self.settings.assessment_maximum_requests
            ),
        )
        duration = min(
            int(configured_budget.get("max_duration_seconds", profile_definition.budget.max_duration_seconds)),
            (
                self.settings.assessment_maximum_duration_seconds * 2
                if selected == AssessmentProfile.DEEP_LAB
                else self.settings.assessment_maximum_duration_seconds
            ),
        )
        budget = AssessmentBudget(
            max_rounds=1,
            max_probes=max(1, maximum_probes),
            max_model_calls=0,
            max_duration_seconds=max(1, duration),
        )
        canary = "RT-CANARY-" + hashlib.sha256(
            f"{target.stable_id}|{selected}".encode()
        ).hexdigest()[:16].upper()
        registered = probes_for(
            target,
            active=selected != AssessmentProfile.PASSIVE,
            canary=canary,
            ports=port_allowlist,
            paths=path_allowlist,
        )
        registered = registered[: budget.max_probes]
        steps = [
            AssessmentStep(
                step_id="GEN-STEP-001",
                phase_id="preflight",
                name="Validate exact target scope",
                category="scope_validation",
                mode=StepMode.PASSIVE,
                expected_operations=["revalidate normalized target and every step scope"],
                maximum_requests=0,
                timeout_seconds=5,
                scope_target=target.normalized_target,
                authorization_required=False,
                evidence_type="policy",
            ),
            AssessmentStep(
                step_id="GEN-STEP-002",
                phase_id="discovery",
                name="Attach target and inventory relationships",
                category="discovery",
                mode=StepMode.PASSIVE,
                expected_operations=["persist typed target and Phase 2 inventory"],
                maximum_requests=0,
                timeout_seconds=5,
                scope_target=target.normalized_target,
                authorization_required=False,
                evidence_type="inventory",
            ),
        ]
        for probe in registered:
            steps.append(
                AssessmentStep(
                    step_id=f"GEN-STEP-{len(steps) + 1:03d}",
                    phase_id="assessment",
                    name=probe.name,
                    category=probe.category,
                    mode=probe.mode,
                    expected_operations=[f"{probe.required_tool}:{probe.operation}"],
                    maximum_requests=probe.request_count,
                    timeout_seconds=probe.timeout_seconds,
                    required_capability=self._required_capability(probe.required_tool),
                    required_tool=probe.required_tool,
                    scope_target=str(
                        probe.parameters.get("url") or target.normalized_target
                    ),
                    authorization_required=probe.mode == StepMode.ACTIVE,
                    skip_conditions=[
                        f"{probe.required_tool} unavailable",
                        "target protected or unavailable",
                    ],
                    evidence_type=probe.expected_evidence,
                    cleanup_required=probe.required_tool in {"subprocess", "kali"},
                    probe=probe,
                )
            )
        if include_kali:
            from redteam_platform.assessments.models import ProbeDefinition

            kali_probe = ProbeDefinition(
                probe_id="GEN-KALI-001",
                category="kali_validation",
                name="fixed_single_host_kali_validation",
                target_kinds=[target.target_kind],
                mode=StepMode.ACTIVE,
                request_count=1,
                timeout_seconds=60,
                required_tool="kali",
                expected_evidence="fixed Kali result",
                evaluation_rule="port_state",
                safety_constraints=[
                    "explicit opt-in",
                    "one authorized host",
                    "explicit ports only",
                    "no scripts or aggressive scan",
                ],
                operation="scan",
                parameters={"ports": port_allowlist},
            )
            steps.append(
                AssessmentStep(
                    step_id=f"GEN-STEP-{len(steps) + 1:03d}",
                    phase_id="assessment",
                    name=kali_probe.name,
                    category=kali_probe.category,
                    mode=StepMode.ACTIVE,
                    expected_operations=["kali:scan"],
                    maximum_requests=1,
                    timeout_seconds=60,
                    required_capability="kali",
                    required_tool="kali",
                    scope_target=target.normalized_target,
                    authorization_required=True,
                    skip_conditions=["Kali not configured or fixed tool unavailable"],
                    evidence_type=kali_probe.expected_evidence,
                    cleanup_required=True,
                    probe=kali_probe,
                )
            )
        for name, category in (
            ("Normalize and deduplicate findings", "evaluation"),
            ("Finalize coverage, artifacts, and reports", "reporting"),
        ):
            steps.append(
                AssessmentStep(
                    step_id=f"GEN-STEP-{len(steps) + 1:03d}",
                    phase_id=category,
                    name=name,
                    category=category,
                    mode=StepMode.PASSIVE,
                    expected_operations=[name.lower()],
                    maximum_requests=0,
                    timeout_seconds=10,
                    scope_target=target.normalized_target,
                    authorization_required=False,
                    evidence_type=category,
                )
            )
        identity = "|".join(
            [
                target.stable_id,
                selected,
                ",".join(str(port) for port in port_allowlist),
                ",".join(path_allowlist),
                str(include_kali),
                ",".join(step.step_id + ":" + step.name for step in steps),
            ]
        )
        return AssessmentPlan(
            plan_id="plan_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
            target_id=target.stable_id,
            target_kind=target.target_kind,
            profile=selected,
            scope_targets=sorted({step.scope_target for step in steps}),
            authorization_required=selected != AssessmentProfile.PASSIVE,
            phases=PHASES,
            steps=steps,
            budget=budget,
            port_allowlist=port_allowlist,
        )

    def _ports(self, ports: list[int] | None) -> list[int]:
        selected = list(ports if ports is not None else self.settings.approved_host_ports)
        normalized: list[int] = []
        for raw in selected:
            port = int(raw)
            if not 1 <= port <= 65535:
                raise ValueError("Ports must be explicit integers between 1 and 65535.")
            if port not in normalized:
                normalized.append(port)
        if len(normalized) > 64:
            raise ValueError("Address ranges and port lists larger than 64 are not allowed.")
        return normalized

    @staticmethod
    def _required_capability(tool: str) -> str:
        return {
            "python": "invoke",
            "http": "http",
            "socket": "socket",
            "tls": "tls",
            "kali": "kali",
        }.get(tool, tool)
