"""Current-generation Markdown and JSON Dexter reporting."""

from __future__ import annotations

from redteam_platform.artifacts import RunArtifacts, sanitize
from redteam_platform.dexter.models import (
    DexterAssessmentPlan,
    DexterAssessmentSummary,
    DexterCoverage,
    DexterFinding,
    DexterHealth,
    DexterProbeResult,
    DexterTarget,
)
from redteam_platform.schemas import AuthorizationRecord


class DexterReporter:
    def write(
        self,
        artifacts: RunArtifacts,
        *,
        target: DexterTarget,
        readiness: DexterHealth,
        plan: DexterAssessmentPlan,
        authorization: AuthorizationRecord,
        results: list[DexterProbeResult],
        findings: list[DexterFinding],
        coverage: DexterCoverage,
        summary: DexterAssessmentSummary,
        tools: dict,
        errors: list[str],
    ) -> dict[str, str]:
        markdown = self._markdown(
            target=target,
            readiness=readiness,
            plan=plan,
            authorization=authorization,
            findings=findings,
            coverage=coverage,
            summary=summary,
            tools=tools,
            errors=errors,
        )
        artifacts._write_text("report.md", markdown + "\n")
        artifacts.write_json(
            "report.json",
            {
                "run": summary,
                "authorization": {
                    "id": authorization.id,
                    "normalized_target": authorization.normalized_target,
                    "scope_classification": authorization.scope_classification,
                    "statement_present": bool(authorization.statement),
                },
                "target": target,
                "readiness": readiness,
                "plan": plan,
                "tools": tools,
                "findings": findings,
                "coverage": coverage,
                "probe_results": results,
                "errors": errors,
            },
        )
        return {
            "markdown": str(artifacts.run_dir / "report.md"),
            "json": str(artifacts.run_dir / "report.json"),
        }

    @staticmethod
    def _markdown(
        *,
        target,
        readiness,
        plan,
        authorization,
        findings,
        coverage,
        summary,
        tools,
        errors,
    ) -> str:
        lines = [
            "# Dexter Security Assessment",
            "",
            "> This is a bounded deterministic assessment. Incomplete coverage is not evidence of security.",
            "",
            "## Run Information",
            "",
            f"- Run ID: {summary.run_id}",
            f"- Status: {summary.status}",
            f"- Started: {summary.started_at.isoformat()}",
            f"- Ended: {summary.ended_at.isoformat()}",
            f"- Stop reason: {summary.stop_reason}",
            "",
            "## Authorization and Scope",
            "",
            f"- Authorization record: {authorization.id}",
            f"- Normalized target: {authorization.normalized_target}",
            f"- Scope: {authorization.scope_classification}",
            f"- Human statement recorded: {bool(authorization.statement)}",
            "",
            "## Dexter Deployment Summary",
            "",
            f"- Name: {target.deployment_name}",
            f"- Stable ID: {target.stable_id}",
            f"- Deployment type: {target.deployment_type}",
            f"- Main endpoint: {target.main_endpoint}",
            f"- Discovery confidence: {target.discovery_confidence}",
            "",
            "## Component Inventory",
            "",
            "| Component | Type | Status | Endpoint |",
            "| --- | --- | --- | --- |",
        ]
        for component in readiness.components:
            lines.append(
                f"| {component.name} | {component.component_type} | {component.status} | {component.endpoint or ''} |"
            )
        lines.extend(
            [
                "",
                "## Readiness Summary",
                "",
                f"- Overall: {readiness.overall}",
                f"- Available coverage: {', '.join(readiness.available_coverage) or 'none'}",
                f"- Unavailable coverage: {', '.join(readiness.unavailable_coverage) or 'none'}",
                "",
                "## Selected Profile",
                "",
                f"- Profile: {plan.profile}",
                f"- Maximum probes: {plan.budget.max_probes}",
                f"- Maximum duration: {plan.budget.max_duration_seconds} seconds",
                "",
                "## Assessment Plan",
                "",
                "| Step | Phase | Mode | Category | Requests | Operation |",
                "| --- | --- | --- | --- | ---: | --- |",
            ]
        )
        for step in plan.steps:
            lines.append(
                f"| {step.step_id} | {step.phase} | {step.mode} | {step.category} | "
                f"{step.maximum_requests} | {'; '.join(step.expected_operations)} |"
            )
        lines.extend(
            [
                "",
                "## Tools and Model Versions",
                "",
                f"- Tools: {sanitize(tools)}",
                f"- Expected model: {target.model_name or 'not configured'}",
                "",
                "## Findings Summary",
                "",
                "| ID | Severity | Status | Category | Title |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        if findings:
            for finding in findings:
                lines.append(
                    f"| {finding.finding_id} | {finding.severity} | {finding.status} | "
                    f"{finding.category} | {finding.title} |"
                )
        else:
            lines.append("| — | Informational | INFORMATIONAL | coverage | No deterministic finding |")
        lines.extend(["", "## Detailed Findings", ""])
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.finding_id} — {finding.title}",
                    "",
                    f"- Affected component: {finding.affected_component}",
                    f"- Probe: {finding.probe_id}",
                    f"- Confidence: {finding.confidence:.2f}",
                    f"- Technical impact: {finding.technical_impact}",
                    f"- Business impact: {finding.business_impact}",
                    f"- Root cause: {finding.root_cause}",
                    f"- Remediation: {finding.remediation}",
                    f"- Evidence: {', '.join(finding.evidence_references) or 'none'}",
                    f"- Standards: {', '.join(finding.standards)}",
                    f"- Retest: {finding.retest_guidance}",
                    "",
                ]
            )
        lines.extend(
            [
                "## Evidence References",
                "",
                "- Sanitized evidence is stored in the run evidence directory and referenced by stable ID.",
                "",
                "## Coverage",
                "",
                f"- Overall: {coverage.overall_percentage:.1f}%",
                f"- Complete: {coverage.complete}",
                "",
                "| Category | Planned | Completed | Skipped | Failed | Unavailable | Coverage |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for item in coverage.categories:
            lines.append(
                f"| {item.category} | {item.planned_steps} | {item.completed_steps} | "
                f"{item.skipped_steps} | {item.failed_steps} | {item.unavailable_steps} | "
                f"{item.coverage_percentage:.1f}% |"
            )
        lines.extend(
            [
                "",
                "## Errors and Skipped Checks",
                "",
                *([f"- {sanitize(error)}" for error in errors] or ["- None recorded."]),
                "",
                "## Limitations",
                "",
                "- The assessment is deterministic, bounded, and non-destructive.",
                "- Protected or unavailable components remain incomplete coverage.",
                "- No real user data, secrets, or external public infrastructure was used.",
                "- Kali evidence is absent unless explicitly enabled and available.",
                "",
                "## Remediation Priorities",
                "",
                "1. Fix confirmed authentication, authorization, prompt, and tool-boundary findings.",
                "2. Resolve coverage errors that can hide additional risk.",
                "3. Add each fixed probe to deployment regression testing.",
                "",
                "## Retest Recommendations",
                "",
                "- Retest with new synthetic markers after remediation.",
                "- Re-run readiness after model, tool, memory, or deployment changes.",
                "- Do not expand beyond the recorded scope without new authorization.",
                "",
            ]
        )
        return "\n".join(lines)
