"""Generic truthful Markdown and JSON reporting."""

from __future__ import annotations

from redteam_platform.assessments.models import (
    AssessmentPlan,
    AssessmentSummary,
    CoverageSummary,
    Finding,
    ProbeResult,
)
from redteam_platform.targets.models import TargetDescriptor, TargetHealth


SECTIONS = (
    "Run information", "Authorization and scope", "Target summary",
    "Target type and capabilities", "Health and discovery", "Profile",
    "Assessment plan", "Tools and versions", "Models and versions",
    "Findings summary", "Detailed findings", "Evidence references",
    "Coverage", "Errors", "Protected and unavailable checks", "Limitations",
    "Remediation priorities", "Retest recommendations",
)


def report_payload(target, health, plan, results, findings, coverage, summary):
    return {
        "schema_version": "1.0",
        "sections": list(SECTIONS),
        "target": target.model_dump(mode="json"),
        "health": health.model_dump(mode="json"),
        "plan": plan.model_dump(mode="json"),
        "results": [item.model_dump(mode="json") for item in results],
        "findings": [item.model_dump(mode="json") for item in findings],
        "coverage": coverage.model_dump(mode="json"),
        "summary": summary.model_dump(mode="json"),
        "limitations": sorted({
            limitation
            for category in coverage.categories
            for limitation in category.limitations
        }),
        "integrity_note": "Artifact hashes are recorded in manifest.json after report generation.",
    }


def markdown_report(
    target: TargetDescriptor,
    health: TargetHealth,
    plan: AssessmentPlan,
    results: list[ProbeResult],
    findings: list[Finding],
    coverage: CoverageSummary,
    summary: AssessmentSummary,
) -> str:
    finding_lines = [
        f"- **{item.severity}** `{item.finding_id}` — {item.title}"
        for item in findings
    ] or ["- No deterministic findings were produced."]
    limitations = sorted({
        limitation for item in coverage.categories for limitation in item.limitations
    })
    tool_names = sorted({step.required_tool for step in plan.steps if step.required_tool})
    capability_lines = [
        f"- `{item.name}`: {'available' if item.available else 'unavailable'} "
        f"(passive={item.passive}, active={item.active})"
        for item in target.capabilities
    ] or ["- No capabilities were confirmed."]
    evidence_lines = [
        f"- `{evidence.evidence_id}` ({evidence.sha256})"
        for result in results for evidence in result.evidence
    ] or ["- No evidence records."]
    return f"""# Red-team assessment: {target.display_name}

## Run information

Run `{summary.run_id}` started {summary.started_at.isoformat()} and ended {summary.ended_at.isoformat()} with status **{summary.status}**.

## Authorization and scope

The run was limited to `{target.normalized_target}`. Authorization details are stored separately in `authorization.json`.

## Target summary

- Stable ID: `{target.stable_id}`
- Name: {target.display_name}
- Normalized target: `{target.normalized_target}`

## Target type and capabilities

- Kind: `{str(target.target_kind)}`
{chr(10).join(capability_lines)}

## Health and discovery

Overall health: **{str(health.overall)}**. Discovery: `{target.discovery_source}` ({target.discovery_confidence}). Related inventory IDs: {', '.join(target.related_inventory_ids) or 'none observed'}.

## Profile

Profile `{str(plan.profile)}`; at most {plan.budget.max_probes} probes and {plan.budget.max_duration_seconds} seconds.

## Assessment plan

Plan `{plan.plan_id}` contained {len(plan.steps)} explicit steps. Hidden steps were disabled.

## Tools and versions

Registered tools: {', '.join(tool_names) or 'none'}. Evaluator: `phase5-evaluator-1.0`. Exact scope revalidation, bounded timeouts, response caps, explicit ports, and argument-array subprocess execution were enforced.

## Models and versions

Selected model: `{target.model_name or 'none'}`. The framework does not infer a model version that the target did not report.

## Findings summary

{len(findings)} findings were produced from {len(results)} probe results.

## Detailed findings

{chr(10).join(finding_lines)}

## Evidence references

{chr(10).join(evidence_lines)}

## Coverage

Overall: {coverage.overall_percentage}% ({'complete' if coverage.complete else 'incomplete'}).

## Errors

{chr(10).join('- ' + item for item in limitations if 'failed' in item or 'timeout' in item) or '- None observed.'}

## Protected and unavailable checks

{chr(10).join('- ' + item for item in limitations if 'protected' in item or 'unavailable' in item or 'timeout' in item) or '- None observed.'}

## Limitations

{chr(10).join('- ' + item for item in limitations) or '- No probe-level limitations recorded.'}

## Remediation priorities

Address confirmed high-severity findings first, then likely configuration findings. Informational observations require contextual review.

## Retest recommendations

Use the same stable target ID and profile after remediation. Compare evidence hashes and finding IDs.
"""
