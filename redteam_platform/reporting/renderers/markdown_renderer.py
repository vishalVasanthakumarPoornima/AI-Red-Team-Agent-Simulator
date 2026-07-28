"""GitHub-compatible Markdown renderer with conditional sections."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from redteam_platform.reporting.models import CanonicalReport


def _anchor(value: str) -> str:
    return "-".join("".join(character.lower() if character.isalnum() else " " for character in value).split())


def _table(headers: list[str], rows: Iterable[list[object]]) -> list[str]:
    output = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    output.extend("| " + " | ".join(str(value).replace("|", "\\|") for value in row) + " |" for row in rows)
    return output


class MarkdownRenderer:
    media_type = "text/markdown"
    suffix = ".md"

    def render(self, report: CanonicalReport) -> str:
        banner = (
            "SAFE-SHARE REPORT — personal and machine-specific details are aliased."
            if report.mode == "safe_share"
            else "INTERNAL REPORT — authorized technical detail; secrets remain redacted."
        )
        lines = [
            f"# {report.branding.report_title}",
            "",
            f"> **{banner}**",
            "",
            f"**Run:** `{report.run_id}`  ",
            f"**Target:** {report.target.name}  ",
            f"**Classification:** {report.branding.classification_label}  ",
            f"**Generated:** {report.generated_at.isoformat()}",
            "",
            "## Document control",
            "",
            *_table(
                ["Field", "Value"],
                [
                    ["Report ID", report.report_id],
                    ["Schema", report.schema_version],
                    ["Version", report.branding.report_version],
                    ["Mode", report.mode],
                    ["Owner", report.branding.assessment_owner],
                ],
            ),
            "",
            "## Executive summary",
            "",
            *[f"- {item}" for item in report.executive_summary],
            "",
            "## Assessment outcome",
            "",
            f"- Status: **{report.assessment_status}**",
            f"- Profile: `{report.profile}`",
            f"- Duration: {report.duration_seconds if report.duration_seconds is not None else 'unknown'} seconds",
            f"- Stop reason: {report.stop_reason or 'not recorded'}",
            "",
            "## Scope and authorization — Authorization and Scope",
            "",
            f"- Authorized scope: `{report.authorization.scope}`",
            f"- Scope classification: `{report.authorization.scope_classification}`",
            f"- Authorization record present: {'yes' if report.authorization.statement_present else 'no'}",
            "",
            "## Target overview — Dexter Deployment Summary",
            "",
            f"- Stable ID: `{report.target.target_id}`",
            f"- Type: `{report.target.target_type}`",
            f"- Endpoint: `{report.target.endpoint or 'not recorded'}`",
            f"- Reachable: {report.target.reachable if report.target.reachable is not None else 'unverified'}",
            "",
        ]
        if report.inventory.item_count or report.environment:
            lines.extend(["## Environment and inventory — Readiness Summary", ""])
            lines.extend(
                _table(
                    ["Inventory items", "Ready", "Degraded", "Unavailable"],
                    [[report.inventory.item_count, report.inventory.ready, report.inventory.degraded, report.inventory.unavailable]],
                )
            )
            lines.extend(["", f"- Environment: `{report.environment}`", ""])
        if report.target.components:
            lines.extend(["## Architecture and component summary", ""])
            lines.extend(
                _table(
                    ["Component", "Type", "Status"],
                    [
                        [
                            item.get("name") or item.get("stable_id") or "component",
                            item.get("component_type") or "unknown",
                            item.get("status") or "unknown",
                        ]
                        for item in report.target.components
                    ],
                )
            )
            lines.append("")
        lines.extend(
            [
                "## Methodology",
                "",
                *[f"- {item}" for item in report.methodology],
                "",
                "## Assessment profiles and safety controls",
                "",
                "- Exact authorized targets and registered probes were used.",
                "- Models could not add destinations, commands, tools, or budgets.",
                "- Unavailable, skipped, error, and timeout outcomes are not security passes.",
                "",
                "## Attack surface",
                "",
                f"- Planned probes: {report.probe_statistics.planned}",
                f"- Completed probes: {report.probe_statistics.completed}",
                f"- Available components: {len(report.target.components)}",
                "",
                "## Findings summary",
                "",
            ]
        )
        severity_counts = Counter(item.severity for item in report.findings)
        lines.extend(
            _table(
                ["Critical", "High", "Medium", "Low", "Informational"],
                [[severity_counts.get(item, 0) for item in ("critical", "high", "medium", "low", "informational")]],
            )
        )
        lines.extend(["", "## Detailed Findings", ""])
        if not report.findings:
            lines.extend(["No findings were recorded by completed probes.", ""])
        for finding in report.findings:
            lines.extend(
                [
                    f"### {finding.finding_id}: {finding.title}",
                    "",
                    f"<a id=\"{_anchor(finding.finding_id)}\"></a>",
                    f"- Fingerprint: `{finding.fingerprint}`",
                    f"- Severity / confidence: **{finding.severity}** / **{finding.confidence}**",
                    f"- Status: `{finding.status}`",
                    f"- Category: `{finding.category}`",
                    f"- Component: `{finding.affected_component or 'target-wide'}`",
                    f"- Risk: **{finding.risk.rating}** (qualitative ordinal {finding.risk.ordinal}/4)",
                    f"- Risk inputs: `{finding.risk.inputs.model_dump(mode='json')}`",
                    "",
                    finding.description or finding.technical_details or "No additional description was retained.",
                    "",
                    f"**Impact:** {finding.impact or 'Contextual review required.'}",
                    "",
                    f"**Evidence:** {finding.evidence_summary or 'See referenced run evidence.'}",
                    "",
                    f"**Remediation:** {finding.remediation or 'Review and strengthen the affected control.'}",
                    "",
                ]
            )
        categories = {item.category for item in report.findings}
        conditional = [
            ("AI and prompt-security results", {"prompt_injection", "prompt_disclosure", "synthetic_secret", "weak_refusal"}),
            ("Tool and authorization-boundary results", {"tool_security", "unsafe_tool_claim", "authorization"}),
            ("Memory and retrieval results", {"memory", "retrieval"}),
            ("API and web-security results", {"api_surface", "authentication", "web_security", "missing_security_headers"}),
            ("Host and service-exposure results", {"host_security", "service_exposure"}),
        ]
        for title, relevant in conditional:
            selected = [item for item in report.findings if item.category in relevant]
            if selected:
                lines.extend([f"## {title}", "", *[f"- `{item.finding_id}` — {item.title}" for item in selected], ""])
        if report.kali.configured or report.kali.used:
            lines.extend(
                [
                    "## Kali-assisted results",
                    "",
                    f"- Used: {report.kali.used}",
                    f"- Checks completed: {report.kali.checks_completed}",
                    f"- Checks skipped: {report.kali.checks_skipped}",
                    f"- Bounded tunnel used: {report.kali.tunnel_used}",
                    "",
                ]
            )
        if report.adaptive_mode != "off":
            lines.extend(
                [
                    "## Adaptive assessment activity",
                    "",
                    f"- Mode: `{report.adaptive_statistics.mode}`",
                    f"- Rounds: {report.adaptive_statistics.rounds_completed}",
                    f"- Model calls: {report.adaptive_statistics.model_calls}",
                    f"- Accepted proposals: {report.adaptive_statistics.proposals_accepted}",
                    f"- Rejected proposals: {report.adaptive_statistics.proposals_rejected}",
                    "",
                ]
            )
        lines.extend(["## Coverage analysis", ""])
        lines.extend(
            _table(
                ["Category", "State", "Planned", "Completed", "Passed", "Findings", "Unavailable", "Error", "Timeout", "Coverage"],
                [
                    [
                        item.category, item.state, item.planned, item.completed, item.passed,
                        item.findings, item.unavailable, item.errors, item.timeouts,
                        f"{item.percentage:.1f}%",
                    ]
                    for item in report.coverage.categories
                ],
            )
        )
        lines.extend(["", f"Overall: **{report.coverage.overall_percentage:.1f}%**. {report.coverage.denominator_explanation}", ""])
        if report.errors or report.timeouts or report.unavailable_capabilities or report.skipped_tests:
            lines.extend(
                [
                    "## Errors, timeouts, and unavailable tests",
                    "",
                    *[f"- Error: {item}" for item in report.errors],
                    *[f"- Timeout: {item}" for item in report.timeouts],
                    *[f"- Unavailable: {item}" for item in report.unavailable_capabilities],
                    *[f"- Skipped: {item}" for item in report.skipped_tests],
                    "",
                ]
            )
        lines.extend(["## Risk analysis", "", "- Ratings are qualitative, evidence-backed ordinals; no official CVSS score is claimed without complete metrics.", ""])
        if report.recommendations:
            lines.extend(["## Prioritized remediation plan", ""])
            for priority in ("immediate", "near_term", "long_term"):
                selected = [item for item in report.recommendations if item.priority == priority]
                if selected:
                    lines.extend([f"### {priority.replace('_', ' ').title()}", ""])
                    lines.extend(f"- **{item.title}** — {item.rationale}" for item in selected)
                    lines.append("")
        lines.extend(
            [
                "## Retest guidance — Retest Recommendations",
                "",
                "- Re-run the same registered probes after remediation and compare stable finding fingerprints.",
                "- A finding is not resolved when its relevant probe is skipped, unavailable, errors, or times out.",
                "",
                "## Artifact and evidence integrity",
                "",
                f"- Status: **{report.integrity.status}**",
                f"- Hashes verified: {report.integrity.hashes_verified}/{report.integrity.files_checked}",
                f"- Missing: {len(report.integrity.missing)}; modified: {len(report.integrity.modified)}; invalid paths: {len(report.integrity.invalid_paths)}",
                "",
                "### Evidence references",
                "",
                *(
                    [
                        f"- `{item.evidence_id}` · probe `{item.source_probe or 'unknown'}` · "
                        f"{item.description or item.evidence_type} · hash "
                        f"`{item.content_hash or 'not recorded'}`"
                        for item in report.evidence_references[:50]
                    ]
                    or ["- No structured evidence references were retained."]
                ),
                "",
                "## Limitations and assumptions",
                "",
                "- This report provides bounded security-assessment evidence, not compliance certification.",
                "- Absence of a finding does not prove absence of a vulnerability.",
                *[f"- {item}" for item in report.limitations],
                "",
                "## Appendices",
                "",
                f"- Tools: `{report.tool_versions}`",
                f"- Model roles: `{report.model_roles}`",
                f"- Source schema versions: `{report.appendices.get('source_schema_versions', [])}`",
                "",
                f"_{report.branding.footer_text}_",
                "",
            ]
        )
        return "\n".join(lines)
