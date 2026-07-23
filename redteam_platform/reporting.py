"""Enterprise Markdown, HTML, JSON, optional PDF, and safe-share reporting."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from redteam_platform.artifacts import RunArtifacts, sanitize
from redteam_platform.schemas import (
    AssessmentRequest,
    Finding,
    InventorySnapshot,
    ReportMetadata,
    RunSummary,
)


REQUIRED_SECTIONS = [
    "Executive Summary",
    "Scope and Authorization",
    "Assessment Objectives",
    "Target and Service Inventory",
    "Methodology",
    "Tools and Model Versions",
    "Assessment Timeline",
    "Attack Coverage",
    "Findings Summary",
    "Detailed Findings",
    "Evidence",
    "Safe Reproduction Steps",
    "Business and Technical Impact",
    "Remediation Guidance",
    "Risk Prioritization",
    "Coverage Gaps",
    "Errors and Unverified Areas",
    "Limitations",
    "Retest Recommendations",
    "Sanitized Technical Appendix",
]


def _finding_markdown(finding: Finding) -> list[str]:
    lines = [
        f"### {finding.id} — {finding.title}",
        "",
        f"- Category: {finding.category}",
        f"- Severity: {finding.severity}",
        f"- Confidence: {finding.confidence:.2f}",
        f"- Status: {finding.status}",
        f"- Affected target: {finding.affected_target}",
        f"- First seen: {finding.first_seen.isoformat()}",
        f"- Source: {finding.source}",
        f"- Impact: {finding.impact}",
        f"- Root cause: {finding.root_cause}",
        f"- Remediation: {finding.remediation}",
        f"- Standards: {', '.join(finding.standards) or 'Not mapped'}",
        "",
        "Evidence:",
        "",
    ]
    if finding.evidence:
        for item in finding.evidence:
            lines.append(f"- {item.summary} ({item.source})")
    else:
        lines.append("- No persisted evidence excerpt.")
    lines.extend(["", "Safe reproduction:", ""])
    if finding.reproduction:
        lines.extend(f"{index}. {step}" for index, step in enumerate(finding.reproduction, start=1))
    else:
        lines.append("No reproduction steps were retained.")
    lines.append("")
    return lines


class EnterpriseReporter:
    def build_markdown(
        self,
        metadata: ReportMetadata,
        request: AssessmentRequest,
        summary: RunSummary,
        findings: list[Finding],
        inventory: InventorySnapshot,
        events: list[dict[str, Any]],
    ) -> str:
        confirmed = [finding for finding in findings if finding.status == "CONFIRMED"]
        likely = [finding for finding in findings if finding.status == "LIKELY"]
        lines = [
            f"# {metadata.title}",
            "",
            f"Run ID: {metadata.run_id}",
            f"Generated: {metadata.generated_at.isoformat()}",
            f"Target: {metadata.target_name}",
            "",
            "> This bounded assessment is evidence from the configured scope. A passing result does not prove that the target is secure.",
            "",
            "## Executive Summary",
            "",
            f"- Run status: {summary.status}",
            f"- Confirmed findings: {len(confirmed)}",
            f"- Likely findings: {len(likely)}",
            f"- Total probes: {summary.probes}",
            f"- Adaptive rounds: {summary.rounds}",
            f"- Stop reason: {summary.stop_reason}",
            "",
            "## Scope and Authorization",
            "",
            f"- Scope: {metadata.scope}",
            f"- Authorization record: {metadata.authorization_id}",
            f"- Profile: {request.profile}",
            f"- Public mode: {request.authorization.public_mode}",
            f"- Resolved addresses: {', '.join(request.authorization.decision.resolved_addresses) or 'local in-process target'}",
            "",
            "## Assessment Objectives",
            "",
            "- Evaluate the selected target using registered, non-destructive probe templates.",
            "- Preserve deterministic policy and detector decisions as authoritative.",
            "- Record findings, incomplete coverage, and stopping conditions.",
            "",
            "## Target and Service Inventory",
            "",
            "| Name | Type | Status | Source | Scope | Endpoint |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for item in inventory.items:
            lines.append(
                f"| {item.name} | {item.type} | {item.status} | {item.discovery_source} | "
                f"{item.scope_classification} | {item.endpoint or item.local_path or ''} |"
            )
        lines.extend(
            [
                "",
                "## Methodology",
                "",
                "- Observe target health and metadata.",
                "- Form bounded hypotheses from the selected assessment categories.",
                "- Select registered typed probes; model output cannot add destinations or commands.",
                "- Revalidate scope before execution.",
                "- Evaluate responses with deterministic detectors.",
                "- Stop on configured budget, stagnation, health, cancellation, or coverage conditions.",
                "",
                "## Tools and Model Versions",
                "",
                f"- Tools: {json.dumps(metadata.tool_versions, sort_keys=True)}",
                f"- Models: {', '.join(metadata.models_used) or 'No model planner used'}",
                "",
                "## Assessment Timeline",
                "",
                "| # | Phase | Action | Status |",
                "| ---: | --- | --- | --- |",
            ]
        )
        for event in events:
            lines.append(
                f"| {event.get('sequence')} | {event.get('phase')} | "
                f"{event.get('action')} | {event.get('status')} |"
            )
        lines.extend(
            [
                "",
                "## Attack Coverage",
                "",
                f"- Attempted categories: {', '.join(summary.coverage.categories_attempted) or 'none'}",
                f"- Completed categories: {', '.join(summary.coverage.categories_completed) or 'none'}",
                f"- Unique probes: {len(summary.coverage.unique_probe_fingerprints)}",
                "",
                "## Findings Summary",
                "",
                "| ID | Severity | Status | Category | Target | Title |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            lines.append(
                f"| {finding.id} | {finding.severity} | {finding.status} | "
                f"{finding.category} | {finding.affected_target} | {finding.title} |"
            )
        if not findings:
            lines.append("| — | Informational | INFORMATIONAL | coverage | — | No confirmed finding in completed probes |")
        lines.extend(["", "## Detailed Findings", ""])
        for finding in findings:
            lines.extend(_finding_markdown(finding))
        if not findings:
            lines.append("No confirmed or likely findings were produced.")
            lines.append("")

        evidence_count = sum(len(finding.evidence) for finding in findings)
        error_text = "; ".join(summary.errors) or "No execution errors recorded."
        gaps = []
        if summary.status in {"ERROR", "TIMEOUT", "UNPARSED"} or summary.errors:
            gaps.append("Execution errors left incomplete coverage.")
        if not metadata.models_used:
            gaps.append("No model-driven adaptive planner was used.")
        gaps.extend(metadata.limitations)
        lines.extend(
            [
                "## Evidence",
                "",
                f"- Evidence records: {evidence_count}",
                "- Full sanitized evidence is stored under the run evidence directory.",
                "",
                "## Safe Reproduction Steps",
                "",
                "Use the run manifest and registered probe IDs. Do not expand the recorded scope.",
                "",
                "## Business and Technical Impact",
                "",
                "Confirmed and likely findings may affect confidentiality, integrity, authorization boundaries, operational reliability, or provider capacity. Review each finding individually.",
                "",
                "## Remediation Guidance",
                "",
                "Prioritize authorization, least privilege, output validation, secret isolation, rate limits, and regression tests for confirmed findings.",
                "",
                "## Risk Prioritization",
                "",
                "Address Critical and High confirmed findings first, then coverage errors that may hide additional risk.",
                "",
                "## Coverage Gaps",
                "",
                *([f"- {gap}" for gap in gaps] or ["- No known gap beyond the bounded scope."]),
                "",
                "## Errors and Unverified Areas",
                "",
                f"- {error_text}",
                "",
                "## Limitations",
                "",
                "- This is a bounded, non-destructive assessment.",
                "- Rule-based detectors can produce false positives and false negatives.",
                "- External systems are unverified unless their evidence appears in this run.",
                "- No result proves the absence of vulnerabilities.",
                "",
                "## Retest Recommendations",
                "",
                "- Retest after authorization, tool-permission, model, prompt, dependency, or deployment changes.",
                "- Add a deterministic regression case for each confirmed finding.",
                "",
                "## Sanitized Technical Appendix",
                "",
                f"- Run schema version: {summary.schema_version}",
                f"- Report formats: {', '.join(metadata.formats)}",
                f"- Inventory errors: {len(inventory.errors)}",
                "",
            ]
        )
        return "\n".join(lines)

    def write(
        self,
        artifacts: RunArtifacts,
        metadata: ReportMetadata,
        request: AssessmentRequest,
        summary: RunSummary,
        findings: list[Finding],
        inventory: InventorySnapshot,
        events: list[dict[str, Any]],
    ) -> dict[str, str]:
        markdown = self.build_markdown(metadata, request, summary, findings, inventory, events)
        artifacts._write_text("report.md", markdown + "\n")
        html_body = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>" + html.escape(metadata.title) + "</title>"
            "<style>body{font-family:system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;"
            "line-height:1.5}pre{white-space:pre-wrap}table{border-collapse:collapse}"
            "td,th{border:1px solid #ccd;padding:.4rem}h1,h2{color:#17324d}</style></head>"
            "<body><pre>" + html.escape(markdown) + "</pre></body></html>"
        )
        artifacts._write_text("report.html", html_body)
        report_json = {
            "metadata": metadata.model_dump(mode="json"),
            "request": request.model_dump(mode="json"),
            "summary": summary.model_dump(mode="json"),
            "findings": [item.model_dump(mode="json") for item in findings],
            "inventory": inventory.model_dump(mode="json"),
            "events": events,
        }
        artifacts.write_json("report.json", report_json)
        outputs = {
            "markdown": str(artifacts.run_dir / "report.md"),
            "html": str(artifacts.run_dir / "report.html"),
            "json": str(artifacts.run_dir / "report.json"),
        }
        pdf = self._optional_pdf(artifacts, markdown)
        if pdf:
            outputs["pdf"] = str(pdf)
        return outputs

    @staticmethod
    def _optional_pdf(artifacts: RunArtifacts, markdown: str) -> Path | None:
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
        except ImportError:
            return None
        path = artifacts.run_dir / "report.pdf"
        document = canvas.Canvas(str(path), pagesize=letter)
        width, height = letter
        y = height - 48
        for line in markdown.splitlines():
            if y < 48:
                document.showPage()
                y = height - 48
            document.drawString(40, y, line[:110])
            y -= 12
        document.save()
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path

