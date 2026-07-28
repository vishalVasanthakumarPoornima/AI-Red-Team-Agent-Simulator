"""Deterministic report analysis and enrichment."""

from __future__ import annotations

from collections import Counter, defaultdict

from redteam_platform.reporting.models import (
    CanonicalReport,
    RemediationItem,
    ReportMode,
)
from redteam_platform.reporting.normalizer import ArtifactNormalizer
from redteam_platform.reporting.severity import severity_rank


class ReportBuilder:
    def build(self, run_dir, *, mode: ReportMode = ReportMode.INTERNAL) -> CanonicalReport:
        report = ArtifactNormalizer(run_dir).normalize(mode=mode)
        report.recommendations = self.remediation_plan(report)
        report.executive_summary = self.executive_summary(report)
        return report

    @staticmethod
    def executive_summary(report: CanonicalReport) -> list[str]:
        counts = Counter(item.severity for item in report.findings if not item.suppressed)
        count_text = ", ".join(
            f"{counts.get(severity, 0)} {severity}"
            for severity in ("critical", "high", "medium", "low", "informational")
        )
        reachable = (
            "reachable" if report.target.reachable is True
            else "not reachable" if report.target.reachable is False
            else "reachability was not conclusively established"
        )
        outcome = (
            f"{len(report.findings)} finding(s) were recorded ({count_text})."
            if report.findings
            else "No findings were recorded in the completed checks; this does not prove security."
        )
        risks = sorted(report.findings, key=lambda item: severity_rank(item.severity), reverse=True)[:3]
        top_risks = (
            "Most significant observed risks: " + "; ".join(item.title for item in risks) + "."
            if risks else "No significant risk was confirmed by completed probes."
        )
        unavailable = (
            "Important unavailable areas: " + ", ".join(report.unavailable_capabilities) + "."
            if report.unavailable_capabilities else "No unavailable area was recorded."
        )
        priorities = (
            "Top remediation priorities: "
            + "; ".join(item.title for item in report.recommendations[:3])
            + "."
            if report.recommendations else "No finding-driven remediation priority was generated."
        )
        return [
            (
                f"{report.target.name} ({report.target.target_type}) was assessed for "
                f"{report.purpose.lower()}; the target was {reachable}."
            ),
            f"Assessment status: {report.assessment_status}. {outcome}",
            top_risks,
            (
                f"Measured coverage was {report.coverage.overall_percentage:.1f}% using the "
                "documented denominator; unavailable, skipped, error, and timeout outcomes are not passes."
            ),
            unavailable,
            (
                f"Kali-assisted testing was {'used' if report.kali.used else 'not used'}; "
                f"adaptive testing was {'used' if report.adaptive_mode != 'off' else 'not used'}."
            ),
            (
                f"The run recorded {len(report.errors)} error(s) and "
                f"{len(report.timeouts)} timeout(s)."
            ),
            priorities,
        ]

    @staticmethod
    def remediation_plan(report: CanonicalReport) -> list[RemediationItem]:
        grouped: dict[tuple[str, str], list] = defaultdict(list)
        for finding in report.findings:
            if finding.suppressed or finding.status in {"resolved", "false_positive"}:
                continue
            root = finding.technical_details.strip().lower() or finding.category
            grouped[(root, finding.remediation.strip())].append(finding)
        items: list[RemediationItem] = []
        for (_, remediation), findings in grouped.items():
            highest = max(severity_rank(item.severity) for item in findings)
            confidence = max(item.risk.ordinal for item in findings)
            priority = "immediate" if highest >= 3 and confidence >= 2 else "near_term" if highest >= 1 else "long_term"
            title = remediation or f"Address {findings[0].category.replace('_', ' ')} controls"
            items.append(
                RemediationItem(
                    priority=priority,
                    title=title,
                    rationale=(
                        f"Addresses {len(findings)} finding(s); highest technical severity is "
                        f"{max(findings, key=lambda item: severity_rank(item.severity)).severity}."
                    ),
                    finding_fingerprints=sorted(item.fingerprint for item in findings),
                    verification=(
                        findings[0].verification_guidance
                        or "Repeat the registered probes and compare evidence-backed outcomes."
                    ),
                )
            )
        priority_order = {"immediate": 0, "near_term": 1, "long_term": 2}
        return sorted(items, key=lambda item: (priority_order[item.priority], item.title.lower()))
