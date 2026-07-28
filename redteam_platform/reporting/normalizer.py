"""Backward-compatible normalization of Phase 1-6 run artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from redteam_platform.reporting.confidence import normalize_confidence
from redteam_platform.reporting.coverage import normalize_legacy_coverage
from redteam_platform.reporting.integrity import verify_manifest
from redteam_platform.reporting.mappings import (
    mappings_for_category,
    remediation_for_structured_finding,
)
from redteam_platform.reporting.models import (
    AdaptiveStatistics,
    AuthorizationSummary,
    CanonicalFinding,
    CanonicalReport,
    EvidenceReference,
    FindingStatus,
    InventorySummary,
    KaliSummary,
    ProbeStatistics,
    ReportMode,
    RiskInputs,
    TargetSummary,
)
from redteam_platform.reporting.redaction import Redactor
from redteam_platform.reporting.risk import calculate_risk
from redteam_platform.reporting.severity import normalize_severity


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def stable_finding_fingerprint(
    *,
    target: str,
    category: str,
    component: str,
    title: str,
) -> str:
    normalized = "|".join(
        re.sub(r"\s+", " ", str(value or "").strip().lower())
        for value in (target, category, component, title)
    )
    return hashlib.sha256(normalized.encode()).hexdigest()


def _status(value: object) -> FindingStatus:
    text = str(value or "").strip().upper()
    return {
        "CONFIRMED": FindingStatus.CONFIRMED,
        "LIKELY": FindingStatus.LIKELY,
        "INFORMATIONAL": FindingStatus.INFORMATIONAL,
        "FALSE_POSITIVE": FindingStatus.FALSE_POSITIVE,
        "RESOLVED": FindingStatus.RESOLVED,
        "MITIGATED": FindingStatus.MITIGATED,
        "ACCEPTED_RISK": FindingStatus.ACCEPTED_RISK,
        "NOT_RETESTED": FindingStatus.NOT_RETESTED,
        "OPEN": FindingStatus.OPEN,
    }.get(text, FindingStatus.OPEN)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class ArtifactNormalizer:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir).resolve()
        if not self.run_dir.is_dir() or not self.run_dir.name.startswith("run_"):
            raise FileNotFoundError(f"Run directory not found: {self.run_dir}")

    def normalize(self, *, mode: ReportMode = ReportMode.INTERNAL) -> CanonicalReport:
        redactor = Redactor(mode)
        summary = _read_json(self.run_dir / "summary.json", {})
        dexter_summary = _read_json(self.run_dir / "dexter_summary.json", {})
        report = _read_json(self.run_dir / "report.json", {})
        target = _read_json(self.run_dir / "dexter_target.json", {})
        if not target and isinstance(report, dict):
            target = report.get("target") or {}
        authorization = _read_json(self.run_dir / "authorization.json", {})
        inventory = _read_json(self.run_dir / "inventory.json", {})
        readiness = _read_json(self.run_dir / "dexter_readiness.json", {})
        plan = _read_json(self.run_dir / "assessment_plan.json", {})
        results = _read_json(self.run_dir / "probe_results.json", [])
        findings_payload = _read_json(self.run_dir / "findings.json", [])
        coverage_payload = _read_json(self.run_dir / "coverage.json", {})
        adaptive = _read_json(self.run_dir / "adaptive_summary.json", {})
        adaptive_state = _read_json(self.run_dir / "adaptive_state.json", {})
        models = _read_json(self.run_dir / "model_roles.json", [])
        kali_plan = _read_json(self.run_dir / "dexter_kali_plan.json", {})
        events = _read_jsonl(self.run_dir / "events.jsonl")

        if not isinstance(summary, dict):
            summary = {}
        if not isinstance(dexter_summary, dict):
            dexter_summary = {}
        if not isinstance(target, dict):
            target = {}
        if not isinstance(results, list):
            results = []
        if not isinstance(findings_payload, list):
            findings_payload = []
        if not isinstance(coverage_payload, dict):
            coverage_payload = {}

        target_id = str(
            summary.get("target_id")
            or dexter_summary.get("target_id")
            or target.get("stable_id")
            or "unknown-target"
        )
        started = _parse_time(summary.get("started_at") or dexter_summary.get("started_at"))
        ended = _parse_time(summary.get("ended_at") or dexter_summary.get("ended_at"))
        duration = max(0, (ended - started).total_seconds()) if started and ended else None
        evidence_index = self._evidence_index(results, redactor)
        findings = [
            self._finding(item, target_id, evidence_index, redactor)
            for item in findings_payload
            if isinstance(item, dict)
        ]
        coverage = normalize_legacy_coverage(coverage_payload, results)
        finding_counts: dict[str, int] = {}
        for finding in findings:
            finding_counts[finding.category] = finding_counts.get(finding.category, 0) + 1
        for category in coverage.categories:
            category.findings = finding_counts.get(category.category, category.findings)
            if category.findings:
                category.state = "finding"
                category.passed = max(0, category.passed - category.findings)
        result_statuses = [str(item.get("status") or "").upper() for item in results if isinstance(item, dict)]
        planned = self._planned_count(plan, coverage)
        completed = sum(
            status in {"PASS", "CONFIRMED", "LIKELY", "INFORMATIONAL"}
            for status in result_statuses
        )
        unavailable = list(readiness.get("unavailable_coverage") or []) if isinstance(readiness, dict) else []
        limitations = sorted(
            {
                str(value)
                for category in coverage.categories
                for value in category.limitations + category.exclusions
            }
            | set(str(value) for value in (adaptive.get("limitations") or []))
        )
        inventory_items = inventory.get("items") if isinstance(inventory, dict) else []
        inventory_items = inventory_items if isinstance(inventory_items, list) else []
        statuses = [str(item.get("status") or "").lower() for item in inventory_items if isinstance(item, dict)]
        target_components = target.get("components") if isinstance(target.get("components"), list) else []
        auth_decision = authorization.get("decision") or authorization.get("policy_decision") or {}
        auth_decision = auth_decision if isinstance(auth_decision, dict) else {}
        errors = [str(item) for item in (summary.get("errors") or report.get("errors") or [])]
        errors.extend(
            str(item.get("error"))
            for item in results
            if isinstance(item, dict) and item.get("error") and str(item.get("status")).upper() != "TIMEOUT"
        )
        timeouts = [
            str(item.get("error") or item.get("probe_id") or "probe timeout")
            for item in results
            if isinstance(item, dict) and str(item.get("status")).upper() == "TIMEOUT"
        ]
        endpoint = target.get("main_endpoint") or target.get("normalized_target")
        environment = {
            "readiness": readiness.get("overall") if isinstance(readiness, dict) else None,
            "model": target.get("model_name"),
            "deployment_type": target.get("deployment_type"),
        }
        model_roles = {
            str(item.get("role") or item.get("provider") or index): str(
                item.get("model") or item.get("name") or "unknown"
            )
            for index, item in enumerate(models if isinstance(models, list) else [])
            if isinstance(item, dict)
        }
        report_model = CanonicalReport(
            report_id=f"report_{hashlib.sha256((self.run_dir.name + ':' + mode).encode()).hexdigest()[:16]}",
            run_id=self.run_dir.name,
            mode=mode,
            assessment_started_at=started,
            assessment_completed_at=ended,
            duration_seconds=duration,
            assessment_status=str(summary.get("status") or dexter_summary.get("status") or "unknown"),
            profile=str(summary.get("profile") or dexter_summary.get("profile") or "unknown"),
            adaptive_mode=str(adaptive.get("mode") or adaptive_state.get("mode") or "off"),
            target=TargetSummary(
                target_id=target_id,
                name=str(target.get("deployment_name") or target.get("display_name") or target_id),
                target_type=str(target.get("deployment_type") or target.get("target_kind") or "unknown"),
                endpoint=redactor.text(str(endpoint)) if endpoint else None,
                reachable=self._reachable(readiness),
                components=redactor.value(target_components),
            ),
            authorization=AuthorizationSummary(
                authorization_id=authorization.get("id"),
                statement_present=bool(
                    authorization.get("statement") or authorization.get("human_authorization_statement")
                ),
                allowed=auth_decision.get("allowed"),
                scope=redactor.text(str(
                    authorization.get("normalized_target")
                    or auth_decision.get("normalized_target")
                    or endpoint
                    or ""
                )),
                scope_classification=str(
                    authorization.get("scope_classification")
                    or auth_decision.get("classification")
                    or target.get("scope_classification")
                    or "unknown"
                ),
                source=authorization.get("source"),
            ),
            methodology=[
                "Revalidated authorized scope before bounded probe execution.",
                "Executed only registered deterministic probes and adapters.",
                "Evaluated responses with deterministic rules; errors and unavailable checks are not passes.",
            ],
            environment=redactor.value(environment),
            inventory=InventorySummary(
                item_count=len(inventory_items),
                ready=statuses.count("ready") + statuses.count("active"),
                degraded=statuses.count("degraded"),
                unavailable=statuses.count("unavailable"),
                items=redactor.value(inventory_items),
                warnings=[str(item) for item in (inventory.get("errors") or [])] if isinstance(inventory, dict) else [],
            ),
            kali=self._kali(
                plan,
                results,
                inventory_items,
                report.get("tools") if isinstance(report, dict) else {},
                kali_plan,
                report.get("kali") if isinstance(report, dict) else {},
                events,
            ),
            assessment_plan=redactor.value(self._plan_summary(plan)),
            probe_statistics=ProbeStatistics(
                planned=planned,
                completed=completed,
                passed=result_statuses.count("PASS"),
                failed=sum(status in {"FAILED", "DENIED", "CANCELLED"} for status in result_statuses),
                findings=len(findings),
                skipped=max(0, sum(item.skipped for item in coverage.categories)),
                unsupported=sum(item.unsupported for item in coverage.categories),
                errors=sum(status in {"ERROR", "COVERAGE_ERROR"} for status in result_statuses),
                timeouts=result_statuses.count("TIMEOUT"),
            ),
            adaptive_statistics=AdaptiveStatistics(
                mode=str(adaptive.get("mode") or adaptive_state.get("mode") or "off"),
                rounds_completed=int(adaptive.get("rounds") or adaptive_state.get("current_round") or 0),
                model_calls=int(adaptive.get("model_calls") or adaptive_state.get("total_model_calls") or 0),
                proposals_accepted=int(adaptive.get("accepted_proposals") or adaptive.get("novel_proposals") or 0),
                proposals_rejected=int(adaptive.get("rejected_proposals") or 0),
                duplicate_proposals=int(adaptive_state.get("duplicate_proposals") or 0),
            ),
            findings=findings,
            evidence_references=list(evidence_index.values()),
            coverage=coverage,
            errors=redactor.value(errors),
            timeouts=redactor.value(timeouts),
            unavailable_capabilities=redactor.value(unavailable),
            skipped_tests=[
                item.category for item in coverage.categories if item.state in {"skipped", "not_tested"}
            ],
            limitations=redactor.value(limitations),
            integrity=verify_manifest(self.run_dir),
            model_roles=model_roles,
            stop_reason=str(summary.get("stop_reason") or dexter_summary.get("stop_reason") or adaptive.get("stop_reason") or ""),
            appendices={
                "source_schema_versions": sorted(
                    {
                        str(value.get("schema_version"))
                        for value in (summary, report, target, coverage_payload)
                        if isinstance(value, dict) and value.get("schema_version")
                    }
                ),
            },
        )
        # Every untrusted source field is redacted as it enters the typed model.
        # A second dictionary-wide pass would mistake the model field named
        # ``authorization`` for an HTTP Authorization header.
        return report_model

    @staticmethod
    def _evidence_index(results: list[dict[str, Any]], redactor: Redactor) -> dict[str, EvidenceReference]:
        index: dict[str, EvidenceReference] = {}
        for result in results:
            if not isinstance(result, dict):
                continue
            for item in result.get("evidence") or []:
                if not isinstance(item, dict):
                    continue
                evidence_id = str(item.get("evidence_id") or item.get("id") or "")
                if not evidence_id:
                    continue
                content = str(item.get("content") or "")
                excerpt = redactor.text(content[:2048]) if content else None
                index[evidence_id] = EvidenceReference(
                    evidence_id=evidence_id,
                    evidence_type=str(item.get("kind") or "text"),
                    source_probe=str(item.get("probe_id") or result.get("probe_id") or "") or None,
                    content_hash=item.get("sha256"),
                    timestamp=_parse_time(item.get("collected_at")),
                    sanitized=True,
                    truncated=len(content) > 2048,
                    description=redactor.text(str(item.get("summary") or "")),
                    excerpt=excerpt,
                )
        return index

    @staticmethod
    def _finding(
        item: dict[str, Any],
        target_id: str,
        evidence_index: dict[str, EvidenceReference],
        redactor: Redactor,
    ) -> CanonicalFinding:
        category = str(item.get("category") or "unclassified")
        component = str(item.get("affected_component") or "")
        title = redactor.text(str(item.get("title") or "Untitled finding"))
        severity = normalize_severity(item.get("severity"))
        confidence = normalize_confidence(item.get("confidence"), item.get("status"))
        fingerprint = str(item.get("fingerprint") or stable_finding_fingerprint(
            target=str(item.get("target_stable_id") or item.get("affected_target") or target_id),
            category=category,
            component=component,
            title=title,
        ))
        evidence = [
            evidence_index[reference]
            for reference in item.get("evidence_references") or []
            if reference in evidence_index
        ]
        standards = mappings_for_category(category)
        return CanonicalFinding(
            finding_id=str(item.get("finding_id") or item.get("id") or fingerprint[:12]),
            fingerprint=fingerprint,
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            status=_status(item.get("status")),
            affected_target=redactor.text(str(
                item.get("target_stable_id") or item.get("affected_target") or target_id
            )),
            affected_component=redactor.text(component),
            affected_endpoint=redactor.text(str(item["affected_endpoint"])) if item.get("affected_endpoint") else None,
            description=redactor.text(str(item.get("description") or item.get("technical_impact") or "")),
            technical_details=redactor.text(str(item.get("technical_details") or item.get("root_cause") or "")),
            evidence_summary="; ".join(reference.description for reference in evidence),
            evidence_references=evidence,
            impact=redactor.text(str(item.get("business_impact") or item.get("impact") or "")),
            likelihood=str(item.get("likelihood") or "unknown"),
            reproduction_guidance=redactor.text(str(
                item.get("reproduction_summary") or item.get("reproduction") or ""
            )),
            safe_validation_steps=[
                redactor.text(str(step)) for step in (item.get("safe_validation_steps") or [])
            ],
            remediation=redactor.text(
                remediation_for_structured_finding(
                    category,
                    str(item.get("root_cause") or ""),
                    str(item.get("remediation") or ""),
                )
            ),
            verification_guidance=redactor.text(str(item.get("retest_guidance") or "")),
            first_observed=_parse_time(item.get("first_seen") or item.get("first_observed")),
            last_observed=_parse_time(item.get("last_seen") or item.get("last_observed")),
            source_probe_ids=[str(item["probe_id"])] if item.get("probe_id") else [],
            source_tool_ids=[str(value) for value in (item.get("source_tool_ids") or [])],
            standards_mappings=standards,
            risk=calculate_risk(
                RiskInputs(
                    technical_severity=severity,
                    confidence=confidence,
                    exposure="unknown",
                    business_impact="unknown",
                )
            ),
            false_positive_rationale=item.get("false_positive_rationale"),
        )

    @staticmethod
    def _planned_count(plan: dict[str, Any], coverage) -> int:
        steps = plan.get("steps") if isinstance(plan, dict) else None
        return len(steps) if isinstance(steps, list) else sum(item.planned for item in coverage.categories)

    @staticmethod
    def _reachable(readiness: dict[str, Any]) -> bool | None:
        if not isinstance(readiness, dict) or not readiness:
            return None
        return str(readiness.get("overall") or "").lower() in {
            "ready", "active", "healthy", "degraded",
        }

    @staticmethod
    def _plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(plan, dict):
            return {}
        budget = plan.get("budget") if isinstance(plan.get("budget"), dict) else {}
        return {
            "plan_id": plan.get("plan_id"),
            "target_id": plan.get("target_id"),
            "profile": plan.get("profile"),
            "steps": len(plan.get("steps") or []),
            "scope_targets": plan.get("scope_targets") or [],
            "budget": budget,
            "deterministic": plan.get("deterministic"),
            "hidden_steps_allowed": plan.get("hidden_steps_allowed"),
        }

    @staticmethod
    def _kali(
        plan: dict[str, Any],
        results: list[dict[str, Any]],
        inventory_items: list[dict[str, Any]],
        report_tools: dict[str, Any],
        kali_plan: dict[str, Any],
        canonical_kali: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> KaliSummary:
        steps = plan.get("steps") if isinstance(plan, dict) else []
        steps = steps if isinstance(steps, list) else []
        kali_steps = [
            item for item in steps
            if isinstance(item, dict) and "kali" in str(item.get("required_tool") or item.get("phase") or "").lower()
        ]
        kali_results = [
            item for item in results
            if isinstance(item, dict)
            and (
                "kali" in str(item.get("probe_id") or "").lower()
                or any(str(item.get("step_id")) == str(step.get("step_id")) for step in kali_steps)
            )
        ]
        configured = bool(kali_steps) or bool(kali_plan.get("enabled")) or any(
            isinstance(item, dict) and "kali" in str(item.get("type") or item.get("name") or "").lower()
            for item in inventory_items
        )
        probe_completed = sum(
            str(item.get("status") or "").upper() in {"PASS", "CONFIRMED", "LIKELY", "INFORMATIONAL"}
            for item in kali_results
        )
        tool_rows = report_tools.get("kali") if isinstance(report_tools, dict) else []
        tool_rows = tool_rows if isinstance(tool_rows, list) else []
        activity_rows = [
            item
            for item in tool_rows
            if isinstance(item, dict)
            and item.get("tool")
            not in {"registered-reverse-tunnel", "registered-reverse-tunnel-cleanup"}
        ]
        completed = sum(
            str(item.get("status") or "").lower() in {"complete", "completed", "pass"}
            and item.get("returncode", 0) == 0
            for item in activity_rows
        ) or probe_completed
        if not completed and isinstance(canonical_kali, dict):
            completed = int(canonical_kali.get("checks_completed") or 0)
        kali_phase_completed = any(
            str(item.get("phase") or "").lower() == "kali"
            and str(item.get("status") or "").lower() in {"complete", "completed"}
            for item in events
        )
        if not completed and kali_plan.get("enabled") and kali_phase_completed:
            completed = len(kali_plan.get("tools") or []) + 2
        skipped = sum(
            str(item.get("status") or "").lower() in {"skipped", "unavailable"}
            for item in activity_rows
        )
        available_tools = sorted(
            {
                str(item.get("tool"))
                for item in activity_rows
                if item.get("tool") in {"nmap", "whatweb", "nikto", "curl"}
                and item.get("returncode", 0) == 0
            }
        )
        if not available_tools and completed:
            available_tools = sorted(str(item) for item in (kali_plan.get("tools") or []))
        return KaliSummary(
            configured=configured,
            reachable=True if completed else None,
            used=bool(kali_results or activity_rows),
            checks_completed=completed,
            checks_skipped=skipped or max(0, len(kali_steps) - probe_completed) if not activity_rows else skipped,
            tools_available=available_tools,
            tunnel_used=bool(kali_plan.get("requires_tunnel")) or any(
                "tunnel" in str(item.get("tool") or "").lower() for item in tool_rows
            ),
        )
