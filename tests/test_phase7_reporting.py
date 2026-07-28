import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from redteam_platform.cli import app
from redteam_platform.reporting.builder import ReportBuilder
from redteam_platform.reporting.comparison import compare_reports
from redteam_platform.reporting.confidence import normalize_confidence
from redteam_platform.reporting.coverage import category_from_counts, summarize_coverage
from redteam_platform.reporting.evidence import EvidenceError, EvidenceResolver
from redteam_platform.reporting.integrity import verify_manifest, write_report_manifest
from redteam_platform.reporting.mappings import mappings_for_category
from redteam_platform.reporting.models import (
    CoverageState,
    FindingConfidence,
    FindingStatus,
    ReportMode,
    RiskInputs,
    Severity,
)
from redteam_platform.reporting.normalizer import (
    ArtifactNormalizer,
    stable_finding_fingerprint,
)
from redteam_platform.reporting.redaction import Redactor
from redteam_platform.reporting.renderers import (
    HtmlRenderer,
    JsonRenderer,
    MarkdownRenderer,
    PdfRenderer,
)
from redteam_platform.reporting.renderers.pdf_renderer import PdfUnavailable
from redteam_platform.reporting.retest import classify_retest
from redteam_platform.reporting.risk import calculate_risk
from redteam_platform.reporting.service import ReportingService, generate_automatic_reports
from redteam_platform.reporting.severity import normalize_severity, severity_rank


def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def create_run(
    root: Path,
    run_id: str,
    *,
    severity: str = "High",
    category: str = "prompt_injection",
    title: str = "Synthetic prompt isolation failure",
    include_finding: bool = True,
    skipped: bool = False,
    coverage: float = 80,
) -> Path:
    run = root / run_id
    run.mkdir()
    write_json(
        run / "summary.json",
        {
            "schema_version": "1.0",
            "run_id": run_id,
            "status": "PASS",
            "target_id": "dexter_synthetic",
            "profile": "standard",
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": "2026-01-01T00:01:00Z",
            "rounds": 2,
            "probes": 2,
            "errors": [],
            "stop_reason": "coverage complete",
        },
    )
    write_json(
        run / "dexter_target.json",
        {
            "schema_version": "1.0",
            "stable_id": "dexter_synthetic",
            "deployment_name": "Synthetic Dexter",
            "deployment_type": "configured_http",
            "main_endpoint": "http://127.0.0.1:8000",
            "scope_classification": "loopback",
            "health": "ready",
            "model_name": "synthetic-model",
            "components": [
                {"stable_id": "api", "name": "API", "component_type": "api", "status": "ready"}
            ],
        },
    )
    write_json(
        run / "authorization.json",
        {
            "id": "auth_synthetic",
            "normalized_target": "http://127.0.0.1:8000",
            "scope_classification": "loopback",
            "statement": "Synthetic authorization statement",
            "source": "human-cli",
            "decision": {"allowed": True, "classification": "loopback"},
        },
    )
    write_json(
        run / "dexter_readiness.json",
        {
            "overall": "ready",
            "available_coverage": ["prompt_security"],
            "unavailable_coverage": ["retrieval"],
            "components": [],
        },
    )
    evidence = {
        "evidence_id": "evidence_synthetic",
        "probe_id": "probe_prompt",
        "component_id": "api",
        "kind": "response",
        "summary": "Synthetic canary crossed the boundary",
        "content": "canary only; token=synthetic-secret",
        "sha256": hashlib.sha256(b"synthetic").hexdigest(),
        "collected_at": "2026-01-01T00:00:30Z",
    }
    status = "NOT_APPLICABLE" if skipped else ("CONFIRMED" if include_finding else "PASS")
    write_json(
        run / "probe_results.json",
        [
            {
                "probe_id": "probe_prompt",
                "step_id": "step_prompt",
                "target_id": "dexter_synthetic",
                "component_id": "api",
                "status": status,
                "evidence": [evidence],
                "duration_seconds": 1.0,
            }
        ],
    )
    finding = {
        "finding_id": "finding_synthetic",
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": 0.98,
        "status": "CONFIRMED",
        "affected_component": "api",
        "target_stable_id": "dexter_synthetic",
        "probe_id": "probe_prompt",
        "evidence_references": ["evidence_synthetic"],
        "reproduction_summary": "Repeat the registered synthetic probe.",
        "technical_impact": "Prompt context may cross an isolation boundary.",
        "business_impact": "Sensitive context could be exposed.",
        "root_cause": "Insufficient context isolation.",
        "remediation": "Strengthen prompt and context isolation.",
        "retest_guidance": "Repeat probe_prompt.",
        "first_seen": "2026-01-01T00:00:30Z",
        "last_seen": "2026-01-01T00:00:30Z",
    }
    write_json(run / "findings.json", [finding] if include_finding else [])
    write_json(
        run / "coverage.json",
        {
            "target_id": "dexter_synthetic",
            "overall_percentage": coverage,
            "complete": not skipped,
            "categories": [
                {
                    "category": category,
                    "planned_steps": 1,
                    "completed_steps": 0 if skipped else 1,
                    "skipped_steps": 1 if skipped else 0,
                    "failed_steps": 0,
                    "unavailable_steps": 0,
                    "coverage_percentage": 0 if skipped else coverage,
                    "limitations": ["probe skipped"] if skipped else [],
                }
            ],
        },
    )
    write_json(
        run / "assessment_plan.json",
        {
            "plan_id": "plan_synthetic",
            "target_id": "dexter_synthetic",
            "profile": "standard",
            "steps": [
                {
                    "step_id": "step_prompt",
                    "category": category,
                    "required_tool": "httpx",
                }
            ],
            "scope_targets": ["http://127.0.0.1:8000"],
            "deterministic": True,
            "hidden_steps_allowed": False,
            "budget": {"max_probes": 2, "max_duration_seconds": 60},
        },
    )
    write_json(
        run / "adaptive_summary.json",
        {
            "mode": "guided",
            "rounds": 2,
            "model_calls": 1,
            "accepted_proposals": 1,
            "rejected_proposals": 0,
            "limitations": [],
        },
    )
    write_json(run / "inventory.json", {"items": [], "errors": []})
    write_json(run / "report.json", {"legacy": True})
    (run / "report.md").write_text("# Legacy synthetic report\n", encoding="utf-8")
    entries = []
    for path in sorted(run.iterdir()):
        if path.name == "manifest.json":
            continue
        data = path.read_bytes()
        entries.append(
            {"path": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        )
    write_json(run / "manifest.json", {"run_id": run_id, "artifacts": entries})
    return run


class CanonicalModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run = create_run(self.root, "run_20260101T000000Z_phase7")

    def tearDown(self):
        self.temp.cleanup()

    def test_phase6_shape_normalizes_and_preserves_nested_objects(self):
        report = ArtifactNormalizer(self.run).normalize()
        self.assertEqual(report.target.target_id, "dexter_synthetic")
        self.assertEqual(report.target.components[0]["component_type"], "api")
        self.assertEqual(report.findings[0].evidence_references[0].evidence_id, "evidence_synthetic")

    def test_schema_round_trip(self):
        report = ReportBuilder().build(self.run)
        parsed = type(report).model_validate_json(report.model_dump_json())
        self.assertEqual(parsed.schema_version, "7.0")

    def test_backward_missing_optional_artifacts(self):
        (self.run / "adaptive_summary.json").unlink()
        report = ArtifactNormalizer(self.run).normalize()
        self.assertEqual(report.adaptive_mode, "off")

    def test_stable_fingerprint(self):
        first = stable_finding_fingerprint(target="A", category="B", component="C", title=" D ")
        second = stable_finding_fingerprint(target="a", category="b", component="c", title="d")
        self.assertEqual(first, second)


class FindingRiskTests(unittest.TestCase):
    def test_severity_order_and_alias(self):
        self.assertGreater(severity_rank("critical"), severity_rank("high"))
        self.assertEqual(normalize_severity("info"), Severity.INFORMATIONAL)

    def test_confidence_numeric_bands(self):
        self.assertEqual(normalize_confidence(.99), FindingConfidence.CONFIRMED)
        self.assertEqual(normalize_confidence(.1), FindingConfidence.LOW)
        self.assertEqual(normalize_confidence(0), FindingConfidence.UNVERIFIED)

    def test_risk_is_ordinal_not_fake_cvss(self):
        result = calculate_risk(
            RiskInputs(
                technical_severity=Severity.HIGH,
                confidence=FindingConfidence.HIGH,
                exposure="network",
            )
        )
        self.assertEqual(result.ordinal, 3)
        self.assertIsNone(result.cvss_score)
        self.assertFalse(result.official_cvss)

    def test_structured_mapping_not_title_keyword(self):
        self.assertTrue(mappings_for_category("prompt_injection"))
        self.assertFalse(mappings_for_category("title says prompt injection"))

    def test_false_positive_requires_rationale(self):
        report = create_run
        self.assertIsNotNone(report)
        self.assertEqual(FindingStatus.FALSE_POSITIVE, "false_positive")


class CoverageTests(unittest.TestCase):
    def test_unavailable_is_not_pass(self):
        item = category_from_counts("retrieval", {"planned": 1, "unavailable": 1})
        self.assertEqual(item.state, CoverageState.UNAVAILABLE)
        self.assertEqual(item.passed, 0)

    def test_timeout_is_not_pass(self):
        item = category_from_counts("api", {"planned": 1, "timeouts": 1})
        self.assertEqual(item.state, CoverageState.TIMEOUT)
        self.assertEqual(item.passed, 0)

    def test_error_is_not_pass(self):
        item = category_from_counts("api", {"planned": 1, "errors": 1})
        self.assertEqual(item.state, CoverageState.ERROR)
        self.assertEqual(item.passed, 0)

    def test_denominator_keeps_unavailable_and_skipped_uncompleted(self):
        summary = summarize_coverage(
            [
                category_from_counts("tested", {"planned": 2, "completed": 2, "passed": 2}),
                category_from_counts("unavailable", {"planned": 1, "unavailable": 1}),
                category_from_counts("skipped", {"planned": 1, "skipped": 1}),
            ]
        )
        self.assertEqual(summary.denominator, 4)
        self.assertEqual(summary.overall_percentage, 50)


class RedactionTests(unittest.TestCase):
    def test_internal_secrets(self):
        output = Redactor().value(
            {
                "api_key": "sk-secret",
                "text": "Authorization: Bearer abc.def token=xyz",
                "cookie": "session=private",
            }
        )
        self.assertNotIn("sk-secret", json.dumps(output))
        self.assertNotIn("abc.def", json.dumps(output))
        self.assertNotIn("xyz", json.dumps(output))

    def test_safe_share_personal_fields_and_paths(self):
        text = (
            "person@example.com +1 (510) 555-1212 "
            "/Users/alice/project /Users/alice/.ssh/id_ed25519"
        )
        output = Redactor(ReportMode.SAFE_SHARE).text(text)
        self.assertNotIn("person@example.com", output)
        self.assertNotIn("555-1212", output)
        self.assertNotIn("/Users/alice", output)

    def test_query_and_credential_url(self):
        output = Redactor().text("https://user:pass@example.test/a?token=secret&safe=1")
        self.assertNotIn("user:pass", output)
        self.assertNotIn("secret", output)
        self.assertIn("safe=1", output)

    def test_escaped_invalid_url_port_does_not_abort_redaction(self):
        output = Redactor().text(r"http://127.0.0.1:11434\\")
        self.assertIn("127.0.0.1", output)

    def test_private_key_material(self):
        key = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
        self.assertNotIn("abc", Redactor().text(key))

    def test_stable_aliases(self):
        redactor = Redactor(ReportMode.SAFE_SHARE)
        self.assertEqual(redactor.text("a@example.com"), redactor.text("a@example.com"))


class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "evidence.txt").write_text("token=secret " + "x" * 50)

    def tearDown(self):
        self.temp.cleanup()

    def test_relative_reference_hash_and_truncation(self):
        reference = EvidenceResolver(self.root).reference(
            "evidence.txt", evidence_id="e1", excerpt_bytes=10
        )
        self.assertTrue(reference.truncated)
        self.assertEqual(len(reference.content_hash), 64)
        self.assertNotIn("secret", reference.excerpt)

    def test_traversal_and_absolute_rejected(self):
        resolver = EvidenceResolver(self.root)
        with self.assertRaises(EvidenceError):
            resolver.resolve("../outside")
        with self.assertRaises(EvidenceError):
            resolver.resolve("/etc/passwd")

    def test_symlink_escape_rejected(self):
        outside = Path(self.temp.name).parent / "phase7-outside.txt"
        outside.write_text("outside")
        link = self.root / "link"
        try:
            link.symlink_to(outside)
            with self.assertRaises(EvidenceError):
                EvidenceResolver(self.root).resolve("link")
        finally:
            if link.exists() or link.is_symlink():
                link.unlink()
            outside.unlink()

    def test_missing_evidence(self):
        with self.assertRaises(FileNotFoundError):
            EvidenceResolver(self.root).resolve("missing.txt")

    def test_modified_and_missing_manifest_fail(self):
        write_report_manifest(self.root, ["evidence.txt"])
        (self.root / "evidence.txt").write_text("changed")
        self.assertEqual(verify_manifest(self.root, "report_manifest.json").status, "failed")
        (self.root / "evidence.txt").unlink()
        self.assertTrue(verify_manifest(self.root, "report_manifest.json").missing)


class RendererServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run = create_run(
            self.root,
            "run_20260101T000001Z_render",
            title="<script>alert(1)</script>",
        )
        self.report = ReportBuilder().build(self.run)

    def tearDown(self):
        self.temp.cleanup()

    def test_json_validity(self):
        parsed = json.loads(JsonRenderer().render(self.report))
        self.assertEqual(parsed["schema_version"], "7.0")
        self.assertIsInstance(parsed["target"], dict)

    def test_markdown_sections_and_no_absolute_path(self):
        output = MarkdownRenderer().render(self.report)
        self.assertIn("## Executive summary", output)
        self.assertIn("## Detailed Findings", output)
        self.assertIn("## Coverage analysis", output)
        self.assertNotIn(str(self.root), output)

    def test_html_escapes_and_is_accessible_local_only(self):
        output = HtmlRenderer().render(self.report)
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertIn("<html lang=\"en\">", output)
        self.assertIn("aria-label", output)
        self.assertIn("@media print", output)
        self.assertNotIn("https://", output)
        self.assertNotIn("<script", output)

    def test_service_build_and_hashes(self):
        result = ReportingService(self.root).build(self.run.name)
        self.assertIn("json", result["outputs"])
        self.assertTrue((self.run / "report_v7.html").is_file())
        self.assertEqual(verify_manifest(self.run, "report_manifest.json").status, "ok")

    def test_versioned_rebuild_never_overwrites_legacy_reports(self):
        legacy_json = (self.run / "report.json").read_bytes()
        legacy_markdown = (self.run / "report.md").read_bytes()
        ReportingService(self.root).build(
            self.run.name,
            formats=["json", "markdown", "html"],
            overwrite=True,
            standard_names=False,
        )
        self.assertEqual((self.run / "report.json").read_bytes(), legacy_json)
        self.assertEqual((self.run / "report.md").read_bytes(), legacy_markdown)
        self.assertTrue((self.run / "report_v7.json").is_file())

    def test_automatic_standard_reports(self):
        generate_automatic_reports(self.root, self.run.name)
        for filename in (
            "report.json", "report.md", "report.html", "report_summary.json",
            "findings_summary.json", "coverage_summary.json", "remediation_plan.json",
            "report_manifest.json",
        ):
            self.assertTrue((self.run / filename).is_file(), filename)

    def test_safe_share_export(self):
        destination = self.root / "export"
        destination.mkdir()
        ReportingService(self.root).export(
            self.run.name, destination, safe_share=True
        )
        combined = (destination / "report.md").read_text() + (destination / "report.html").read_text()
        self.assertIn("SAFE-SHARE", combined)
        self.assertNotIn("/Users/", combined)

    def test_optional_pdf_contract(self):
        target = self.root / "optional.pdf"
        if PdfRenderer.available():
            PdfRenderer().render_to_path(self.report, target)
            self.assertTrue(target.read_bytes().startswith(b"%PDF"))
        else:
            with self.assertRaises(PdfUnavailable):
                PdfRenderer().render_to_path(self.report, target)


class ComparisonRetestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_new_resolved_and_persistent(self):
        old_run = create_run(self.root, "run_20260101T000002Z_old")
        persistent_run = create_run(self.root, "run_20260101T000003Z_persistent")
        resolved_run = create_run(self.root, "run_20260101T000004Z_resolved", include_finding=False)
        old = ReportBuilder().build(old_run)
        persistent = compare_reports(old, ReportBuilder().build(persistent_run))
        resolved = compare_reports(old, ReportBuilder().build(resolved_run))
        reverse = compare_reports(ReportBuilder().build(resolved_run), old)
        self.assertEqual(len(persistent.persistent_findings), 1)
        self.assertEqual(len(resolved.resolved_findings), 1)
        self.assertEqual(len(reverse.new_findings), 1)

    def test_changed_severity(self):
        old = ReportBuilder().build(create_run(self.root, "run_20260101T000005Z_old"))
        new = ReportBuilder().build(
            create_run(self.root, "run_20260101T000006Z_new", severity="Medium")
        )
        comparison = compare_reports(old, new)
        self.assertEqual(comparison.changed_findings[0].changes, ["severity"])

    def test_coverage_regression(self):
        old = ReportBuilder().build(create_run(self.root, "run_20260101T000007Z_old"))
        new = ReportBuilder().build(
            create_run(self.root, "run_20260101T000008Z_new", skipped=True, include_finding=False)
        )
        self.assertLess(compare_reports(old, new).coverage_change, 0)

    def test_skipped_retest_is_not_resolved(self):
        old = ReportBuilder().build(create_run(self.root, "run_20260101T000009Z_old"))
        new = ReportBuilder().build(
            create_run(self.root, "run_20260101T000010Z_new", skipped=True, include_finding=False)
        )
        result = classify_retest(old, new)
        self.assertFalse(result.resolved_findings)
        self.assertIn("not_retested", result.persistent_findings[0].changes)


class ReportingCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run = create_run(self.root, "run_20260101T000011Z_cli")
        self.runner = CliRunner()

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, arguments):
        with patch.dict(os.environ, {"REDTEAM_REPORT_ROOT": str(self.root)}):
            return self.runner.invoke(app, arguments)

    def test_build_human_and_json(self):
        human = self.invoke(["reports", "build", self.run.name, "--format", "html"])
        machine = self.invoke(["reports", "build", self.run.name, "--format", "json", "--json"])
        self.assertEqual(human.exit_code, 0, human.stdout)
        self.assertEqual(machine.exit_code, 0, machine.stdout)
        self.assertTrue(json.loads(machine.stdout)["success"])

    def test_filters_and_coverage(self):
        findings = self.invoke(
            ["reports", "findings", self.run.name, "--severity", "high", "--json"]
        )
        coverage = self.invoke(["reports", "coverage", self.run.name, "--json"])
        self.assertEqual(len(json.loads(findings.stdout)["data"]), 1)
        self.assertIn("overall_percentage", json.loads(coverage.stdout)["data"])

    def test_verify_and_compare(self):
        ReportingService(self.root).build(self.run.name)
        other = create_run(self.root, "run_20260101T000012Z_cli_other", include_finding=False)
        verified = self.invoke(["reports", "verify", self.run.name, "--json"])
        compared = self.invoke(["reports", "compare", self.run.name, other.name, "--json"])
        self.assertEqual(verified.exit_code, 0, verified.stdout)
        self.assertEqual(compared.exit_code, 0, compared.stdout)

    def test_safe_share_and_retest(self):
        other = create_run(self.root, "run_20260101T000013Z_cli_retest", skipped=True, include_finding=False)
        destination = self.root / "shared"
        exported = self.invoke(
            [
                "reports", "export", self.run.name, "--safe-share",
                "--destination", str(destination),
            ]
        )
        retest = self.invoke(["reports", "retest", self.run.name, other.name, "--json"])
        self.assertEqual(exported.exit_code, 0, exported.stdout)
        self.assertEqual(retest.exit_code, 0, retest.stdout)
        self.assertTrue((destination / "report.md").is_file())

    def test_invalid_run_and_traversal_exit(self):
        missing = self.invoke(["reports", "build", "run_missing", "--json"])
        traversal = self.invoke(["reports", "build", "../run_escape", "--json"])
        self.assertNotEqual(missing.exit_code, 0)
        self.assertNotEqual(traversal.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
