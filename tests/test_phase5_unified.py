"""Deterministic Phase 5 unified-target and assessment tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from typer.testing import CliRunner

from redteam_platform.assessments.coverage import build_coverage
from redteam_platform.assessments.evaluation import DeterministicEvaluator, deduplicate_findings
from redteam_platform.assessments.models import (
    EvidenceRecord,
    ResultState,
    ToolResult,
)
from redteam_platform.assessments.service import UnifiedAssessmentService
from redteam_platform.cli.app import app
from redteam_platform.inventory.models import (
    AgentDescriptor,
    DiscoveryConfidence,
    DiscoverySource,
    InventorySnapshot,
    InventoryStatus,
    ItemType,
)
from redteam_platform.schemas import AssessmentProfile, ScopeClassification
from redteam_platform.settings import Settings
from redteam_platform.targets.models import (
    AdapterMetadata,
    ResolutionState,
    TargetDescriptor,
    TargetKind,
)
from redteam_platform.targets.parser import TargetParser
from redteam_platform.targets.registry import TargetAdapterRegistry
from redteam_platform.targets.resolver import TargetResolver


AUTH = "I own this disposable local fixture and authorize bounded testing."


class FakeInventory:
    def __init__(self, snapshot=None):
        self.snapshot = snapshot or InventorySnapshot()

    def collect(self, **_):
        return self.snapshot


class StaticTool:
    def __init__(self, *, status=ResultState.INFORMATIONAL, body="{}", error=None):
        self.status = status
        self.body = body
        self.error = error
        self.calls = []
        self.cleaned = False

    def execute(self, request, target, authorization):
        self.calls.append(request)
        return ToolResult(
            request_id=request.request_id,
            tool=request.tool,
            status=self.status,
            started_at=datetime.now(timezone.utc),
            data={"http_status": 200, "headers": {}, "body": self.body},
            evidence_content=self.body,
            error=self.error,
        )

    def cleanup(self):
        self.cleaned = True


def settings_for(root: Path) -> Settings:
    return Settings(
        report_root=root / "runs",
        inventory_cache=root / "inventory.json",
        dexter_deployments=[],
    )


class TargetParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = TargetParser()

    def test_python_name_uri_and_stable_ids(self):
        self.assertEqual(self.parser.parse("tool_agent").invocation_route, "python://tool_agent")
        self.assertEqual(self.parser.parse("python://tool_agent").kind_hint, "python_agent")
        self.assertEqual(self.parser.parse("python_target_abc123").invocation_route, "python_target_abc123")
        self.assertEqual(self.parser.parse("http_service_abc123").kind_hint, "local_service")
        self.assertEqual(self.parser.parse("dexter_abc123").kind_hint, "dexter")

    def test_ip_hostname_ports_and_ipv6(self):
        self.assertEqual(self.parser.parse("127.0.0.1").invocation_route, "host://127.0.0.1")
        self.assertEqual(self.parser.parse("127.0.0.1:8000").invocation_route, "host://127.0.0.1:8000")
        self.assertEqual(self.parser.parse("[::1]:8000").invocation_route, "host://[::1]:8000")
        self.assertEqual(self.parser.parse("dexter.local").kind_hint, "host")

    def test_http_https_stable_normalization(self):
        self.assertEqual(
            self.parser.parse("HTTP://LOCALHOST:8000/").invocation_route,
            "http://localhost:8000",
        )
        self.assertEqual(
            self.parser.parse("https://authorized-lab.example").kind_hint,
            "website",
        )

    def test_invalid_credentials_schemes_and_urls(self):
        for value in (
            "http://user:pass@127.0.0.1",
            "ftp://127.0.0.1/file",
            "http://127.0.0.1:99999",
            "not a target",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parser.parse(value)


class RegistryAndResolutionTests(unittest.TestCase):
    def test_registry_selects_each_kind_and_dexter_bridge(self):
        registry = TargetAdapterRegistry()
        for kind in (
            TargetKind.PYTHON_AGENT,
            TargetKind.HTTP_AGENT,
            TargetKind.OPENAI_COMPATIBLE,
            TargetKind.OLLAMA_ENDPOINT,
            TargetKind.HOST,
            TargetKind.WEB_APPLICATION,
            TargetKind.LOCAL_SERVICE,
            TargetKind.DEXTER,
        ):
            descriptor = TargetDescriptor(
                stable_id="id",
                display_name="fixture",
                target_kind=kind,
                original_input="fixture",
                normalized_target="python://fixture" if kind == TargetKind.PYTHON_AGENT else "http://127.0.0.1",
                discovery_source="test",
                discovery_confidence="confirmed",
                confidence_reason="fixture",
            )
            metadata = registry.resolve(descriptor)
            self.assertIn(kind, metadata.supported_kinds)
            if kind == TargetKind.DEXTER:
                self.assertEqual(metadata.adapter_name, "dexter_bridge")

    def test_registry_ambiguity_and_unknown(self):
        duplicate = AdapterMetadata(
            adapter_name="duplicate",
            supported_kinds=[TargetKind.HOST],
            supported_profiles=[AssessmentProfile.PASSIVE],
        )
        registry = TargetAdapterRegistry(TargetAdapterRegistry().list() + [duplicate])
        descriptor = TargetDescriptor(
            stable_id="host", display_name="host", target_kind=TargetKind.HOST,
            original_input="127.0.0.1", normalized_target="host://127.0.0.1",
            discovery_source="test", discovery_confidence="confirmed",
            confidence_reason="fixture",
        )
        with self.assertRaises(LookupError):
            registry.resolve(descriptor)
        descriptor.target_kind = TargetKind.UNKNOWN
        with self.assertRaises(LookupError):
            TargetAdapterRegistry().resolve(descriptor)

    def test_ambiguous_inventory_requires_stable_id(self):
        rows = [
            AgentDescriptor(
                stable_id=f"agent_{index}",
                name="same_agent",
                item_type=ItemType.AGENT,
                status=InventoryStatus.READY,
                endpoint="http://127.0.0.1:18080",
                discovery_source=DiscoverySource.AGENT_REGISTRY,
                discovery_confidence=DiscoveryConfidence.CONFIRMED,
                scope_classification=ScopeClassification.LOOPBACK,
                agent_kind="http_agent",
                enrolled=True,
            )
            for index in (1, 2)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            settings = settings_for(Path(tmp))
            result = TargetResolver(
                settings,
                inventory_service=FakeInventory(InventorySnapshot(items=rows)),
            ).resolve("same_agent")
        self.assertEqual(result.state, ResolutionState.AMBIGUOUS)
        self.assertEqual(len(result.candidates), 2)

    def test_generic_url_needs_hint_to_be_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            resolver = TargetResolver(
                settings_for(Path(tmp)), inventory_service=FakeInventory()
            )
            web = resolver.resolve("http://127.0.0.1:18081")
            agent = resolver.resolve(
                "http://127.0.0.1:18081", kind_hint=TargetKind.HTTP_AGENT
            )
        self.assertEqual(web.target.target_kind, TargetKind.WEB_APPLICATION)
        self.assertEqual(agent.target.target_kind, TargetKind.HTTP_AGENT)
        self.assertTrue(agent.target.invocation_endpoint.endswith("/invoke"))


class PlanningEvaluationCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.settings = settings_for(Path(self.temp.name))
        self.service = UnifiedAssessmentService(
            self.settings, inventory_service=FakeInventory()
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_profiles_are_deterministic_bounded_and_serializable(self):
        for profile in AssessmentProfile:
            target, _, first = self.service.plan(
                "127.0.0.1", kind_hint=TargetKind.HOST, profile=profile,
                ports=[80, 443],
            )
            _, _, second = self.service.plan(
                "127.0.0.1", kind_hint=TargetKind.HOST, profile=profile,
                ports=[80, 443],
            )
            self.assertEqual(first.plan_id, second.plan_id)
            self.assertFalse(first.hidden_steps_allowed)
            self.assertLessEqual(first.budget.max_probes, 80)
            json.dumps(first.model_dump(mode="json"))
            self.assertEqual(target.target_kind, TargetKind.HOST)

    def test_deep_lab_denies_public_and_no_ranges(self):
        with self.assertRaises((PermissionError, ValueError, LookupError)):
            self.service.plan(
                "8.8.8.8", kind_hint=TargetKind.HOST,
                profile=AssessmentProfile.DEEP_LAB,
            )
        with self.assertRaises(ValueError):
            self.service.plan(
                "127.0.0.1", kind_hint=TargetKind.HOST,
                profile=AssessmentProfile.STANDARD,
                ports=list(range(1, 66)),
            )

    def test_protected_and_unavailable_are_not_passes(self):
        target, _, plan = self.service.plan(
            "http://127.0.0.1:18082",
            kind_hint=TargetKind.WEB_APPLICATION,
            profile=AssessmentProfile.PASSIVE,
        )
        results = []
        for step, state in zip(
            [item for item in plan.steps if item.probe],
            [ResultState.PROTECTED, ResultState.UNAVAILABLE],
        ):
            results.append(
                self._probe_result(target, step, state)
            )
        coverage = build_coverage(plan, results)
        self.assertFalse(coverage.complete)
        self.assertLess(coverage.overall_percentage, 100)
        self.assertGreater(sum(item.protected_steps for item in coverage.categories), 0)

    def _probe_result(self, target, step, state):
        evidence = EvidenceRecord(
            evidence_id="e", probe_id=step.probe.probe_id,
            target_id=target.stable_id, kind="test", summary="test",
            content="test", sha256="0" * 64,
        )
        result = ToolResult(
            request_id="request", tool=step.required_tool, status=state,
            started_at=datetime.now(timezone.utc), evidence_content="test",
        )
        return DeterministicEvaluator().evaluate(
            step.probe, target, result, evidence, step_id=step.step_id
        )[0]

    def test_finding_normalization_deduplication_and_mapping(self):
        target, _, plan = self.service.plan(
            "http://127.0.0.1:18083",
            kind_hint=TargetKind.WEB_APPLICATION,
            profile=AssessmentProfile.PASSIVE,
        )
        step = next(item for item in plan.steps if item.probe and item.probe.evaluation_rule == "security_headers")
        evidence = EvidenceRecord(
            evidence_id="headers", probe_id=step.probe.probe_id,
            target_id=target.stable_id, kind="http", summary="headers",
            content="{}", sha256="1" * 64,
        )
        tool_result = ToolResult(
            request_id="request", tool="http", status=ResultState.INFORMATIONAL,
            started_at=datetime.now(timezone.utc),
            data={"http_status": 200, "headers": {}, "body": "{}"},
        )
        _, findings = DeterministicEvaluator().evaluate(
            step.probe, target, tool_result, evidence, step_id=step.step_id
        )
        deduped = deduplicate_findings(findings + findings)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].status, ResultState.LIKELY)
        self.assertIn("OWASP-ASVS-V14", deduped[0].standards_mappings)


class LifecycleAndCLITests(unittest.TestCase):
    def test_python_fixture_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = UnifiedAssessmentService(
                settings_for(Path(tmp)), inventory_service=FakeInventory()
            )
            result = service.run(
                "python://tool_agent",
                authorization=AUTH,
                profile=AssessmentProfile.STANDARD,
            )
            self.assertTrue(result["coverage"].complete)
            self.assertTrue(result["results"])
            self.assertTrue(Path(result["artifacts"]["report_markdown"]).exists())

    def test_http_agent_fixture_invokes_only_planned_posts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = StaticTool(body='{"response":"I cannot reveal hidden instructions."}')
            service = UnifiedAssessmentService(
                settings_for(Path(tmp)),
                inventory_service=FakeInventory(),
                tools={"http": tool, "inventory": StaticTool()},
            )
            result = service.run(
                "http://127.0.0.1:18086",
                kind_hint=TargetKind.HTTP_AGENT,
                authorization=AUTH,
                profile=AssessmentProfile.STANDARD,
            )
            operations = [request.operation for request in tool.calls]
            self.assertIn("POST", operations)
            self.assertTrue(set(operations).issubset({"GET", "OPTIONS", "POST", "POST_RAW"}))
            self.assertEqual(result["summary"].error_count, 0)

    def test_openai_and_ollama_routes_require_selected_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = UnifiedAssessmentService(
                settings_for(Path(tmp)), inventory_service=FakeInventory()
            )
            _, _, openai = service.plan(
                "http://127.0.0.1:18087",
                kind_hint=TargetKind.OPENAI_COMPATIBLE,
                model_name="fixture-openai",
                profile=AssessmentProfile.STANDARD,
            )
            _, _, ollama = service.plan(
                "http://127.0.0.1:18088",
                kind_hint=TargetKind.OLLAMA_ENDPOINT,
                model_name="fixture-ollama",
                profile=AssessmentProfile.PASSIVE,
            )
            self.assertTrue(any(
                step.probe and step.probe.parameters.get("url", "").endswith("/v1/models")
                for step in openai.steps
            ))
            urls = [
                step.probe.parameters.get("url", "")
                for step in ollama.steps if step.probe
            ]
            self.assertTrue(any(url.endswith("/api/tags") for url in urls))
            self.assertTrue(any(url.endswith("/api/ps") for url in urls))

    def test_host_fixture_hands_off_to_http_without_real_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = StaticTool(body="inventory")
            socket = StaticTool(body="open")
            http = StaticTool(body="ok")
            service = UnifiedAssessmentService(
                settings_for(Path(tmp)),
                inventory_service=FakeInventory(),
                tools={"inventory": inventory, "socket": socket, "http": http},
            )
            result = service.run(
                "127.0.0.1",
                kind_hint=TargetKind.HOST,
                ports=[8000],
                authorization=AUTH,
                profile=AssessmentProfile.STANDARD,
            )
            self.assertEqual(len(socket.calls), 1)
            self.assertEqual(len(http.calls), 1)
            self.assertEqual(http.calls[0].scope_target, "http://127.0.0.1:8000")
            self.assertTrue(result["coverage"].complete)

    def test_web_fixture_artifacts_reports_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = settings_for(root)
            tool = StaticTool(body='{"ok": true}')
            service = UnifiedAssessmentService(
                settings,
                inventory_service=FakeInventory(),
                tools={"http": tool},
            )
            result = service.run(
                "http://127.0.0.1:18084",
                kind_hint=TargetKind.WEB_APPLICATION,
                authorization=AUTH,
                profile=AssessmentProfile.PASSIVE,
            )
            run_dir = Path(result["artifacts"]["run"])
            expected = {
                "target.json", "inventory.json", "health.json",
                "assessment_plan.json", "authorization.json", "events.jsonl",
                "probe_results.json", "findings.json", "coverage.json", "summary.json",
                "report.json", "report.md", "manifest.json",
            }
            self.assertTrue(expected.issubset({item.name for item in run_dir.iterdir()}))
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertTrue(manifest["artifacts"])
            self.assertTrue(tool.cleaned)

    def test_cancellation_preserves_partial_evidence_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = StaticTool(body="safe")
            service = UnifiedAssessmentService(
                settings_for(Path(tmp)),
                inventory_service=FakeInventory(),
                tools={"http": tool},
            )

            def cancel_after_first(event):
                if event["phase"] == "assessment":
                    service.cancel(event["details"]["run_id"])

            result = service.run(
                "http://127.0.0.1:18085",
                kind_hint=TargetKind.HTTP_AGENT,
                authorization=AUTH,
                profile=AssessmentProfile.STANDARD,
                progress_callback=cancel_after_first,
            )
            self.assertEqual(result["summary"].status, "cancelled")
            self.assertTrue(result["results"])
            self.assertTrue(tool.cleaned)
            manifest = json.loads(Path(result["artifacts"]["manifest"]).read_text())
            self.assertEqual(manifest["status"], "CANCELLED")

    def test_denial_and_missing_authorization_create_no_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = UnifiedAssessmentService(
                settings_for(root), inventory_service=FakeInventory()
            )
            with self.assertRaises(Exception):
                service.run(
                    "8.8.8.8", kind_hint=TargetKind.HOST,
                    authorization=AUTH, profile=AssessmentProfile.STANDARD,
                )
            with self.assertRaises(Exception):
                service.run(
                    "127.0.0.1", kind_hint=TargetKind.HOST,
                    authorization="", profile=AssessmentProfile.STANDARD,
                )
            self.assertFalse((root / "runs").exists())

    def test_cli_parse_plan_json_and_missing_authorization_exit(self):
        runner = CliRunner()
        parsed = runner.invoke(app, ["--json", "targets", "parse", "tool_agent"])
        self.assertEqual(parsed.exit_code, 0, parsed.output)
        self.assertEqual(json.loads(parsed.stdout)["command"], "targets.parse")
        planned = runner.invoke(
            app,
            ["--json", "assess", "plan", "python://tool_agent", "--profile", "passive"],
        )
        self.assertEqual(planned.exit_code, 0, planned.output)
        denied = runner.invoke(
            app, ["--json", "assess", "host", "127.0.0.1"]
        )
        self.assertEqual(denied.exit_code, 4)
