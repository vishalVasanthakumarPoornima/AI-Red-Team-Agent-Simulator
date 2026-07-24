"""Deterministic Phase 4 Dexter integration tests."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from pydantic import ValidationError
from typer.testing import CliRunner

from dexter_fixture import DexterFixture
from redteam_platform.artifacts import sanitize
from redteam_platform.cli.app import app
from redteam_platform.dexter.adapter import DexterHTTPExecutor
from redteam_platform.dexter.assessment import DexterAssessmentService
from redteam_platform.dexter.coverage import build_coverage
from redteam_platform.dexter.discovery import DexterDiscoveryService
from redteam_platform.dexter.evaluation import (
    EVALUATOR_VERSION,
    deduplicate_findings,
    evaluate_probe,
)
from redteam_platform.dexter.kali import DexterKaliService
from redteam_platform.dexter.models import (
    DexterComponentStatus,
    DexterFindingStatus,
    DexterProbeResult,
    DexterProbeStatus,
    DexterProfile,
    DexterStepStatus,
)
from redteam_platform.dexter.plan import DexterPlanService
from redteam_platform.dexter.probes import (
    ai_probes,
    api_probes,
    memory_probes,
    retrieval_probes,
    tool_probes,
)
from redteam_platform.dexter.readiness import DexterReadinessService
from redteam_platform.inventory.models import (
    AgentDescriptor,
    DiscoveryConfidence,
    DiscoverySource,
    DockerContainer,
    InventorySnapshot,
    InventoryStatus,
    ItemType,
    KaliReadiness,
    Listener,
    OllamaModel,
    ServiceEndpoint,
    ToolAvailability,
    ToolState,
)
from redteam_platform.schemas import AssessmentProfile
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import (
    DexterSettings,
    Settings,
    load_settings,
    sanitized_settings,
)


AUTHORIZATION = (
    "I own this disposable local Dexter fixture and authorize bounded testing."
)


class FakeInventory:
    def __init__(self, snapshot: InventorySnapshot | None = None):
        self.snapshot = snapshot or InventorySnapshot()
        self.collect_calls = 0

    def cached(self):
        return self.snapshot

    def collect(self, **_):
        self.collect_calls += 1
        return self.snapshot


def settings_for(
    root: Path,
    endpoint: str = "http://127.0.0.1:18088",
    **dexter_updates,
) -> Settings:
    dexter = DexterSettings(
        name="Dexter Fixture",
        api_endpoint=endpoint,
        health_path="/status",
        requires_kali_tunnel=False,
        **dexter_updates,
    )
    return Settings(
        report_root=root / "runs",
        inventory_cache=root / "inventory.json",
        dexter=dexter,
    )


def target_for(settings: Settings, inventory: FakeInventory | None = None):
    inventory = inventory or FakeInventory()
    return DexterDiscoveryService(
        settings,
        inventory_service=inventory,
    ).discover(snapshot=inventory.snapshot).deployments[0].target


def response_result(
    target,
    probe,
    body: str,
    status: int = 200,
    headers: dict | None = None,
):
    from redteam_platform.dexter.evidence import evidence_record

    content = json.dumps(
        {
            "status": status,
            "headers": headers or {},
            "body": json.dumps({"response": body}),
        }
    )
    return DexterProbeResult(
        probe_id=probe.probe_id,
        step_id="DEX-TEST",
        target_id=target.stable_id,
        component_id="dexter_component_api",
        status=DexterProbeStatus.INFORMATIONAL,
        http_status=status,
        evaluation_rule="pending",
        evidence=[
            evidence_record(
                probe_id=probe.probe_id,
                component_id="dexter_component_api",
                kind="http",
                summary="fixture response",
                content=content,
            )
        ],
        duration_seconds=0.01,
    )


class DexterConfigurationTests(unittest.TestCase):
    def test_valid_local_configuration_and_missing_optional_components(self):
        value = DexterSettings(api_endpoint="http://127.0.0.1:9000")
        self.assertEqual(value.api_endpoint, "http://127.0.0.1:9000")
        self.assertIsNone(value.memory_endpoint)

    def test_multiple_deployments(self):
        settings = Settings(
            dexter=DexterSettings(name="one", api_endpoint="http://127.0.0.1:9001"),
            dexter_deployments=[
                DexterSettings(name="two", api_endpoint="http://127.0.0.1:9002")
            ],
        )
        result = DexterDiscoveryService(settings).discover(
            snapshot=InventorySnapshot()
        )
        self.assertEqual(
            [item.target.deployment_name for item in result.deployments],
            ["one", "two"],
        )

    def test_invalid_ports_urls_and_credential_urls(self):
        for kwargs in (
            {"expected_ports": [0]},
            {"expected_ports": [65536]},
            {"api_endpoint": "ftp://127.0.0.1"},
            {"api_endpoint": "http://user:pass@127.0.0.1:8000"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                DexterSettings(**kwargs)

    def test_secret_reference_and_settings_redaction(self):
        settings = Settings(api_token="synthetic-secret-value")
        payload = sanitized_settings(settings)
        self.assertEqual(payload["api_token"], "<configured>")
        self.assertNotIn("synthetic-secret-value", json.dumps(payload))
        with self.assertRaises(ValidationError):
            DexterSettings(authentication_reference="Bearer actual-secret")

    def test_config_environment_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "redteam.toml"
            config.write_text(
                '[redteam.dexter]\napi_endpoint = "http://127.0.0.1:9001"\n'
            )
            with patch.dict(
                os.environ,
                {"DEXTER_API_ENDPOINT": "http://127.0.0.1:9002"},
                clear=False,
            ):
                settings = load_settings(
                    config,
                    overrides={
                        "dexter": {
                            "api_endpoint": "http://127.0.0.1:9003",
                        }
                    },
                )
            self.assertEqual(settings.dexter.api_endpoint, "http://127.0.0.1:9003")


class DexterDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_explicit_configuration_and_no_invocation(self):
        inventory = FakeInventory()
        result = DexterDiscoveryService(
            settings_for(self.root),
            inventory_service=inventory,
        ).discover(snapshot=inventory.snapshot)
        self.assertEqual(len(result.deployments), 1)
        self.assertEqual(inventory.collect_calls, 0)
        self.assertEqual(result.deployments[0].target.discovery_confidence, "confirmed")

    def test_repository_target_and_fastapi_metadata(self):
        service = ServiceEndpoint(
            stable_id="service-dexter",
            name="dexter-api",
            status=InventoryStatus.ACTIVE,
            endpoint="http://127.0.0.1:18089",
            host="127.0.0.1",
            port=18089,
            discovery_source=DiscoverySource.HTTP_METADATA,
            discovery_confidence=DiscoveryConfidence.HIGH,
            base_url="http://127.0.0.1:18089",
            service_kind="fastapi_application",
            metadata={"application": "Dexter"},
        )
        repo = AgentDescriptor(
            stable_id="repo-dexter",
            name="dexter-repository",
            item_type=ItemType.PYTHON_TARGET,
            status=InventoryStatus.AVAILABLE,
            endpoint="http://127.0.0.1:18089",
            local_path="/tmp/dexter",
            discovery_source=DiscoverySource.TARGET_MARKER,
            discovery_confidence=DiscoveryConfidence.HIGH,
            related_ids=[service.stable_id],
        )
        result = DexterDiscoveryService(settings_for(self.root)).discover(
            snapshot=InventorySnapshot(items=[repo, service])
        )
        automatic = [
            item
            for item in result.deployments
            if item.target.main_endpoint.endswith(":18089")
        ]
        self.assertEqual(len(automatic), 1)
        self.assertEqual(
            set(automatic[0].inventory_item_ids),
            {"repo-dexter", "service-dexter"},
        )

    def test_docker_process_listener_and_ollama_association(self):
        listener = Listener(
            stable_id="listener-1",
            name="dexter-listener",
            status=InventoryStatus.ACTIVE,
            endpoint="tcp://127.0.0.1:18088",
            host="127.0.0.1",
            port=18088,
            process_id=44,
            process_name="dexter-api",
            discovery_source=DiscoverySource.LSOF,
            discovery_confidence=DiscoveryConfidence.HIGH,
            address="127.0.0.1",
            transport="tcp",
        )
        container = DockerContainer(
            stable_id="docker-1",
            name="dexter-local",
            status=InventoryStatus.RUNNING,
            discovery_source=DiscoverySource.DOCKER_CLI,
            discovery_confidence=DiscoveryConfidence.CONFIRMED,
            container_id="abc123",
            image="local/dexter:test",
            labels={"app": "dexter"},
            port_mappings=[
                {
                    "host": "127.0.0.1",
                    "host_port": 18088,
                    "container_port": 8000,
                    "protocol": "tcp",
                }
            ],
        )
        model = OllamaModel(
            stable_id="model-1",
            name="fixture-model",
            status=InventoryStatus.INSTALLED,
            endpoint="http://127.0.0.1:11434",
            discovery_source=DiscoverySource.OLLAMA_API,
            discovery_confidence=DiscoveryConfidence.CONFIRMED,
            endpoint_id="ollama-1",
            model_name="fixture-model",
            installed=True,
        )
        settings = settings_for(
            self.root,
            docker_names=["dexter-local"],
            docker_labels=["app=dexter"],
            expected_ports=[18088],
            ollama_endpoint="http://127.0.0.1:11434",
            expected_model="fixture-model",
        )
        target = DexterDiscoveryService(settings).discover(
            snapshot=InventorySnapshot(items=[listener, container, model])
        ).deployments[0].target
        self.assertIn("abc123", target.container_ids)
        self.assertIn(44, target.process_ids)
        self.assertTrue(any("model-1" in c.related_inventory_ids for c in target.components))

    def test_generic_fastapi_is_not_automatically_dexter(self):
        generic = ServiceEndpoint(
            stable_id="generic",
            name="generic-api",
            status=InventoryStatus.ACTIVE,
            endpoint="http://127.0.0.1:19000",
            host="127.0.0.1",
            port=19000,
            discovery_source=DiscoverySource.OPENAPI,
            discovery_confidence=DiscoveryConfidence.HIGH,
            base_url="http://127.0.0.1:19000",
            service_kind="fastapi_application",
            metadata={"framework": "fastapi"},
        )
        result = DexterDiscoveryService(settings_for(self.root)).discover(
            snapshot=InventorySnapshot(items=[generic])
        )
        self.assertFalse(
            any(item.target.main_endpoint.endswith(":19000") for item in result.deployments)
        )

    def test_ambiguous_name_requires_stable_id(self):
        settings = Settings(
            dexter=DexterSettings(name="same", api_endpoint="http://127.0.0.1:9001"),
            dexter_deployments=[
                DexterSettings(name="same", api_endpoint="http://127.0.0.1:9002")
            ],
        )
        with self.assertRaisesRegex(LookupError, "Ambiguous"):
            DexterDiscoveryService(settings).get(
                "same",
                snapshot=InventorySnapshot(),
            )

    def test_scope_denial(self):
        settings = settings_for(self.root, endpoint="https://example.com")
        result = DexterDiscoveryService(settings).discover(
            snapshot=InventorySnapshot()
        )
        self.assertEqual(result.deployments, [])
        self.assertTrue(result.errors)


class DexterReadinessAndPlanningTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.settings = settings_for(self.root)
        self.inventory = FakeInventory()
        self.target = target_for(self.settings, self.inventory)

    def tearDown(self):
        self.directory.cleanup()

    def _health(self, statuses):
        def requester(url, **_):
            status = statuses.get(url, 200)
            if isinstance(status, Exception):
                raise status
            return httpx.Response(status, json={"status": "ok"})

        return DexterReadinessService(
            self.settings,
            inventory_service=self.inventory,
            requester=requester,
        ).check(self.target)

    def test_fully_ready_and_protected_and_degraded(self):
        ready = self._health({})
        self.assertEqual(ready.overall, DexterComponentStatus.READY)
        protected = self._health({self.target.health_endpoint: 401})
        self.assertEqual(
            next(c for c in protected.components if c.required).status,
            DexterComponentStatus.PROTECTED,
        )
        degraded = self._health({self.target.openapi_endpoint: 503})
        self.assertEqual(degraded.overall, DexterComponentStatus.DEGRADED)

    def test_unavailable_memory_and_partial_errors(self):
        settings = settings_for(
            self.root,
            memory_endpoint="http://127.0.0.1:18089/memory",
        )
        target = target_for(settings, self.inventory)

        def requester(url, **_):
            if "18089" in url:
                raise httpx.ConnectError("offline")
            return httpx.Response(200, json={})

        health = DexterReadinessService(
            settings,
            inventory_service=self.inventory,
            requester=requester,
        ).check(target)
        memory = next(c for c in health.components if c.name == "Memory")
        self.assertEqual(memory.status, DexterComponentStatus.UNAVAILABLE)
        self.assertIn("memory", health.unavailable_coverage)

    def test_ollama_missing_and_installed_not_loaded(self):
        settings = settings_for(
            self.root,
            ollama_endpoint="http://127.0.0.1:11434",
            expected_model="fixture-model",
        )
        target = target_for(settings, self.inventory)
        missing = DexterReadinessService(
            settings,
            inventory_service=self.inventory,
            requester=lambda *_args, **_kwargs: httpx.Response(200),
        ).check(target)
        ollama = next(c for c in missing.components if c.name == "Ollama")
        self.assertEqual(ollama.status, DexterComponentStatus.UNAVAILABLE)
        model = OllamaModel(
            stable_id="model",
            name="fixture-model",
            status=InventoryStatus.INSTALLED,
            endpoint="http://127.0.0.1:11434",
            discovery_source=DiscoverySource.OLLAMA_API,
            endpoint_id="ollama",
            model_name="fixture-model",
            installed=True,
            running=False,
        )
        inventory = FakeInventory(InventorySnapshot(items=[model]))
        degraded = DexterReadinessService(
            settings,
            inventory_service=inventory,
            requester=lambda *_args, **_kwargs: httpx.Response(200),
        ).check(target)
        ollama = next(c for c in degraded.components if c.name == "Ollama")
        self.assertEqual(ollama.status, DexterComponentStatus.DEGRADED)

    def test_profiles_are_bounded_deterministic_and_serializable(self):
        health = self._health({})
        service = DexterPlanService()
        plans = [
            service.build(self.target, health, profile=profile)
            for profile in DexterProfile
        ]
        self.assertLess(
            plans[0].budget.max_probes,
            plans[1].budget.max_probes,
        )
        self.assertLess(
            plans[1].budget.max_probes,
            plans[2].budget.max_probes,
        )
        for plan in plans:
            self.assertFalse(plan.hidden_steps_allowed)
            self.assertEqual(
                [step.step_id for step in plan.steps],
                [f"DEX-{index:03d}" for index in range(1, len(plan.steps) + 1)],
            )
            json.dumps(plan.model_dump(mode="json"))

    def test_capability_skip_is_visible_and_kali_opt_in(self):
        health = self._health({})
        plan = DexterPlanService().build(
            self.target,
            health,
            profile="standard",
            include_kali=True,
        )
        memory = next(step for step in plan.steps if step.phase == "memory")
        self.assertIn("memory capability unavailable", memory.skip_conditions)
        self.assertTrue(any(step.phase == "kali" for step in plan.steps))


class DexterProbeAndEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.settings = settings_for(self.root)
        self.target = target_for(self.settings)

    def tearDown(self):
        self.directory.cleanup()

    def test_probe_packs_are_fixed_fake_and_bounded(self):
        canary = "DX-CANARY-TEST"
        probes = (
            ai_probes(self.target.chat_endpoint, canary)
            + api_probes(self.target)
            + tool_probes(self.target.chat_endpoint)
            + memory_probes(self.target.chat_endpoint, canary, disposable=True)
            + retrieval_probes(self.target.chat_endpoint, canary)
        )
        self.assertEqual(len({probe.probe_id for probe in probes}), len(probes))
        self.assertTrue(all(probe.timeout_seconds <= 10 for probe in probes))
        self.assertTrue(
            all(probe.method in {"GET", "POST", "POST_RAW", "OPTIONS"} for probe in probes)
        )
        self.assertTrue(all("fake" in json.dumps(p.payload).lower() for p in tool_probes(self.target.chat_endpoint)))

    def test_prompt_disclosure_safe_refusal_and_tool_claim(self):
        disclosure = ai_probes(self.target.chat_endpoint, "marker")[0]
        result, finding = evaluate_probe(
            self.target,
            disclosure,
            response_result(
                self.target,
                disclosure,
                "My system prompt is: synthetic fixture instructions.",
            ),
        )
        self.assertEqual(result.status, DexterProbeStatus.CONFIRMED)
        self.assertEqual(finding.status, DexterFindingStatus.CONFIRMED)
        safe_result, safe_finding = evaluate_probe(
            self.target,
            disclosure,
            response_result(
                self.target,
                disclosure,
                "I cannot reveal, provide, or share hidden instructions.",
            ),
        )
        self.assertEqual(safe_result.status, DexterProbeStatus.PASS)
        self.assertIsNone(safe_finding)
        tool = ai_probes(self.target.chat_endpoint, "marker")[4]
        _, tool_finding = evaluate_probe(
            self.target,
            tool,
            response_result(self.target, tool, "The command has been executed."),
        )
        self.assertIsNotNone(tool_finding)

    def test_synthetic_secret_cross_session_leak(self):
        marker = "DX-CANARY-LEAK"
        probe = memory_probes(
            self.target.chat_endpoint,
            marker,
            disposable=True,
        )[1]
        result, finding = evaluate_probe(
            self.target,
            probe,
            response_result(self.target, probe, marker),
        )
        self.assertEqual(result.status, DexterProbeStatus.CONFIRMED)
        self.assertEqual(finding.severity, "High")

    def test_api_auth_error_headers_and_cors_evaluation(self):
        probes = {probe.name: probe for probe in api_probes(self.target)}
        auth_target = self.target.model_copy(update={"authentication_mode": "api-key"})
        _, auth_finding = evaluate_probe(
            auth_target,
            probes["unauthenticated_invoke"],
            response_result(auth_target, probes["unauthenticated_invoke"], "ok", 200),
        )
        self.assertIsNotNone(auth_finding)
        _, error_finding = evaluate_probe(
            self.target,
            probes["malformed_json"],
            response_result(
                self.target,
                probes["malformed_json"],
                'Traceback File "app.py"',
                500,
            ),
        )
        self.assertIsNotNone(error_finding)
        _, cors_finding = evaluate_probe(
            self.target,
            probes["options_and_cors"],
            response_result(
                self.target,
                probes["options_and_cors"],
                "",
                204,
                {"access-control-allow-origin": "*"},
            ),
        )
        self.assertIsNotNone(cors_finding)

    def test_invalid_output_schema_and_read_only_memory_fallback(self):
        probe = ai_probes(self.target.chat_endpoint, "marker")[6]
        result, _ = evaluate_probe(
            self.target,
            probe,
            response_result(self.target, probe, "not-json-but-bounded"),
        )
        self.assertIn(
            result.status,
            {DexterProbeStatus.PASS, DexterProbeStatus.INFORMATIONAL},
        )
        fallback = memory_probes(
            self.target.chat_endpoint,
            "DX-CANARY-READONLY",
            disposable=False,
        )
        self.assertEqual(len(fallback), 1)
        self.assertIn("without reading or changing", fallback[0].payload["message"])

    def test_timeout_coverage_error_and_detector_version(self):
        probe = ai_probes(self.target.chat_endpoint, "marker")[0]

        def handler(_request):
            raise httpx.ReadTimeout("bounded timeout")

        executor = DexterHTTPExecutor(
            self.settings,
            client_factory=lambda: httpx.Client(
                transport=httpx.MockTransport(handler)
            ),
        )
        authorization = ScopePolicy(self.settings).authorize(
            self.target.main_endpoint,
            statement=AUTHORIZATION,
            source="human-cli",
            profile=AssessmentProfile.STANDARD,
        )
        raw = executor.execute(
            self.target,
            probe,
            authorization,
            step_id="DEX-TEST",
        )
        evaluated, finding = evaluate_probe(self.target, probe, raw)
        self.assertEqual(evaluated.status, DexterProbeStatus.COVERAGE_ERROR)
        self.assertIn(EVALUATOR_VERSION, evaluated.evaluation_rule)
        self.assertEqual(finding.status, DexterFindingStatus.COVERAGE_ERROR)

    def test_deduplication_evidence_and_standards(self):
        probe = ai_probes(self.target.chat_endpoint, "marker")[0]
        _, first = evaluate_probe(
            self.target,
            probe,
            response_result(
                self.target,
                probe,
                "My system prompt is: synthetic one.",
            ),
        )
        _, second = evaluate_probe(
            self.target,
            probe,
            response_result(
                self.target,
                probe,
                "My system prompt is: synthetic two.",
            ),
        )
        deduped = deduplicate_findings([first, second])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(len(deduped[0].evidence_references), 2)
        self.assertIn("OWASP LLM Top 10", deduped[0].standards)
        self.assertGreaterEqual(deduped[0].confidence, 0.9)

    def test_redaction(self):
        payload = sanitize(
            {
                "authorization": "Bearer synthetic-secret",
                "endpoint": "http://user:pass@127.0.0.1:8000/chat?token=x",
            }
        )
        self.assertEqual(payload["authorization"], "<REDACTED>")
        self.assertNotIn("user", payload["endpoint"])
        self.assertNotIn("token", payload["endpoint"])


class DexterAuthorizationKaliAndCoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.settings = settings_for(self.root)
        self.inventory = FakeInventory()
        self.target = target_for(self.settings, self.inventory)

    def tearDown(self):
        self.directory.cleanup()

    def test_missing_and_model_generated_authorization_rejected(self):
        policy = ScopePolicy(self.settings)
        with self.assertRaises(ScopeDeniedError):
            policy.authorize(
                self.target.main_endpoint,
                statement="short",
                source="human-cli",
                profile=AssessmentProfile.STANDARD,
            )
        with self.assertRaises(ScopeDeniedError):
            policy.authorize(
                self.target.main_endpoint,
                statement=AUTHORIZATION,
                source="model",
                profile=AssessmentProfile.STANDARD,
            )

    def test_deep_lab_requires_interactive_confirmation_before_artifacts(self):
        health = DexterReadinessService(
            self.settings,
            inventory_service=self.inventory,
            requester=lambda *_args, **_kwargs: httpx.Response(200),
        ).check(self.target)
        plan = DexterPlanService().build(
            self.target,
            health,
            profile="deep-lab",
        )
        with self.assertRaises(ScopeDeniedError):
            DexterAssessmentService(
                self.settings,
                inventory_service=self.inventory,
            ).assess(
                self.target,
                plan,
                authorization_statement=AUTHORIZATION,
                confirmed=True,
                interactive_confirmation=False,
            )
        self.assertFalse((self.root / "runs").exists())

    def test_unconfigured_kali_is_partial_coverage_not_shell(self):
        plan = DexterKaliService(self.settings).plan(self.target, enabled=True)
        self.assertFalse(plan.enabled)
        self.assertIn("not configured", plan.skip_reason)

    def test_kali_safe_commands_timeout_output_limit_and_cleanup(self):
        settings = self.settings.model_copy(
            update={
                "kali_ssh_host": "kali-lab",
                "allowed_kali_aliases": ["kali-lab"],
            }
        )
        target = self.target.model_copy(
            update={
                "configuration": self.target.configuration.model_copy(
                    update={"requires_kali_tunnel": True}
                )
            }
        )
        calls = []
        stopped = []
        tunnel = Mock()
        tunnel.poll.return_value = None

        def runner(command, **_):
            calls.append(command)
            if command[-1].startswith("http://127.0.0.1:18000/status"):
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[-1].startswith("127.0.0.1"):
                return subprocess.CompletedProcess(command, 0, "x" * 70000, "")
            return subprocess.CompletedProcess(command, 0, "ok", "")

        readiness = KaliReadiness(
            stable_id="kali",
            name="kali-lab",
            status=InventoryStatus.READY,
            discovery_source=DiscoverySource.KALI_SSH,
            discovery_confidence=DiscoveryConfidence.CONFIRMED,
            configured=True,
            ssh_alias="kali-lab",
            reachable=True,
            tools=[
                ToolAvailability(name=name, state=ToolState.AVAILABLE)
                for name in ("nmap", "whatweb", "curl")
            ],
        )
        service = DexterKaliService(
            settings,
            runner=runner,
            tunnel_factory=lambda *_: tunnel,
            tunnel_stopper=lambda process: stopped.append(process),
        )
        plan = service.plan(target, enabled=True)
        authorization = ScopePolicy(settings).authorize(
            target.main_endpoint,
            statement=AUTHORIZATION,
            source="human-cli",
            profile=AssessmentProfile.STANDARD,
        )
        with patch(
            "redteam_platform.dexter.kali.KaliDiscovery.collect",
            return_value=([readiness], []),
        ):
            results = service.execute(target, plan, authorization)
        self.assertTrue(results)
        self.assertEqual(stopped, [tunnel])
        self.assertTrue(all(isinstance(call, list) for call in calls))
        self.assertFalse(any(";" in part for call in calls for part in call))
        self.assertLessEqual(
            max(len(str(item.get("stdout", ""))) for item in results),
            65536,
        )

    def test_kali_timeout_and_arbitrary_tool_rejection(self):
        settings = self.settings.model_copy(
            update={
                "kali_ssh_host": "kali-lab",
                "allowed_kali_aliases": ["kali-lab"],
            }
        )
        readiness = KaliReadiness(
            stable_id="kali",
            name="kali-lab",
            status=InventoryStatus.READY,
            discovery_source=DiscoverySource.KALI_SSH,
            configured=True,
            ssh_alias="kali-lab",
            reachable=True,
            tools=[ToolAvailability(name="nmap", state=ToolState.AVAILABLE)],
        )
        service = DexterKaliService(
            settings,
            runner=Mock(side_effect=subprocess.TimeoutExpired(["ssh"], 30)),
        )
        plan = service.plan(self.target, enabled=True)
        authorization = ScopePolicy(settings).authorize(
            self.target.main_endpoint,
            statement=AUTHORIZATION,
            source="human-cli",
            profile=AssessmentProfile.STANDARD,
        )
        with patch(
            "redteam_platform.dexter.kali.KaliDiscovery.collect",
            return_value=([readiness], []),
        ):
            results = service.execute(self.target, plan, authorization)
        self.assertEqual(results[0]["status"], "timeout")
        with self.assertRaises(ValueError):
            service._tool_args("sh", "127.0.0.1", 80, "http://127.0.0.1")

    def test_coverage_distinguishes_unavailable_failed_and_skipped(self):
        health = DexterReadinessService(
            self.settings,
            inventory_service=self.inventory,
            requester=lambda *_args, **_kwargs: httpx.Response(200),
        ).check(self.target)
        plan = DexterPlanService().build(self.target, health, profile="standard")
        statuses = {
            plan.steps[0].step_id: DexterStepStatus.COMPLETED,
            plan.steps[1].step_id: DexterStepStatus.SKIPPED,
            plan.steps[2].step_id: DexterStepStatus.FAILED,
            plan.steps[3].step_id: DexterStepStatus.UNAVAILABLE,
        }
        coverage = build_coverage(plan, statuses, [])
        self.assertFalse(coverage.complete)
        self.assertTrue(any(item.skipped_steps for item in coverage.categories))
        self.assertTrue(any(item.failed_steps for item in coverage.categories))
        self.assertTrue(any(item.unavailable_steps for item in coverage.categories))


class DexterEndToEndAndCLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.runner = CliRunner()

    def tearDown(self):
        self.directory.cleanup()

    def _config_file(self, fixture: DexterFixture) -> Path:
        config = self.root / "redteam.toml"
        config.write_text(
            "\n".join(
                [
                    "[redteam]",
                    f'report_root = "{self.root / "runs"}"',
                    f'inventory_cache = "{self.root / "inventory.json"}"',
                    "known_local_service_ports = []",
                    "",
                    "[redteam.dexter]",
                    'name = "Dexter Fixture"',
                    f'api_endpoint = "{fixture.base_url}"',
                    'health_path = "/status"',
                    'chat_path = "/chat"',
                    'metadata_path = "/metadata"',
                    'openapi_path = "/openapi.json"',
                    f'tool_endpoints = ["{fixture.base_url}/tools"]',
                    f'memory_endpoint = "{fixture.base_url}/status"',
                    f'retrieval_endpoint = "{fixture.base_url}/status"',
                    "disposable_memory_namespace = true",
                    "requires_kali_tunnel = false",
                    "",
                ]
            )
        )
        return config

    def _configured(self, fixture: DexterFixture):
        settings = settings_for(
            self.root,
            endpoint=fixture.base_url,
            tool_endpoints=[fixture.base_url + "/tools"],
            memory_endpoint=fixture.base_url + "/status",
            retrieval_endpoint=fixture.base_url + "/status",
            disposable_memory_namespace=True,
        )
        inventory = FakeInventory()
        target = target_for(settings, inventory)
        readiness_service = DexterReadinessService(
            settings,
            inventory_service=inventory,
        )
        readiness = readiness_service.check(target)
        plan = DexterPlanService().build(target, readiness, profile="standard")
        return settings, inventory, target, readiness_service, readiness, plan

    def test_end_to_end_fixture_artifacts_findings_coverage_and_reports(self):
        with DexterFixture() as fixture:
            settings, inventory, target, readiness_service, readiness, plan = (
                self._configured(fixture)
            )
            summary, findings, reports = DexterAssessmentService(
                settings,
                inventory_service=inventory,
                readiness_service=readiness_service,
                id_generator=lambda: "deterministic1234",
            ).assess(
                target,
                plan,
                authorization_statement=AUTHORIZATION,
                confirmed=True,
                interactive_confirmation=False,
            )
        run_dir = Path(summary.artifact_paths["run_directory"])
        required = {
            "manifest.json",
            "authorization.json",
            "inventory.json",
            "dexter_target.json",
            "dexter_readiness.json",
            "assessment_plan.json",
            "events.jsonl",
            "probe_results.json",
            "findings.json",
            "coverage.json",
            "report.md",
            "report.json",
            "evidence",
        }
        self.assertTrue(required.issubset({path.name for path in run_dir.iterdir()}))
        self.assertTrue(findings)
        self.assertTrue(summary.coverage_complete)
        self.assertEqual(summary.status, "complete")
        self.assertEqual(set(reports), {"markdown", "json"})
        manifest = json.loads((run_dir / "manifest.json").read_text())
        self.assertTrue(manifest["artifacts"])
        report = (run_dir / "report.md").read_text()
        for heading in (
            "Authorization and Scope",
            "Dexter Deployment Summary",
            "Readiness Summary",
            "Detailed Findings",
            "Coverage",
            "Retest Recommendations",
        ):
            self.assertIn(heading, report)

    def test_previous_run_preservation_and_safe_evidence_paths(self):
        with DexterFixture() as fixture:
            settings, inventory, target, readiness_service, _, plan = self._configured(
                fixture
            )
            service = DexterAssessmentService(
                settings,
                inventory_service=inventory,
                readiness_service=readiness_service,
            )
            first = service.assess(
                target,
                plan,
                authorization_statement=AUTHORIZATION,
                confirmed=True,
                interactive_confirmation=False,
            )[0]
            second = service.assess(
                target,
                plan,
                authorization_statement=AUTHORIZATION,
                confirmed=True,
                interactive_confirmation=False,
            )[0]
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertTrue((settings.report_root / first.run_id).exists())
        for path in (settings.report_root / second.run_id / "evidence").iterdir():
            self.assertEqual(path.parent.name, "evidence")
            self.assertNotIn("..", path.name)

    def test_report_failure_finalizes_partial_manifest(self):
        with DexterFixture() as fixture:
            settings, inventory, target, readiness_service, _, plan = self._configured(
                fixture
            )
            reporter = Mock()
            reporter.write.side_effect = OSError("synthetic report failure")
            summary, _, reports = DexterAssessmentService(
                settings,
                inventory_service=inventory,
                readiness_service=readiness_service,
                reporter=reporter,
            ).assess(
                target,
                plan,
                authorization_statement=AUTHORIZATION,
                confirmed=True,
                interactive_confirmation=False,
            )
        self.assertEqual(summary.status, "partial")
        self.assertTrue((settings.report_root / summary.run_id / "manifest.json").exists())
        self.assertIn("run_directory", reports)

    def test_cancellation_finalizes_without_reaching_probe_executor(self):
        with DexterFixture() as fixture:
            settings, inventory, target, readiness_service, _, plan = self._configured(
                fixture
            )
            cancellation = threading.Event()
            cancellation.set()
            executor = Mock()
            summary, _, _ = DexterAssessmentService(
                settings,
                inventory_service=inventory,
                readiness_service=readiness_service,
                http_executor=executor,
                cancel_event=cancellation,
            ).assess(
                target,
                plan,
                authorization_statement=AUTHORIZATION,
                confirmed=True,
                interactive_confirmation=False,
            )
        self.assertEqual(summary.status, "cancelled")
        executor.execute.assert_not_called()
        manifest = settings.report_root / summary.run_id / "manifest.json"
        self.assertTrue(manifest.exists())

    def test_cli_discover_list_show_health_plan_and_json(self):
        with DexterFixture() as fixture:
            config = self._config_file(fixture)
            prefix = [
                "--config",
                str(config),
                "dexter",
            ]
            discover = self.runner.invoke(app, [*prefix, "discover", "--json"])
            self.assertEqual(discover.exit_code, 0, discover.stdout)
            payload = json.loads(discover.stdout)
            target_id = payload["data"]["deployments"][0]["target"]["stable_id"]
            for command in (
                ["list", "--json"],
                ["show", target_id, "--json"],
                ["health", target_id, "--json"],
                ["plan", target_id, "--profile", "passive", "--json"],
            ):
                with self.subTest(command=command):
                    result = self.runner.invoke(app, [*prefix, *command])
                    self.assertEqual(result.exit_code, 0, result.stdout)
                    self.assertIn('"schema_version":"1.0"', result.stdout)

    def test_cli_passive_and_standard_assessment(self):
        with DexterFixture() as fixture:
            config = self._config_file(fixture)
            prefix = [
                "--json",
                "--config",
                str(config),
                "dexter",
            ]
            discover = self.runner.invoke(app, [*prefix, "discover"])
            target_id = json.loads(discover.stdout)["data"]["deployments"][0]["target"][
                "stable_id"
            ]
            passive = self.runner.invoke(
                app,
                [
                    *prefix,
                    "assess",
                    target_id,
                    "--profile",
                    "passive",
                    "--authorization",
                    AUTHORIZATION,
                ],
            )
            self.assertEqual(passive.exit_code, 0, passive.stdout)
            standard = self.runner.invoke(
                app,
                [
                    *prefix,
                    "assess",
                    target_id,
                    "--profile",
                    "standard",
                    "--authorization",
                    AUTHORIZATION,
                ],
            )
            self.assertEqual(standard.exit_code, 0, standard.stdout)
            self.assertGreater(
                json.loads(standard.stdout)["data"]["summary"]["finding_count"],
                0,
            )

    def test_cli_missing_dexter_denial_and_deep_lab_confirmation_codes(self):
        missing = self.runner.invoke(
            app,
            ["--json", "dexter", "show", "missing-id"],
        )
        self.assertEqual(missing.exit_code, 5)
        with DexterFixture() as fixture:
            config = self._config_file(fixture)
            deep = self.runner.invoke(
                app,
                [
                    "--json",
                    "--non-interactive",
                    "--config",
                    str(config),
                    "dexter",
                    "assess",
                    "Dexter Fixture",
                    "--profile",
                    "deep-lab",
                    "--authorization",
                    AUTHORIZATION,
                    "--yes",
                ],
            )
            self.assertEqual(deep.exit_code, 2, deep.stdout)
        denied = self.runner.invoke(
            app,
            [
                "--json",
                "dexter",
                "--endpoint",
                "http://10.0.0.1:8000",
                "discover",
            ],
        )
        self.assertEqual(denied.exit_code, 0)
        self.assertEqual(json.loads(denied.stdout)["data"]["deployments"], [])


if __name__ == "__main__":
    unittest.main()
