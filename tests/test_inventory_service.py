import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from redteam_platform.inventory.models import (
    AgentDescriptor,
    DiscoveryConfidence,
    DiscoveryError,
    DiscoverySource,
    HealthState,
    InventorySnapshot,
    InventoryStatus,
    KaliReadiness,
    OllamaModel,
)
from redteam_platform.inventory.service import InventoryService
from redteam_platform.schemas import ScopeClassification
from redteam_platform.settings import Settings


class FakeAdapter:
    def __init__(self, items=None, errors=None, raises=False):
        self.items = items or []
        self.errors = errors or []
        self.raises = raises
        self.calls = 0

    def collect(self):
        self.calls += 1
        if self.raises:
            raise RuntimeError("synthetic")
        return self.items, self.errors


class FakeHTTP(FakeAdapter):
    def collect(self, listeners, registry):
        return super().collect()


class FakeKali(FakeAdapter):
    def collect(self, live=False):
        return super().collect()


def python_target(stable_id="python_one"):
    return AgentDescriptor(
        stable_id=stable_id,
        name="fixture",
        item_type="python_target",
        status=InventoryStatus.READY,
        endpoint="python://fixture",
        discovery_source=DiscoverySource.TARGET_MARKER,
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        confidence_reason="fixture",
        health=HealthState.HEALTHY,
        scope_classification=ScopeClassification.LOOPBACK,
        agent_kind="python_target",
        enrolled=True,
    )


def ollama_model(running=True):
    return OllamaModel(
        stable_id="model_one",
        name="fixture:latest",
        status=InventoryStatus.RUNNING if running else InventoryStatus.INSTALLED,
        endpoint="http://127.0.0.1:11434",
        discovery_source=DiscoverySource.OLLAMA_API,
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        confidence_reason="fixture",
        health=HealthState.HEALTHY,
        scope_classification=ScopeClassification.LOOPBACK,
        endpoint_id="endpoint_one",
        model_name="fixture:latest",
        installed=True,
        running=running,
    )


def active_http_agent():
    return AgentDescriptor(
        stable_id="http_agent_one",
        name="fixture-http-agent",
        item_type="agent",
        status=InventoryStatus.ACTIVE,
        endpoint="http://127.0.0.1:18101",
        discovery_source=DiscoverySource.HTTP_METADATA,
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        confidence_reason="fixture",
        health=HealthState.HEALTHY,
        scope_classification=ScopeClassification.LOOPBACK,
        agent_kind="project_agent_service",
    )


class InventoryServiceTests(unittest.TestCase):
    def make_service(self, directory, adapters):
        settings = Settings(
            _env_file=None,
            inventory_cache=Path(directory) / "cache.json",
            report_root=Path(directory) / "runs",
        )
        return InventoryService(settings, adapters=adapters)

    def test_full_inventory_summary_stable_sort_and_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            target = python_target()
            kali = KaliReadiness(
                stable_id="kali_one",
                name="Kali",
                status=InventoryStatus.NOT_CONFIGURED,
                discovery_source=DiscoverySource.CONFIGURATION,
                discovery_confidence=DiscoveryConfidence.CONFIRMED,
                confidence_reason="fixture",
                health=HealthState.NOT_CHECKED,
                scope_classification=ScopeClassification.UNKNOWN,
            )
            service = self.make_service(
                directory,
                {
                    "listeners": FakeAdapter(),
                    "python_targets": FakeAdapter([target, target.model_copy(deep=True)]),
                    "agent_registry": FakeAdapter(),
                    "ollama": FakeAdapter([ollama_model()]),
                    "http": FakeHTTP([active_http_agent()]),
                    "docker": FakeAdapter(),
                    "kali": FakeKali([kali]),
                },
            )
            snapshot = service.collect(include_docker=True, include_kali=True)
        self.assertEqual(len([item for item in snapshot.items if item.stable_id == "python_one"]), 1)
        self.assertEqual(snapshot.summary.enrolled_python_targets, 1)
        self.assertEqual(snapshot.summary.installed_ollama_models, 1)
        self.assertEqual(snapshot.summary.running_ollama_models, 1)
        self.assertEqual(snapshot.summary.active_compatible_agents, 1)
        self.assertEqual(snapshot.summary.docker_status, "available")
        self.assertEqual(snapshot.summary.kali_status, "not_configured")
        self.assertTrue(snapshot.adapter_runs)
        self.assertTrue(
            all(run.duration_seconds >= 0 for run in snapshot.adapter_runs)
        )
        self.assertTrue(
            all(str(run.state) == "success" for run in snapshot.adapter_runs)
        )
        self.assertEqual(
            [item.stable_id for item in snapshot.items],
            [item.stable_id for item in sorted(snapshot.items, key=lambda item: (str(item.item_type), item.name.lower(), item.stable_id))],
        )

    def test_partial_adapter_failure_preserves_errors_and_valid_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            service = self.make_service(
                directory,
                {
                    "listeners": FakeAdapter(raises=True),
                    "python_targets": FakeAdapter([python_target()]),
                    "agent_registry": FakeAdapter(),
                    "ollama": FakeAdapter(
                        errors=[
                            DiscoveryError(
                                source="ollama",
                                code="unavailable",
                                message="synthetic",
                            )
                        ]
                    ),
                    "http": FakeHTTP(),
                },
            )
            snapshot = service.collect(include_docker=False, include_kali=False)
        self.assertEqual(snapshot.summary.enrolled_python_targets, 1)
        self.assertEqual(snapshot.summary.error_count, 2)
        self.assertEqual(
            {error.code for error in snapshot.errors},
            {"adapter_exception", "unavailable"},
        )

    def test_cached_only_and_force_refresh_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            target_adapter = FakeAdapter([python_target()])
            service = self.make_service(
                directory,
                {
                    "listeners": FakeAdapter(),
                    "python_targets": target_adapter,
                    "agent_registry": FakeAdapter(),
                    "ollama": FakeAdapter(),
                    "http": FakeHTTP(),
                },
            )
            first = service.collect()
            cached = service.collect(cached_only=True)
            forced = service.collect(force_refresh=True)
        self.assertFalse(first.cached)
        self.assertTrue(cached.cached)
        self.assertEqual(target_adapter.calls, 2)
        self.assertEqual(str(forced.refresh_mode), "force_refresh")

    def test_inventory_artifact_is_hashed_registered_and_requires_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            service = self.make_service(directory, {})
            run_id = "run_inventory_fixture"
            run_dir = service.settings.report_root / run_id
            run_dir.mkdir(parents=True)
            snapshot = InventorySnapshot(items=[python_target()])
            path = service.attach_to_run(run_id, snapshot)
            data = path.read_bytes()
            manifest = json.loads((run_dir / "manifest.json").read_text())
            artifact = next(
                item for item in manifest["artifacts"] if item["path"] == "inventory.json"
            )
            self.assertEqual(artifact["sha256"], hashlib.sha256(data).hexdigest())
            with self.assertRaises(FileExistsError):
                service.attach_to_run(run_id, snapshot)
            service.attach_to_run(run_id, snapshot, overwrite=True)
            self.assertEqual(
                len(
                    [
                        item
                        for item in json.loads(
                            (run_dir / "manifest.json").read_text()
                        )["artifacts"]
                        if item["path"] == "inventory.json"
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
