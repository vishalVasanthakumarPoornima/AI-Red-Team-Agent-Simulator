import json
import os
import stat
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from redteam_platform.inventory.cache import InventoryCache
from redteam_platform.inventory.correlation import InventoryCorrelator
from redteam_platform.inventory.models import (
    AgentDescriptor,
    DiscoveryConfidence,
    DiscoveryEvidence,
    DiscoverySource,
    HealthState,
    InventorySnapshot,
    InventoryStatus,
    Listener,
    RefreshMode,
    ServiceEndpoint,
)
from redteam_platform.schemas import ScopeClassification, utc_now


def listener(stable_id="listener_one", namespace=None):
    return Listener(
        stable_id=stable_id,
        name="python",
        status=InventoryStatus.ACTIVE,
        endpoint="tcp://127.0.0.1:18101",
        host="127.0.0.1",
        port=18101,
        protocol="tcp",
        discovery_source=DiscoverySource.PSUTIL,
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        confidence_reason="fixture",
        health=HealthState.NOT_CHECKED,
        scope_classification=ScopeClassification.LOOPBACK,
        evidence=[
            DiscoveryEvidence(
                source=DiscoverySource.PSUTIL,
                fact="listener",
                value=True,
                confidence=DiscoveryConfidence.CONFIRMED,
            )
        ],
        address="127.0.0.1",
        transport="tcp",
        loopback_only=True,
        network_namespace=namespace,
    )


def service():
    return ServiceEndpoint(
        stable_id="service_one",
        name="weather_insight_agent",
        status=InventoryStatus.ACTIVE,
        endpoint="http://127.0.0.1:18101",
        base_url="http://127.0.0.1:18101",
        host="127.0.0.1",
        port=18101,
        protocol="http",
        discovery_source=DiscoverySource.HTTP_METADATA,
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        confidence_reason="fixture",
        health=HealthState.HEALTHY,
        scope_classification=ScopeClassification.LOOPBACK,
    )


def agent(stable_id="agent_one", item_type="agent", registered=True):
    return AgentDescriptor(
        stable_id=stable_id,
        name="weather_insight_agent",
        item_type=item_type,
        status=InventoryStatus.ACTIVE,
        endpoint=(
            "python://weather_insight_agent"
            if item_type == "python_target"
            else "http://127.0.0.1:18101"
        ),
        local_path=(
            "targets/weather_insight_agent/weather_insight_agent.py"
            if item_type == "python_target"
            else None
        ),
        discovery_source=(
            DiscoverySource.TARGET_MARKER
            if item_type == "python_target"
            else DiscoverySource.AGENT_REGISTRY
        ),
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        confidence_reason="fixture",
        health=HealthState.HEALTHY,
        scope_classification=ScopeClassification.LOOPBACK,
        agent_kind="fixture",
        enrolled=item_type == "python_target",
        registered=registered,
        service_endpoint_id="service_one" if item_type == "agent" else None,
    )


class CorrelationTests(unittest.TestCase):
    def test_listener_service_registry_and_target_are_related_deterministically(self):
        items, correlations = InventoryCorrelator().correlate(
            [
                listener(),
                service(),
                agent(),
                agent("python_one", "python_target", False),
            ]
        )
        by_id = {item.stable_id: item for item in items}
        self.assertIn("service_one", by_id["listener_one"].related_ids)
        self.assertIn("service_one", by_id["agent_one"].related_ids)
        self.assertIn("agent_one", by_id["python_one"].related_ids)
        self.assertTrue(
            all(record.confidence in {"confirmed", "high"} for record in correlations)
        )
        self.assertEqual(len(by_id["listener_one"].evidence), 1)

    def test_ambiguous_same_port_different_namespaces_remains_separate(self):
        first = listener("listener_ns1", "container-a")
        second = listener("listener_ns2", "container-b")
        items, correlations = InventoryCorrelator().correlate(
            [first, second, service()]
        )
        self.assertEqual(correlations, [])
        self.assertTrue(all(not item.related_ids for item in items))

    def test_deduplication_preserves_evidence_and_related_ids(self):
        first = listener()
        second = listener()
        second.related_ids = ["other"]
        items, _ = InventoryCorrelator().correlate([first, second])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].related_ids, ["other"])


class InventoryCacheTests(unittest.TestCase):
    def test_write_read_ttl_stale_permissions_and_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            generated = utc_now()
            snapshot = InventorySnapshot(
                generated_at=generated,
                items=[
                    ServiceEndpoint(
                        **{
                            **service().model_dump(),
                            "metadata": {"api_token": "do-not-store"},
                        }
                    )
                ],
            )
            cache = InventoryCache(path, ttl_seconds=10, source_host_id="host_fixture")
            cache.write(snapshot)
            text = path.read_text()
            self.assertNotIn("do-not-store", text)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
            fresh, error = cache.read(now=generated + timedelta(seconds=5))
            self.assertIsNone(error)
            self.assertTrue(fresh.cached)
            self.assertFalse(fresh.stale)
            stale, error = cache.read(now=generated + timedelta(seconds=11))
            self.assertIsNone(error)
            self.assertTrue(stale.stale)
            self.assertTrue(stale.items[0].stale)

    def test_corrupt_schema_mismatch_and_expired_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            cache = InventoryCache(path, 1, "host")
            path.write_text("{broken", encoding="utf-8")
            _, error = cache.read()
            self.assertEqual(error.code, "cache_corrupt")
            path.write_text(
                json.dumps({"schema_version": "999", "items": []}),
                encoding="utf-8",
            )
            _, error = cache.read()
            self.assertEqual(error.code, "cache_schema_mismatch")
            snapshot = InventorySnapshot(generated_at=utc_now())
            cache.write(snapshot)
            _, error = cache.read(
                allow_stale=False,
                now=snapshot.generated_at + timedelta(seconds=2),
            )
            self.assertEqual(error.code, "cache_expired")

    def test_atomic_failure_preserves_previous_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            cache = InventoryCache(path, 60, "host")
            cache.write(InventorySnapshot())
            original = path.read_text()
            with patch(
                "redteam_platform.inventory.cache.os.replace",
                side_effect=OSError("synthetic"),
            ):
                with self.assertRaises(OSError):
                    cache.write(InventorySnapshot())
            self.assertEqual(path.read_text(), original)
            self.assertEqual(list(path.parent.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
