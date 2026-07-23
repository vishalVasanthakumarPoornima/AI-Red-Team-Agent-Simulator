import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from redteam_platform.inventory.agents import (
    HTTPAgentDiscovery,
    PythonTargetDiscovery,
    RegistryDiscovery,
)
from redteam_platform.inventory.http_probe import HTTPProbeResult
from redteam_platform.inventory.models import (
    AgentDescriptor,
    DiscoveryConfidence,
    InventoryStatus,
    ServiceEndpoint,
)
from redteam_platform.settings import Settings


ROUTES = ("/health", "/metadata", "/targets", "/openapi.json", "/v1/models")


class FakeProbe:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def get_json(self, base, route):
        self.calls.append(("GET", base, route))
        value = self.mapping.get(route)
        if value:
            return value
        return HTTPProbeResult(
            url=base + route,
            status_code=404,
            error_code="http_error",
            error="HTTP metadata route returned 404.",
        )


def response(route, data=None, status=200, **kwargs):
    return HTTPProbeResult(
        url="http://127.0.0.1:18080" + route,
        status_code=status,
        data=data,
        **kwargs,
    )


class AgentInventoryTests(unittest.TestCase):
    def settings(self):
        return Settings(
            _env_file=None,
            configured_agent_endpoints=["http://127.0.0.1:18080"],
        )

    def discover(self, mapping):
        probe = FakeProbe(mapping)
        items, errors = HTTPAgentDiscovery(self.settings(), probe=probe).collect([], [])
        return items, errors, probe

    def test_enrolled_python_targets_are_imported_without_invocation(self):
        items, errors = PythonTargetDiscovery().collect()
        self.assertEqual(errors, [])
        self.assertEqual(len(items), 6)
        self.assertTrue(all(item.enrolled for item in items))
        self.assertTrue(all(item.callable_contract == "run_agent(prompt)" for item in items))

    def test_enrolled_import_failure_is_partial_not_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.py"
            path.write_text("REDTEAM_TARGET = True\nthis is invalid python", encoding="utf-8")
            row = {"name": "broken", "path": "targets/broken.py", "absolute_path": str(path)}
            with patch(
                "redteam_platform.inventory.agents.discover_targets",
                return_value=[row],
            ):
                items, errors = PythonTargetDiscovery().collect()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].import_status, "error")
        self.assertEqual(errors[0].code, "target_import_failed")

    def test_registry_entry_is_typed_and_not_claimed_online(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(
                '{"agents":[{"name":"fixture","kind":"http","health_url":"http://127.0.0.1:19000/health","invoke_url":"http://127.0.0.1:19000/invoke"}]}',
                encoding="utf-8",
            )
            items, errors = RegistryDiscovery(
                Settings(_env_file=None), registry_path=path
            ).collect()
        self.assertEqual(errors, [])
        self.assertEqual(items[0].status, InventoryStatus.INACTIVE)
        self.assertTrue(items[0].registered)

    def test_project_compatible_service_is_confirmed_agent(self):
        items, errors, probe = self.discover(
            {
                "/health": response("/health", {"status": "ok", "agent": "fixture"}),
                "/metadata": response(
                    "/metadata",
                    {"name": "fixture", "kind": "ollama-langgraph-agent", "invoke": "/invoke"},
                ),
            }
        )
        agent = next(item for item in items if isinstance(item, AgentDescriptor))
        service = next(item for item in items if isinstance(item, ServiceEndpoint))
        self.assertEqual(errors, [])
        self.assertEqual(agent.discovery_confidence, DiscoveryConfidence.CONFIRMED)
        self.assertEqual(service.service_kind, "project_agent_service")
        self.assertTrue(all(call[0] == "GET" for call in probe.calls))
        self.assertFalse(any(call[2] == "/invoke" for call in probe.calls))

    def test_multi_agent_lab_uses_targets_evidence(self):
        items, _, _ = self.discover(
            {
                "/health": response("/health", {"status": "ok", "targets": ["one"]}),
                "/targets": response(
                    "/targets", {"targets": [{"name": "one"}, {"name": "two"}]}
                ),
            }
        )
        service = next(item for item in items if isinstance(item, ServiceEndpoint))
        self.assertEqual(service.service_kind, "project_multi_agent_lab")
        self.assertEqual(service.metadata["target_names"], ["one", "two"])

    def test_openai_compatible_endpoint_is_service_not_agent(self):
        items, _, _ = self.discover(
            {"/v1/models": response("/v1/models", {"data": [{"id": "model"}]})}
        )
        service = next(item for item in items if isinstance(item, ServiceEndpoint))
        self.assertEqual(service.service_kind, "openai_compatible")
        self.assertFalse(any(isinstance(item, AgentDescriptor) for item in items))

    def test_fastapi_openapi_endpoint_is_generic_service(self):
        items, _, _ = self.discover(
            {
                "/openapi.json": response(
                    "/openapi.json",
                    {"openapi": "3.1.0", "paths": {"/health": {"get": {}}}},
                )
            }
        )
        service = next(item for item in items if isinstance(item, ServiceEndpoint))
        self.assertEqual(service.service_kind, "fastapi_application")
        self.assertFalse(any(isinstance(item, AgentDescriptor) for item in items))

    def test_protected_endpoint_exists_without_authentication_bypass(self):
        protected = HTTPProbeResult(
            url="http://127.0.0.1:18080/health",
            status_code=401,
            protected=True,
        )
        items, _, _ = self.discover({route: protected for route in ROUTES})
        service = next(item for item in items if isinstance(item, ServiceEndpoint))
        self.assertEqual(service.status, InventoryStatus.PROTECTED)
        self.assertTrue(service.protected)
        self.assertFalse(any(isinstance(item, AgentDescriptor) for item in items))

    def test_unknown_http_and_invalid_metadata_are_not_agents(self):
        for mapping in (
            {},
            {"/metadata": response("/metadata", ["not", "an", "object"])},
            {"/metadata": response("/metadata", {"name": "generic-service"})},
            {
                "/metadata": response(
                    "/metadata",
                    error_code="response_too_large",
                    error="too large",
                    status=200,
                )
            },
        ):
            with self.subTest(mapping=mapping):
                items, _, _ = self.discover(mapping)
                self.assertTrue(any(isinstance(item, ServiceEndpoint) for item in items))
                self.assertFalse(any(isinstance(item, AgentDescriptor) for item in items))


if __name__ == "__main__":
    unittest.main()
