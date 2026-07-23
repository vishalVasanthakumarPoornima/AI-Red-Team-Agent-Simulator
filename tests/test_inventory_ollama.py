import unittest

from redteam_platform.inventory.http_probe import HTTPProbeResult, SafeHTTPProbe
from redteam_platform.inventory.models import InventoryStatus, OllamaEndpoint, OllamaModel
from redteam_platform.inventory.ollama import OllamaDiscovery
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings


class FakeProbe:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def get_json(self, base, route):
        self.calls.append(("GET", base, route))
        return self.results[route]


def result(route, data=None, status=200, error_code=None, error=None, redirect=None):
    return HTTPProbeResult(
        url="http://127.0.0.1:11434" + route,
        status_code=status,
        data=data,
        latency_seconds=0.01,
        error_code=error_code,
        error=error,
        redirect_location=redirect,
    )


class OllamaInventoryTests(unittest.TestCase):
    def settings(self, **updates):
        return Settings(
            _env_file=None,
            ollama_endpoints=["http://127.0.0.1:11434"],
            ollama_live_check=True,
            **updates,
        )

    def test_available_endpoint_version_installed_and_running_models(self):
        probe = FakeProbe(
            {
                "/api/version": result("/api/version", {"version": "0.9.1"}),
                "/api/tags": result(
                    "/api/tags",
                    {
                        "models": [
                            {
                                "name": "fixture:latest",
                                "size": 100,
                                "digest": "digest",
                                "modified_at": "2026-01-01T00:00:00Z",
                                "details": {
                                    "parameter_size": "1B",
                                    "quantization_level": "Q4",
                                },
                            },
                            {"name": "installed-only:latest", "size": 50},
                        ]
                    },
                ),
                "/api/ps": result(
                    "/api/ps",
                    {
                        "models": [
                            {
                                "name": "fixture:latest",
                                "size": 90,
                                "size_vram": 80,
                                "context_length": 4096,
                                "expires_at": "2026-01-01T01:00:00Z",
                            }
                        ]
                    },
                ),
            }
        )
        items, errors = OllamaDiscovery(self.settings(), probe=probe).collect()
        endpoint = next(item for item in items if isinstance(item, OllamaEndpoint))
        models = [item for item in items if isinstance(item, OllamaModel)]
        running = next(item for item in models if item.model_name == "fixture:latest")
        installed_only = next(
            item for item in models if item.model_name == "installed-only:latest"
        )
        self.assertEqual(errors, [])
        self.assertEqual(endpoint.version, "0.9.1")
        self.assertEqual(endpoint.installed_model_count, 2)
        self.assertEqual(endpoint.running_model_count, 1)
        self.assertTrue(running.installed)
        self.assertTrue(running.running)
        self.assertEqual(running.vram_bytes, 80)
        self.assertTrue(installed_only.installed)
        self.assertFalse(installed_only.running)
        self.assertEqual([call[0] for call in probe.calls], ["GET", "GET", "GET"])

    def test_empty_model_lists_are_distinguished_from_unavailability(self):
        probe = FakeProbe(
            {
                "/api/version": result("/api/version", {"version": "1"}),
                "/api/tags": result("/api/tags", {"models": []}),
                "/api/ps": result("/api/ps", {"models": []}),
            }
        )
        items, errors = OllamaDiscovery(self.settings(), probe=probe).collect()
        endpoint = next(item for item in items if isinstance(item, OllamaEndpoint))
        self.assertEqual(errors, [])
        self.assertEqual(endpoint.status, InventoryStatus.AVAILABLE)
        self.assertEqual(endpoint.health_details["installed_state"], "none_installed")
        self.assertEqual(endpoint.health_details["running_state"], "none_running")
        self.assertFalse(any(isinstance(item, OllamaModel) for item in items))

    def test_unavailable_timeout_invalid_and_oversized_responses_are_errors(self):
        for code in ("unavailable", "timeout", "invalid_json", "response_too_large"):
            with self.subTest(code=code):
                probe = FakeProbe(
                    {
                        route: result(
                            route,
                            status=None,
                            error_code=code,
                            error="synthetic",
                        )
                        for route in ("/api/version", "/api/tags", "/api/ps")
                    }
                )
                items, errors = OllamaDiscovery(self.settings(), probe=probe).collect()
                endpoint = next(
                    item for item in items if isinstance(item, OllamaEndpoint)
                )
                self.assertEqual(len(errors), 3)
                self.assertIn(
                    endpoint.status,
                    {InventoryStatus.UNAVAILABLE, InventoryStatus.ERROR},
                )
                expected = (
                    "invalid_response"
                    if code in {"invalid_json", "response_too_large"}
                    else "endpoint_unavailable"
                )
                self.assertEqual(
                    endpoint.health_details["availability_state"], expected
                )

    def test_http_endpoint_without_ollama_api_is_distinguished(self):
        probe = FakeProbe(
            {
                route: result(
                    route,
                    status=404,
                    error_code="http_error",
                    error="not found",
                )
                for route in ("/api/version", "/api/tags", "/api/ps")
            }
        )
        items, errors = OllamaDiscovery(self.settings(), probe=probe).collect()
        endpoint = next(item for item in items if isinstance(item, OllamaEndpoint))
        self.assertEqual(len(errors), 3)
        self.assertEqual(endpoint.status, InventoryStatus.UNAVAILABLE)
        self.assertEqual(
            endpoint.health_details["availability_state"],
            "ollama_unavailable",
        )

    def test_invalid_model_shape_is_not_treated_as_empty_list(self):
        probe = FakeProbe(
            {
                "/api/version": result("/api/version", {"version": "1"}),
                "/api/tags": result("/api/tags", {"models": "invalid"}),
                "/api/ps": result("/api/ps", {"models": []}),
            }
        )
        _, errors = OllamaDiscovery(self.settings(), probe=probe).collect()
        self.assertTrue(any(error.code == "invalid_response" for error in errors))

    def test_scope_denial_happens_before_probe(self):
        settings = Settings(
            _env_file=None,
            ollama_endpoints=["https://8.8.8.8"],
            ollama_live_check=True,
        )
        probe = FakeProbe({})
        items, errors = OllamaDiscovery(settings, probe=probe).collect()
        self.assertEqual(probe.calls, [])
        self.assertEqual(items[0].status, InventoryStatus.UNAVAILABLE)
        self.assertEqual(errors[0].code, "scope_denied")

    def test_live_discovery_is_opt_in(self):
        settings = Settings(
            _env_file=None,
            ollama_endpoints=["http://127.0.0.1:11434"],
            ollama_live_check=False,
        )
        probe = FakeProbe({})
        items, errors = OllamaDiscovery(settings, probe=probe).collect()
        self.assertEqual(probe.calls, [])
        self.assertEqual(errors, [])
        self.assertEqual(items[0].status, InventoryStatus.INACTIVE)

    def test_redirect_is_denied_and_credentials_are_sanitized(self):
        transport_calls = []

        def transport(url, timeout, maximum):
            transport_calls.append(url)
            return HTTPProbeResult(
                url="http://user:secret@127.0.0.1:11434/api/version",
                status_code=302,
                redirect_location="http://user:secret@127.0.0.1:9999/private?token=x",
            )

        probe = SafeHTTPProbe(
            ScopePolicy(self.settings()),
            timeout=1,
            maximum_bytes=1024,
            transport=transport,
        )
        response = probe.get_json("http://127.0.0.1:11434", "/api/version")
        self.assertEqual(response.error_code, "redirect_denied")
        self.assertNotIn("secret", response.model_dump_json())
        self.assertNotIn("token=x", response.model_dump_json())
        self.assertEqual(len(transport_calls), 1)


if __name__ == "__main__":
    unittest.main()
