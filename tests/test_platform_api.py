import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from redteam_platform import __version__
from redteam_platform.api import create_app
from redteam_platform.settings import Settings


class PlatformAPITests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.settings = Settings(
            api_token="test-token-not-a-real-secret",
            report_root=Path(self.tempdir.name) / "runs",
            inventory_cache=Path(self.tempdir.name) / "inventory.json",
        )
        self.client = TestClient(create_app(self.settings))

    def tearDown(self):
        self.client.close()
        self.tempdir.cleanup()

    def test_health_is_public_but_inventory_requires_token(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/inventory").status_code, 401)
        self.assertEqual(
            self.client.get("/openapi.json").json()["info"]["version"],
            __version__,
        )

    def test_plan_enforces_scope_and_authorization(self):
        headers = {"Authorization": "Bearer test-token-not-a-real-secret"}
        response = self.client.post(
            "/assessments/plan",
            headers=headers,
            json={
                "kind": "python",
                "target": "tool_agent",
                "authorization_statement": "I own this local synthetic target and authorize testing.",
                "budget": {"max_rounds": 1, "max_probes": 1, "max_model_calls": 0, "max_duration_seconds": 30},
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["authorization"]["decision"]["allowed"])

    def test_inventory_targets_and_models_use_phase_two_types(self):
        headers = {"Authorization": "Bearer test-token-not-a-real-secret"}
        empty_listeners = SimpleNamespace(collect=lambda: ([], []))
        with patch(
            "redteam_platform.inventory.service.ListenerDiscovery",
            return_value=empty_listeners,
        ):
            inventory = self.client.get("/inventory?refresh=true", headers=headers)
        self.assertEqual(inventory.status_code, 200, inventory.text)
        self.assertIn("summary", inventory.json())
        targets = self.client.get("/targets", headers=headers)
        models = self.client.get("/models", headers=headers)
        self.assertEqual(targets.status_code, 200, targets.text)
        self.assertEqual(models.status_code, 200, models.text)
        self.assertTrue(targets.json())
        self.assertTrue(
            all(item["item_type"] == "python_target" for item in targets.json())
        )
        self.assertTrue(
            all(item["item_type"] == "ollama_model" for item in models.json())
        )


if __name__ == "__main__":
    unittest.main()
