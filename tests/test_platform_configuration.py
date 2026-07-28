import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from redteam_platform.settings import ConfigurationError, Settings, load_settings, sanitized_settings


class ConfigurationTests(unittest.TestCase):
    def test_safe_defaults_are_loopback_and_public_disabled(self):
        settings = Settings(_env_file=None)
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertFalse(settings.allow_public)
        self.assertIn("127.0.0.0/8", settings.allowed_cidrs)

    def test_invalid_hosts_ports_cidrs_domains_urls_and_aliases_fail(self):
        invalid_cases = (
            {"bind_host": "bad host"},
            {"api_port": 70000},
            {"allowed_cidrs": ["10.0.0.0/99"]},
            {"allowed_domains": ["https://example.com"]},
            {"allowed_kali_aliases": ["-oProxyCommand=bad"]},
            {"ollama_endpoints": ["file:///tmp/model"]},
            {"configured_agent_endpoints": ["http://user:pass@localhost:8000"]},
            {"request_timeout_seconds": 0},
            {"retention_days": 0},
            {"report_root": ""},
            {"ollama_discovery_timeout": 0},
            {"metadata_response_size": 100},
            {"listener_discovery_method": "scan"},
            {"docker_timeout": 0},
            {"kali_readiness_timeout": 0},
            {"http_metadata_routes": ["https://public.example/health"]},
            {"http_metadata_routes": ["/../private"]},
            {"known_local_service_ports": [0]},
            {"inventory_cache_ttl_seconds": 0},
        )
        for values in invalid_cases:
            with self.subTest(values=values), self.assertRaises(ValidationError):
                Settings(_env_file=None, **values)

    def test_dotenv_environment_and_override_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "REDTEAM_API_PORT=18151\nREDTEAM_ALLOWED_CIDRS=10.55.0.0/16\n",
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"REDTEAM_API_PORT": "18152"}, clear=False):
                    settings = load_settings(overrides={"api_port": 18153})
            finally:
                os.chdir(previous)
        self.assertEqual(settings.api_port, 18153)
        self.assertEqual(settings.allowed_cidrs, ["10.55.0.0/16"])

    def test_invalid_loaded_configuration_has_actionable_field_name(self):
        with self.assertRaisesRegex(ConfigurationError, "api_port"):
            load_settings(overrides={"api_port": "not-a-port"})

    def test_sanitized_settings_never_prints_secrets(self):
        payload = sanitized_settings(
            Settings(_env_file=None, api_token="private-token", kali_ssh_key="/secret/key")
        )
        text = str(payload)
        self.assertNotIn("private-token", text)
        self.assertNotIn("/secret/key", text)


if __name__ == "__main__":
    unittest.main()
