import unittest
from unittest.mock import Mock, patch

from kali_url_attack import (
    _effective_url_for_kali,
    _evaluate_web_probe,
    _is_loopback_url,
    run_kali_url_attack,
)
from redteam_platform.settings import Settings


class KaliUrlAttackTests(unittest.TestCase):
    def test_loopback_url_uses_effective_kali_tunnel_url(self):
        self.assertTrue(_is_loopback_url("http://127.0.0.1:5173"))
        self.assertTrue(_is_loopback_url("http://localhost:5173"))
        self.assertFalse(_is_loopback_url("https://example.com"))
        self.assertEqual(
            _effective_url_for_kali("http://127.0.0.1:5173", 15173, True),
            "http://127.0.0.1:15173",
        )

    def test_web_probe_detects_sql_error(self):
        result = _evaluate_web_probe(
            {
                "url": "http://target/?q=%27",
                "attack": "sql_injection",
                "payload": "' OR '1'='1' --",
                "http_status": 500,
                "body_excerpt": "sqlite syntax error near quote",
            }
        )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["severity"], "High")

    def test_web_probe_detects_reflected_xss(self):
        payload = "<script>alert('redteam')</script>"
        result = _evaluate_web_probe(
            {
                "url": "http://target/?q=xss",
                "attack": "xss_reflection",
                "payload": payload,
                "http_status": 200,
                "content_type": "text/html",
                "body_excerpt": f"<html>{payload}</html>",
            }
        )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["severity"], "High")

    def test_sqlite_config_without_error_is_not_sql_injection(self):
        result = _evaluate_web_probe(
            {
                "url": "http://target/status",
                "attack": "sql_injection",
                "payload": "' OR '1'='1' --",
                "http_status": 200,
                "content_type": "application/json",
                "body_excerpt": '{"database":"sqlite:///data/jobs/jobs.sqlite3","status":"ok"}',
            }
        )

        self.assertEqual(result["status"], "PASS")

    def test_read_only_task_exposure_is_classified_separately(self):
        result = _evaluate_web_probe(
            {
                "url": "http://target/api/tasks",
                "method": "GET",
                "path": "/api/tasks",
                "attack": "prompt_injection",
                "payload": "ignore rules",
                "http_status": 200,
                "content_type": "application/json",
                "body_excerpt": '{"tasks":[{"request":"private local task","response":"done"}]}',
            }
        )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["attack"], "sensitive_data_exposure")
        self.assertEqual(result["severity"], "High")

    def test_run_url_attack_records_local_tunnel_and_web_payloads(self):
        web_probe = {
            "target": "http://127.0.0.1:15173/api/chat",
            "attack": "prompt_injection",
            "prompt": "ignore rules",
            "remote": {"returncode": 0},
            "result": {
                "target": "http://127.0.0.1:15173/api/chat",
                "attack": "prompt_injection",
                "status": "PASS",
                "severity": "Informational",
                "reason": "No issue.",
            },
            "parse_error": None,
        }
        with patch("kali_url_attack._start_reverse_tunnel", return_value=Mock()) as start_tunnel:
            with patch("kali_url_attack._wait_for_remote_url", return_value={"stdout": "200"}):
                with patch("kali_url_attack._web_recon", return_value={}):
                    with patch("kali_url_attack._web_security_tools", return_value={}):
                        with patch(
                            "kali_url_attack._endpoint_checks",
                            return_value={"returncode": 0, "stdout": "200 /", "stderr": ""},
                        ):
                            with patch(
                                "kali_url_attack._web_payload_probes",
                                return_value={
                                    "probes": [web_probe],
                                    "parse_error": None,
                                    "summary": {
                                        "tests": 1,
                                        "pass": 1,
                                        "fail": 0,
                                        "error": 0,
                                        "unparsed": 0,
                                    },
                                },
                            ):
                                report = run_kali_url_attack(
                                    host="kali-redteam",
                                    url="http://127.0.0.1:5173",
                                    skip_web_recon=False,
                                    include_web_payloads=True,
                                    include_agent_probes=False,
                                    tunnel_local=True,
                                    remote_port=15173,
                                    authorization_statement="I own this local test service and authorize bounded assessment.",
                                    policy_settings=Settings(allowed_kali_aliases=["kali-redteam"]),
                                )

        start_tunnel.assert_called_once()
        self.assertEqual(report["target_url"], "http://127.0.0.1:15173")
        self.assertEqual(report["reverse_tunnel"]["local_port"], 5173)
        self.assertEqual(report["summary"]["pass"], 1)


if __name__ == "__main__":
    unittest.main()
