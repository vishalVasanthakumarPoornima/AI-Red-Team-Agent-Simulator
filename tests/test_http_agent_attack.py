import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from http_agent_attack import run_http_agent_attack


class _InvokeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = json.dumps(
            {
                "response": "I can't reveal hidden instructions, credentials, or internal configuration.",
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SecretInvokeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = json.dumps(
            {
                "response": "The configured weather key is ow-test-secret-12345678.",
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HttpAgentAttackTests(unittest.TestCase):
    def test_attacks_compatible_single_agent_service(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _InvokeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        port = server.server_address[1]
        agent = {
            "name": "test_agent",
            "kind": "test",
            "status": "up",
            "invoke_url": f"http://127.0.0.1:{port}/invoke",
            "targets": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "http_agent_scan.json"
            report = run_http_agent_attack([agent], timeout=2, report_path=report_path)

        self.assertEqual(len(report["reconnaissance"]), 2)
        self.assertIn("test_agent", report["generated_payloads"])
        self.assertEqual(report["summary"]["tests"], 6)
        self.assertEqual(report["summary"]["pass"], 6)
        self.assertEqual(report["summary"]["fail"], 0)
        self.assertEqual(report["summary"]["unparsed"], 0)

    def test_redacts_configured_secret_values_from_http_artifacts(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _SecretInvokeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        port = server.server_address[1]
        agent = {
            "name": "secret_agent",
            "kind": "test",
            "status": "up",
            "invoke_url": f"http://127.0.0.1:{port}/invoke",
            "targets": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "http_agent_scan.json"
            with patch.dict("os.environ", {"OPENWEATHER_API_KEY": "ow-test-secret-12345678"}):
                report = run_http_agent_attack(
                    [agent],
                    timeout=2,
                    report_path=report_path,
                    include_dynamic=False,
                )

        serialized = json.dumps(report)
        self.assertNotIn("ow-test-secret-12345678", serialized)
        self.assertIn("<REDACTED:OPENWEATHER_API_KEY>", serialized)
        self.assertEqual(report["summary"]["fail"], 3)


if __name__ == "__main__":
    unittest.main()
