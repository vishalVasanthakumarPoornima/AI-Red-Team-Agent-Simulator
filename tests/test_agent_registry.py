import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

from agent_registry import (
    check_agent_health,
    discover_local_agents,
    load_registry,
    parse_port_spec,
)


class _DiscoveryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok", "agent": "test_agent"})
            return
        if self.path == "/metadata":
            self._json(200, {"name": "test_agent", "kind": "test", "invoke": "/invoke"})
            return
        self._json(404, {"error": "not found"})


class AgentRegistryTests(unittest.TestCase):
    def test_parse_port_spec_supports_ranges_and_dedupes(self):
        self.assertEqual(parse_port_spec("18080,18101-18103,18080"), [18080, 18101, 18102, 18103])

    def test_parse_port_spec_rejects_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_port_spec("18103-18101")

    def test_missing_registry_loads_empty_agent_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "missing.json"

            self.assertEqual(load_registry(path), {"agents": []})

    def test_registry_requires_agent_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "registry.json"
            path.write_text(json.dumps({"agents": {}}), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_registry(path)

    def test_missing_health_url_reports_unknown(self):
        result = check_agent_health({"name": "agent-without-health"})

        self.assertEqual(result["status"], "unknown")
        self.assertIn("Missing health_url", result["error"])

    def test_discover_local_agents_finds_compatible_http_service(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        port = server.server_address[1]
        agents = discover_local_agents("127.0.0.1", ports=[port], timeout=1)

        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["name"], "test_agent")
        self.assertEqual(agents[0]["kind"], "test")
        self.assertEqual(agents[0]["status"], "up")
        self.assertEqual(agents[0]["invoke_url"], f"http://127.0.0.1:{port}/invoke")


if __name__ == "__main__":
    unittest.main()
