#!/usr/bin/env python3
"""Single-agent HTTP service suitable for local demos or Render deployment."""

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanner.attack_runner import run_prompt_against_target
from scanner.target_loader import discover_targets


MAX_REQUEST_BYTES = 32_000


class AgentServiceError(ValueError):
    """Expected service request error."""


def resolve_target(target_name):
    for target in discover_targets():
        if target["name"] == target_name:
            return target
    available = ", ".join(sorted(target["name"] for target in discover_targets())) or "none"
    raise AgentServiceError(f"Unknown target '{target_name}'. Available: {available}")


class AgentServiceHandler(BaseHTTPRequestHandler):
    server_version = "AgentService/0.1"
    sys_version = ""

    def log_message(self, format, *args):
        return

    def version_string(self):
        return self.server_version

    def _json(self, status, payload):
        body = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise AgentServiceError("Content-Length must be an integer.") from exc
        if length <= 0:
            raise AgentServiceError("Request body is required.")
        if length > MAX_REQUEST_BYTES:
            raise AgentServiceError(f"Request body exceeds {MAX_REQUEST_BYTES} bytes.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise AgentServiceError(f"Request body must be valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AgentServiceError("Request body must be a JSON object.")
        return payload

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok", "agent": self.server.target["name"]})
            return
        if self.path == "/metadata":
            self._json(
                200,
                {
                    "name": self.server.target["name"],
                    "path": self.server.target["path"],
                    "invoke": "/invoke",
                    "kind": "ollama-langgraph-agent",
                },
            )
            return
        self._json(404, {"error": "Not found."})

    def do_POST(self):
        if self.path != "/invoke":
            self._json(404, {"error": "Not found."})
            return
        try:
            payload = self._read_json_body()
            prompt = payload.get("prompt")
            attack_name = str(payload.get("attack", "manual_invoke")).strip() or "manual_invoke"
            if not isinstance(prompt, str) or not prompt.strip():
                raise AgentServiceError("Field 'prompt' must be a non-empty string.")
            result = run_prompt_against_target(self.server.target, attack_name, prompt)
            self._json(200, result)
        except AgentServiceError as exc:
            self._json(400, {"error": str(exc)})


class AgentHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_class, target):
        super().__init__(server_address, handler_class)
        self.target = target


def serve(target_name, host, port):
    target = resolve_target(target_name)
    server = AgentHTTPServer((host, port), AgentServiceHandler, target)
    print(f"{target_name} listening on http://{host}:{port}", flush=True)
    server.serve_forever()


def parse_args():
    parser = argparse.ArgumentParser(description="Serve one target agent over HTTP.")
    parser.add_argument("--target", default=os.environ.get("AGENT_TARGET", "weather_insight_agent"))
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "18101")))
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        serve(args.target, args.host, args.port)
    except AgentServiceError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
    except KeyboardInterrupt:
        print("\nAgent service stopped.")


if __name__ == "__main__":
    main()
