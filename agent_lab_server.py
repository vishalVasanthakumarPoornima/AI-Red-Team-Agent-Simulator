#!/usr/bin/env python3
"""Loopback-only HTTP adapter for testing local agent modules from Kali."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanner.attack_runner import run_prompt_against_target
from scanner.target_loader import discover_targets


DEFAULT_TARGETS = ("ollama_agent", "travel_agent", "tutor_agent")
MAX_REQUEST_BYTES = 32_000


class AgentLabError(ValueError):
    """Expected user-facing request error."""


def resolve_allowed_targets(target_names):
    discovered = {target["name"]: target for target in discover_targets()}
    missing = [name for name in target_names if name not in discovered]
    if missing:
        available = ", ".join(sorted(discovered)) or "none"
        raise AgentLabError(f"Unknown target(s): {', '.join(missing)}. Available: {available}")
    return {name: discovered[name] for name in target_names}


class AgentLabHandler(BaseHTTPRequestHandler):
    server_version = "AgentLab/0.1"
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
            raise AgentLabError("Content-Length must be an integer.") from exc

        if length <= 0:
            raise AgentLabError("Request body is required.")
        if length > MAX_REQUEST_BYTES:
            raise AgentLabError(f"Request body exceeds {MAX_REQUEST_BYTES} bytes.")

        raw_body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise AgentLabError(f"Request body must be valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AgentLabError("Request body must be a JSON object.")
        return payload

    def do_GET(self):
        if self.path == "/health":
            self._json(
                200,
                {
                    "status": "ok",
                    "targets": sorted(self.server.allowed_targets),
                },
            )
            return

        if self.path == "/targets":
            self._json(
                200,
                {
                    "targets": [
                        {
                            "name": target["name"],
                            "path": target["path"],
                        }
                        for target in self.server.allowed_targets.values()
                    ]
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
            target_name = str(payload.get("target", "")).strip()
            prompt = payload.get("prompt")
            attack_name = str(payload.get("attack", "kali_manual_probe")).strip()

            if target_name not in self.server.allowed_targets:
                raise AgentLabError(
                    f"Target '{target_name}' is not exposed by this lab server."
                )
            if not isinstance(prompt, str) or not prompt.strip():
                raise AgentLabError("Field 'prompt' must be a non-empty string.")
            if not attack_name:
                attack_name = "kali_manual_probe"

            result = run_prompt_against_target(
                self.server.allowed_targets[target_name],
                attack_name,
                prompt,
            )
            self._json(200, result)
        except AgentLabError as exc:
            self._json(400, {"error": str(exc)})


class AgentLabHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_class, allowed_targets):
        super().__init__(server_address, handler_class)
        self.allowed_targets = allowed_targets


def serve(host, port, target_names):
    allowed_targets = resolve_allowed_targets(target_names)
    server = AgentLabHTTPServer((host, port), AgentLabHandler, allowed_targets)
    print(
        f"Agent lab server listening on http://{host}:{port} "
        f"for targets: {', '.join(sorted(allowed_targets))}",
        flush=True,
    )
    server.serve_forever()


def parse_args():
    parser = argparse.ArgumentParser(description="Expose selected local agents on loopback.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=18080, help="Bind port. Default: 18080")
    parser.add_argument(
        "--target",
        action="append",
        dest="targets",
        help="Target name to expose. Can be repeated.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target_names = tuple(args.targets or DEFAULT_TARGETS)
    try:
        serve(args.host, args.port, target_names)
    except AgentLabError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
    except KeyboardInterrupt:
        print("\nAgent lab server stopped.")


if __name__ == "__main__":
    main()
