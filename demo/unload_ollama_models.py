#!/usr/bin/env python3
"""Unload local Ollama models without deleting installed model files."""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request


def request_json(url: str, payload: dict | None = None, timeout: float = 15.0) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(1024 * 1024)
    return json.loads(raw) if raw else {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--except", dest="keep_model")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    if base not in {"http://127.0.0.1:11434", "http://localhost:11434"}:
        raise SystemExit("Only the local Ollama endpoint is permitted.")

    try:
        payload = request_json(f"{base}/api/ps")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__}))
        return 2

    loaded = [
        str(item.get("name") or item.get("model"))
        for item in payload.get("models", [])
        if isinstance(item, dict) and (item.get("name") or item.get("model"))
    ]
    stopped: list[str] = []
    kept: list[str] = []
    for model in loaded:
        if not args.all and args.keep_model and model == args.keep_model:
            kept.append(model)
            continue
        try:
            request_json(
                f"{base}/api/generate",
                {"model": model, "keep_alive": 0},
            )
            stopped.append(model)
        except Exception:
            # A failed unload is reported honestly but does not delete anything.
            kept.append(model)

    print(
        json.dumps(
            {
                "ok": True,
                "initially_loaded": loaded,
                "unloaded": stopped,
                "remaining_or_failed": kept,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
