#!/usr/bin/env python3
"""Verify Dexter is using the expected local Ollama model without printing secrets."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify_dexter_local.py HEALTH_JSON EXPECTED_MODEL")
        return 2
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    expected = sys.argv[2]
    ollama = None
    for item in data.get("services", []):
        if isinstance(item, dict) and item.get("name") == "ollama":
            ollama = item
            break
    if not isinstance(ollama, dict):
        print("Dexter health did not contain the Ollama service record.")
        return 3
    details = ollama.get("details") if isinstance(ollama.get("details"), dict) else {}
    local = details.get("local") if isinstance(details.get("local"), dict) else {}
    cloud = details.get("cloud") if isinstance(details.get("cloud"), dict) else {}
    provider_mode = str(details.get("provider_mode", "")).lower()
    model = str(local.get("model", ""))
    cloud_configured = bool(cloud.get("configured", False))
    result = {
        "api_status": data.get("status", "unknown"),
        "provider_mode": provider_mode,
        "local_model": model,
        "cloud_configured": cloud_configured,
        "expected_model_matches": model == expected,
    }
    print(json.dumps(result, indent=2))
    if provider_mode not in {"ollama", "local"}:
        return 4
    if model != expected:
        return 5
    if cloud_configured:
        return 6
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
