#!/usr/bin/env python3
"""Emit safe environment assignments for the Phase 6 adaptive Ollama provider.

The helper introspects the installed Settings model when possible, while also
emitting backward-compatible candidate names used by earlier Phase 6 builds.
It prints NAME=VALUE pairs only; no secrets are read or displayed.
"""

from __future__ import annotations

import argparse
import re
from collections import OrderedDict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    return parser.parse_args()


def valid_env_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", name))


def main() -> int:
    args = parse_args()
    values: "OrderedDict[str, str]" = OrderedDict()

    # Conservative compatibility candidates. Unknown environment variables are
    # harmless; the installed Pydantic settings model ignores names it does not use.
    candidates = {
        "REDTEAM_ADAPTIVE_PROVIDER": "ollama",
        "REDTEAM_ADAPTIVE_MODEL_PROVIDER": "ollama",
        "ADAPTIVE_PROVIDER": "ollama",
        "ADAPTIVE_MODEL_PROVIDER": "ollama",
        "REDTEAM_ADAPTIVE_MODEL": args.model,
        "REDTEAM_ADAPTIVE_PLANNER_MODEL": args.model,
        "REDTEAM_ADAPTIVE_PROPOSER_MODEL": args.model,
        "ADAPTIVE_MODEL": args.model,
        "ADAPTIVE_PLANNER_MODEL": args.model,
        "REDTEAM_ADAPTIVE_BASE_URL": args.base_url,
        "REDTEAM_ADAPTIVE_OLLAMA_BASE_URL": args.base_url,
        "REDTEAM_OLLAMA_BASE_URL": args.base_url,
        "ADAPTIVE_BASE_URL": args.base_url,
    }
    values.update(candidates)

    try:
        from redteam_platform.settings import Settings

        prefix = str(Settings.model_config.get("env_prefix", "") or "")
        for field_name in Settings.model_fields:
            lowered = field_name.lower()
            env_name = f"{prefix}{field_name}".upper()
            if not valid_env_name(env_name):
                continue
            if "adaptive" in lowered and "provider" in lowered:
                values[env_name] = "ollama"
            elif "adaptive" in lowered and "model" in lowered:
                values[env_name] = args.model
            elif "adaptive" in lowered and ("base_url" in lowered or "endpoint" in lowered):
                values[env_name] = args.base_url
    except Exception:
        # The explicit candidates above remain available when introspection is not
        # supported by an older installed build.
        pass

    for name, value in values.items():
        if valid_env_name(name) and "\n" not in value and "\r" not in value:
            print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
