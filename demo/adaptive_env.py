#!/usr/bin/env python3
"""Prepare and validate a safe local-Ollama adaptive-demo environment.

This helper never edits the repository .env file. It emits non-empty process
variables, validates the installed Settings model, and performs a deliberately
minimal Ollama liveness/model-call preflight. The real adaptive engine remains
the authoritative structured-output and policy validator.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Any

SAFE_BASE_URL = "http://127.0.0.1:11434"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="llama3.1:8b-instruct-q4_K_M")
    p.add_argument("--base-url", default=SAFE_BASE_URL)
    p.add_argument("--max-rounds", type=int, default=4)
    p.add_argument("--max-probes", type=int, default=30)
    p.add_argument("--max-probes-per-round", type=int, default=8)
    p.add_argument("--max-model-calls", type=int, default=8)
    p.add_argument("--max-duration", type=int, default=600)
    p.add_argument("--provider-timeout", type=float, default=120.0)
    p.add_argument("--provider-retries", type=int, default=1)
    p.add_argument("--provider-repairs", type=int, default=2)
    p.add_argument("--format", choices=("tsv", "json"), default="tsv")
    p.add_argument("--check", action="store_true")
    p.add_argument("--ollama-preflight", action="store_true")
    return p.parse_args()


def valid_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", name))


def aliases(field: Any) -> set[str]:
    result: set[str] = set()
    for value in (getattr(field, "alias", None), getattr(field, "validation_alias", None)):
        if isinstance(value, str):
            result.add(value)
        choices = getattr(value, "choices", None)
        if choices:
            for choice in choices:
                if isinstance(choice, str):
                    result.add(choice)
    return result


def build_environment(args: argparse.Namespace) -> OrderedDict[str, str]:
    base = args.base_url.rstrip("/")
    role_json = json.dumps(
        {
            role: {"provider": "ollama", "model": args.model}
            for role in ("planner", "proposer", "reviewer", "summarizer")
        },
        separators=(",", ":"),
    )
    values: OrderedDict[str, str] = OrderedDict()

    explicit = {
        "ADAPTIVE_PROVIDER": "ollama",
        "REDTEAM_ADAPTIVE_PROVIDER": "ollama",
        "ADAPTIVE_MODEL_PROVIDER": "ollama",
        "REDTEAM_ADAPTIVE_MODEL_PROVIDER": "ollama",
        "ADAPTIVE_PLANNER_PROVIDER": "ollama",
        "REDTEAM_ADAPTIVE_PLANNER_PROVIDER": "ollama",
        "PLANNER_PROVIDER": "ollama",
        "REDTEAM_PLANNER_PROVIDER": "ollama",
        "MODEL_PROVIDER": "ollama",
        "REDTEAM_MODEL_PROVIDER": "ollama",
        "DEFAULT_MODEL_PROVIDER": "ollama",
        "REDTEAM_DEFAULT_MODEL_PROVIDER": "ollama",
        "ADAPTIVE_MODEL": args.model,
        "REDTEAM_ADAPTIVE_MODEL": args.model,
        "ADAPTIVE_PLANNER_MODEL": args.model,
        "REDTEAM_ADAPTIVE_PLANNER_MODEL": args.model,
        "PLANNER_MODEL": args.model,
        "REDTEAM_PLANNER_MODEL": args.model,
        "ADAPTIVE_BASE_URL": base,
        "REDTEAM_ADAPTIVE_BASE_URL": base,
        "ADAPTIVE_OLLAMA_BASE_URL": base,
        "REDTEAM_ADAPTIVE_OLLAMA_BASE_URL": base,
        "OLLAMA_BASE_URL": base,
        "REDTEAM_OLLAMA_BASE_URL": base,
        "ADAPTIVE_MODEL_ROLES": role_json,
        "REDTEAM_ADAPTIVE_MODEL_ROLES": role_json,
        "MODEL_ROLES": role_json,
        "REDTEAM_MODEL_ROLES": role_json,
        "ADAPTIVE_ROLE_ASSIGNMENTS": role_json,
        "REDTEAM_ADAPTIVE_ROLE_ASSIGNMENTS": role_json,
        "ADAPTIVE_MAX_ROUNDS": str(args.max_rounds),
        "REDTEAM_ADAPTIVE_MAX_ROUNDS": str(args.max_rounds),
        "ADAPTIVE_MAX_TOTAL_PROBES": str(args.max_probes),
        "REDTEAM_ADAPTIVE_MAX_TOTAL_PROBES": str(args.max_probes),
        "ADAPTIVE_MAX_PROBES": str(args.max_probes),
        "REDTEAM_ADAPTIVE_MAX_PROBES": str(args.max_probes),
        "ADAPTIVE_MAX_PROBES_PER_ROUND": str(args.max_probes_per_round),
        "REDTEAM_ADAPTIVE_MAX_PROBES_PER_ROUND": str(args.max_probes_per_round),
        "ADAPTIVE_MAX_MODEL_CALLS": str(args.max_model_calls),
        "REDTEAM_ADAPTIVE_MAX_MODEL_CALLS": str(args.max_model_calls),
        "ADAPTIVE_MAX_DURATION": str(args.max_duration),
        "REDTEAM_ADAPTIVE_MAX_DURATION": str(args.max_duration),
        "ADAPTIVE_MAX_DURATION_SECONDS": str(args.max_duration),
        "REDTEAM_ADAPTIVE_MAX_DURATION_SECONDS": str(args.max_duration),
        "ADAPTIVE_PROVIDER_TIMEOUT_SECONDS": str(args.provider_timeout),
        "REDTEAM_ADAPTIVE_PROVIDER_TIMEOUT_SECONDS": str(args.provider_timeout),
        "ADAPTIVE_PROVIDER_RETRIES": str(args.provider_retries),
        "REDTEAM_ADAPTIVE_PROVIDER_RETRIES": str(args.provider_retries),
        "ADAPTIVE_PROVIDER_REPAIRS": str(args.provider_repairs),
        "REDTEAM_ADAPTIVE_PROVIDER_REPAIRS": str(args.provider_repairs),
        "ADAPTIVE_STRUCTURED_OUTPUT_REPAIR_ATTEMPTS": str(args.provider_repairs),
        "REDTEAM_ADAPTIVE_STRUCTURED_OUTPUT_REPAIR_ATTEMPTS": str(args.provider_repairs),
        "ADAPTIVE_NO_NOVELTY_ROUNDS": "2",
        "REDTEAM_ADAPTIVE_NO_NOVELTY_ROUNDS": "2",
        "ADAPTIVE_NO_NEW_FINDING_ROUNDS": "2",
        "REDTEAM_ADAPTIVE_NO_NEW_FINDING_ROUNDS": "2",
        "ADAPTIVE_MAX_DUPLICATE_RATE": "0.5",
        "REDTEAM_ADAPTIVE_MAX_DUPLICATE_RATE": "0.5",
        "ADAPTIVE_ALLOW_MODEL_FALLBACK": "false",
        "REDTEAM_ADAPTIVE_ALLOW_MODEL_FALLBACK": "false",
    }
    values.update(explicit)

    try:
        from redteam_platform.settings import Settings

        prefix = str(Settings.model_config.get("env_prefix", "") or "")
        for field_name, field in Settings.model_fields.items():
            lower = field_name.lower()
            selected: str | None = None
            if "provider" in lower and not any(x in lower for x in ("timeout", "retries", "repairs", "url", "endpoint")):
                selected = "ollama"
            elif ("planner" in lower or "adaptive" in lower) and "model" in lower and "calls" not in lower:
                selected = args.model
            elif ("ollama" in lower or "provider" in lower or "adaptive" in lower) and ("base_url" in lower or "endpoint" in lower):
                selected = base
            elif "role" in lower and ("adaptive" in lower or "model" in lower):
                selected = role_json
            elif lower == "adaptive_max_rounds":
                selected = str(args.max_rounds)
            elif lower in {"adaptive_max_total_probes", "adaptive_max_probes"}:
                selected = str(args.max_probes)
            elif lower == "adaptive_max_probes_per_round":
                selected = str(args.max_probes_per_round)
            elif lower == "adaptive_max_model_calls":
                selected = str(args.max_model_calls)
            elif lower in {"adaptive_max_duration", "adaptive_max_duration_seconds"}:
                selected = str(args.max_duration)
            elif lower == "adaptive_provider_timeout_seconds":
                selected = str(args.provider_timeout)
            elif lower == "adaptive_provider_retries":
                selected = str(args.provider_retries)
            elif lower in {"adaptive_provider_repairs", "adaptive_structured_output_repair_attempts"}:
                selected = str(args.provider_repairs)
            if selected is None:
                continue
            names = {
                field_name.upper(),
                f"{prefix}{field_name}".upper(),
                *{x.upper() for x in aliases(field)},
            }
            for name in names:
                if valid_name(name):
                    values[name] = selected
    except Exception:
        # The non-executing adaptive plan preflight later discovers the actual
        # provider contract. Settings introspection is helpful, not authoritative.
        pass

    return OrderedDict(
        (key, value)
        for key, value in values.items()
        if valid_name(key) and str(value).strip()
    )


def apply(values: dict[str, str]) -> None:
    for key, value in values.items():
        os.environ[key] = value


def check_settings(values: dict[str, str]) -> dict[str, Any]:
    apply(values)
    from redteam_platform.settings import Settings

    settings = Settings()
    snapshot: dict[str, Any] = {}
    provider_fields: dict[str, Any] = {}
    for field_name in Settings.model_fields:
        lower = field_name.lower()
        if not (lower.startswith("adaptive_") or "provider" in lower or "planner" in lower):
            continue
        value = getattr(settings, field_name, None)
        if isinstance(value, Path):
            value = "<LOCAL_PATH>"
        elif hasattr(value, "value"):
            value = value.value
        elif not isinstance(value, (str, int, float, bool, type(None), list, dict)):
            value = str(value)
        snapshot[field_name] = value
        if "provider" in lower and not any(x in lower for x in ("timeout", "retries", "repairs")):
            provider_fields[field_name] = value

    explicit_env = sorted(key for key, value in values.items() if "PROVIDER" in key and value == "ollama")
    return {
        "settings_valid": True,
        "adaptive_settings": snapshot,
        "provider_fields": provider_fields,
        "explicit_provider_environment": explicit_env,
        "provider_visibility": (
            "settings"
            if any(str(value).lower() == "ollama" for value in provider_fields.values())
            else "plan_preflight_required"
        ),
    }


def http_json(url: str, *, body: dict[str, Any] | None = None, timeout: float = 30.0) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(2 * 1024 * 1024)
    decoded = json.loads(raw) if raw else {}
    if not isinstance(decoded, dict):
        raise RuntimeError("Ollama returned a non-object response.")
    return decoded


def parse_structured_response(value: Any) -> tuple[dict[str, Any] | None, str]:
    if isinstance(value, dict):
        return value, "object"
    text = str(value or "").strip()
    if not text:
        return None, "empty"
    try:
        parsed = json.loads(text)
        return (parsed, "json") if isinstance(parsed, dict) else (None, "json_non_object")
    except json.JSONDecodeError:
        pass

    # Some models wrap valid JSON in prose or a fenced code block. Extract only
    # the first object for diagnostics; the adaptive engine itself still applies
    # its strict schema and repair policy during the real run.
    first = text.find("{")
    if first >= 0:
        try:
            parsed, _ = json.JSONDecoder().raw_decode(text[first:])
            if isinstance(parsed, dict):
                return parsed, "embedded_json"
        except json.JSONDecodeError:
            pass
    return None, "unstructured"


def ollama_preflight(args: argparse.Namespace) -> dict[str, Any]:
    base = args.base_url.rstrip("/")
    if base not in {"http://127.0.0.1:11434", "http://localhost:11434"}:
        raise RuntimeError("Only the local Ollama endpoint is permitted.")

    tags = http_json(f"{base}/api/tags", timeout=min(args.provider_timeout, 30.0))
    installed = {
        str(item.get("name") or item.get("model"))
        for item in tags.get("models", [])
        if isinstance(item, dict) and (item.get("name") or item.get("model"))
    }
    if args.model not in installed:
        raise RuntimeError(f"Planner model is not installed: {args.model}")

    body = {
        "model": args.model,
        "prompt": (
            "Return one small JSON object confirming readiness. "
            "Use keys ready and provider. Do not call tools."
        ),
        "stream": False,
        "format": "json",
        "keep_alive": "30s",
        "options": {
            "num_ctx": 2048,
            "num_predict": 48,
            "temperature": 0,
        },
    }
    try:
        payload = http_json(
            f"{base}/api/generate",
            body=body,
            timeout=args.provider_timeout,
        )
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Local Ollama preflight failed: {type(exc).__name__}") from exc

    response_text = payload.get("response", "")
    structured, parse_mode = parse_structured_response(response_text)
    response_chars = len(str(response_text or ""))
    done = payload.get("done") is True
    returned_model = str(payload.get("model") or "")

    # The preflight proves only transport, installed-model resolution, and a real
    # local model call. It must not reject a healthy model because it capitalized
    # "Ollama", returned an extra key, or wrapped JSON in a code fence. The real
    # adaptive provider performs strict proposal-schema validation, repair, and
    # deterministic rejection later, and the demo requires model_calls > 0.
    if not done:
        raise RuntimeError("Ollama did not report completion for the preflight call.")
    if response_chars == 0:
        raise RuntimeError("Ollama returned an empty model response.")
    if returned_model and returned_model != args.model:
        raise RuntimeError(
            f"Ollama answered with an unexpected model: {returned_model}"
        )

    ready_value = structured.get("ready") if isinstance(structured, dict) else None
    provider_value = structured.get("provider") if isinstance(structured, dict) else None
    ready_normalized = str(ready_value).strip().lower() in {"true", "1", "yes", "ready"}
    provider_normalized = str(provider_value or "").strip().lower()
    semantic_match = ready_normalized and provider_normalized in {"", "ollama", "local"}

    return {
        "ok": True,
        "ready": True,
        "provider": "ollama",
        "model": args.model,
        "endpoint": base,
        "model_call_verified": True,
        "ollama_done": done,
        "done_reason": payload.get("done_reason"),
        "response_characters": response_chars,
        "structured_output_parsed": structured is not None,
        "structured_parse_mode": parse_mode,
        "structured_semantic_match": semantic_match,
        "structured_keys": sorted(structured) if isinstance(structured, dict) else [],
        "note": (
            "Transport/model-call preflight passed. Strict adaptive proposal "
            "schema validation remains authoritative during the real run."
        ),
    }


def main() -> int:
    args = parse_args()
    values = build_environment(args)
    if args.check:
        try:
            result = check_settings(values)
        except Exception as exc:
            print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
            return 2
        print(json.dumps({"ok": True, **result}, indent=2, default=str))
        return 0
    if args.ollama_preflight:
        try:
            result = ollama_preflight(args)
        except Exception as exc:
            print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
            return 3
        print(json.dumps(result, indent=2))
        return 0
    if args.format == "json":
        print(json.dumps(values, indent=2, sort_keys=True))
    else:
        for key, value in values.items():
            print(f"{key}\t{value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
