#!/usr/bin/env python3
"""Strictly validate a real model-driven adaptive run for the demo."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

TERMINAL_REASONS = {
    "coverage_saturated",
    "novelty_exhausted",
    "no_novel_proposals",
    "duplicate_saturation",
    "duplicate_threshold",
    "max_rounds",
    "max_total_probes",
    "max_probes",
    "max_model_calls",
    "max_duration",
    "duration_limit",
    "budget_exhausted",
    "categories_complete",
    "policy_stop",
    "completed",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def load(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {} if default is None else default


def walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def find_named_text(values: list[Any], exact_keys: tuple[str, ...], contains: tuple[str, ...] = ()) -> str:
    """Prefer exact semantic keys before looser key-name matching."""
    normalized_exact = {key.lower() for key in exact_keys}
    for value in values:
        for item in walk(value):
            for key, candidate in item.items():
                if str(key).lower() in normalized_exact and candidate not in (None, "", [], {}):
                    if isinstance(candidate, dict):
                        for nested_key in ("model", "model_name", "provider", "name", "value"):
                            nested = candidate.get(nested_key)
                            if nested not in (None, "", [], {}):
                                if hasattr(nested, "value"):
                                    nested = nested.value
                                return str(nested)
                        continue
                    if hasattr(candidate, "value"):
                        candidate = candidate.value
                    return str(candidate)
    if contains:
        for value in values:
            for item in walk(value):
                for key, candidate in item.items():
                    lowered = str(key).lower()
                    if any(token in lowered for token in contains) and candidate not in (None, "", [], {}):
                        if isinstance(candidate, dict):
                            for nested_key in ("model", "model_name", "provider", "name", "value"):
                                nested = candidate.get(nested_key)
                                if nested not in (None, "", [], {}):
                                    if hasattr(nested, "value"):
                                        nested = nested.value
                                    return str(nested)
                            continue
                        if hasattr(candidate, "value"):
                            candidate = candidate.value
                        return str(candidate)
    return ""

def manifest_entries(manifest: Any) -> list[tuple[str, str]]:
    """Accept list-style and path-keyed manifest layouts used across phases."""
    entries: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(path: Any, digest: Any) -> None:
        if not isinstance(path, str) or not isinstance(digest, str):
            return
        digest = digest.lower().removeprefix("sha256:")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            return
        pair = (path, digest)
        if pair not in seen:
            seen.add(pair)
            entries.append(pair)

    for item in walk(manifest):
        path = item.get("path") or item.get("relative_path") or item.get("artifact_path") or item.get("name")
        digest = item.get("sha256") or item.get("hash") or item.get("digest")
        add(path, digest)
        for key, value in item.items():
            key_text = str(key)
            key_lower = key_text.lower()
            path_like = key_lower not in {"sha256", "hash", "digest"} and (
                "/" in key_text or "." in Path(key_text).name
            )
            if isinstance(value, str) and path_like:
                add(key_text, value)
            elif isinstance(value, dict) and path_like:
                nested_digest = value.get("sha256") or value.get("hash") or value.get("digest")
                add(key_text, nested_digest)
    return entries

def verify_manifest(run_dir: Path) -> tuple[bool, int, int, list[str]]:
    manifest_path = run_dir / "manifest.json"
    manifest = load(manifest_path, {})
    entries = manifest_entries(manifest)
    if not manifest_path.exists() or not entries:
        return False, 0, 0, ["manifest missing or contained no SHA-256 entries"]

    checked = 0
    valid = 0
    errors: list[str] = []
    root = run_dir.resolve()
    for relative, expected in entries:
        candidate = (run_dir / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            errors.append(f"path escaped run root: {relative}")
            continue
        if not candidate.is_file():
            errors.append(f"missing artifact: {relative}")
            continue
        if candidate == manifest_path.resolve():
            # Self-hashes are not stable and are ignored when present.
            continue
        checked += 1
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual == expected:
            valid += 1
        else:
            errors.append(f"hash mismatch: {relative}")
    return checked > 0 and checked == valid and not errors, checked, valid, errors


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = load(run_dir / "adaptive_summary.json", {})
    stop = load(run_dir / "stop_decision.json", {})
    configuration = load(run_dir / "adaptive_configuration.json", {})
    roles = load(run_dir / "model_roles.json", {})
    state = load(run_dir / "adaptive_state.json", {})

    status = str(summary.get("status", "unknown")).lower()
    mode = str(summary.get("mode", configuration.get("mode", "unknown"))).lower()
    rounds = as_int(summary.get("rounds"))
    probes = as_int(summary.get("probes"))
    model_calls = as_int(summary.get("model_calls"))
    accepted = as_int(summary.get("accepted_proposals"))
    rejected = as_int(summary.get("rejected_proposals"))
    duplicates = as_int(summary.get("duplicate_proposals", summary.get("duplicates", 0)))
    stop_reason = str(
        summary.get("stop_reason")
        or stop.get("reason")
        or stop.get("stop_reason")
        or "unknown"
    ).lower()

    provider = find_named_text(
        [configuration, roles, state, summary],
        ("provider", "provider_name", "model_provider", "adaptive_provider"),
        ("provider",),
    )
    planner_model = find_named_text(
        [roles, configuration, state, summary],
        ("planner_model", "planner", "model_name", "model"),
        ("planner_model", "planner model"),
    )
    manifest_ok, manifest_checked, manifest_valid, manifest_errors = verify_manifest(run_dir)

    conditions = {
        "run_directory_exists": run_dir.is_dir(),
        "mode_is_adaptive": mode == "adaptive",
        "status_is_complete": status in {"complete", "completed", "success", "succeeded"},
        "rounds_greater_than_zero": rounds > 0,
        "probes_greater_than_zero": probes > 0,
        "model_calls_greater_than_zero": model_calls > 0,
        "proposal_decision_recorded": accepted + rejected > 0,
        "deterministic_stop_reason": stop_reason in TERMINAL_REASONS,
        "provider_is_ollama": provider.lower() == "ollama",
        "planner_model_recorded": bool(planner_model),
        "manifest_verified": manifest_ok,
    }
    proper_result = all(conditions.values())

    result = {
        "proper_result": proper_result,
        "definition": (
            "A real model-driven adaptive run with at least one model call, one round, "
            "executed registered probes, proposal decisions, a deterministic stop reason, "
            "and verified run artifacts."
        ),
        "run_id": summary.get("run_id", run_dir.name),
        "mode": mode,
        "status": status,
        "provider": provider or "unknown",
        "planner_model": planner_model or "unknown",
        "rounds": rounds,
        "probes": probes,
        "model_calls": model_calls,
        "accepted_proposals": accepted,
        "rejected_proposals": rejected,
        "duplicate_proposals": duplicates,
        "stop_reason": stop_reason,
        "manifest": {
            "verified": manifest_ok,
            "checked": manifest_checked,
            "valid": manifest_valid,
            "errors": manifest_errors,
        },
        "conditions": conditions,
        "safety_note": (
            "The local model proposed typed registered probes only. Deterministic code "
            "controlled authorization, scope, tools, execution, budgets, findings, and stopping."
        ),
    }

    (output_dir / "DYNAMIC_RESULT.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Full Adaptive Demo Result",
        "",
        f"- Proper model-driven terminal result: **{'yes' if proper_result else 'no'}**",
        f"- Run ID: `{result['run_id']}`",
        f"- Provider / planner: `{result['provider']}` / `{result['planner_model']}`",
        f"- Mode / status: `{mode}` / `{status}`",
        f"- Rounds / probes / model calls: **{rounds} / {probes} / {model_calls}**",
        f"- Accepted / rejected / duplicate proposals: **{accepted} / {rejected} / {duplicates}**",
        f"- Stop reason: `{stop_reason}`",
        f"- Manifest hashes: **{manifest_valid}/{manifest_checked} verified**",
        "",
        "## Required conditions",
        "",
    ]
    lines.extend(
        f"- {'PASS' if passed else 'FAIL'} — {name.replace('_', ' ')}"
        for name, passed in conditions.items()
    )
    lines.extend(["", result["safety_note"], ""])
    (output_dir / "DYNAMIC_RESULT.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if proper_result else 2


if __name__ == "__main__":
    raise SystemExit(main())
