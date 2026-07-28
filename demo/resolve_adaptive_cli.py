#!/usr/bin/env python3
"""Resolve a working model-driven adaptive CLI invocation against the installed build.

The Phase 6 CLI changed while the demo scripts evolved. This helper discovers the
actual provider/model contract at runtime, tests only the non-executing plan command,
and writes the exact arguments/environment that passed validation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--base-url", default="http://127.0.0.1:11434")
    p.add_argument("--profile", default="standard")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--run-args", type=Path, required=True)
    p.add_argument("--env-output", type=Path, required=True)
    p.add_argument("--plan-output", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=45.0)
    return p.parse_args()


def run(cmd: list[str], env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def safe_json(command: list[str], env: dict[str, str], timeout: float) -> Any:
    try:
        result = run(command, env, timeout)
        if result.returncode != 0:
            return None
        text = result.stdout.strip()
        if not text:
            return None
        return json.loads(text)
    except Exception:
        return None


def collect_strings(value: Any) -> list[str]:
    rows: list[str] = []
    if isinstance(value, str):
        rows.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            rows.extend(collect_strings(item))
    elif isinstance(value, list):
        for item in value:
            rows.extend(collect_strings(item))
    return rows


def model_candidates(model: str, env: dict[str, str], timeout: float) -> list[str]:
    candidates = [
        model,
        f"ollama:{model}",
        f"ollama/{model}",
        f"ollama::{model}",
        f"ollama|{model}",
    ]
    for command in (
        ["redteam", "adaptive", "models", "--json"],
        ["redteam", "models", "list", "--json"],
        ["redteam", "inventory", "--json"],
    ):
        payload = safe_json(command, env, timeout)
        if payload is None:
            continue
        for text in collect_strings(payload):
            lower = text.lower()
            if model.lower() in lower or ("ollama" in lower and "llama3.1" in lower):
                candidates.append(text)
    # Human adaptive-model output can expose stable IDs even when JSON is absent.
    try:
        result = run(["redteam", "adaptive", "models"], env, timeout)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if model.lower() not in line.lower() and not ("ollama" in line.lower() and "llama3.1" in line.lower()):
                    continue
                for token in re.findall(r"[A-Za-z0-9_.:/|@-]+", line):
                    if "llama" in token.lower() or "ollama" in token.lower():
                        candidates.append(token)
    except Exception:
        pass
    unique: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        item = item.strip()
        if not item or item in seen or len(item) > 240:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def help_text(command: list[str], env: dict[str, str], timeout: float) -> str:
    try:
        return run(command + ["--help"], env, timeout).stdout
    except Exception:
        return ""


def has_flag(help_output: str, flag: str) -> bool:
    return flag in help_output


def write_lines(path: Path, values: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{item}\n" for item in values), encoding="utf-8")


def main() -> int:
    args = parse_args()
    base_url = args.base_url.rstrip("/")
    if base_url not in {"http://127.0.0.1:11434", "http://localhost:11434"}:
        raise SystemExit("Only the local Ollama endpoint is permitted.")

    env = os.environ.copy()
    # Explicit provider aliases. Unknown values are ignored by the installed settings model.
    provider_names = [
        "ADAPTIVE_PROVIDER", "REDTEAM_ADAPTIVE_PROVIDER",
        "ADAPTIVE_MODEL_PROVIDER", "REDTEAM_ADAPTIVE_MODEL_PROVIDER",
        "ADAPTIVE_PLANNER_PROVIDER", "REDTEAM_ADAPTIVE_PLANNER_PROVIDER",
        "PLANNER_PROVIDER", "REDTEAM_PLANNER_PROVIDER",
        "MODEL_PROVIDER", "REDTEAM_MODEL_PROVIDER",
        "DEFAULT_MODEL_PROVIDER", "REDTEAM_DEFAULT_MODEL_PROVIDER",
    ]
    model_names = [
        "ADAPTIVE_MODEL", "REDTEAM_ADAPTIVE_MODEL",
        "ADAPTIVE_PLANNER_MODEL", "REDTEAM_ADAPTIVE_PLANNER_MODEL",
        "PLANNER_MODEL", "REDTEAM_PLANNER_MODEL",
    ]
    url_names = [
        "ADAPTIVE_BASE_URL", "REDTEAM_ADAPTIVE_BASE_URL",
        "ADAPTIVE_OLLAMA_BASE_URL", "REDTEAM_ADAPTIVE_OLLAMA_BASE_URL",
        "OLLAMA_BASE_URL", "REDTEAM_OLLAMA_BASE_URL",
    ]
    for name in provider_names:
        env[name] = "ollama"
    for name in model_names:
        env[name] = args.model
    for name in url_names:
        env[name] = base_url

    role_payloads = {
        "planner": {"provider": "ollama", "model": args.model},
        "proposer": {"provider": "ollama", "model": args.model},
        "reviewer": {"provider": "ollama", "model": args.model},
        "summarizer": {"provider": "ollama", "model": args.model},
    }
    role_json = json.dumps(role_payloads, separators=(",", ":"))
    for name in (
        "ADAPTIVE_MODEL_ROLES", "REDTEAM_ADAPTIVE_MODEL_ROLES",
        "MODEL_ROLES", "REDTEAM_MODEL_ROLES",
        "ADAPTIVE_ROLE_ASSIGNMENTS", "REDTEAM_ADAPTIVE_ROLE_ASSIGNMENTS",
    ):
        env[name] = role_json

    # Introspect exact Settings aliases, including provider fields not prefixed adaptive_.
    introspected: dict[str, str] = {}
    try:
        from redteam_platform.settings import Settings
        from typing import get_args, get_origin

        prefix = str(Settings.model_config.get("env_prefix", "") or "")
        for field_name, field in Settings.model_fields.items():
            lower = field_name.lower()
            value: str | None = None
            if "provider" in lower and not any(x in lower for x in ("timeout", "retries", "repairs", "url", "endpoint")):
                value = "ollama"
            elif ("planner" in lower or "adaptive" in lower) and "model" in lower and "calls" not in lower:
                value = args.model
            elif ("ollama" in lower or "provider" in lower or "adaptive" in lower) and ("base_url" in lower or "endpoint" in lower):
                value = base_url
            elif ("role" in lower and ("adaptive" in lower or "model" in lower)):
                value = role_json
            if value is None:
                continue
            names = {field_name.upper(), f"{prefix}{field_name}".upper()}
            alias = getattr(field, "alias", None)
            if isinstance(alias, str):
                names.add(alias.upper())
            validation_alias = getattr(field, "validation_alias", None)
            if isinstance(validation_alias, str):
                names.add(validation_alias.upper())
            choices = getattr(validation_alias, "choices", None)
            if choices:
                for choice in choices:
                    if isinstance(choice, str):
                        names.add(choice.upper())
            for name in names:
                if re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
                    env[name] = value
                    introspected[name] = value
    except Exception:
        pass

    run_help = help_text(["redteam", "assess", "run"], env, args.timeout)
    plan_help = help_text(["redteam", "assess", "plan"], env, args.timeout)

    provider_flags = [None]
    for flag in ("--model-provider", "--adaptive-provider", "--planner-provider", "--provider"):
        if has_flag(run_help, flag):
            provider_flags.insert(0, flag)
    model_flags = [None]
    for flag in ("--planner-model", "--adaptive-model", "--proposal-model", "--model"):
        if has_flag(run_help, flag):
            model_flags.insert(0, flag)
    url_flags = [None]
    for flag in ("--ollama-base-url", "--provider-base-url", "--base-url"):
        if has_flag(run_help, flag):
            url_flags.insert(0, flag)

    candidates = model_candidates(args.model, env, args.timeout)
    attempts: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None

    base_plan = [
        "redteam", "assess", "plan",
        "--kind", "dexter",
        "--target", args.target,
        "--profile", args.profile,
        "--adaptive-mode", "adaptive",
    ]
    base_run = [
        "assess", "run",
        "--kind", "dexter",
        "--target", args.target,
        "--profile", args.profile,
        "--adaptive-mode", "adaptive",
    ]

    # Prefer explicit flags, then provider-qualified model identifiers, then raw model.
    for provider_flag in provider_flags:
        for model_flag in model_flags:
            for model_value in candidates:
                for url_flag in url_flags:
                    cmd = list(base_plan)
                    run_args = list(base_run)
                    if provider_flag:
                        cmd += [provider_flag, "ollama"]
                        run_args += [provider_flag, "ollama"]
                    if model_flag:
                        cmd += [model_flag, model_value]
                        run_args += [model_flag, model_value]
                    if url_flag:
                        cmd += [url_flag, base_url]
                        run_args += [url_flag, base_url]
                    try:
                        result = run(cmd, env, args.timeout)
                        output = result.stdout
                        code = result.returncode
                    except subprocess.TimeoutExpired:
                        output = "plan preflight timed out"
                        code = 124
                    attempts.append({
                        "provider_flag": provider_flag,
                        "model_flag": model_flag,
                        "model_value": model_value,
                        "url_flag": url_flag,
                        "returncode": code,
                        "output_tail": output[-1200:],
                    })
                    if code == 0:
                        selected = {
                            "plan_command": cmd,
                            "run_args": run_args,
                            "provider_flag": provider_flag,
                            "model_flag": model_flag,
                            "model_value": model_value,
                            "url_flag": url_flag,
                            "plan_output": output,
                        }
                        break
                if selected:
                    break
            if selected:
                break
        if selected:
            break

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if selected is None:
        payload = {
            "ok": False,
            "error": "No installed adaptive provider/model invocation passed the non-executing plan preflight.",
            "attempts": attempts[-24:],
            "settings_provider_env": sorted(name for name, value in env.items() if "PROVIDER" in name and value == "ollama"),
            "model_candidates": candidates,
            "run_help_excerpt": run_help[-5000:],
        }
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        args.plan_output.write_text(attempts[-1]["output_tail"] if attempts else "No attempts were made.\n", encoding="utf-8")
        return 2

    # Persist only non-secret values needed by the winning invocation.
    safe_env = {
        name: value for name, value in env.items()
        if (
            name in provider_names
            or name in model_names
            or name in url_names
            or name in introspected
            or name in {
                "ADAPTIVE_MODEL_ROLES", "REDTEAM_ADAPTIVE_MODEL_ROLES",
                "MODEL_ROLES", "REDTEAM_MODEL_ROLES",
                "ADAPTIVE_ROLE_ASSIGNMENTS", "REDTEAM_ADAPTIVE_ROLE_ASSIGNMENTS",
            }
        ) and value
    }
    write_lines(args.run_args, selected["run_args"])
    args.env_output.write_text("".join(f"{k}\t{v}\n" for k, v in sorted(safe_env.items())), encoding="utf-8")
    args.plan_output.write_text(selected["plan_output"], encoding="utf-8")
    payload = {
        "ok": True,
        "provider": "ollama",
        "planner_model_requested": args.model,
        "planner_model_resolved": selected["model_value"],
        "provider_flag": selected["provider_flag"],
        "model_flag": selected["model_flag"],
        "url_flag": selected["url_flag"],
        "attempt_count": len(attempts),
        "run_args": selected["run_args"],
        "environment_names": sorted(safe_env),
    }
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
