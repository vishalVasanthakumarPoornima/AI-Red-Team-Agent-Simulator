#!/usr/bin/env python3
"""Validate a real baseline Dexter + Kali run before adaptive follow-up."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from build_attack_walkthrough import kali_activity
from evaluate_dynamic_result import verify_manifest


def load(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {} if default is None else default


def find_first(value: Any, keys: tuple[str, ...], default: Any = None) -> Any:
    if isinstance(value, dict):
        for key in keys:
            if key in value and value[key] not in (None, "", [], {}):
                return value[key]
        for child in value.values():
            found = find_first(child, keys, None)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_first(child, keys, None)
            if found not in (None, "", [], {}):
                return found
    return default


def integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    dexter_summary = load(run / "dexter_summary.json", {})
    summary = dexter_summary or load(run / "summary.json", {})
    report = load(run / "report.json", {})
    coverage_data = load(run / "coverage.json", {})
    sources = [summary, report, coverage_data]

    status = str(
        (summary.get("status") if isinstance(summary, dict) else None)
        or (report.get("status") if isinstance(report, dict) else None)
        or "unknown"
    ).lower()
    failed_steps = integer(
        (summary.get("failed_steps") if isinstance(summary, dict) else None)
        or (report.get("failed_steps") if isinstance(report, dict) else None)
        or 0
    )
    raw_errors = (
        summary.get("error_count") if isinstance(summary, dict) else None
    )
    if raw_errors is None and isinstance(report, dict):
        raw_errors = report.get("error_count")
    if raw_errors is None and isinstance(report, dict):
        raw_errors = report.get("errors", [])
    error_count = len(raw_errors) if isinstance(raw_errors, (list, dict)) else integer(raw_errors)
    unavailable_steps = integer(find_first(sources, ("unavailable_steps",), 0))
    coverage = number(find_first(sources, ("coverage_percentage", "overall_percentage", "coverage"), 0))
    findings = integer(find_first(sources, ("finding_count",), 0))
    if findings == 0:
        finding_rows = report.get("findings", []) if isinstance(report, dict) else []
        if isinstance(finding_rows, list):
            findings = len(finding_rows)
    kali = kali_activity(run)
    manifest_ok, manifest_checked, manifest_valid, manifest_errors = verify_manifest(run)

    conditions = {
        "run_directory_exists": run.is_dir(),
        "status_supported": status in {"complete", "completed", "partial"},
        "no_failed_steps": failed_steps == 0,
        "no_unexpected_errors": error_count == 0,
        "coverage_recorded": coverage > 0,
        "markdown_report_exists": (run / "report.md").is_file(),
        "json_report_exists": (run / "report.json").is_file(),
        "manifest_verified": manifest_ok,
        "kali_checks_completed": int(kali.get("completed_count", 0)) > 0,
    }
    valid = all(conditions.values())
    result = {
        "valid_baseline": valid,
        "run_id": run.name,
        "status": status,
        "coverage_percentage": coverage,
        "finding_count": findings,
        "failed_steps": failed_steps,
        "error_count": error_count,
        "unavailable_steps": unavailable_steps,
        "kali": kali,
        "manifest": {
            "verified": manifest_ok,
            "checked": manifest_checked,
            "valid": manifest_valid,
            "errors": manifest_errors,
        },
        "conditions": conditions,
        "note": "Unavailable retrieval is permitted; failed steps, unexpected errors, or zero completed Kali checks are not.",
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
