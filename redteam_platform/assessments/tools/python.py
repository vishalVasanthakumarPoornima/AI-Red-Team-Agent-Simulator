"""Explicitly enrolled in-process Python target tool."""

from __future__ import annotations

from datetime import datetime, timezone

from redteam_platform.assessments.models import ResultState, ToolRequest, ToolResult
from redteam_platform.assessments.tools.base import RegisteredTool
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings
from scanner.attack_runner import run_prompt_against_target
from scanner.target_loader import discover_targets


class PythonTargetTool(RegisteredTool):
    name = "python"

    def __init__(self, settings: Settings, *, policy=None, runner=run_prompt_against_target):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.runner = runner

    def execute(self, request: ToolRequest, target, authorization) -> ToolResult:
        started = datetime.now(timezone.utc)
        self.policy.require_record(target.normalized_target, authorization)
        name = target.normalized_target.removeprefix("python://")
        descriptor = next(
            (row for row in discover_targets() if row["name"] == name),
            None,
        )
        if descriptor is None:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.UNAVAILABLE,
                started_at=started,
                error="Target is not explicitly enrolled with REDTEAM_TARGET.",
            )
        try:
            result = self.runner(
                descriptor,
                str(request.parameters.get("category") or "prompt_injection"),
                str(request.parameters.get("prompt") or ""),
            )
        except Exception as exc:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.COVERAGE_ERROR,
                started_at=started,
                error=f"{type(exc).__name__}: target invocation failed",
            )
        state = {
            "PASS": ResultState.PASS,
            "FAIL": ResultState.CONFIRMED,
            "ERROR": ResultState.COVERAGE_ERROR,
        }.get(result.get("status"), ResultState.COVERAGE_ERROR)
        return ToolResult(
            request_id=request.request_id,
            tool=self.name,
            status=state,
            started_at=started,
            data=result,
            error=result.get("reason") if state == ResultState.COVERAGE_ERROR else None,
            evidence_content=str(result.get("response") or ""),
        )
