"""Allowlisted deterministic subprocess tool; no shell or arbitrary command text."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from typing import Callable

from redteam_platform.artifacts import sanitize
from redteam_platform.assessments.models import ResultState, ToolRequest, ToolResult


class RegisteredSubprocessTool:
    def __init__(self, *, runner=subprocess.run):
        self.runner = runner
        self._builders: dict[str, Callable[[ToolRequest], list[str]]] = {}

    def register(self, name: str, builder: Callable[[ToolRequest], list[str]]) -> None:
        self._builders[name] = builder

    def execute(self, request: ToolRequest, target, authorization) -> ToolResult:
        started = datetime.now(timezone.utc)
        builder = self._builders.get(request.operation)
        if builder is None:
            raise ValueError("Subprocess operation is not registered.")
        command = builder(request)
        if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
            raise ValueError("Registered subprocess commands must be argument arrays.")
        try:
            result = self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=request.timeout_seconds,
                check=False,
                env={},
            )
            return ToolResult(
                request_id=request.request_id,
                tool="subprocess",
                status=ResultState.INFORMATIONAL if result.returncode == 0 else ResultState.COVERAGE_ERROR,
                started_at=started,
                data={"returncode": result.returncode, "command": command},
                evidence_content=str(sanitize((result.stdout or "")[: request.maximum_output_bytes])),
                error=str(sanitize((result.stderr or "")[: request.maximum_output_bytes])) or None,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                request_id=request.request_id,
                tool="subprocess",
                status=ResultState.TIMEOUT,
                started_at=started,
                error="Registered subprocess timed out.",
            )
