"""Explicit opt-in, fixed-argument Kali validation for one authorized host."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone

from redteam_platform.artifacts import sanitize
from redteam_platform.assessments.models import ResultState, ToolRequest, ToolResult
from redteam_platform.assessments.tools.base import RegisteredTool
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy


class KaliTool(RegisteredTool):
    name = "kali"

    def __init__(self, settings, *, policy=None, runner=subprocess.run):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.runner = runner

    def execute(self, request, target, authorization):
        started = datetime.now(timezone.utc)
        if not self.settings.kali_ssh_host:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.UNAVAILABLE,
                started_at=started,
                error="Kali is not configured.",
            )
        if not target.host:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.UNAVAILABLE,
                started_at=started,
                error="This target has no network host for Kali validation.",
            )
        if "nmap" not in self.settings.kali_tool_allowlist:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.UNAVAILABLE,
                started_at=started,
                error="The fixed nmap operation is not allowlisted.",
            )
        self.policy.require_record(target.normalized_target, authorization)
        ssh = self.policy.decide(f"ssh://{self.settings.kali_ssh_host}", active=False)
        if not ssh.allowed:
            raise ScopeDeniedError(ssh.reason)
        ports = [int(value) for value in request.parameters.get("ports", [])]
        if not ports or len(ports) > 64 or any(not 1 <= port <= 65535 for port in ports):
            raise ScopeDeniedError("Kali ports must be an explicit list of at most 64 ports.")
        command = [
            "ssh", "-T", "-o", "BatchMode=yes", "-o", "RequestTTY=no",
            "-o", f"ConnectTimeout={max(1, int(self.settings.kali_readiness_timeout))}",
        ]
        if self.settings.kali_ssh_key:
            command.extend(["-i", str(self.settings.kali_ssh_key), "-o", "IdentitiesOnly=yes"])
        command.extend([
            self.settings.kali_ssh_host, "--", "nmap", "-sT", "-Pn",
            "--host-timeout", "30s", "-p", ",".join(str(port) for port in ports),
            target.host,
        ])
        try:
            completed = self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=min(request.timeout_seconds, 60),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.TIMEOUT,
                started_at=started,
                error="Fixed Kali validation timed out.",
            )
        redacted = [
            "<key-path>" if self.settings.kali_ssh_key and part == str(self.settings.kali_ssh_key) else part
            for part in command
        ]
        return ToolResult(
            request_id=request.request_id,
            tool=self.name,
            status=(
                ResultState.INFORMATIONAL
                if completed.returncode == 0
                else ResultState.COVERAGE_ERROR
            ),
            started_at=started,
            data={"returncode": completed.returncode, "command": redacted},
            evidence_content=str(sanitize((completed.stdout or "")[: request.maximum_output_bytes])),
            error=str(sanitize((completed.stderr or "")[: request.maximum_output_bytes])) or None,
        )
