"""Single-host explicit-port socket tool with no payload sending."""

from __future__ import annotations

import socket
from datetime import datetime, timezone

from redteam_platform.assessments.models import ResultState, ToolRequest, ToolResult
from redteam_platform.assessments.tools.base import RegisteredTool
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


class SocketTool(RegisteredTool):
    name = "socket"

    def __init__(self, settings: Settings, *, policy=None, connector=None):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.connector = connector or socket.create_connection

    def execute(self, request: ToolRequest, target, authorization) -> ToolResult:
        started = datetime.now(timezone.utc)
        port = int(request.parameters["port"])
        if (
            port not in self.settings.approved_host_ports
            and port not in target.safe_metadata.get("ports", [])
            and not request.parameters.get("approved_by_plan")
        ):
            raise ScopeDeniedError("Port is outside the explicit approved list.")
        decision = self.policy.decide(
            request.scope_target,
            active=True,
            authorization_statement=authorization.statement,
            public_mode=authorization.public_mode,
            interactive_confirmation=authorization.confirmed_interactively,
        )
        if not decision.allowed:
            raise ScopeDeniedError(decision.reason)
        try:
            connection = self.connector(
                (target.host, port),
                timeout=min(request.timeout_seconds, self.settings.host_timeout_seconds),
            )
            connection.close()
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.INFORMATIONAL,
                started_at=started,
                data={"port": port, "state": "open", "payload_sent": False},
                evidence_content=f"TCP port {port} accepted a connection; no payload was sent.",
            )
        except TimeoutError:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.TIMEOUT,
                started_at=started,
                data={"port": port, "state": "timeout"},
                error="Socket timeout.",
            )
        except OSError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.UNAVAILABLE,
                started_at=started,
                data={"port": port, "state": "closed_or_filtered"},
                error=f"{type(exc).__name__}: closed, filtered, or unavailable",
            )
