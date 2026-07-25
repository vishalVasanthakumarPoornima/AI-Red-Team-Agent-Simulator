"""Verified TLS metadata collection."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from redteam_platform.artifacts import sanitize
from redteam_platform.assessments.models import ResultState, ToolRequest, ToolResult
from redteam_platform.assessments.tools.base import RegisteredTool
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings


class TLSTool(RegisteredTool):
    name = "tls"

    def __init__(self, settings: Settings, *, policy=None):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)

    def execute(self, request: ToolRequest, target, authorization) -> ToolResult:
        started = datetime.now(timezone.utc)
        decision = self.policy.decide(
            request.scope_target,
            active=False,
            authorization_statement=authorization.statement,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)
        if not self.settings.tls_verify:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.UNAVAILABLE,
                started_at=started,
                error="Verified TLS collection is disabled; an unverified connection was not attempted.",
            )
        context = ssl.create_default_context()
        context.minimum_version = {
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }[self.settings.tls_minimum_version]
        parsed = urlparse(request.scope_target)
        host = parsed.hostname or target.host
        port = parsed.port or target.port or 443
        try:
            with socket.create_connection(
                (host, port),
                timeout=min(request.timeout_seconds, self.settings.host_timeout_seconds),
            ) as raw:
                with context.wrap_socket(raw, server_hostname=host) as wrapped:
                    certificate = wrapped.getpeercert()
                    data = {
                        "version": wrapped.version(),
                        "cipher": wrapped.cipher(),
                        "subject": certificate.get("subject"),
                        "issuer": certificate.get("issuer"),
                        "notAfter": certificate.get("notAfter"),
                        "subjectAltName": certificate.get("subjectAltName"),
                        "verified": True,
                    }
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.INFORMATIONAL,
                started_at=started,
                data=sanitize(data),
                evidence_content=str(sanitize(data)),
            )
        except (OSError, ssl.SSLError) as exc:
            return ToolResult(
                request_id=request.request_id,
                tool=self.name,
                status=ResultState.COVERAGE_ERROR,
                started_at=started,
                error=f"{type(exc).__name__}: TLS verification or connection failed",
            )
