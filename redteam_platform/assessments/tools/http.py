"""Bounded scope-checked HTTP tool."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from redteam_platform.artifacts import sanitize
from redteam_platform.assessments.models import ResultState, ToolRequest, ToolResult
from redteam_platform.assessments.tools.base import RegisteredTool
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


class HTTPTool(RegisteredTool):
    name = "http"
    allowed_methods = {"GET", "HEAD", "OPTIONS", "POST", "POST_RAW"}

    def __init__(self, settings: Settings, *, policy=None, client_factory=None):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.client_factory = client_factory or (
            lambda: httpx.Client(follow_redirects=False)
        )

    def execute(self, request: ToolRequest, target, authorization) -> ToolResult:
        started = datetime.now(timezone.utc)
        method = request.operation.upper()
        if method not in self.allowed_methods:
            raise ValueError("Unregistered HTTP method.")
        active = method in {"POST", "POST_RAW"}
        decision = self.policy.decide(
            request.scope_target,
            active=active,
            authorization_statement=authorization.statement,
            public_mode=authorization.public_mode,
            interactive_confirmation=authorization.confirmed_interactively,
        )
        if not decision.allowed:
            raise ScopeDeniedError(decision.reason)
        headers = {"Accept": "application/json"}
        reference = target.authentication.reference_name
        if reference:
            env_name = self.settings.authentication_references.get(reference)
            secret = os.environ.get(env_name or "") if env_name else None
            if secret:
                if target.authentication.mode in {"bearer", "api-key"}:
                    header = "Authorization" if target.authentication.mode == "bearer" else "X-API-Key"
                    headers[header] = (
                        f"Bearer {secret}" if target.authentication.mode == "bearer" else secret
                    )
        kwargs = {
            "headers": headers,
            "timeout": min(request.timeout_seconds, self.settings.request_timeout_seconds),
        }
        payload = request.parameters.get("payload")
        if method == "POST":
            kwargs["json"] = payload if payload is not None else {}
        elif method == "POST_RAW":
            kwargs["content"] = str(payload or "{")
            headers["Content-Type"] = "application/json"
        try:
            with self.client_factory() as client:
                with client.stream(
                    "POST" if method == "POST_RAW" else method,
                    decision.normalized_target,
                    **kwargs,
                ) as response:
                    status = response.status_code
                    response_headers = dict(response.headers)
                    if 300 <= status < 400 and response_headers.get("location"):
                        self.policy.validate_redirect(
                            target.normalized_target,
                            response_headers["location"],
                            authorization,
                        )
                        return self._result(
                            request,
                            started,
                            ResultState.COVERAGE_ERROR,
                            error="Redirect was validated but not followed.",
                            data={"http_status": status},
                        )
                    body = bytearray()
                    oversized = False
                    for chunk in response.iter_bytes():
                        remaining = request.maximum_output_bytes + 1 - len(body)
                        if remaining <= 0:
                            oversized = True
                            break
                        body.extend(chunk[:remaining])
                        if len(body) > request.maximum_output_bytes:
                            oversized = True
                            break
                    if oversized:
                        return self._result(
                            request,
                            started,
                            ResultState.COVERAGE_ERROR,
                            error="HTTP response exceeded the configured limit.",
                            data={"http_status": status},
                        )
                    text = bytes(body).decode(response.encoding or "utf-8", errors="replace")
            selected_headers = {
                key.lower(): value
                for key, value in response_headers.items()
                if key.lower()
                in {
                    "content-type",
                    "allow",
                    "access-control-allow-origin",
                    "content-security-policy",
                    "strict-transport-security",
                    "x-content-type-options",
                    "x-frame-options",
                    "set-cookie",
                    "server",
                    "retry-after",
                    "ratelimit-limit",
                    "ratelimit-remaining",
                    "location",
                }
            }
            state = (
                ResultState.PROTECTED
                if status in {401, 403}
                else ResultState.INFORMATIONAL
            )
            content = json.dumps(
                sanitize(
                    {
                        "status": status,
                        "headers": selected_headers,
                        "body": text,
                    }
                ),
                ensure_ascii=False,
            )
            return self._result(
                request,
                started,
                state,
                data={"http_status": status, "headers": selected_headers, "body": text},
                content=content,
            )
        except httpx.TimeoutException:
            return self._result(request, started, ResultState.TIMEOUT, error="HTTP timeout.")
        except httpx.HTTPError as exc:
            return self._result(
                request,
                started,
                ResultState.UNAVAILABLE,
                error=f"{type(exc).__name__}: unavailable",
            )

    def _result(self, request, started, status, *, error=None, data=None, content=""):
        return ToolResult(
            request_id=request.request_id,
            tool=self.name,
            status=status,
            started_at=started,
            data=data or {},
            error=error,
            evidence_content=str(sanitize(content)),
        )
