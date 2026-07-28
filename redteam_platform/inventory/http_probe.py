"""Bounded read-only HTTP metadata probing guarded by the Phase 1 scope policy."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

import httpx
from pydantic import Field

from redteam_platform.artifacts import sanitize, sanitize_url
from redteam_platform.schemas import VersionedModel
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy


class HTTPProbeResult(VersionedModel):
    url: str
    status_code: int | None = None
    data: Any = None
    headers: dict[str, str] = Field(default_factory=dict)
    latency_seconds: float | None = None
    protected: bool = False
    error_code: str | None = None
    error: str | None = None
    oversized: bool = False
    redirect_location: str | None = None


Transport = Callable[[str, float, int], HTTPProbeResult]


class SafeHTTPProbe:
    def __init__(
        self,
        policy: ScopePolicy,
        *,
        timeout: float,
        maximum_bytes: int,
        transport: Transport | None = None,
    ):
        self.policy = policy
        self.timeout = timeout
        self.maximum_bytes = maximum_bytes
        self.transport = transport or self._httpx_get

    def get_json(self, base_url: str, route: str) -> HTTPProbeResult:
        url = urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))
        try:
            decision = self.policy.decide(url, active=False)
        except ScopeDeniedError as exc:
            return HTTPProbeResult(
                url=sanitize_url(url),
                error_code="scope_denied",
                error=str(sanitize(str(exc))),
            )
        if not decision.allowed:
            return HTTPProbeResult(
                url=sanitize_url(url),
                error_code="scope_denied",
                error=decision.reason,
            )
        result = self.transport(decision.normalized_target, self.timeout, self.maximum_bytes)
        result.url = sanitize_url(result.url)
        if result.redirect_location:
            result.redirect_location = sanitize_url(result.redirect_location)
            result.error_code = "redirect_denied"
            result.error = "Redirect was not followed; destination requires explicit validation."
            result.data = None
        result.error = str(sanitize(result.error)) if result.error else None
        result.headers = {
            str(key): str(sanitize(value))
            for key, value in result.headers.items()
            if key.lower() in {"content-type", "server", "location"}
        }
        return result

    @staticmethod
    def _httpx_get(url: str, timeout: float, maximum_bytes: int) -> HTTPProbeResult:
        started = time.monotonic()
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                with client.stream(
                    "GET",
                    url,
                    headers={"Accept": "application/json"},
                ) as response:
                    headers = dict(response.headers)
                    if 300 <= response.status_code < 400:
                        return HTTPProbeResult(
                            url=url,
                            status_code=response.status_code,
                            headers=headers,
                            latency_seconds=time.monotonic() - started,
                            redirect_location=response.headers.get("location"),
                        )
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > maximum_bytes:
                            return HTTPProbeResult(
                                url=url,
                                status_code=response.status_code,
                                headers=headers,
                                latency_seconds=time.monotonic() - started,
                                error_code="response_too_large",
                                error=f"Metadata response exceeded {maximum_bytes} bytes.",
                                oversized=True,
                            )
                    protected = response.status_code in {401, 403}
                    if protected:
                        return HTTPProbeResult(
                            url=url,
                            status_code=response.status_code,
                            headers=headers,
                            latency_seconds=time.monotonic() - started,
                            protected=True,
                        )
                    if not 200 <= response.status_code < 300:
                        return HTTPProbeResult(
                            url=url,
                            status_code=response.status_code,
                            headers=headers,
                            latency_seconds=time.monotonic() - started,
                            error_code="http_error",
                            error=f"HTTP metadata route returned {response.status_code}.",
                        )
                    try:
                        data = json.loads(body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        return HTTPProbeResult(
                            url=url,
                            status_code=response.status_code,
                            headers=headers,
                            latency_seconds=time.monotonic() - started,
                            error_code="invalid_json",
                            error="HTTP metadata route did not return valid JSON.",
                        )
                    return HTTPProbeResult(
                        url=url,
                        status_code=response.status_code,
                        data=data,
                        headers=headers,
                        latency_seconds=time.monotonic() - started,
                    )
        except httpx.TimeoutException:
            return HTTPProbeResult(
                url=url,
                latency_seconds=time.monotonic() - started,
                error_code="timeout",
                error=f"HTTP metadata request timed out after {timeout} seconds.",
            )
        except httpx.HTTPError as exc:
            return HTTPProbeResult(
                url=url,
                latency_seconds=time.monotonic() - started,
                error_code="unavailable",
                error=f"HTTP endpoint unavailable: {type(exc).__name__}.",
            )

