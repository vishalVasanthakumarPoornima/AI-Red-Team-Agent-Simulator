"""Scope-checked bounded HTTP execution for registered Dexter probes."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from urllib.parse import urljoin, urlparse

import httpx

from redteam_platform.dexter.evidence import evidence_record
from redteam_platform.dexter.models import (
    DexterProbe,
    DexterProbeResult,
    DexterProbeStatus,
    DexterTarget,
)
from redteam_platform.schemas import AuthorizationRecord
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


class DexterHTTPExecutor:
    def __init__(
        self,
        settings: Settings,
        *,
        policy: ScopePolicy | None = None,
        client_factory: Callable[[], httpx.Client] | None = None,
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.client_factory = client_factory or (
            lambda: httpx.Client(follow_redirects=False)
        )

    def execute(
        self,
        target: DexterTarget,
        probe: DexterProbe,
        authorization: AuthorizationRecord,
        *,
        step_id: str,
    ) -> DexterProbeResult:
        endpoint = self._endpoint(target, probe.route)
        decision = self.policy.decide(
            endpoint,
            active=True,
            public_mode=authorization.public_mode,
            interactive_confirmation=authorization.confirmed_interactively,
            authorization_statement=authorization.statement,
        )
        if not decision.allowed:
            raise ScopeDeniedError(decision.reason)
        target_host = urlparse(target.main_endpoint).hostname
        endpoint_host = urlparse(decision.normalized_target).hostname
        configured = {
            urlparse(value).hostname
            for value in (
                target.main_endpoint,
                *target.tool_service_endpoints,
                target.memory_service,
                target.vector_store,
                target.retrieval_service,
                *target.voice_services,
            )
            if value
        }
        if endpoint_host != target_host and endpoint_host not in configured:
            raise ScopeDeniedError("Probe endpoint is outside the configured Dexter component set.")

        started = time.monotonic()
        try:
            with self.client_factory() as client:
                kwargs = {
                    "headers": {"Accept": "application/json", **probe.headers},
                    "timeout": probe.timeout_seconds,
                }
                if probe.method == "POST":
                    kwargs["json"] = probe.payload or {}
                elif probe.method == "POST_RAW":
                    kwargs["content"] = str((probe.payload or {}).get("raw", ""))
                with client.stream(
                    "POST" if probe.method == "POST_RAW" else probe.method,
                    decision.normalized_target,
                    **kwargs,
                ) as response:
                    status_code = response.status_code
                    response_headers = dict(response.headers)
                    encoding = response.encoding or "utf-8"
                    body_buffer = bytearray()
                    oversized = False
                    for chunk in response.iter_bytes():
                        remaining = probe.maximum_response_bytes + 1 - len(body_buffer)
                        if remaining <= 0:
                            oversized = True
                            break
                        body_buffer.extend(chunk[:remaining])
                        if len(body_buffer) > probe.maximum_response_bytes:
                            oversized = True
                            break
        except httpx.TimeoutException as exc:
            return self._error(probe, target, step_id, started, "timeout", exc)
        except httpx.HTTPError as exc:
            return self._error(probe, target, step_id, started, "http_error", exc)
        if 300 <= status_code < 400:
            location = response_headers.get("location")
            if location:
                self.policy.validate_redirect(target.main_endpoint, location, authorization)
            return self._error(
                probe,
                target,
                step_id,
                started,
                "redirect_not_followed",
                ValueError("Redirect was validated but not followed."),
            )
        if oversized:
            return self._error(
                probe,
                target,
                step_id,
                started,
                "response_too_large",
                ValueError("Response exceeded the configured evidence limit."),
            )
        text = bytes(body_buffer).decode(encoding, errors="replace")
        headers = {
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
                "x-request-id",
                "ratelimit-limit",
                "ratelimit-remaining",
                "retry-after",
            }
        }
        combined = json.dumps(
            {
                "status": status_code,
                "headers": headers,
                "body": text,
            },
            ensure_ascii=False,
        )
        return DexterProbeResult(
            probe_id=probe.probe_id,
            step_id=step_id,
            target_id=target.stable_id,
            component_id="dexter_component_api",
            status=DexterProbeStatus.INFORMATIONAL,
            http_status=status_code,
            evaluation_rule="pending_evaluation",
            evidence=[
                evidence_record(
                    probe_id=probe.probe_id,
                    component_id="dexter_component_api",
                    kind="http",
                    summary=f"{probe.method} {urlparse(endpoint).path} returned HTTP {status_code}",
                    content=combined,
                )
            ],
            duration_seconds=time.monotonic() - started,
        )

    @staticmethod
    def _endpoint(target: DexterTarget, route: str) -> str:
        if "://" in route:
            return route
        return urljoin(target.main_endpoint.rstrip("/") + "/", route.lstrip("/"))

    @staticmethod
    def _error(probe, target, step_id, started, rule, exc) -> DexterProbeResult:
        return DexterProbeResult(
            probe_id=probe.probe_id,
            step_id=step_id,
            target_id=target.stable_id,
            component_id="dexter_component_api",
            status=DexterProbeStatus.COVERAGE_ERROR,
            evaluation_rule=rule,
            error=f"{type(exc).__name__}: {exc}",
            duration_seconds=time.monotonic() - started,
        )
