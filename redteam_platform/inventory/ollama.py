"""Passive Ollama endpoint, installed-model, and running-model discovery."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from redteam_platform.artifacts import sanitize_url
from redteam_platform.inventory.http_probe import SafeHTTPProbe
from redteam_platform.inventory.models import (
    DiscoveryConfidence,
    DiscoveryError,
    DiscoveryEvidence,
    DiscoverySource,
    HealthState,
    InventoryItem,
    InventoryStatus,
    OllamaEndpoint,
    OllamaModel,
)
from redteam_platform.inventory.platform import normalize_identity_url, stable_id
from redteam_platform.schemas import ScopeClassification
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


def _as_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class OllamaDiscovery:
    def __init__(
        self,
        settings: Settings,
        policy: ScopePolicy | None = None,
        probe: SafeHTTPProbe | None = None,
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.probe = probe or SafeHTTPProbe(
            self.policy,
            timeout=settings.ollama_discovery_timeout,
            maximum_bytes=settings.metadata_response_size,
        )

    def collect(
        self, *, live: bool | None = None
    ) -> tuple[list[InventoryItem], list[DiscoveryError]]:
        items: list[InventoryItem] = []
        errors: list[DiscoveryError] = []
        perform_live = self.settings.ollama_live_check if live is None else live
        for configured in self.settings.ollama_endpoints:
            if not perform_live:
                endpoint, endpoint_errors = self._configured_endpoint(configured)
                items.append(endpoint)
                errors.extend(endpoint_errors)
                continue
            endpoint_items, endpoint_errors = self._endpoint(configured)
            items.extend(endpoint_items)
            errors.extend(endpoint_errors)
        return items, errors

    def _configured_endpoint(
        self, configured: str
    ) -> tuple[OllamaEndpoint, list[DiscoveryError]]:
        base = normalize_identity_url(configured)
        endpoint_id = stable_id("ollama_endpoint", base)
        try:
            decision = self.policy.decide(base, active=False)
        except ScopeDeniedError as exc:
            decision = None
            reason = str(exc)
        else:
            reason = decision.reason
        denied = decision is None or not decision.allowed
        errors = (
            [
                DiscoveryError(
                    source="ollama",
                    code="scope_denied",
                    message=f"Ollama endpoint denied by scope policy: {reason}",
                )
            ]
            if denied
            else []
        )
        return (
            OllamaEndpoint(
                stable_id=endpoint_id,
                name="Ollama",
                status=(
                    InventoryStatus.UNAVAILABLE
                    if denied
                    else InventoryStatus.INACTIVE
                ),
                endpoint=sanitize_url(base),
                base_url=sanitize_url(base),
                host=decision.evidence.get("hostname") if decision else None,
                port=decision.evidence.get("port") if decision else None,
                protocol="http",
                discovery_source=DiscoverySource.CONFIGURATION,
                discovery_confidence=DiscoveryConfidence.CONFIRMED,
                confidence_reason=(
                    "Endpoint is configured; live Ollama discovery was not requested."
                    if not denied
                    else "Endpoint is configured but denied by scope policy."
                ),
                capabilities=["live_discovery_opt_in"],
                health=(
                    HealthState.NOT_CHECKED
                    if not denied
                    else HealthState.UNAVAILABLE
                ),
                scope_classification=(
                    decision.classification
                    if decision
                    else ScopeClassification.BLOCKED
                ),
                errors=errors,
            ),
            errors,
        )

    def _endpoint(
        self, configured: str
    ) -> tuple[list[InventoryItem], list[DiscoveryError]]:
        base = normalize_identity_url(configured)
        endpoint_id = stable_id("ollama_endpoint", base)
        try:
            decision = self.policy.decide(base, active=False)
        except ScopeDeniedError as exc:
            decision = None
            message = str(exc)
        else:
            message = decision.reason
        if decision is None or not decision.allowed:
            error = DiscoveryError(
                source="ollama",
                code="scope_denied",
                message=f"Ollama endpoint denied by scope policy: {message}",
            )
            endpoint = OllamaEndpoint(
                stable_id=endpoint_id,
                name="Ollama",
                status=InventoryStatus.UNAVAILABLE,
                endpoint=sanitize_url(base),
                base_url=sanitize_url(base),
                host=None,
                discovery_source=DiscoverySource.CONFIGURATION,
                discovery_confidence=DiscoveryConfidence.CONFIRMED,
                confidence_reason="Endpoint was explicitly configured but denied by policy.",
                health=HealthState.UNAVAILABLE,
                scope_classification=ScopeClassification.BLOCKED,
                errors=[error],
            )
            return [endpoint], [error]

        version_result = self.probe.get_json(base, "/api/version")
        installed_result = self.probe.get_json(base, "/api/tags")
        running_result = self.probe.get_json(base, "/api/ps")
        results = [version_result, installed_result, running_result]
        endpoint_errors: list[DiscoveryError] = []
        for route, result in zip(("/api/version", "/api/tags", "/api/ps"), results):
            if result.error_code:
                endpoint_errors.append(
                    DiscoveryError(
                        source="ollama",
                        code=result.error_code,
                        message=f"{route}: {result.error}",
                        details={"status_code": result.status_code},
                    )
                )

        successful = [
            result
            for result in results
            if result.status_code
            and 200 <= result.status_code < 300
            and result.data is not None
        ]
        invalid = any(result.error_code in {"invalid_json", "response_too_large"} for result in results)
        received_http = any(result.status_code is not None for result in results)
        if successful:
            status = InventoryStatus.AVAILABLE
            health = HealthState.DEGRADED if endpoint_errors else HealthState.HEALTHY
            availability_state = "available"
        elif invalid:
            status = InventoryStatus.ERROR
            health = HealthState.UNHEALTHY
            availability_state = "invalid_response"
        elif received_http:
            status = InventoryStatus.UNAVAILABLE
            health = HealthState.UNAVAILABLE
            availability_state = "ollama_unavailable"
        else:
            status = InventoryStatus.UNAVAILABLE
            health = HealthState.UNAVAILABLE
            availability_state = "endpoint_unavailable"

        installed_rows = self._model_rows(installed_result.data, "models", endpoint_errors, "installed")
        running_rows = self._model_rows(running_result.data, "models", endpoint_errors, "running")
        running_by_name = {
            str(row.get("name") or row.get("model")): row
            for row in running_rows
            if row.get("name") or row.get("model")
        }
        installed_by_name = {
            str(row.get("name") or row.get("model")): row
            for row in installed_rows
            if row.get("name") or row.get("model")
        }
        names = sorted(set(installed_by_name) | set(running_by_name))
        version = (
            str(version_result.data.get("version"))
            if isinstance(version_result.data, dict) and version_result.data.get("version")
            else None
        )
        endpoint = OllamaEndpoint(
            stable_id=endpoint_id,
            name="Ollama",
            status=status,
            endpoint=sanitize_url(base),
            base_url=sanitize_url(base),
            host=decision.evidence.get("hostname"),
            port=decision.evidence.get("port"),
            protocol="http",
            discovery_source=DiscoverySource.OLLAMA_API,
            discovery_confidence=(
                DiscoveryConfidence.CONFIRMED if successful else DiscoveryConfidence.MEDIUM
            ),
            confidence_reason=(
                "Ollama API returned supported metadata."
                if successful
                else "Endpoint was configured but no valid Ollama metadata was returned."
            ),
            capabilities=["version", "installed_models", "running_models"],
            health=health,
            health_details={
                "availability_state": availability_state,
                "version_status": version_result.status_code,
                "installed_status": installed_result.status_code,
                "running_status": running_result.status_code,
                "installed_state": (
                    "none_installed" if installed_result.data is not None and not installed_rows else "reported"
                ),
                "running_state": (
                    "none_running" if running_result.data is not None and not running_rows else "reported"
                ),
            },
            scope_classification=decision.classification,
            evidence=[
                DiscoveryEvidence(
                    source=DiscoverySource.OLLAMA_API,
                    fact="supported_api_response",
                    value=bool(successful),
                    confidence=DiscoveryConfidence.CONFIRMED,
                )
            ],
            errors=endpoint_errors,
            version=version,
            latency_seconds=max(
                (result.latency_seconds or 0 for result in results),
                default=0,
            ),
            installed_model_count=len(installed_by_name),
            running_model_count=len(running_by_name),
        )
        items: list[InventoryItem] = [endpoint]
        for name in names:
            installed = installed_by_name.get(name) or {}
            running = running_by_name.get(name) or {}
            details = installed.get("details") or running.get("details") or {}
            is_installed = name in installed_by_name
            is_running = name in running_by_name
            items.append(
                OllamaModel(
                    stable_id=stable_id("ollama_model", endpoint_id, name),
                    name=name,
                    model_name=name,
                    item_type="ollama_model",
                    status=(
                        InventoryStatus.RUNNING
                        if is_running
                        else InventoryStatus.INSTALLED
                    ),
                    endpoint=sanitize_url(base),
                    host=decision.evidence.get("hostname"),
                    port=decision.evidence.get("port"),
                    protocol="http",
                    discovery_source=DiscoverySource.OLLAMA_API,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Model was reported by an Ollama API endpoint.",
                    capabilities=["generate"],
                    health=HealthState.HEALTHY if is_running else HealthState.NOT_CHECKED,
                    scope_classification=decision.classification,
                    related_ids=[endpoint_id],
                    evidence=[
                        DiscoveryEvidence(
                            source=DiscoverySource.OLLAMA_API,
                            fact="installed",
                            value=is_installed,
                            confidence=DiscoveryConfidence.CONFIRMED,
                        ),
                        DiscoveryEvidence(
                            source=DiscoverySource.OLLAMA_API,
                            fact="running",
                            value=is_running,
                            confidence=DiscoveryConfidence.CONFIRMED,
                        ),
                    ],
                    endpoint_id=endpoint_id,
                    installed=is_installed,
                    running=is_running,
                    size_bytes=installed.get("size"),
                    parameter_size=details.get("parameter_size"),
                    quantization=details.get("quantization_level"),
                    context_length=running.get("context_length"),
                    digest=installed.get("digest") or running.get("digest"),
                    modified_at=_as_datetime(installed.get("modified_at")),
                    loaded_size_bytes=running.get("size"),
                    vram_bytes=running.get("size_vram"),
                    expires_at=_as_datetime(running.get("expires_at")),
                    metadata={
                        "family": details.get("family"),
                        "format": details.get("format"),
                    },
                )
            )
        return items, endpoint_errors

    @staticmethod
    def _model_rows(
        payload: Any,
        key: str,
        errors: list[DiscoveryError],
        kind: str,
    ) -> list[dict[str, Any]]:
        if payload is None:
            return []
        if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
            errors.append(
                DiscoveryError(
                    source="ollama",
                    code="invalid_response",
                    message=f"Ollama {kind} model response did not contain a models list.",
                )
            )
            return []
        return [row for row in payload[key] if isinstance(row, dict)]
