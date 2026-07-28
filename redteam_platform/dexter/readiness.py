"""Passive Dexter component health and coverage readiness."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import httpx

from redteam_platform.dexter.models import (
    DexterComponent,
    DexterComponentStatus,
    DexterComponentType,
    DexterHealth,
    DexterTarget,
)
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import OllamaModel
from redteam_platform.inventory.ollama import OllamaDiscovery
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


class DexterReadinessService:
    def __init__(
        self,
        settings: Settings,
        *,
        policy: ScopePolicy | None = None,
        inventory_service: InventoryService | None = None,
        requester: Callable[..., httpx.Response] | None = None,
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.inventory_service = inventory_service or InventoryService(settings)
        self.requester = requester or httpx.get

    def check(self, target: DexterTarget, *, live: bool = True) -> DexterHealth:
        components = [component.model_copy(deep=True) for component in target.components]
        api = next(
            (
                component
                for component in components
                if component.component_type == DexterComponentType.API
                and component.required
            ),
            None,
        )
        explanations: list[str] = []
        if api:
            if live:
                status, explanation = self._get_status(target.health_endpoint)
                api.status = status
                api.evidence.append(explanation)
            elif api.related_inventory_ids:
                api.status = DexterComponentStatus.READY
                api.evidence.append("correlated active inventory")
            else:
                api.status = DexterComponentStatus.UNKNOWN
                explanations.append("Live HTTP readiness was not requested.")

        openapi = DexterComponent(
            stable_id="dexter_component_openapi",
            name="OpenAPI",
            component_type=DexterComponentType.API,
            endpoint=target.openapi_endpoint,
            required=False,
        )
        if live:
            openapi.status, openapi_evidence = self._get_status(target.openapi_endpoint)
            openapi.evidence.append(openapi_evidence)
        components.append(openapi)

        cached = self.inventory_service.cached()
        if target.ollama_endpoint:
            ollama = next(
                (
                    component
                    for component in components
                    if component.component_type == DexterComponentType.OLLAMA
                ),
                None,
            )
            if ollama:
                models = (
                    [
                        item
                        for item in cached.items
                        if isinstance(item, OllamaModel)
                        and (
                            not target.model_name
                            or item.model_name == target.model_name
                        )
                    ]
                    if cached
                    else []
                )
                if live:
                    live_settings = self.settings.model_copy(
                        update={"ollama_live_check": True}
                    )
                    live_models, _ = OllamaDiscovery(live_settings).collect()
                    selected_live_models = [
                        item
                        for item in live_models
                        if isinstance(item, OllamaModel)
                        and (
                            not target.model_name
                            or item.model_name == target.model_name
                        )
                    ]
                    if selected_live_models:
                        models = selected_live_models
                if not models:
                    ollama.status = DexterComponentStatus.UNAVAILABLE
                    ollama.errors.append("Expected Ollama model was not found in cached inventory.")
                elif any(item.running for item in models):
                    ollama.status = DexterComponentStatus.READY
                    ollama.evidence.append("Expected model is installed and running.")
                elif any(item.installed for item in models):
                    ollama.status = DexterComponentStatus.DEGRADED
                    ollama.evidence.append("Expected model is installed but not loaded.")

        reports = next(
            (
                component
                for component in components
                if component.component_type == DexterComponentType.REPORTS
            ),
            None,
        )
        if reports:
            root = Path(self.settings.report_root)
            parent = root if root.exists() else root.parent
            if parent.exists() and os.access(parent, os.W_OK):
                reports.status = DexterComponentStatus.READY
            else:
                reports.status = DexterComponentStatus.UNAVAILABLE
                reports.errors.append("Reports root is not writable.")

        for component in components:
            if component.endpoint and component.component_type in {
                DexterComponentType.TOOL,
                DexterComponentType.MEMORY,
                DexterComponentType.VECTOR,
                DexterComponentType.RETRIEVAL,
                DexterComponentType.VOICE,
            }:
                if live:
                    component.status, evidence = self._get_status(component.endpoint)
                    component.evidence.append(evidence)

        required = [component for component in components if component.required]
        if any(
            component.status == DexterComponentStatus.UNAVAILABLE
            for component in required
        ):
            overall = DexterComponentStatus.UNAVAILABLE
        elif any(
            component.status
            in {
                DexterComponentStatus.DEGRADED,
                DexterComponentStatus.UNAVAILABLE,
                DexterComponentStatus.PROTECTED,
                DexterComponentStatus.UNKNOWN,
            }
            for component in components
        ):
            overall = DexterComponentStatus.DEGRADED
        else:
            overall = DexterComponentStatus.READY

        mapping = {
            DexterComponentType.API: "api_surface",
            DexterComponentType.TOOL: "tool_security",
            DexterComponentType.MEMORY: "memory",
            DexterComponentType.VECTOR: "retrieval",
            DexterComponentType.RETRIEVAL: "retrieval",
            DexterComponentType.OLLAMA: "prompt_security",
            DexterComponentType.KALI: "kali_network_checks",
            DexterComponentType.LISTENER: "service_exposure",
            DexterComponentType.REPORTS: "reporting",
        }
        available: set[str] = {"deployment_discovery", "service_exposure"}
        unavailable: set[str] = set()
        for component in components:
            category = mapping.get(component.component_type)
            if not category:
                continue
            if component.status in {
                DexterComponentStatus.READY,
                DexterComponentStatus.DEGRADED,
                DexterComponentStatus.PROTECTED,
            }:
                available.add(category)
            elif component.status in {
                DexterComponentStatus.UNAVAILABLE,
                DexterComponentStatus.NOT_CONFIGURED,
            }:
                unavailable.add(category)
        if api and api.status in {
            DexterComponentStatus.READY,
            DexterComponentStatus.PROTECTED,
        }:
            available.update({"authentication", "authorization", "error_handling"})
        explanations.extend(
            f"{component.name}: {component.status}"
            for component in components
            if component.status != DexterComponentStatus.READY
        )
        return DexterHealth(
            target_id=target.stable_id,
            overall=overall,
            components=components,
            available_coverage=sorted(available),
            unavailable_coverage=sorted(unavailable - available),
            explanations=explanations,
        )

    def _get_status(self, endpoint: str) -> tuple[DexterComponentStatus, str]:
        try:
            decision = self.policy.decide(endpoint, active=False)
        except ScopeDeniedError as exc:
            return DexterComponentStatus.UNAVAILABLE, f"scope denied: {exc}"
        if not decision.allowed:
            return DexterComponentStatus.UNAVAILABLE, f"scope denied: {decision.reason}"
        try:
            response = self.requester(
                decision.normalized_target,
                timeout=min(self.settings.request_timeout_seconds, 10),
                follow_redirects=False,
                headers={"Accept": "application/json"},
            )
        except (httpx.HTTPError, OSError) as exc:
            return DexterComponentStatus.UNAVAILABLE, f"{type(exc).__name__}: unavailable"
        if 300 <= response.status_code < 400:
            location = response.headers.get("location")
            if location:
                return DexterComponentStatus.UNAVAILABLE, "redirect denied during readiness"
        if response.status_code in {401, 403}:
            return DexterComponentStatus.PROTECTED, f"HTTP {response.status_code}"
        if response.status_code < 500:
            return DexterComponentStatus.READY, f"HTTP {response.status_code}"
        return DexterComponentStatus.DEGRADED, f"HTTP {response.status_code}"
