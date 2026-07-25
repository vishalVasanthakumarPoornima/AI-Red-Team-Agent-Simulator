"""Bounded structured-output providers for deterministic and local Ollama use."""

from __future__ import annotations

import json
import time
from typing import Any, Callable
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, ValidationError

from redteam_platform.adaptive_engine.models import (
    AdaptiveModelCandidate,
    ModelCapability,
    ModelRole,
    ProviderKind,
    ProviderResponse,
)
from redteam_platform.artifacts import sanitize
from redteam_platform.inventory.models import OllamaModel
from redteam_platform.inventory.ollama import OllamaDiscovery
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings


class AdaptiveProvider:
    kind = ProviderKind.DETERMINISTIC

    def candidates(self, *, live: bool = False) -> list[AdaptiveModelCandidate]:
        return []

    def generate(
        self,
        *,
        model: str,
        role: ModelRole,
        system_prompt: str,
        context: dict[str, Any],
        response_model: type[BaseModel],
    ) -> tuple[BaseModel | None, ProviderResponse]:
        raise NotImplementedError


class DeterministicProvider(AdaptiveProvider):
    kind = ProviderKind.DETERMINISTIC

    def generate(self, **kwargs):
        role = kwargs["role"]
        model = kwargs.get("model") or "deterministic"
        return None, ProviderResponse(
            provider=self.kind,
            model=model,
            role=role,
            available=True,
            valid=False,
            error="Deterministic provider does not generate model output.",
        )


class OllamaStructuredProvider(AdaptiveProvider):
    kind = ProviderKind.OLLAMA

    def __init__(
        self,
        settings: Settings,
        *,
        client_factory: Callable[[], Any] | None = None,
        discovery: OllamaDiscovery | None = None,
    ):
        self.settings = settings
        self.policy = ScopePolicy(settings)
        self.discovery = discovery or OllamaDiscovery(settings, policy=self.policy)
        self.client_factory = client_factory or (
            lambda: httpx.Client(follow_redirects=False)
        )

    def candidates(self, *, live: bool = False) -> list[AdaptiveModelCandidate]:
        items, _ = self.discovery.collect(live=live)
        candidates: list[AdaptiveModelCandidate] = []
        for item in items:
            if not isinstance(item, OllamaModel):
                continue
            candidates.append(
                AdaptiveModelCandidate(
                    model=item.model_name,
                    provider=self.kind,
                    endpoint=item.endpoint,
                    installed=item.installed,
                    running=item.running,
                    digest=item.digest,
                    size_bytes=item.size_bytes,
                    quantization=item.quantization,
                    context_length=item.context_length,
                    capabilities=[
                        ModelCapability(
                            role=role,
                            supported=True,
                            reason="Ollama reports the model as installed with generate capability.",
                        )
                        for role in ModelRole
                    ],
                    policy_eligible=item.scope_classification in {"loopback", "lab"},
                    notes=[
                        "Live generation requires explicit adaptive mode and model selection.",
                        "The provider never pulls, loads, unloads, or deletes models.",
                    ],
                )
            )
        return candidates

    def generate(
        self,
        *,
        model: str,
        role: ModelRole,
        system_prompt: str,
        context: dict[str, Any],
        response_model: type[BaseModel],
    ) -> tuple[BaseModel | None, ProviderResponse]:
        candidates = {item.model: item for item in self.candidates(live=True)}
        candidate = candidates.get(model)
        if candidate is None or not candidate.installed:
            return None, ProviderResponse(
                provider=self.kind,
                model=model,
                role=role,
                available=False,
                valid=False,
                error=f"Selected model {model!r} is not installed in scoped Ollama inventory.",
            )
        endpoint = candidate.endpoint or (
            self.settings.ollama_endpoints[0] if self.settings.ollama_endpoints else ""
        )
        decision = self.policy.decide(endpoint, active=False)
        if not decision.allowed:
            return None, ProviderResponse(
                provider=self.kind,
                model=model,
                role=role,
                available=False,
                valid=False,
                error=decision.reason,
            )
        prompt_payload = json.dumps(sanitize(context), separators=(",", ":"))
        maximum_input = self.settings.adaptive_prompt_max_characters
        if len(prompt_payload) > maximum_input:
            prompt_payload = prompt_payload[:maximum_input]
        schema = response_model.model_json_schema()
        repair_attempts = 0
        last_error = None
        raw = ""
        started = time.monotonic()
        maximum_attempts = (
            1
            + self.settings.adaptive_provider_retries
            + self.settings.adaptive_provider_repairs
        )
        for attempt in range(maximum_attempts):
            repair = attempt > self.settings.adaptive_provider_retries
            if repair:
                repair_attempts += 1
            instruction = system_prompt
            if repair:
                instruction += (
                    " Repair the prior output. Return only one JSON value matching "
                    "the provided schema; do not add fields or prose."
                )
            request_payload = {
                "model": model,
                "system": instruction,
                "prompt": prompt_payload,
                "format": schema,
                "stream": False,
                "options": {"temperature": 0},
                "keep_alive": 0,
            }
            try:
                with self.client_factory() as client:
                    response = client.post(
                        urljoin(decision.normalized_target.rstrip("/") + "/", "api/generate"),
                        json=request_payload,
                        timeout=self.settings.adaptive_provider_timeout_seconds,
                    )
                if 300 <= response.status_code < 400:
                    last_error = "Ollama redirect was not followed."
                    continue
                response.raise_for_status()
                envelope = response.json()
                raw = str(envelope.get("response") or "")
                if len(raw) > self.settings.maximum_response_bytes:
                    last_error = "Ollama structured response exceeded the configured bound."
                    continue
                parsed_json = json.loads(raw)
                parsed = response_model.model_validate(parsed_json)
                return parsed, ProviderResponse(
                    provider=self.kind,
                    model=model,
                    role=role,
                    available=True,
                    valid=True,
                    raw_response=str(sanitize(raw)),
                    parsed=parsed.model_dump(mode="json"),
                    latency_seconds=time.monotonic() - started,
                    input_characters=len(prompt_payload),
                    output_characters=len(raw),
                    repair_attempts=repair_attempts,
                )
            except (httpx.TimeoutException, httpx.HTTPError, ValueError, ValidationError) as exc:
                last_error = f"{type(exc).__name__}: invalid or unavailable provider response"
        return None, ProviderResponse(
            provider=self.kind,
            model=model,
            role=role,
            available=True,
            valid=False,
            raw_response=str(sanitize(raw)),
            error=last_error,
            latency_seconds=time.monotonic() - started,
            input_characters=len(prompt_payload),
            output_characters=len(raw),
            repair_attempts=repair_attempts,
        )
