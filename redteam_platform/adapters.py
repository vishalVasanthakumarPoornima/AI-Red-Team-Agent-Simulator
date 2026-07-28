"""Typed target adapters for Python, HTTP, OpenAI, Ollama, host, web, and Dexter targets."""

from __future__ import annotations

import json
import hashlib
import socket
import ssl
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from redteam_platform.schemas import (
    AssessmentProfile,
    AuthorizationRecord,
    Confidence,
    Evidence,
    InvocationOutcome,
    Probe,
    ResultStatus,
    ScopeClassification,
    Status,
    Target,
    TargetType,
)
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import DexterSettings, Settings
from scanner.attack_runner import run_prompt_against_target
from scanner.detectors import evaluate_response
from scanner.target_loader import discover_targets


class AdapterError(RuntimeError):
    pass


def _excerpt(value: Any, limit: int = 2000) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _stable_adapter_id(kind: str, value: str) -> str:
    return f"{kind}_{hashlib.sha256(value.encode()).hexdigest()[:16]}"


class TargetAdapter(ABC):
    name: str

    def __init__(self, settings: Settings, policy: ScopePolicy | None = None):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)

    @abstractmethod
    def identify(self, value: str) -> Target:
        raise NotImplementedError

    @abstractmethod
    def health(self, target: Target) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def metadata(self, target: Target) -> dict[str, Any]:
        raise NotImplementedError

    def validate_scope(self, target: Target, authorization: AuthorizationRecord) -> None:
        self.policy.require_record(target.endpoint or target.local_path or target.name, authorization)

    @abstractmethod
    def invoke(
        self,
        target: Target,
        probe: Probe,
        authorization: AuthorizationRecord,
    ) -> InvocationOutcome:
        raise NotImplementedError

    def collect_evidence(self, outcome: InvocationOutcome) -> list[Evidence]:
        if not outcome.response_excerpt and not outcome.error:
            return []
        return [
            Evidence(
                kind="response",
                summary=outcome.error or outcome.evaluation.get("reason", "Probe response"),
                content=outcome.response_excerpt,
                source=self.name,
            )
        ]

    def cleanup(self) -> None:
        return


class PythonAgentAdapter(TargetAdapter):
    name = "python"

    def identify(self, value: str) -> Target:
        for row in discover_targets():
            if value in {row["name"], row["path"], row["absolute_path"]}:
                return Target(
                    id=f"python_{row['name']}",
                    name=row["name"],
                    type="ai_agent",
                    endpoint=f"python://{row['name']}",
                    local_path=row["path"],
                    status=Status.READY,
                    discovery_source="redteam_target_marker",
                    confidence=Confidence.HIGH,
                    capabilities=["run_agent", "static_assessment", "adaptive_assessment"],
                    scope_classification=ScopeClassification.LOOPBACK,
                    target_type=TargetType.PYTHON_AGENT,
                    adapter=self.name,
                    supported_profiles=list(AssessmentProfile),
                    metadata={"absolute_path": row["absolute_path"]},
                )
        raise AdapterError(f"Python target not found: {value}")

    def health(self, target: Target) -> dict[str, Any]:
        path = target.metadata.get("absolute_path")
        return {"ready": bool(path and Path(path).exists())}

    def metadata(self, target: Target) -> dict[str, Any]:
        return {"path": target.local_path, "contract": "run_agent(prompt)"}

    def invoke(
        self,
        target: Target,
        probe: Probe,
        authorization: AuthorizationRecord,
    ) -> InvocationOutcome:
        self.validate_scope(target, authorization)
        started = datetime.now(timezone.utc)
        descriptor = {
            "name": target.name,
            "path": target.local_path,
            "absolute_path": target.metadata["absolute_path"],
        }
        result = run_prompt_against_target(
            descriptor, probe.category, probe.prompt or ""
        )
        status = {
            "PASS": ResultStatus.PASS,
            "FAIL": ResultStatus.CONFIRMED,
            "ERROR": ResultStatus.ERROR,
        }.get(result.get("status"), ResultStatus.UNPARSED)
        return InvocationOutcome(
            probe_id=probe.id,
            target_id=target.id,
            status=status,
            response_excerpt=_excerpt(result.get("response")),
            evaluation=result,
            transport={"type": "in_process"},
            error=result.get("reason") if status == ResultStatus.ERROR else None,
            started_at=started,
        )


class HTTPAgentAdapter(TargetAdapter):
    name = "http"

    def identify(self, value: str) -> Target:
        decision = self.policy.decide(value, active=False)
        if not decision.allowed:
            raise AdapterError("Target is outside passive inventory scope: " + "; ".join(decision.reasons))
        return Target(
            id=_stable_adapter_id("http", decision.normalized_target),
            name=urlparse(decision.normalized_target).hostname or "http-agent",
            type="ai_agent",
            endpoint=decision.normalized_target.rstrip("/"),
            status=Status.UNKNOWN,
            discovery_source="configured_http_endpoint",
            confidence=Confidence.MEDIUM,
            capabilities=["health", "metadata", "invoke"],
            scope_classification=decision.classification,
            target_type=TargetType.HTTP_AGENT,
            adapter=self.name,
            supported_profiles=list(AssessmentProfile),
        )

    def _get(self, url: str) -> tuple[int | None, Any, dict[str, str]]:
        decision = self.policy.decide(url, active=False)
        if not decision.allowed:
            return None, {"error": "; ".join(decision.reasons)}, {}
        try:
            with httpx.Client(
                timeout=self.settings.request_timeout_seconds,
                follow_redirects=False,
            ) as client:
                response = client.get(url, headers={"Accept": "application/json"})
            data = None
            try:
                data = response.json()
            except ValueError:
                data = _excerpt(response.text)
            return response.status_code, data, dict(response.headers)
        except httpx.HTTPError as exc:
            return None, {"error": str(exc)}, {}

    def health(self, target: Target) -> dict[str, Any]:
        status, data, headers = self._get(urljoin(target.endpoint + "/", "health"))
        return {"ready": bool(status and status < 500), "status": status, "data": data, "headers": headers}

    def metadata(self, target: Target) -> dict[str, Any]:
        status, data, _ = self._get(urljoin(target.endpoint + "/", "metadata"))
        return {"status": status, "data": data}

    def invocation_payload(self, probe: Probe) -> dict[str, Any]:
        return {"prompt": probe.prompt or "", "attack": probe.category}

    def invocation_path(self) -> str:
        return "/invoke"

    def extract_response(self, payload: Any) -> str:
        if isinstance(payload, dict):
            return str(payload.get("response") or payload.get("message") or "")
        return str(payload)

    def invoke(
        self,
        target: Target,
        probe: Probe,
        authorization: AuthorizationRecord,
    ) -> InvocationOutcome:
        self.validate_scope(target, authorization)
        started = datetime.now(timezone.utc)
        url = urljoin(target.endpoint.rstrip("/") + "/", self.invocation_path().lstrip("/"))
        try:
            if target.metadata.get("model") and "model" not in probe.parameters:
                probe.parameters["model"] = target.metadata["model"]
            with httpx.Client(
                timeout=self.settings.request_timeout_seconds,
                follow_redirects=False,
            ) as client:
                response = client.post(
                    url,
                    json=self.invocation_payload(probe),
                    headers={"Accept": "application/json"},
                )
            if 300 <= response.status_code < 400:
                return InvocationOutcome(
                    probe_id=probe.id,
                    target_id=target.id,
                    status=ResultStatus.DENIED,
                    error="Redirect was not followed; destination requires separate authorization.",
                    transport={"http_status": response.status_code},
                    started_at=started,
                )
            parsed = response.json()
            if isinstance(parsed, dict) and "status" in parsed:
                evaluation = parsed
                response_text = self.extract_response(parsed)
            else:
                response_text = self.extract_response(parsed)
                evaluation = evaluate_response(probe.prompt or "", response_text, probe.category)
            status = {
                "PASS": ResultStatus.PASS,
                "FAIL": ResultStatus.CONFIRMED,
                "ERROR": ResultStatus.ERROR,
            }.get(evaluation.get("status"), ResultStatus.UNPARSED)
            return InvocationOutcome(
                probe_id=probe.id,
                target_id=target.id,
                status=status,
                response_excerpt=_excerpt(response_text),
                evaluation=evaluation,
                transport={"http_status": response.status_code, "url": target.endpoint},
                started_at=started,
            )
        except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
            return InvocationOutcome(
                probe_id=probe.id,
                target_id=target.id,
                status=ResultStatus.ERROR,
                error=str(exc),
                transport={"url": target.endpoint},
                started_at=started,
            )


class OpenAICompatibleAdapter(HTTPAgentAdapter):
    name = "openai"

    def identify(self, value: str) -> Target:
        target = super().identify(value)
        target.target_type = TargetType.OPENAI_AGENT
        target.adapter = self.name
        target.name = f"OpenAI-compatible {target.name}"
        target.capabilities = ["v1/models", "chat/completions"]
        return target

    def metadata(self, target: Target) -> dict[str, Any]:
        status, data, _ = self._get(urljoin(target.endpoint + "/", "v1/models"))
        return {"status": status, "models": data}

    def invocation_path(self) -> str:
        return "/v1/chat/completions"

    def invocation_payload(self, probe: Probe) -> dict[str, Any]:
        model = probe.parameters.get("model")
        if not model:
            raise AdapterError("OpenAI-compatible probe requires an explicitly selected model.")
        return {
            "model": model,
            "messages": [{"role": "user", "content": probe.prompt or ""}],
            "temperature": 0,
        }

    def extract_response(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            return str(payload)
        choices = payload.get("choices") or []
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or {}
            if isinstance(message, dict):
                return str(message.get("content") or "")
        return ""


class OllamaAgentAdapter(HTTPAgentAdapter):
    name = "ollama"

    def identify(self, value: str) -> Target:
        target = super().identify(value)
        target.target_type = TargetType.OLLAMA_AGENT
        target.adapter = self.name
        target.name = f"Ollama {target.name}"
        target.capabilities = ["api/tags", "api/ps", "api/generate"]
        return target

    def invocation_path(self) -> str:
        return "/api/generate"

    def invocation_payload(self, probe: Probe) -> dict[str, Any]:
        model = probe.parameters.get("model")
        if not model:
            raise AdapterError("Ollama probe requires an explicitly selected model.")
        return {
            "model": model,
            "prompt": probe.prompt or "",
            "stream": False,
            "options": {"temperature": 0},
        }


class HostAdapter(TargetAdapter):
    name = "host"

    def identify(self, value: str) -> Target:
        raw = value if "://" in value else f"host://{value}"
        decision = self.policy.decide(raw, active=False)
        if not decision.allowed:
            raise AdapterError("Target is outside passive inventory scope: " + "; ".join(decision.reasons))
        parsed = urlparse(decision.normalized_target)
        return Target(
            id=_stable_adapter_id("host", decision.normalized_target),
            name=parsed.hostname or value,
            type="network_host",
            endpoint=decision.normalized_target,
            status=Status.UNKNOWN,
            discovery_source="operator_configured",
            confidence=Confidence.HIGH,
            capabilities=["reachability", "approved_port_check", "service_identification"],
            scope_classification=decision.classification,
            target_type=TargetType.HOST,
            adapter=self.name,
            supported_profiles=list(AssessmentProfile),
        )

    def health(self, target: Target) -> dict[str, Any]:
        return {"ready": True, "note": "Reachability requires an authorized probe."}

    def metadata(self, target: Target) -> dict[str, Any]:
        return {"hostname": urlparse(target.endpoint).hostname}

    def invoke(
        self,
        target: Target,
        probe: Probe,
        authorization: AuthorizationRecord,
    ) -> InvocationOutcome:
        self.validate_scope(target, authorization)
        started = datetime.now(timezone.utc)
        host = urlparse(target.endpoint).hostname
        port = int(probe.parameters.get("port", 443))
        try:
            with socket.create_connection((host, port), timeout=5):
                return InvocationOutcome(
                    probe_id=probe.id,
                    target_id=target.id,
                    status=ResultStatus.INFORMATIONAL,
                    response_excerpt=f"TCP connection succeeded on approved port {port}.",
                    evaluation={"reason": "Approved port reachable."},
                    transport={"port": port},
                    started_at=started,
                )
        except OSError as exc:
            return InvocationOutcome(
                probe_id=probe.id,
                target_id=target.id,
                status=ResultStatus.ERROR,
                error=str(exc),
                transport={"port": port},
                started_at=started,
            )


class WebAdapter(HTTPAgentAdapter):
    name = "web"

    def identify(self, value: str) -> Target:
        target = super().identify(value)
        target.target_type = TargetType.WEB
        target.adapter = self.name
        target.type = "web_application"
        target.name = urlparse(target.endpoint).hostname or "web-application"
        target.capabilities = ["headers", "tls", "endpoint_inventory", "safe_input_checks"]
        return target

    def metadata(self, target: Target) -> dict[str, Any]:
        status, data, headers = self._get(target.endpoint)
        tls: dict[str, Any] = {}
        parsed = urlparse(target.endpoint)
        if parsed.scheme == "https" and parsed.hostname:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed.hostname) as wrapped:
                        tls = {"version": wrapped.version(), "cipher": wrapped.cipher()}
            except OSError as exc:
                tls = {"error": str(exc)}
        return {
            "status": status,
            "headers": headers,
            "tls": tls,
            "body_type": type(data).__name__,
        }

    def invoke(
        self,
        target: Target,
        probe: Probe,
        authorization: AuthorizationRecord,
    ) -> InvocationOutcome:
        """Run registered read-only web observations; never invent request paths or payloads."""
        self.validate_scope(target, authorization)
        started = datetime.now(timezone.utc)
        if probe.template_id not in {"web_headers", "web_metadata", "tls_observation"}:
            return InvocationOutcome(
                probe_id=probe.id,
                target_id=target.id,
                status=ResultStatus.DENIED,
                error="Probe is not a registered read-only web action.",
                transport={"url": target.endpoint},
                started_at=started,
            )
        metadata = self.metadata(target)
        status = ResultStatus.INFORMATIONAL if metadata.get("status") else ResultStatus.ERROR
        return InvocationOutcome(
            probe_id=probe.id,
            target_id=target.id,
            status=status,
            response_excerpt=_excerpt(metadata),
            evaluation={"reason": "Read-only web metadata collected.", "severity": "Informational"},
            transport={"url": target.endpoint, "method": "GET"},
            error=None if metadata.get("status") else "Target did not return an HTTP response.",
            started_at=started,
        )


class DexterAdapter(WebAdapter):
    name = "dexter"

    def __init__(
        self,
        settings: Settings,
        policy: ScopePolicy | None = None,
        dexter: DexterSettings | None = None,
    ):
        super().__init__(settings, policy)
        self.dexter = dexter or settings.dexter

    def identify(self, value: str = "") -> Target:
        endpoint = value or self.dexter.api_endpoint
        target = super().identify(endpoint)
        target.target_type = TargetType.DEXTER
        target.adapter = self.name
        target.name = self.dexter.name
        target.capabilities = [
            "service_inventory",
            "api_assessment",
            "ai_agent_assessment",
            "kali_assessment",
            "openapi",
            "tool_boundaries",
            "memory_boundaries",
        ]
        target.metadata = {
            "health_path": self.dexter.health_path,
            "chat_path": self.dexter.chat_path,
            "openapi_path": self.dexter.openapi_path,
            "ollama_endpoint": self.dexter.ollama_endpoint,
            "tool_endpoints": self.dexter.tool_endpoints,
            "memory_endpoint": self.dexter.memory_endpoint,
            "vector_endpoint": self.dexter.vector_endpoint,
            "voice_endpoints": self.dexter.voice_endpoints,
            "authentication_mode": self.dexter.authentication_mode,
            "requires_kali_tunnel": self.dexter.requires_kali_tunnel,
        }
        return target

    def health(self, target: Target) -> dict[str, Any]:
        status, data, headers = self._get(
            urljoin(target.endpoint + "/", self.dexter.health_path.lstrip("/"))
        )
        return {"ready": bool(status and status < 500), "status": status, "data": data, "headers": headers}

    def metadata(self, target: Target) -> dict[str, Any]:
        result = super().metadata(target)
        openapi_status, openapi, _ = self._get(
            urljoin(target.endpoint + "/", self.dexter.openapi_path.lstrip("/"))
        )
        result.update(
            {
                "configuration": target.metadata,
                "openapi_status": openapi_status,
                "openapi_paths": sorted((openapi or {}).get("paths", {}))
                if isinstance(openapi, dict)
                else [],
            }
        )
        return result

    def invocation_path(self) -> str:
        return self.dexter.chat_path

    def invocation_payload(self, probe: Probe) -> dict[str, Any]:
        return {
            "message": probe.prompt or "",
            "prompt": probe.prompt or "",
            "dry_run": True,
            "redteam": True,
        }

    def invoke(
        self,
        target: Target,
        probe: Probe,
        authorization: AuthorizationRecord,
    ) -> InvocationOutcome:
        return HTTPAgentAdapter.invoke(self, target, probe, authorization)


ADAPTERS = {
    "python": PythonAgentAdapter,
    "http": HTTPAgentAdapter,
    "openai": OpenAICompatibleAdapter,
    "ollama": OllamaAgentAdapter,
    "host": HostAdapter,
    "web": WebAdapter,
    "dexter": DexterAdapter,
}


def create_adapter(kind: str, settings: Settings) -> TargetAdapter:
    adapter = ADAPTERS.get(kind)
    if adapter is None:
        raise AdapterError(f"Unknown target adapter: {kind}")
    return adapter(settings)
