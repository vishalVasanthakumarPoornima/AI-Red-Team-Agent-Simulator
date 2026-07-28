"""Network-free deterministic target input parsing."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

from redteam_platform.targets.models import TargetInput, TargetKind


STABLE_PREFIXES = {
    "python_": TargetKind.PYTHON_AGENT,
    "python_target_": TargetKind.PYTHON_AGENT,
    "http_service_": TargetKind.LOCAL_SERVICE,
    "http_agent_": TargetKind.HTTP_AGENT,
    "ollama_endpoint_": TargetKind.OLLAMA_ENDPOINT,
    "ollama_model_": TargetKind.OLLAMA_ENDPOINT,
    "dexter_": TargetKind.DEXTER,
    "listener_": TargetKind.LOCAL_SERVICE,
    "docker_container_": TargetKind.LOCAL_SERVICE,
}
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
PYTHON_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class TargetParser:
    def parse(
        self,
        value: str,
        *,
        kind_hint: TargetKind | str | None = None,
        model_name: str | None = None,
        ports: list[int] | None = None,
    ) -> TargetInput:
        original = str(value or "").strip()
        if not original or any(character.isspace() for character in original):
            raise ValueError("Target must be non-empty and cannot contain whitespace.")
        hinted = TargetKind(kind_hint) if kind_hint else None
        parsed_kind = hinted or self._kind(original)
        stable_id = hinted is None and any(
            original.startswith(prefix) for prefix in STABLE_PREFIXES
        )
        normalized = original if stable_id else self.normalize(original, parsed_kind)
        return TargetInput(
            original=original,
            kind_hint=parsed_kind,
            normalized_target=normalized,
            model_name=model_name,
            ports=list(ports or []),
            invocation_route=normalized,
        )

    def normalize(self, value: str, kind: TargetKind) -> str:
        if kind == TargetKind.PYTHON_AGENT:
            name = value.removeprefix("python://")
            if not PYTHON_NAME_RE.fullmatch(name):
                raise ValueError("Python target names must be simple identifiers.")
            return f"python://{name}"
        if kind in {
            TargetKind.WEBSITE,
            TargetKind.WEB_APPLICATION,
            TargetKind.HTTP_AGENT,
            TargetKind.OPENAI_COMPATIBLE,
            TargetKind.OLLAMA_ENDPOINT,
            TargetKind.OLLAMA_AGENT,
        }:
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("HTTP targets must use http or https and include a host.")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("Credential-bearing URLs are not permitted.")
            if parsed.fragment or parsed.query:
                raise ValueError("Target URLs cannot contain query strings or fragments.")
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError("Target URL has an invalid port.") from exc
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            netloc = f"[{host}]" if ":" in host else host
            if port:
                netloc += f":{port}"
            return urlunparse(
                (parsed.scheme.lower(), netloc, parsed.path or "/", "", "", "")
            ).rstrip("/") or f"{parsed.scheme.lower()}://{netloc}"
        if kind in {TargetKind.IP_ADDRESS, TargetKind.HOST}:
            raw = value
            if raw.startswith("host://"):
                raw = raw[7:]
            host, port = self._host_port(raw)
            try:
                address = ipaddress.ip_address(host)
                host = str(address)
            except ValueError:
                host = host.encode("idna").decode("ascii").lower().rstrip(".")
                if not HOST_RE.fullmatch(host):
                    raise ValueError("Target is not a valid hostname or IP address.")
            rendered = f"[{host}]" if ":" in host else host
            return f"host://{rendered}" + (f":{port}" if port else "")
        return value

    def _kind(self, value: str) -> TargetKind:
        for prefix, kind in STABLE_PREFIXES.items():
            if value.startswith(prefix):
                return kind
        if value.startswith("python://"):
            return TargetKind.PYTHON_AGENT
        parsed = urlparse(value)
        if parsed.scheme:
            if parsed.scheme not in {"http", "https"}:
                raise ValueError(f"Unsupported target scheme: {parsed.scheme}.")
            return TargetKind.WEBSITE
        host, _ = self._host_port(value)
        try:
            ipaddress.ip_address(host)
            return TargetKind.IP_ADDRESS
        except ValueError:
            pass
        if "." in host or ":" in value:
            return TargetKind.HOST
        if PYTHON_NAME_RE.fullmatch(value) and value.endswith(("_agent", "_target")):
            return TargetKind.PYTHON_AGENT
        if PYTHON_NAME_RE.fullmatch(value):
            return TargetKind.UNKNOWN
        raise ValueError("Target input is malformed.")

    @staticmethod
    def _host_port(value: str) -> tuple[str, int | None]:
        if value.startswith("["):
            parsed = urlparse(f"host://{value}")
            if not parsed.hostname:
                raise ValueError("Invalid bracketed IPv6 target.")
            return parsed.hostname, parsed.port
        if value.count(":") == 1:
            host, raw_port = value.rsplit(":", 1)
            if raw_port.isdigit():
                port = int(raw_port)
                if not 1 <= port <= 65535:
                    raise ValueError("Target port must be between 1 and 65535.")
                return host, port
        return value, None
