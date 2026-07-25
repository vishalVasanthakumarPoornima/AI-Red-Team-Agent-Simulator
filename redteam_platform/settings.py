"""Central validated configuration with file, .env, environment, and CLI layers."""

from __future__ import annotations

import os
import ipaddress
import re
import tomllib
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DexterSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="forbid")

    name: str = "Dexter"
    api_endpoint: str = "http://127.0.0.1:8000"
    health_path: str = "/status"
    chat_path: str = "/chat"
    metadata_path: str = "/metadata"
    openapi_path: str = "/openapi.json"
    authentication_reference: str | None = None
    ollama_endpoint: str | None = None
    expected_model: str | None = None
    tool_endpoints: list[str] = Field(default_factory=list)
    memory_endpoint: str | None = None
    vector_endpoint: str | None = None
    retrieval_endpoint: str | None = None
    voice_endpoints: list[str] = Field(default_factory=list)
    docker_names: list[str] = Field(default_factory=list)
    docker_labels: list[str] = Field(default_factory=list)
    expected_ports: list[int] = Field(default_factory=lambda: [8000])
    allowed_profiles: list[str] = Field(
        default_factory=lambda: ["passive", "standard", "deep-lab"]
    )
    disposable_memory_namespace: bool = False
    authentication_mode: str = "none"
    requires_kali_tunnel: bool = True
    kali_remote_port: int = Field(default=18000, ge=1024, le=65535)

    @field_validator(
        "api_endpoint",
        "ollama_endpoint",
        "memory_endpoint",
        "vector_endpoint",
        "retrieval_endpoint",
        mode="before",
    )
    @classmethod
    def validate_optional_urls(cls, value: Any) -> Any:
        if value is None:
            return None
        return _validated_http_url(value, "Dexter endpoint")

    @field_validator("tool_endpoints", "voice_endpoints", mode="after")
    @classmethod
    def validate_url_lists(cls, values: list[str]) -> list[str]:
        return [_validated_http_url(value, "Dexter endpoint") for value in values]

    @field_validator("health_path", "chat_path", "metadata_path", "openapi_path")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        if not value.startswith("/") or "?" in value or "#" in value:
            raise ValueError("Dexter paths must start with '/' and cannot contain query strings or fragments")
        return value

    @field_validator("expected_ports", mode="after")
    @classmethod
    def validate_expected_ports(cls, values: list[int]) -> list[int]:
        ports: list[int] = []
        for value in values:
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError("Dexter expected ports must be between 1 and 65535")
            if port not in ports:
                ports.append(port)
        return ports

    @field_validator("allowed_profiles", mode="after")
    @classmethod
    def validate_profiles(cls, values: list[str]) -> list[str]:
        allowed = {"passive", "standard", "deep-lab"}
        normalized = [str(value).strip().lower() for value in values]
        invalid = sorted(set(normalized) - allowed)
        if invalid:
            raise ValueError("Unsupported Dexter profiles: " + ", ".join(invalid))
        return list(dict.fromkeys(normalized))

    @field_validator("authentication_reference")
    @classmethod
    def validate_auth_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        reference = value.strip()
        if not reference or any(marker in reference.lower() for marker in ("bearer ", "token=", "password=")):
            raise ValueError("Dexter authentication_reference must be a non-secret reference name")
        return reference


class ConfigurationError(ValueError):
    """Actionable configuration failure raised before application startup."""


HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
SSH_ALIAS_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9._-]*$")


def _validated_host(value: Any, label: str) -> str:
    text = str(value or "").strip().rstrip(".")
    if not text or any(character.isspace() for character in text):
        raise ValueError(f"{label} must be a non-empty hostname or IP address without whitespace")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    try:
        ascii_host = text.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"{label} is not valid IDNA") from exc
    if not HOST_RE.fullmatch(ascii_host) or ".." in ascii_host:
        raise ValueError(f"{label} is not a valid hostname or IP address")
    return ascii_host


def _validated_http_url(value: Any, label: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = urlparse(text)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} has an invalid port") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{label} must use http or https")
    if not parsed.hostname:
        raise ValueError(f"{label} must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} cannot contain credentials")
    _validated_host(parsed.hostname, f"{label} host")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"{label} port must be between 1 and 65535")
    if parsed.fragment:
        raise ValueError(f"{label} cannot contain a URL fragment")
    return text.rstrip("/")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="REDTEAM_",
        env_file=None,
        extra="ignore",
        enable_decoding=False,
    )

    bind_host: str = "127.0.0.1"
    api_port: int = Field(default=18150, ge=1, le=65535)
    report_root: Path = Path("reports/runs")
    inventory_cache: Path = Path("reports/cache/inventory.json")
    user_config: Path = Path.home() / ".config" / "ai-red-team" / "config.toml"
    allowed_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_kali_aliases: list[str] = Field(default_factory=list)
    allow_public: bool = False
    api_token: SecretStr | None = None
    rate_limit_per_minute: int = Field(default=30, ge=1, le=10000)
    max_concurrency: int = Field(default=4, ge=1, le=128)
    request_body_limit: int = Field(default=32768, ge=1024, le=10_000_000)
    request_timeout_seconds: int = Field(default=60, ge=1, le=3600)
    retention_days: int = Field(default=30, ge=1, le=3650)
    configured_agent_endpoints: list[str] = Field(default_factory=list)
    ollama_endpoints: list[str] = Field(
        default_factory=lambda: ["http://127.0.0.1:11434"]
    )
    ollama_discovery_timeout: float = Field(default=1.5, gt=0, le=30)
    ollama_live_check: bool = False
    metadata_response_size: int = Field(default=2_000_000, ge=1024, le=20_000_000)
    listener_discovery_method: Literal["auto", "psutil", "native"] = "auto"
    listener_cache_ttl_seconds: int = Field(default=30, ge=1, le=86400)
    include_udp: bool = False
    include_docker: bool = False
    include_stopped_containers: bool = False
    docker_timeout: float = Field(default=5, gt=0, le=60)
    include_kali_readiness: bool = False
    kali_live_check: bool = False
    kali_readiness_timeout: float = Field(default=8, gt=0, le=60)
    http_metadata_routes: list[str] = Field(
        default_factory=lambda: [
            "/health",
            "/metadata",
            "/targets",
            "/openapi.json",
            "/v1/models",
        ]
    )
    known_local_service_ports: list[int] = Field(
        default_factory=lambda: [
            18080,
            18101,
            18102,
            8000,
            8080,
            5000,
            5001,
        ]
    )
    inventory_cache_ttl_seconds: int = Field(default=60, ge=1, le=86400)
    passive_only: bool = True
    kali_ssh_host: str | None = None
    kali_ssh_key: Path | None = None
    dexter: DexterSettings = Field(default_factory=DexterSettings)
    dexter_deployments: list[DexterSettings] = Field(default_factory=list)
    generic_targets: list[dict[str, Any]] = Field(default_factory=list)
    http_agent_definitions: list[dict[str, Any]] = Field(default_factory=list)
    openai_compatible_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    authentication_references: dict[str, str] = Field(default_factory=dict)
    default_ollama_model: str | None = None
    approved_host_ports: list[int] = Field(
        default_factory=lambda: [22, 80, 443, 8000, 8080, 8443, 11434]
    )
    host_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    web_path_allowlist: list[str] = Field(
        default_factory=lambda: ["/", "/health", "/metadata", "/openapi.json"]
    )
    maximum_redirects: int = Field(default=3, ge=0, le=10)
    maximum_response_bytes: int = Field(default=262_144, ge=1024, le=5_000_000)
    assessment_maximum_requests: int = Field(default=40, ge=1, le=500)
    assessment_maximum_duration_seconds: int = Field(default=300, ge=1, le=3600)
    assessment_maximum_concurrency: int = Field(default=1, ge=1, le=8)
    profile_budgets: dict[str, dict[str, int]] = Field(
        default_factory=lambda: {
            "passive": {"max_probes": 12, "max_duration_seconds": 120},
            "standard": {"max_probes": 40, "max_duration_seconds": 300},
            "deep-lab": {"max_probes": 80, "max_duration_seconds": 600},
        }
    )
    tls_verify: bool = True
    tls_minimum_version: str = "TLSv1.2"
    kali_tool_allowlist: list[str] = Field(
        default_factory=lambda: ["nmap", "whatweb", "curl"]
    )
    nuclei_safe_template_allowlist: list[str] = Field(default_factory=list)

    @field_validator("tls_minimum_version")
    @classmethod
    def validate_tls_minimum_version(cls, value: str) -> str:
        if value not in {"TLSv1.2", "TLSv1.3"}:
            raise ValueError("tls_minimum_version must be TLSv1.2 or TLSv1.3")
        return value

    @field_validator(
        "allowed_cidrs",
        "allowed_domains",
        "allowed_kali_aliases",
        "configured_agent_endpoints",
        "ollama_endpoints",
        "http_metadata_routes",
        "kali_tool_allowlist",
        "nuclei_safe_template_allowlist",
        mode="before",
    )
    @classmethod
    def parse_list(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("known_local_service_ports", mode="before")
    @classmethod
    def parse_ports(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("approved_host_ports", mode="before")
    @classmethod
    def parse_approved_ports(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("approved_host_ports", mode="after")
    @classmethod
    def validate_approved_ports(cls, values: list[int]) -> list[int]:
        ports: list[int] = []
        for raw in values:
            port = int(raw)
            if not 1 <= port <= 65535:
                raise ValueError("approved_host_ports values must be between 1 and 65535")
            if port not in ports:
                ports.append(port)
        if len(ports) > 64:
            raise ValueError("approved_host_ports is limited to 64 explicit ports")
        return ports

    @field_validator("web_path_allowlist", mode="before")
    @classmethod
    def parse_web_paths(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("web_path_allowlist", mode="after")
    @classmethod
    def validate_web_paths(cls, values: list[str]) -> list[str]:
        paths: list[str] = []
        for value in values:
            if not value.startswith("/") or "?" in value or "#" in value or ".." in value:
                raise ValueError("web_path_allowlist entries must be absolute safe paths")
            if value not in paths:
                paths.append(value)
        if len(paths) > 20:
            raise ValueError("web_path_allowlist is limited to 20 paths")
        return paths

    @field_validator("kali_tool_allowlist", mode="after")
    @classmethod
    def validate_kali_tool_allowlist(cls, values: list[str]) -> list[str]:
        allowed = {"nmap", "whatweb", "nikto", "curl"}
        normalized = list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
        if set(normalized) - allowed:
            raise ValueError("kali_tool_allowlist contains an unregistered tool")
        return normalized

    @field_validator("bind_host")
    @classmethod
    def loopback_default(cls, value: str) -> str:
        return _validated_host(value, "bind_host")

    @field_validator("allowed_cidrs", mode="after")
    @classmethod
    def validate_cidrs(cls, values: list[str]) -> list[str]:
        networks: list[str] = []
        for value in values:
            try:
                canonical = str(ipaddress.ip_network(str(value).strip(), strict=False))
            except ValueError as exc:
                raise ValueError(f"allowed_cidrs contains invalid network {value!r}") from exc
            if canonical not in networks:
                networks.append(canonical)
        return networks

    @field_validator("allowed_domains", mode="after")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        domains: list[str] = []
        for value in values:
            text = str(value).strip().lstrip(".")
            if "://" in text or "/" in text or "*" in text:
                raise ValueError("allowed_domains entries must be bare exact or suffix domain names")
            normalized = _validated_host(text, "allowed domain")
            try:
                ipaddress.ip_address(normalized)
            except ValueError:
                pass
            else:
                raise ValueError("allowed_domains cannot contain IP addresses; use allowed_cidrs")
            if normalized not in domains:
                domains.append(normalized)
        return domains

    @field_validator("allowed_kali_aliases", mode="after")
    @classmethod
    def validate_ssh_aliases(cls, values: list[str]) -> list[str]:
        aliases: list[str] = []
        for value in values:
            alias = str(value).strip()
            if not SSH_ALIAS_RE.fullmatch(alias):
                raise ValueError(
                    "allowed_kali_aliases entries must be SSH aliases or user@host without options"
                )
            if alias not in aliases:
                aliases.append(alias)
        return aliases

    @field_validator("configured_agent_endpoints", "ollama_endpoints", mode="after")
    @classmethod
    def validate_model_and_agent_urls(cls, values: list[str]) -> list[str]:
        return [_validated_http_url(value, "configured endpoint") for value in values]

    @field_validator("http_metadata_routes", mode="after")
    @classmethod
    def validate_metadata_routes(cls, values: list[str]) -> list[str]:
        routes: list[str] = []
        for value in values:
            route = str(value).strip()
            if (
                not route.startswith("/")
                or "://" in route
                or "?" in route
                or "#" in route
                or ".." in route
            ):
                raise ValueError(
                    "http_metadata_routes entries must be absolute read-only paths without URLs, queries, fragments, or traversal"
                )
            if route not in routes:
                routes.append(route)
        return routes

    @field_validator("known_local_service_ports", mode="after")
    @classmethod
    def validate_known_ports(cls, values: list[int]) -> list[int]:
        ports: list[int] = []
        for value in values:
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError("known_local_service_ports values must be between 1 and 65535")
            if port not in ports:
                ports.append(port)
        return ports

    @field_validator("report_root", "inventory_cache", "user_config", mode="before")
    @classmethod
    def validate_paths(cls, value: Any) -> Path:
        text = str(value or "").strip()
        if not text or "\x00" in text:
            raise ValueError("configured paths must be non-empty and cannot contain NUL bytes")
        return Path(text).expanduser()

    @field_validator("kali_ssh_host")
    @classmethod
    def validate_kali_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not SSH_ALIAS_RE.fullmatch(candidate):
            raise ValueError("kali_ssh_host must be an SSH alias or user@host without options")
        return candidate


ENV_FIELD_MAP = {
    "REDTEAM_BIND_HOST": "bind_host",
    "REDTEAM_API_PORT": "api_port",
    "REDTEAM_REPORT_ROOT": "report_root",
    "REDTEAM_INVENTORY_CACHE": "inventory_cache",
    "REDTEAM_ALLOWED_CIDRS": "allowed_cidrs",
    "REDTEAM_ALLOWED_DOMAINS": "allowed_domains",
    "REDTEAM_ALLOWED_KALI_ALIASES": "allowed_kali_aliases",
    "REDTEAM_ALLOW_PUBLIC": "allow_public",
    "REDTEAM_API_TOKEN": "api_token",
    "REDTEAM_RATE_LIMIT_PER_MINUTE": "rate_limit_per_minute",
    "REDTEAM_MAX_CONCURRENCY": "max_concurrency",
    "REDTEAM_REQUEST_BODY_LIMIT": "request_body_limit",
    "REDTEAM_REQUEST_TIMEOUT_SECONDS": "request_timeout_seconds",
    "REDTEAM_RETENTION_DAYS": "retention_days",
    "REDTEAM_CONFIGURED_AGENT_ENDPOINTS": "configured_agent_endpoints",
    "REDTEAM_OLLAMA_ENDPOINTS": "ollama_endpoints",
    "REDTEAM_OLLAMA_DISCOVERY_TIMEOUT": "ollama_discovery_timeout",
    "REDTEAM_OLLAMA_LIVE_CHECK": "ollama_live_check",
    "REDTEAM_METADATA_RESPONSE_SIZE": "metadata_response_size",
    "REDTEAM_LISTENER_DISCOVERY_METHOD": "listener_discovery_method",
    "REDTEAM_LISTENER_CACHE_TTL_SECONDS": "listener_cache_ttl_seconds",
    "REDTEAM_INCLUDE_UDP": "include_udp",
    "REDTEAM_INCLUDE_DOCKER": "include_docker",
    "REDTEAM_INCLUDE_STOPPED_CONTAINERS": "include_stopped_containers",
    "REDTEAM_DOCKER_TIMEOUT": "docker_timeout",
    "REDTEAM_INCLUDE_KALI_READINESS": "include_kali_readiness",
    "REDTEAM_KALI_LIVE_CHECK": "kali_live_check",
    "REDTEAM_KALI_READINESS_TIMEOUT": "kali_readiness_timeout",
    "REDTEAM_HTTP_METADATA_ROUTES": "http_metadata_routes",
    "REDTEAM_KNOWN_LOCAL_SERVICE_PORTS": "known_local_service_ports",
    "REDTEAM_INVENTORY_CACHE_TTL_SECONDS": "inventory_cache_ttl_seconds",
    "REDTEAM_PASSIVE_ONLY": "passive_only",
    "KALI_SSH_HOST": "kali_ssh_host",
    "KALI_SSH_KEY": "kali_ssh_key",
    "REDTEAM_DEFAULT_OLLAMA_MODEL": "default_ollama_model",
    "REDTEAM_APPROVED_HOST_PORTS": "approved_host_ports",
    "REDTEAM_HOST_TIMEOUT_SECONDS": "host_timeout_seconds",
    "REDTEAM_WEB_PATH_ALLOWLIST": "web_path_allowlist",
    "REDTEAM_MAXIMUM_REDIRECTS": "maximum_redirects",
    "REDTEAM_MAXIMUM_RESPONSE_BYTES": "maximum_response_bytes",
    "REDTEAM_ASSESSMENT_MAXIMUM_REQUESTS": "assessment_maximum_requests",
    "REDTEAM_ASSESSMENT_MAXIMUM_DURATION_SECONDS": "assessment_maximum_duration_seconds",
    "REDTEAM_ASSESSMENT_MAXIMUM_CONCURRENCY": "assessment_maximum_concurrency",
    "REDTEAM_TLS_VERIFY": "tls_verify",
    "REDTEAM_TLS_MINIMUM_VERSION": "tls_minimum_version",
    "REDTEAM_KALI_TOOL_ALLOWLIST": "kali_tool_allowlist",
    "REDTEAM_NUCLEI_SAFE_TEMPLATE_ALLOWLIST": "nuclei_safe_template_allowlist",
}

DEXTER_ENV_MAP = {
    "DEXTER_NAME": "name",
    "DEXTER_API_ENDPOINT": "api_endpoint",
    "DEXTER_HEALTH_PATH": "health_path",
    "DEXTER_CHAT_PATH": "chat_path",
    "DEXTER_METADATA_PATH": "metadata_path",
    "DEXTER_OPENAPI_PATH": "openapi_path",
    "DEXTER_AUTHENTICATION_MODE": "authentication_mode",
    "DEXTER_AUTHENTICATION_REFERENCE": "authentication_reference",
    "DEXTER_OLLAMA_ENDPOINT": "ollama_endpoint",
    "DEXTER_EXPECTED_MODEL": "expected_model",
    "DEXTER_TOOL_ENDPOINTS": "tool_endpoints",
    "DEXTER_MEMORY_ENDPOINT": "memory_endpoint",
    "DEXTER_VECTOR_ENDPOINT": "vector_endpoint",
    "DEXTER_RETRIEVAL_ENDPOINT": "retrieval_endpoint",
    "DEXTER_VOICE_ENDPOINTS": "voice_endpoints",
    "DEXTER_DOCKER_NAMES": "docker_names",
    "DEXTER_DOCKER_LABELS": "docker_labels",
    "DEXTER_EXPECTED_PORTS": "expected_ports",
    "DEXTER_ALLOWED_PROFILES": "allowed_profiles",
    "DEXTER_DISPOSABLE_MEMORY_NAMESPACE": "disposable_memory_namespace",
    "DEXTER_REQUIRES_KALI_TUNNEL": "requires_kali_tunnel",
    "DEXTER_KALI_REMOTE_PORT": "kali_remote_port",
}


def _dotenv_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def _toml_values(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    section = data.get("redteam", {})
    if not isinstance(section, dict):
        raise ValueError("Configuration file must contain a [redteam] table.")
    return section


def load_settings(
    config_path: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
    env_file: str | Path | None = None,
) -> Settings:
    """Load config file < .env < process environment < explicit overrides."""

    try:
        selected_path = Path(config_path).expanduser() if config_path else Settings().user_config
        merged: dict[str, Any] = _toml_values(selected_path)
        dotenv = _dotenv_values(
            Path(env_file).expanduser() if env_file is not None else Path(".env")
        )
        combined_env = {**dotenv, **os.environ}
        for env_name, field_name in ENV_FIELD_MAP.items():
            if env_name in combined_env:
                merged[field_name] = combined_env[env_name]
        dexter_values = dict(merged.get("dexter") or {})
        for env_name, field_name in DEXTER_ENV_MAP.items():
            if env_name in combined_env:
                value: Any = combined_env[env_name]
                if field_name in {
                    "tool_endpoints",
                    "voice_endpoints",
                    "docker_names",
                    "docker_labels",
                    "expected_ports",
                    "allowed_profiles",
                }:
                    value = [part.strip() for part in value.split(",") if part.strip()]
                dexter_values[field_name] = value
        if dexter_values:
            merged["dexter"] = dexter_values
        if overrides:
            merged.update({key: value for key, value in overrides.items() if value is not None})
        return Settings.model_validate(merged)
    except (OSError, tomllib.TOMLDecodeError, ValidationError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            details = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()
            )
        else:
            details = str(exc)
        raise ConfigurationError(f"Invalid red-team configuration: {details}") from exc


def sanitized_settings(settings: Settings) -> dict[str, Any]:
    payload = settings.model_dump(mode="json")
    payload["api_token"] = "<configured>" if settings.api_token else "<not-configured>"
    if payload.get("kali_ssh_key"):
        payload["kali_ssh_key"] = "<configured-path>"
    return payload
