"""Platform detection and deterministic non-secret identity helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import platform as stdlib_platform
import socket
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def platform_name() -> str:
    return stdlib_platform.system().lower() or "unknown"


def source_host_id() -> str:
    identity = f"{platform_name()}:{socket.gethostname().strip().lower()}"
    return "host_" + hashlib.sha256(identity.encode()).hexdigest()[:16]


def normalize_address(value: str) -> str:
    text = str(value or "").strip().split("%", 1)[0]
    if text in {"*", "0.0.0.0"}:
        return "0.0.0.0"
    if text == "::":
        return "::"
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.rstrip(".").lower()


def normalize_identity_url(value: str) -> str:
    """Normalize a URL while dropping credentials, query data, and fragments."""
    raw = str(value or "").strip()
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.hostname:
        return raw
    scheme = parsed.scheme.lower()
    host = normalize_address(parsed.hostname)
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    rendered_host = f"[{host}]" if ":" in host else host
    netloc = rendered_host + (f":{port}" if port else "")
    path = parsed.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, "", ""))


def stable_id(kind: str, *identity_fields: object) -> str:
    normalized: list[str] = []
    for value in identity_fields:
        text = str(value or "").strip()
        if "://" in text:
            text = normalize_identity_url(text)
        normalized.append(text.lower())
    digest = hashlib.sha256("\x1f".join(normalized).encode()).hexdigest()[:20]
    return f"{kind}_{digest}"


def python_target_id(relative_path: str | Path, name: str) -> str:
    return stable_id("python_target", Path(relative_path).as_posix(), name)


def listener_id(
    protocol: str,
    address: str,
    port: int,
    process_name: str | None,
    executable: str | None,
    namespace: str | None = None,
) -> str:
    return stable_id(
        "listener",
        protocol.lower(),
        normalize_address(address),
        port,
        process_name or "",
        executable or "",
        namespace or "host",
    )

