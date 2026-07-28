"""Central deterministic redaction for internal and safe-share reports."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from redteam_platform.reporting.models import ReportMode

SECRET_KEY = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|oauth|authorization|"
    r"password|passwd|secret|cookie|session(?:id)?|private[_-]?key)"
)
BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)
INLINE_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|token|password|secret|session(?:id)?)\s*[:=]\s*"
    r"([\"']?)[^\s,;&\"']+\2"
)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
HOME_PATH = re.compile(r"(?<!\w)(?:/Users|/home)/[^/\s]+(?:/[^\s,;\"'<>]*)?")
SSH_PATH = re.compile(r"(?<!\w)(?:~|(?:/Users|/home)/[^/\s]+)/\.ssh/[^\s,;\"'<>]+")
ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9:])/(?:Users|home|private|var|opt|srv|etc|Volumes)/[^\s,;\"'<>]+"
)
CLOUD_ACCOUNT = re.compile(r"\b\d{12}\b")

_SENSITIVE_QUERY = {
    "access_token", "api_key", "apikey", "authorization", "code", "credential",
    "key", "oauth_token", "password", "refresh_token", "secret", "session", "sig", "signature", "token",
}


class Redactor:
    def __init__(self, mode: ReportMode | str = ReportMode.INTERNAL):
        self.mode = ReportMode(mode)
        self._aliases: dict[str, str] = {}

    def alias(self, kind: str, value: str) -> str:
        key = f"{kind}:{value}"
        if key not in self._aliases:
            count = sum(item.startswith(f"{kind}:") for item in self._aliases) + 1
            self._aliases[key] = f"<{kind.upper()}-{count:03d}>"
        return self._aliases[key]

    def redact_url(self, value: str) -> str:
        try:
            parts = urlsplit(value)
        except ValueError:
            return value
        if not parts.scheme or not parts.hostname:
            return value
        hostname = parts.hostname
        if self.mode == ReportMode.SAFE_SHARE and hostname not in {"127.0.0.1", "localhost", "::1"}:
            hostname = self.alias("host", hostname)
        host = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = parts.port
        except ValueError:
            port = None
        if port:
            host = f"{host}:{port}"
        query = [
            (key, "<REDACTED>" if key.lower() in _SENSITIVE_QUERY else val)
            for key, val in parse_qsl(parts.query, keep_blank_values=True)
        ]
        if self.mode == ReportMode.SAFE_SHARE:
            query = []
        return urlunsplit((parts.scheme, host, parts.path, urlencode(query), ""))

    def text(self, value: str) -> str:
        text = PRIVATE_KEY.sub("<REDACTED-PRIVATE-KEY>", str(value))
        text = BEARER.sub("Bearer <REDACTED>", text)
        text = INLINE_SECRET.sub(lambda m: f"{m.group(1)}=<REDACTED>", text)
        for match in list(re.finditer(r"https?://[^\s<>'\"]+", text)):
            text = text.replace(match.group(0), self.redact_url(match.group(0)))
        text = SSH_PATH.sub("<REDACTED-SSH-PATH>", text)
        if self.mode == ReportMode.SAFE_SHARE:
            text = EMAIL.sub(lambda m: self.alias("email", m.group(0).lower()), text)
            text = PHONE.sub(lambda m: self.alias("phone", m.group(0)), text)
            text = HOME_PATH.sub(lambda m: self.alias("path", m.group(0)), text)
            text = ABSOLUTE_PATH.sub(lambda m: self.alias("path", m.group(0)), text)
            text = CLOUD_ACCOUNT.sub(lambda m: self.alias("account", m.group(0)), text)
        return text

    def value(self, value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return self.value(value.model_dump(mode="json"))
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, Mapping):
            output: dict[str, Any] = {}
            for key, inner in value.items():
                name = str(key)
                if SECRET_KEY.search(name):
                    output[name] = "<REDACTED>"
                else:
                    output[name] = self.value(inner)
            return output
        if isinstance(value, (list, tuple, set)):
            return [self.value(item) for item in value]
        if isinstance(value, Path):
            return self.text(str(value))
        return value


def redact(value: Any, mode: ReportMode | str = ReportMode.INTERNAL) -> Any:
    return Redactor(mode).value(value)
