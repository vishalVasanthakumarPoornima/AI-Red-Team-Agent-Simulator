"""Run-scoped artifact persistence, hashing, retention, and safe sharing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from redteam_platform.schemas import (
    ArtifactRecord,
    RunManifest,
    AssessmentEvent,
    AuthorizationRecord,
    Finding,
    InventorySnapshot,
    RunSummary,
    new_run_id as schema_new_run_id,
)
from scanner.detectors import redact_configured_secrets


SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(authorization|proxy-authorization|x-api-key|api-key|cookie|set-cookie):.*$"
)
INLINE_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|token|password|secret)\s*[:=]\s*([^\s,;]+)"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def new_run_id() -> str:
    return schema_new_run_id()


def sanitize_url(value: str) -> str:
    text = str(value or "")
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.scheme or not parts.hostname:
        return text
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    try:
        port = parts.port
    except ValueError:
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    if port:
        host = f"{host}:{port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def sanitize(value: Any) -> Any:
    if isinstance(value, str):
        text = redact_configured_secrets(value)
        text = SENSITIVE_HEADER_RE.sub(lambda match: f"{match.group(1)}: <REDACTED>", text)
        text = INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}=<REDACTED>", text)
        text = BEARER_RE.sub("Bearer <REDACTED>", text)
        return text
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, inner in value.items():
            key_text = str(key)
            normalized_key = key_text.lower().replace("-", "_")
            if any(marker in normalized_key for marker in ("password", "secret", "token", "api_key")) or normalized_key in {
                "authorization",
                "proxy_authorization",
                "cookie",
                "set_cookie",
            }:
                cleaned[key_text] = "<REDACTED>"
            elif key_text.lower() in {"url", "target_url", "original_target_url", "endpoint"}:
                cleaned[key_text] = sanitize_url(str(inner))
            else:
                cleaned[key_text] = sanitize(inner)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [sanitize(inner) for inner in value]
    return value


class RunArtifacts:
    def __init__(self, root: str | Path, run_id: str | None = None):
        self.run_id = run_id or new_run_id()
        self.started_at = datetime.now(timezone.utc)
        self.root = Path(root)
        self.run_dir = self.root / self.run_id
        self.evidence_dir = self.run_dir / "evidence"
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.evidence_dir.mkdir(mode=0o700)
        try:
            os.chmod(self.run_dir, 0o700)
            os.chmod(self.evidence_dir, 0o700)
        except OSError:
            pass

    def _write_text(self, relative: str, text: str) -> Path:
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("Artifact path must remain inside the run directory.")
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def write_json(self, relative: str, payload: Any) -> Path:
        if hasattr(payload, "model_dump"):
            payload = payload.model_dump(mode="json")
        return self._write_text(relative, json.dumps(sanitize(payload), indent=2, default=str) + "\n")

    def write_authorization(self, record: AuthorizationRecord) -> Path:
        record.run_id = self.run_id
        payload = record.model_dump(mode="json")
        statement = str(sanitize(record.human_authorization_statement))[:2000]
        payload["statement"] = statement
        payload["human_authorization_statement"] = statement
        payload["target"] = sanitize_url(record.target)
        payload["normalized_target"] = sanitize_url(record.normalized_target)
        return self.write_json("authorization.json", payload)

    def write_inventory(self, inventory: InventorySnapshot) -> Path:
        return self.write_json("inventory.json", inventory)

    def append_event(self, event: AssessmentEvent) -> Path:
        path = self.run_dir / "events.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(sanitize(event.model_dump(mode="json")), default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def write_findings(self, findings: list[Finding]) -> Path:
        return self.write_json("findings.json", [item.model_dump(mode="json") for item in findings])

    def write_summary(self, summary: RunSummary) -> Path:
        return self.write_json("summary.json", summary)

    def write_evidence(self, evidence_id: str, content: str) -> Path:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", evidence_id)
        return self._write_text(f"evidence/{safe_name}.txt", str(sanitize(content)))

    def build_manifest(
        self,
        *,
        summary: RunSummary | None = None,
        authorization: AuthorizationRecord | None = None,
        tools: list[str] | None = None,
        models: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> RunManifest:
        entries: list[ArtifactRecord] = []
        for path in sorted(self.run_dir.rglob("*")):
            if not path.is_file() or path.name == "manifest.json":
                continue
            data = path.read_bytes()
            suffix = path.suffix.lower()
            media_type = {
                ".json": "application/json",
                ".jsonl": "application/x-ndjson",
                ".md": "text/markdown",
                ".html": "text/html",
                ".pdf": "application/pdf",
                ".txt": "text/plain",
            }.get(suffix, "application/octet-stream")
            entries.append(
                ArtifactRecord(
                    path=str(path.relative_to(self.run_dir)),
                    sha256=hashlib.sha256(data).hexdigest(),
                    bytes=len(data),
                    media_type=media_type,
                )
            )
        manifest = RunManifest(
            run_id=self.run_id,
            started_at=summary.started_at if summary else self.started_at,
            ended_at=summary.ended_at if summary else datetime.now(timezone.utc),
            status=str(summary.status) if summary else "created",
            stop_reason=summary.stop_reason if summary else "not started",
            tools=tools or [],
            models=models or [],
            scope=sanitize_url(authorization.normalized_target) if authorization else "",
            authorization_id=authorization.id if authorization else None,
            errors=[str(sanitize(item)) for item in (errors or (summary.errors if summary else []))],
            artifacts=entries,
        )
        self.write_json("manifest.json", manifest)
        return manifest

    def safe_share(self, destination: str | Path) -> Path:
        destination = Path(destination)
        if destination.exists():
            raise FileExistsError(f"Safe-share destination already exists: {destination}")
        destination.mkdir(parents=True, mode=0o700)
        for source in self.run_dir.rglob("*"):
            relative = source.relative_to(self.run_dir)
            target = destination / relative
            if source.is_dir():
                target.mkdir(exist_ok=True)
                continue
            if source.suffix.lower() in {".json", ".jsonl", ".md", ".html", ".txt"}:
                target.write_text(str(sanitize(source.read_text(encoding="utf-8"))), encoding="utf-8")
            elif source.suffix.lower() != ".pdf":
                shutil.copy2(source, target)
        return destination


def apply_retention(root: str | Path, retention_days: int, now: datetime | None = None) -> list[str]:
    root_path = Path(root)
    if not root_path.exists():
        return []
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=retention_days)
    removed: list[str] = []
    for run_dir in root_path.glob("run_*"):
        if not run_dir.is_dir():
            continue
        modified = datetime.fromtimestamp(run_dir.stat().st_mtime, timezone.utc)
        if modified < cutoff:
            shutil.rmtree(run_dir)
            removed.append(run_dir.name)
    return removed
