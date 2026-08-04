"""Atomic extension of an existing Phase 5 run with adaptive artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from redteam_platform.artifacts import sanitize
from redteam_platform.schemas import ArtifactRecord, RunManifest


class AdaptiveArtifactStore:
    def __init__(self, report_root: str | Path, run_id: str):
        if not run_id.startswith("run_") or Path(run_id).name != run_id:
            raise ValueError("Invalid run ID.")
        root = Path(report_root).expanduser().resolve()
        run_dir = (root / run_id).resolve()
        if run_dir.parent != root or not run_dir.is_dir():
            raise FileNotFoundError(f"Existing Phase 5 run not found: {run_id}")
        self.run_id = run_id
        self.run_dir = run_dir

    def _path(self, relative: str) -> Path:
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("Artifact path must remain inside the run directory.")
        path = (self.run_dir / relative_path).resolve()
        if not path.is_relative_to(self.run_dir):
            raise ValueError("Artifact path escapes the run directory.")
        return path

    def write_text(self, relative: str, value: str) -> Path:
        path = self._path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(str(sanitize(value)))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
        return path

    def write_json(self, relative: str, value: Any) -> Path:
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        return self.write_text(
            relative, json.dumps(sanitize(value), indent=2, default=str) + "\n"
        )

    def append_jsonl(self, relative: str, value: Any) -> Path:
        path = self._path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(sanitize(value), default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def read_json(self, relative: str, default: Any = None) -> Any:
        path = self._path(relative)
        if not path.is_file():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def verify_existing_manifest(self) -> list[str]:
        manifest = self.read_json("manifest.json", {})
        problems: list[str] = []
        for entry in manifest.get("artifacts") or []:
            relative = entry.get("path")
            if not relative or relative in {"manifest.json", "report_manifest.json"}:
                continue
            path = self._path(relative)
            if not path.is_file():
                problems.append(f"missing {relative}")
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != entry.get("sha256"):
                problems.append(f"hash mismatch {relative}")
        return problems

    def rebuild_manifest(
        self,
        *,
        status: str,
        stop_reason: str,
        models: list[str],
        errors: list[str] | None = None,
    ) -> RunManifest:
        previous = self.read_json("manifest.json", {})
        entries: list[ArtifactRecord] = []
        for path in sorted(self.run_dir.rglob("*")):
            if not path.is_file() or path.name in {"manifest.json", "report_manifest.json"}:
                continue
            suffix = path.suffix.lower()
            entries.append(
                ArtifactRecord(
                    path=str(path.relative_to(self.run_dir)),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    bytes=path.stat().st_size,
                    media_type={
                        ".json": "application/json",
                        ".jsonl": "application/x-ndjson",
                        ".md": "text/markdown",
                        ".txt": "text/plain",
                    }.get(suffix, "application/octet-stream"),
                )
            )
        manifest = RunManifest(
            run_id=self.run_id,
            started_at=previous.get("started_at"),
            status=status,
            stop_reason=stop_reason,
            tools=sorted(set(previous.get("tools") or []) | {"adaptive_validator"}),
            models=sorted(set(previous.get("models") or []) | set(models)),
            scope=previous.get("scope") or "",
            authorization_id=previous.get("authorization_id"),
            errors=list(previous.get("errors") or []) + list(errors or []),
            artifacts=entries,
        )
        self.write_json("manifest.json", manifest)
        return manifest
