"""Bounded evidence resolution and reference construction."""

from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path

from redteam_platform.reporting.models import EvidenceReference, ReportMode
from redteam_platform.reporting.redaction import Redactor


class EvidenceError(ValueError):
    pass


class EvidenceResolver:
    def __init__(self, run_root: str | Path, *, maximum_bytes: int = 1_000_000):
        self.run_root = Path(run_root).resolve()
        self.maximum_bytes = maximum_bytes

    def resolve(self, relative_path: str) -> Path:
        relative = Path(relative_path)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise EvidenceError("Evidence paths must be normalized relative paths.")
        candidate = self.run_root / relative
        if candidate.is_symlink():
            raise EvidenceError("Evidence symlinks are not allowed.")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.run_root):
            raise EvidenceError("Evidence path escapes the run directory.")
        if not resolved.is_file():
            raise FileNotFoundError(f"Evidence file not found: {relative_path}")
        return resolved

    def reference(
        self,
        relative_path: str,
        *,
        evidence_id: str,
        description: str = "",
        source_probe: str | None = None,
        source_tool: str | None = None,
        mode: ReportMode = ReportMode.INTERNAL,
        excerpt_bytes: int = 2048,
    ) -> EvidenceReference:
        path = self.resolve(relative_path)
        size = path.stat().st_size
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        excerpt: str | None = None
        truncated = size > excerpt_bytes
        if mime_type.startswith("text/") or mime_type in {"application/json", "application/x-ndjson"}:
            with path.open("rb") as handle:
                excerpt = handle.read(min(excerpt_bytes, self.maximum_bytes)).decode(
                    "utf-8", errors="replace"
                )
            excerpt = Redactor(mode).text(excerpt)
        return EvidenceReference(
            evidence_id=evidence_id,
            source_probe=source_probe,
            source_tool=source_tool,
            relative_artifact_path=relative_path,
            content_hash=digest,
            sanitized=True,
            truncated=truncated or size > self.maximum_bytes,
            mime_type=mime_type,
            size=size,
            description=description,
            excerpt=excerpt,
        )
