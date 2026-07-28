"""Report and evidence manifest generation and verification."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from redteam_platform.reporting.models import ArtifactIntegrity


def _safe_path(root: Path, relative: str) -> Path:
    part = Path(relative)
    if part.is_absolute() or not part.parts or ".." in part.parts:
        raise ValueError(f"Invalid manifest path: {relative}")
    candidate = root / part
    if candidate.is_symlink():
        raise ValueError(f"Manifest path is a symlink: {relative}")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"Manifest path escapes run root: {relative}")
    return resolved


def verify_manifest(run_root: str | Path, filename: str = "manifest.json") -> ArtifactIntegrity:
    root = Path(run_root).resolve()
    manifest_path = root / filename
    if not manifest_path.is_file():
        return ArtifactIntegrity(status="unavailable")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ArtifactIntegrity(status="failed", modified=[filename])
    entries = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return ArtifactIntegrity(status="failed", modified=[filename])
    checked = verified = 0
    missing: list[str] = []
    modified: list[str] = []
    invalid: list[str] = []
    report_hashes: dict[str, str] = {}
    for item in entries:
        if not isinstance(item, dict):
            invalid.append("<invalid-entry>")
            continue
        relative = str(item.get("path") or "")
        try:
            path = _safe_path(root, relative)
        except ValueError:
            invalid.append(relative or "<empty>")
            continue
        if not path.is_file():
            missing.append(relative)
            continue
        checked += 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != item.get("sha256"):
            modified.append(relative)
        else:
            verified += 1
        if Path(relative).name.startswith("report"):
            report_hashes[relative] = digest
    status = "ok" if not (missing or modified or invalid) else "failed"
    return ArtifactIntegrity(
        status=status,
        files_checked=checked,
        hashes_verified=verified,
        missing=missing,
        modified=modified,
        invalid_paths=invalid,
        report_hashes=report_hashes,
    )


def write_report_manifest(
    run_root: str | Path,
    report_paths: list[str | Path],
    *,
    evidence_paths: list[str] | None = None,
) -> Path:
    root = Path(run_root).resolve()
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in [*report_paths, *(evidence_paths or [])]:
        path = Path(value)
        if path.is_absolute():
            if not path.resolve().is_relative_to(root):
                raise ValueError("Report manifest files must remain inside the run root.")
            relative = str(path.resolve().relative_to(root))
        else:
            relative = str(path)
        if relative in seen:
            continue
        seen.add(relative)
        resolved = _safe_path(root, relative)
        if not resolved.is_file():
            raise FileNotFoundError(relative)
        data = resolved.read_bytes()
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    payload = {"schema_version": "7.0", "artifacts": sorted(entries, key=lambda item: item["path"])}
    target = root / "report_manifest.json"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".report_manifest.", suffix=".tmp", dir=root)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target
