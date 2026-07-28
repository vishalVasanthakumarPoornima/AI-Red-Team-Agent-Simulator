"""Typed atomic inventory cache with TTL and schema compatibility checks."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from redteam_platform.artifacts import sanitize
from redteam_platform.inventory.models import (
    DiscoveryError,
    InventoryCacheMetadata,
    InventorySnapshot,
    RefreshMode,
)
from redteam_platform.schemas import SCHEMA_VERSION


class InventoryCache:
    def __init__(self, path: str | Path, ttl_seconds: int, source_host_id: str):
        self.path = Path(path)
        self.ttl_seconds = ttl_seconds
        self.source_host_id = source_host_id

    def write(
        self,
        snapshot: InventorySnapshot,
        refresh_mode: RefreshMode = RefreshMode.FRESH,
    ) -> InventoryCacheMetadata:
        generated = snapshot.generated_at
        expires = generated + timedelta(seconds=self.ttl_seconds)
        metadata = InventoryCacheMetadata(
            generated_at=generated,
            expires_at=expires,
            source_host_id=self.source_host_id,
            refresh_mode=refresh_mode,
            cache_path=str(self.path),
            stale=False,
        )
        snapshot.expires_at = expires
        snapshot.source_host_id = self.source_host_id
        snapshot.cache_metadata = metadata
        payload = sanitize(snapshot.model_dump(mode="json"))
        self._atomic_json(payload)
        return metadata

    def read(
        self,
        *,
        allow_stale: bool = True,
        now: datetime | None = None,
    ) -> tuple[InventorySnapshot | None, DiscoveryError | None]:
        if not self.path.is_file():
            return None, DiscoveryError(
                source="cache",
                code="cache_missing",
                message="Inventory cache does not exist.",
            )
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return None, DiscoveryError(
                source="cache",
                code="cache_corrupt",
                message=f"Inventory cache is unreadable: {type(exc).__name__}.",
            )
        if payload.get("schema_version") != SCHEMA_VERSION:
            return None, DiscoveryError(
                source="cache",
                code="cache_schema_mismatch",
                message=(
                    f"Inventory cache schema {payload.get('schema_version')!r} "
                    f"is incompatible with {SCHEMA_VERSION!r}."
                ),
            )
        try:
            snapshot = InventorySnapshot.model_validate(payload)
        except ValueError as exc:
            return None, DiscoveryError(
                source="cache",
                code="cache_invalid",
                message=f"Inventory cache failed schema validation: {exc}",
            )
        current = now or datetime.now(timezone.utc)
        stale = snapshot.expires_at is None or current >= snapshot.expires_at
        if stale and not allow_stale:
            return None, DiscoveryError(
                source="cache",
                code="cache_expired",
                message="Inventory cache has expired.",
            )
        snapshot.cached = True
        snapshot.stale = stale
        snapshot.refresh_mode = RefreshMode.CACHED_ONLY
        snapshot.summary.stale = stale
        for item in snapshot.items:
            item.stale = stale
        if snapshot.cache_metadata:
            snapshot.cache_metadata.stale = stale
            snapshot.cache_metadata.refresh_mode = RefreshMode.CACHED_ONLY
        return snapshot, None

    def _atomic_json(self, payload: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            if temporary.exists():
                temporary.unlink()

