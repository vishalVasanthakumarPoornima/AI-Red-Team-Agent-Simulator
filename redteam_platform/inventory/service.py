"""Unified passive inventory orchestration, summaries, cache, and run attachment."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from redteam_platform.artifacts import sanitize
from redteam_platform.inventory.agents import (
    HTTPAgentDiscovery,
    PythonTargetDiscovery,
    RegistryDiscovery,
)
from redteam_platform.inventory.cache import InventoryCache
from redteam_platform.inventory.correlation import InventoryCorrelator
from redteam_platform.inventory.docker import DockerDiscovery
from redteam_platform.inventory.kali import KaliDiscovery
from redteam_platform.inventory.listeners import ListenerDiscovery
from redteam_platform.inventory.models import (
    AdapterRun,
    AdapterState,
    AgentDescriptor,
    DiscoveryError,
    DockerContainer,
    InventoryItem,
    InventorySnapshot,
    InventoryStatus,
    InventorySummary,
    ItemType,
    KaliReadiness,
    Listener,
    OllamaModel,
    RefreshMode,
)
from redteam_platform.inventory.ollama import OllamaDiscovery
from redteam_platform.inventory.platform import source_host_id
from redteam_platform.schemas import ArtifactRecord, RunManifest, utc_now
from redteam_platform.settings import Settings


class InventoryService:
    def __init__(
        self,
        settings: Settings,
        *,
        adapters: dict[str, Any] | None = None,
    ):
        self.settings = settings
        self.host_id = source_host_id()
        self.cache = InventoryCache(
            settings.inventory_cache,
            settings.inventory_cache_ttl_seconds,
            self.host_id,
        )
        self.adapters = adapters or {}
        self.correlator = InventoryCorrelator()

    def collect(
        self,
        *,
        include_ollama: bool = True,
        include_listeners: bool = True,
        include_targets: bool = True,
        include_http: bool = True,
        include_docker: bool | None = None,
        include_kali: bool | None = None,
        refresh: bool = True,
        cached_only: bool = False,
        force_refresh: bool = False,
    ) -> InventorySnapshot:
        if cached_only:
            cached, error = self.cache.read(allow_stale=True)
            if cached:
                return cached
            return InventorySnapshot(
                generated_at=utc_now(),
                source_host_id=self.host_id,
                refresh_mode=RefreshMode.CACHED_ONLY,
                errors=[error] if error else [],
                summary=InventorySummary(error_count=1 if error else 0),
                cached=True,
                stale=True,
            )
        if not refresh and not force_refresh:
            cached, _ = self.cache.read(allow_stale=False)
            if cached:
                cached.refresh_mode = RefreshMode.CACHE_PREFERRED
                return cached

        docker_enabled = (
            self.settings.include_docker
            if include_docker is None
            else include_docker
        )
        kali_enabled = (
            self.settings.include_kali_readiness
            if include_kali is None
            else include_kali
        )
        items: list[InventoryItem] = []
        errors: list[DiscoveryError] = []
        runs: list[AdapterRun] = []

        listeners: list[Listener] = []
        registry: list[AgentDescriptor] = []

        if include_listeners:
            listener_items, adapter_errors, run = self._run(
                "listeners",
                self.adapters.get("listeners")
                or ListenerDiscovery(self.settings),
            )
            listeners = [
                item for item in listener_items if isinstance(item, Listener)
            ]
            items.extend(listener_items)
            errors.extend(adapter_errors)
            runs.append(run)

        if include_targets:
            target_items, adapter_errors, run = self._run(
                "python_targets",
                self.adapters.get("python_targets")
                or PythonTargetDiscovery(),
            )
            items.extend(target_items)
            errors.extend(adapter_errors)
            runs.append(run)

            registry_items, adapter_errors, run = self._run(
                "agent_registry",
                self.adapters.get("agent_registry")
                or RegistryDiscovery(self.settings),
            )
            registry = [
                item
                for item in registry_items
                if isinstance(item, AgentDescriptor)
            ]
            items.extend(registry_items)
            errors.extend(adapter_errors)
            runs.append(run)

        if include_ollama:
            adapter_items, adapter_errors, run = self._run(
                "ollama",
                self.adapters.get("ollama") or OllamaDiscovery(self.settings),
            )
            items.extend(adapter_items)
            errors.extend(adapter_errors)
            runs.append(run)

        if include_http:
            http_adapter = self.adapters.get("http") or HTTPAgentDiscovery(
                self.settings
            )
            started = time.monotonic()
            try:
                adapter_items, adapter_errors = http_adapter.collect(
                    listeners, registry
                )
                run = self._adapter_run(
                    "http",
                    time.monotonic() - started,
                    adapter_items,
                    adapter_errors,
                )
            except Exception as exc:
                adapter_items = []
                adapter_errors = [
                    DiscoveryError(
                        source="http",
                        code="adapter_exception",
                        message=f"HTTP inventory adapter failed: {type(exc).__name__}.",
                    )
                ]
                run = AdapterRun(
                    adapter="http",
                    state=AdapterState.ERROR,
                    duration_seconds=time.monotonic() - started,
                    item_count=0,
                    errors=adapter_errors,
                )
            items.extend(adapter_items)
            errors.extend(adapter_errors)
            runs.append(run)

        if docker_enabled:
            adapter_items, adapter_errors, run = self._run(
                "docker",
                self.adapters.get("docker") or DockerDiscovery(self.settings),
            )
            items.extend(adapter_items)
            errors.extend(adapter_errors)
            runs.append(run)

        if kali_enabled:
            kali_adapter = self.adapters.get("kali") or KaliDiscovery(self.settings)
            started = time.monotonic()
            try:
                adapter_items, adapter_errors = kali_adapter.collect(
                    live=self.settings.kali_live_check
                )
                run = self._adapter_run(
                    "kali",
                    time.monotonic() - started,
                    adapter_items,
                    adapter_errors,
                )
            except Exception as exc:
                adapter_items = []
                adapter_errors = [
                    DiscoveryError(
                        source="kali",
                        code="adapter_exception",
                        message=f"Kali inventory adapter failed: {type(exc).__name__}.",
                    )
                ]
                run = AdapterRun(
                    adapter="kali",
                    state=AdapterState.ERROR,
                    duration_seconds=time.monotonic() - started,
                    item_count=0,
                    errors=adapter_errors,
                )
            items.extend(adapter_items)
            errors.extend(adapter_errors)
            runs.append(run)

        correlated_items, correlations = self.correlator.correlate(items)
        generated = utc_now()
        snapshot = InventorySnapshot(
            generated_at=generated,
            expires_at=generated
            + timedelta(seconds=self.settings.inventory_cache_ttl_seconds),
            source_host_id=self.host_id,
            refresh_mode=(
                RefreshMode.FORCE_REFRESH if force_refresh else RefreshMode.FRESH
            ),
            items=correlated_items,
            correlations=correlations,
            adapter_runs=sorted(runs, key=lambda run: run.adapter),
            errors=errors,
            summary=self._summary(
                correlated_items,
                errors,
                docker_enabled=docker_enabled,
                kali_enabled=kali_enabled,
                runs=runs,
            ),
            cached=False,
            stale=False,
        )
        self.cache.write(snapshot, snapshot.refresh_mode)
        return snapshot

    def refresh(self, include_docker: bool | None = None) -> InventorySnapshot:
        return self.collect(
            include_docker=include_docker,
            refresh=True,
            force_refresh=True,
        )

    def cached(self) -> InventorySnapshot | None:
        snapshot, _ = self.cache.read(allow_stale=True)
        return snapshot

    def attach_to_run(
        self,
        run_id: str,
        snapshot: InventorySnapshot,
        *,
        overwrite: bool = False,
    ) -> Path:
        if not run_id.startswith("run_") or Path(run_id).name != run_id:
            raise ValueError("Invalid run ID.")
        run_dir = self.settings.report_root / run_id
        if not run_dir.is_dir():
            raise FileNotFoundError(f"Assessment run does not exist: {run_id}")
        inventory_path = run_dir / "inventory.json"
        if inventory_path.exists() and not overwrite:
            raise FileExistsError(
                "Inventory artifact already exists; explicit refresh overwrite is required."
            )
        self._atomic_json(
            inventory_path,
            sanitize(snapshot.model_dump(mode="json")),
        )
        data = inventory_path.read_bytes()
        record = ArtifactRecord(
            path="inventory.json",
            sha256=hashlib.sha256(data).hexdigest(),
            bytes=len(data),
            media_type="application/json",
        )
        manifest_path = run_dir / "manifest.json"
        if manifest_path.exists():
            manifest = RunManifest.model_validate_json(
                manifest_path.read_text(encoding="utf-8")
            )
        else:
            manifest = RunManifest(
                run_id=run_id,
                started_at=snapshot.generated_at,
                status="created",
                stop_reason="inventory attached before assessment completion",
            )
        manifest.artifacts = [
            artifact
            for artifact in manifest.artifacts
            if artifact.path != "inventory.json"
        ]
        manifest.artifacts.append(record)
        manifest.artifacts.sort(key=lambda artifact: artifact.path)
        self._atomic_json(
            manifest_path,
            sanitize(manifest.model_dump(mode="json")),
        )
        return inventory_path

    @staticmethod
    def _run(
        name: str, adapter: Any
    ) -> tuple[list[InventoryItem], list[DiscoveryError], AdapterRun]:
        started = time.monotonic()
        try:
            items, errors = adapter.collect()
        except Exception as exc:
            items = []
            errors = [
                DiscoveryError(
                    source=name,
                    code="adapter_exception",
                    message=f"{name} inventory adapter failed: {type(exc).__name__}.",
                )
            ]
            state = AdapterState.ERROR
        else:
            state = None
        run = InventoryService._adapter_run(
            name,
            time.monotonic() - started,
            items,
            errors,
            state,
        )
        return items, errors, run

    @staticmethod
    def _adapter_run(
        name: str,
        duration: float,
        items: list,
        errors: list[DiscoveryError],
        state: AdapterState | None = None,
    ) -> AdapterRun:
        if state is None:
            if errors and items:
                state = AdapterState.PARTIAL
            elif errors:
                state = AdapterState.UNAVAILABLE
            else:
                state = AdapterState.SUCCESS
        return AdapterRun(
            adapter=name,
            state=state,
            duration_seconds=duration,
            item_count=len(items),
            errors=errors,
        )

    @staticmethod
    def _summary(
        items: list[InventoryItem],
        errors: list[DiscoveryError],
        *,
        docker_enabled: bool,
        kali_enabled: bool,
        runs: list[AdapterRun],
    ) -> InventorySummary:
        service_ids = {
            item.stable_id
            for item in items
            if item.item_type == ItemType.SERVICE
        }
        listeners = [
            item for item in items if isinstance(item, Listener)
        ]
        docker_run = next((run for run in runs if run.adapter == "docker"), None)
        kali_item = next(
            (item for item in items if isinstance(item, KaliReadiness)), None
        )
        return InventorySummary(
            installed_ollama_models=sum(
                1
                for item in items
                if isinstance(item, OllamaModel) and item.installed
            ),
            running_ollama_models=sum(
                1
                for item in items
                if isinstance(item, OllamaModel) and item.running
            ),
            enrolled_python_targets=sum(
                1
                for item in items
                if isinstance(item, AgentDescriptor)
                and item.item_type == ItemType.PYTHON_TARGET
                and item.enrolled
            ),
            active_compatible_agents=sum(
                1
                for item in items
                if isinstance(item, AgentDescriptor)
                and item.item_type == ItemType.AGENT
                and item.status == InventoryStatus.ACTIVE
                and str(item.discovery_source) == "http_metadata"
            ),
            generic_listening_services=sum(
                1
                for listener in listeners
                if not any(related in service_ids for related in listener.related_ids)
            ),
            wildcard_bound_services=sum(
                1 for listener in listeners if listener.wildcard_bound
            ),
            docker_status=(
                "not_requested"
                if not docker_enabled
                else "available"
                if docker_run and docker_run.state in {AdapterState.SUCCESS, AdapterState.PARTIAL}
                else "unavailable"
            ),
            kali_status=(
                "not_requested"
                if not kali_enabled
                else str(kali_item.status) if kali_item else "unavailable"
            ),
            error_count=len(errors),
            stale=False,
        )

    @staticmethod
    def _atomic_json(path: Path, payload: dict) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
