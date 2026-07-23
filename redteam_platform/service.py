"""Application service shared by the CLI and loopback API."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable

from redteam_platform.adapters import create_adapter
from redteam_platform.adaptive import AdaptiveAssessmentEngine, PROBE_TEMPLATES
from redteam_platform.artifacts import RunArtifacts
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import InventorySnapshot
from redteam_platform.schemas import (
    AssessmentBudget,
    AssessmentEvent,
    AssessmentProfile,
    AssessmentRequest,
    RunSummary,
    Target,
)
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings, sanitized_settings


class ApplicationService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.policy = ScopePolicy(settings)
        self.inventory_service = InventoryService(settings)
        self._cancel_events: dict[str, threading.Event] = {}

    def inventory(
        self,
        refresh: bool = False,
        include_docker: bool | None = None,
    ) -> InventorySnapshot:
        if refresh:
            return self.inventory_service.refresh(include_docker=include_docker)
        return self.inventory_service.cached() or self.inventory_service.refresh(
            include_docker=include_docker
        )

    def resolve_target(self, kind: str, value: str) -> Target:
        return create_adapter(kind, self.settings).identify(value)

    def make_request(
        self,
        *,
        kind: str,
        value: str,
        statement: str,
        source: str,
        profile: AssessmentProfile = AssessmentProfile.STANDARD,
        categories: list[str] | None = None,
        planner_model: str | None = None,
        target_model: str | None = None,
        budget: AssessmentBudget | None = None,
        public_mode: bool = False,
        interactive_confirmation: bool = False,
    ) -> AssessmentRequest:
        target = self.resolve_target(kind, value)
        if target_model:
            target.metadata["model"] = target_model
        if kind in {"openai", "ollama"} and not target_model:
            raise ValueError(f"{kind} targets require an explicitly selected target model.")
        selected_categories = categories or []
        unknown = sorted(set(selected_categories) - set(PROBE_TEMPLATES))
        if unknown:
            raise ValueError("Unknown registered probe categories: " + ", ".join(unknown))
        authorization = self.policy.authorize(
            target.endpoint or target.local_path or target.name,
            statement=statement,
            source=source,
            profile=profile,
            public_mode=public_mode,
            interactive_confirmation=interactive_confirmation,
        )
        return AssessmentRequest(
            target=target,
            profile=profile,
            authorization=authorization,
            categories=selected_categories,
            budget=budget or AssessmentBudget(),
            planner_model=planner_model,
        )

    def plan(self, **kwargs: Any) -> AssessmentRequest:
        """Return a fully validated request without executing a probe."""
        return self.make_request(**kwargs)

    def run(
        self,
        request: AssessmentRequest,
        *,
        run_id: str | None = None,
        event_callback: Callable[[AssessmentEvent], None] | None = None,
    ) -> tuple[RunSummary, list, dict[str, str]]:
        # Revalidate immediately before creating a run or handing a target to an adapter.
        self.policy.require_record(
            request.target.endpoint or request.target.local_path or request.target.name,
            request.authorization,
        )
        artifacts = RunArtifacts(
            self.settings.report_root,
            run_id=run_id or request.authorization.run_id,
        )
        cancel_event = threading.Event()
        self._cancel_events[artifacts.run_id] = cancel_event
        try:
            engine = AdaptiveAssessmentEngine(cancel_event=cancel_event)
            adapter = create_adapter(request.target.adapter, self.settings)
            inventory = self.inventory(refresh=False)
            return engine.run(
                request,
                adapter,
                artifacts,
                inventory,
                sanitized_settings(self.settings),
                event_callback=event_callback,
            )
        finally:
            self._cancel_events.pop(artifacts.run_id, None)

    def cancel(self, run_id: str) -> bool:
        event = self._cancel_events.get(run_id)
        if not event:
            return False
        event.set()
        return True

    def list_runs(self) -> list[dict[str, Any]]:
        if not self.settings.report_root.exists():
            return []
        rows: list[dict[str, Any]] = []
        for run_dir in sorted(self.settings.report_root.glob("run_*"), reverse=True):
            if not run_dir.is_dir():
                continue
            summary_path = run_dir / "summary.json"
            summary: dict[str, Any] = {}
            if summary_path.exists():
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    summary = {"status": "unreadable"}
            rows.append({"run_id": run_dir.name, "path": str(run_dir), **summary})
        return rows

    def run_file(self, run_id: str, filename: str) -> Path:
        if not run_id.startswith("run_") or Path(run_id).name != run_id:
            raise ValueError("Invalid run ID.")
        allowed = {"summary.json", "findings.json", "report.md", "report.html", "report.json", "manifest.json"}
        if filename not in allowed:
            raise ValueError("Unsupported run artifact.")
        path = self.settings.report_root / run_id / filename
        if not path.is_file():
            raise FileNotFoundError(path)
        return path
