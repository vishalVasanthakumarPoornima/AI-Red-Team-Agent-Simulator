"""Optional authenticated loopback FastAPI control plane."""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from redteam_platform.inventory.models import AgentDescriptor, ItemType, OllamaModel
from redteam_platform.schemas import AssessmentBudget, AssessmentProfile
from redteam_platform.scope_policy import ScopeDeniedError
from redteam_platform.service import ApplicationService
from redteam_platform.settings import Settings, load_settings


class APIAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    target: str
    authorization_statement: str = Field(min_length=12, max_length=2000)
    profile: AssessmentProfile = AssessmentProfile.STANDARD
    categories: list[str] = Field(default_factory=list, max_length=30)
    planner_model: str | None = Field(default=None, max_length=200)
    target_model: str | None = Field(default=None, max_length=200)
    budget: AssessmentBudget = Field(default_factory=AssessmentBudget)


class RunRegistry:
    def __init__(self, max_workers: int):
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="redteam")
        self.lock = threading.Lock()
        self.runs: dict[str, dict[str, Any]] = {}
        self.event_queues: dict[str, queue.Queue] = {}

    def create(self) -> str:
        from redteam_platform.artifacts import new_run_id

        run_id = new_run_id()
        with self.lock:
            self.runs[run_id] = {"run_id": run_id, "status": "queued"}
            self.event_queues[run_id] = queue.Queue()
        return run_id


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    if settings.bind_host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("The API must bind to loopback.")
    service = ApplicationService(settings)
    registry = RunRegistry(settings.max_concurrency)
    rate_windows: dict[str, deque[float]] = defaultdict(deque)
    app = FastAPI(title="AI Agent Red Team API", version="0.2.0")

    @app.middleware("http")
    async def limits(request: Request, call_next):
        length = int(request.headers.get("content-length") or 0)
        if length > settings.request_body_limit:
            return JSONResponse(
                {"detail": "Request body too large."}, status_code=413
            )
        key = request.client.host if request.client else "local"
        now = time.monotonic()
        window = rate_windows[key]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= settings.rate_limit_per_minute:
            return JSONResponse(
                {"detail": "Rate limit exceeded."}, status_code=429
            )
        window.append(now)
        return await call_next(request)

    def authenticated(authorization: str | None = Header(None)) -> None:
        expected = settings.api_token.get_secret_value() if settings.api_token else None
        if not expected:
            raise HTTPException(503, "API token is not configured.")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer token required.")
        import secrets

        if not secrets.compare_digest(authorization[7:], expected):
            raise HTTPException(403, "Invalid bearer token.")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "loopback_only": True, "authentication_configured": bool(settings.api_token)}

    @app.get("/schema", dependencies=[Depends(authenticated)])
    def schema() -> dict[str, Any]:
        return APIAssessmentRequest.model_json_schema()

    @app.get("/inventory", dependencies=[Depends(authenticated)])
    def inventory(refresh: bool = False) -> dict[str, Any]:
        return service.inventory(refresh=refresh).model_dump(mode="json")

    @app.get("/targets", dependencies=[Depends(authenticated)])
    def targets() -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in service.inventory().items
            if isinstance(item, AgentDescriptor)
            and item.item_type == ItemType.PYTHON_TARGET
        ]

    @app.get("/models", dependencies=[Depends(authenticated)])
    def models() -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in service.inventory().items
            if isinstance(item, OllamaModel)
        ]

    def prepare(body: APIAssessmentRequest):
        try:
            return service.make_request(
                kind=body.kind,
                value=body.target,
                statement=body.authorization_statement,
                source="human-api",
                profile=body.profile,
                categories=body.categories,
                planner_model=body.planner_model,
                target_model=body.target_model,
                budget=body.budget,
                public_mode=False,
                interactive_confirmation=False,
            )
        except (ScopeDeniedError, ValueError) as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.post("/assessments/plan", dependencies=[Depends(authenticated)])
    def plan(body: APIAssessmentRequest) -> dict[str, Any]:
        return prepare(body).model_dump(mode="json")

    @app.post("/assessments/run", dependencies=[Depends(authenticated)])
    def run(body: APIAssessmentRequest) -> dict[str, str]:
        assessment = prepare(body)
        task_id = registry.create()

        def worker() -> None:
            with registry.lock:
                registry.runs[task_id]["status"] = "running"

            def event_callback(event) -> None:
                registry.event_queues[task_id].put(event.model_dump(mode="json"))

            try:
                summary, findings, reports = service.run(assessment, run_id=task_id, event_callback=event_callback)
                payload = {
                    "status": "complete",
                    "actual_run_id": summary.run_id,
                    "summary": summary.model_dump(mode="json"),
                    "finding_count": len(findings),
                    "reports": reports,
                }
            except Exception as exc:  # boundary converts failures to a stable API state
                payload = {"status": "error", "error": type(exc).__name__ + ": " + str(exc)}
            with registry.lock:
                registry.runs[task_id].update(payload)
            registry.event_queues[task_id].put(None)

        registry.executor.submit(worker)
        return {"run_id": task_id, "status": "queued"}

    @app.get("/assessments/{run_id}", dependencies=[Depends(authenticated)])
    def status(run_id: str) -> dict[str, Any]:
        with registry.lock:
            row = registry.runs.get(run_id)
        if row:
            return row
        for persisted in service.list_runs():
            if persisted.get("run_id") == run_id:
                return persisted
        raise HTTPException(404, "Run not found.")

    @app.get("/assessments/{run_id}/events", dependencies=[Depends(authenticated)])
    def events(run_id: str) -> StreamingResponse:
        stream = registry.event_queues.get(run_id)
        if stream is None:
            raise HTTPException(404, "Active run not found.")

        def generate():
            while True:
                item = stream.get(timeout=settings.request_timeout_seconds)
                if item is None:
                    yield "event: end\ndata: {}\n\n"
                    break
                yield "data: " + json.dumps(item) + "\n\n"

        return StreamingResponse(generate(), media_type="text/event-stream")

    @app.post("/assessments/{run_id}/cancel", dependencies=[Depends(authenticated)])
    def cancel(run_id: str) -> dict[str, Any]:
        row = registry.runs.get(run_id)
        actual = row.get("actual_run_id") if row else run_id
        return {"cancel_requested": service.cancel(actual), "run_id": run_id}

    @app.get("/reports/{run_id}/{filename}", dependencies=[Depends(authenticated)])
    def report(run_id: str, filename: str) -> FileResponse:
        try:
            path = service.run_file(run_id, filename)
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(404, str(exc)) from exc
        return FileResponse(path)

    return app
