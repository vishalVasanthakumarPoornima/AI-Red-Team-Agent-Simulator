"""Run and report browsing commands."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope, empty, title
from redteam_platform.run_browser import RunBrowser


def _browser(ctx: typer.Context) -> tuple[CLIContext, RunBrowser]:
    state: CLIContext = ctx.find_root().obj
    return state, RunBrowser(state.settings.report_root)


def _json(state: CLIContext, enabled: bool) -> bool:
    state.json_output = state.json_output or enabled
    return state.json_output


def register(root: typer.Typer, runs_app: typer.Typer, reports_app: typer.Typer) -> None:
    root.add_typer(runs_app, name="runs")
    root.add_typer(reports_app, name="reports")

    @runs_app.command("list", help="List persisted assessment runs. Offline artifact browsing.")
    def list_runs(
        ctx: typer.Context,
        limit: int = typer.Option(20, "--limit", min=0),
        status: Optional[str] = typer.Option(None, "--status"),
        target: Optional[str] = typer.Option(None, "--target"),
        since: Optional[datetime] = typer.Option(None, "--since"),
        sort: str = typer.Option("newest", "--sort"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output)
        rows = browser.list(limit=limit, status=status, target=target, since=since, sort=sort)
        if state.json_output or json_output:
            emit_envelope(state, "runs.list", rows)
        elif not rows:
            empty(state, "No assessment runs are available.")
        else:
            title(state, "Assessment runs")
            state.console.print(
                data_table(
                    "Current and previous runs",
                    ["Run ID", "Start", "End", "Status", "Target", "Profile", "Scope", "Findings", "Errors", "Stop reason"],
                    [
                        (
                            row["run_id"],
                            row["start_time"],
                            row["end_time"],
                            row["status"],
                            row["target"],
                            row["profile"],
                            row["scope"],
                            row["finding_count"],
                            row["error_count"],
                            row["stop_reason"],
                        )
                        for row in rows
                    ],
                )
            )

    @runs_app.command("show", help="Show a run safely; authorization text is summarized, not printed.")
    def show(ctx: typer.Context, run_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output)
        data = browser.show(run_id)
        if state.json_output or json_output:
            emit_envelope(state, "runs.show", data, warnings=data.get("warnings", []))
        else:
            title(state, f"Run {run_id}")
            summary = data.get("summary") or {}
            state.console.print(details_table("Summary", summary.items()))
            state.console.print(details_table("Authorization summary", (data.get("authorization_summary") or {}).items()))
            state.console.print(details_table("Manifest, tools, models, and scope", (data.get("manifest") or {}).items()))
            inventory = data.get("inventory")
            if isinstance(inventory, dict):
                state.console.print(
                    details_table(
                        "Attached inventory",
                        [
                            ("generated_at", inventory.get("generated_at")),
                            ("cached", inventory.get("cached")),
                            ("stale", inventory.get("stale")),
                            ("item_count", len(inventory.get("items") or [])),
                            ("errors", inventory.get("errors") or []),
                        ],
                    )
                )
            findings = data.get("findings") or []
            if findings:
                state.console.print(
                    data_table(
                        "Findings",
                        ["ID", "Severity", "Category", "Title", "Status"],
                        [(item.get("id"), item.get("severity"), item.get("category"), item.get("title"), item.get("status")) for item in findings],
                    )
                )
            state.console.print(details_table("Hash state", data["hash_state"].items()))
            state.console.print(
                data_table(
                    "Artifacts",
                    ["Path", "Bytes", "SHA-256"],
                    [
                        (item["path"], item["bytes"], item["sha256"])
                        for item in data.get("artifacts") or []
                    ],
                )
            )

    @runs_app.command("events", help="Display persisted lifecycle events. Offline.")
    def events(ctx: typer.Context, run_id: str, json_lines: bool = typer.Option(False, "--json-lines"), json_output: bool = typer.Option(False, "--json")) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output or json_lines)
        rows = browser.events(run_id)
        if json_lines:
            for row in rows:
                state.console.print(json.dumps(row, separators=(",", ":")))
        elif state.json_output or json_output:
            emit_envelope(state, "runs.events", rows)
        else:
            state.console.print(
                data_table(
                    f"Events — {run_id}",
                    ["Sequence", "Time", "Phase", "Action", "Status", "Details"],
                    [(item.get("sequence"), item.get("timestamp"), item.get("phase"), item.get("action"), item.get("status"), item.get("details")) for item in rows],
                )
            )

    @runs_app.command("artifacts", help="List run artifacts and computed hashes without opening unsafe paths.")
    def artifacts(ctx: typer.Context, run_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output)
        rows = browser.artifacts(run_id)
        if state.json_output or json_output:
            emit_envelope(state, "runs.artifacts", rows)
        else:
            state.console.print(data_table(f"Artifacts — {run_id}", ["Path", "Bytes", "SHA-256"], [(item["path"], item["bytes"], item["sha256"]) for item in rows]))

    @reports_app.command("list", help="List report formats that already exist. Offline.")
    def reports_list(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output)
        rows = browser.reports()
        if state.json_output or json_output:
            emit_envelope(state, "reports.list", rows)
        elif not rows:
            empty(state, "No existing report artifacts are available.")
        else:
            state.console.print(data_table("Reports", ["Run ID", "Status", "Target", "Formats"], [(item["run_id"], item["status"], item["target"], item["formats"]) for item in rows]))

    @reports_app.command("show", help="Show an existing report; no format is fabricated.")
    def reports_show(ctx: typer.Context, run_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output)
        filename, content = browser.report_text(run_id)
        if state.json_output or json_output:
            emit_envelope(state, "reports.show", {"run_id": run_id, "artifact": filename, "content": content})
        else:
            title(state, f"{filename} — {run_id}")
            state.console.print(content)

    @reports_app.command("export", help="Sanitize and export an existing report; refuses overwrite by default.")
    def reports_export(
        ctx: typer.Context,
        run_id: str,
        format: str = typer.Option("markdown", "--format"),
        destination: Optional[Path] = typer.Option(None, "--destination"),
        overwrite: bool = typer.Option(False, "--overwrite"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output)
        path = browser.export(run_id, format=format, destination=destination, overwrite=overwrite)
        data = {"run_id": run_id, "format": format, "path": str(path)}
        if state.json_output or json_output:
            emit_envelope(state, "reports.export", data)
        else:
            state.console.print(details_table("Report exported", data.items()))
