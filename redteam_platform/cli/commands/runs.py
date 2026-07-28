"""Run and report browsing commands."""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.exit_codes import ExitCode
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope, empty, title
from redteam_platform.reporting.models import ReportMode
from redteam_platform.reporting.service import ReportingService
from redteam_platform.run_browser import RunBrowser


def _browser(ctx: typer.Context) -> tuple[CLIContext, RunBrowser]:
    state: CLIContext = ctx.find_root().obj
    return state, RunBrowser(state.settings.report_root)


def _json(state: CLIContext, enabled: bool) -> bool:
    state.json_output = state.json_output or enabled
    return state.json_output


def _reporting(ctx: typer.Context) -> tuple[CLIContext, ReportingService]:
    state: CLIContext = ctx.find_root().obj
    return state, ReportingService(state.settings.report_root)


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

    @runs_app.command("events", help="Display persisted lifecycle events; --follow polls sanitized artifacts only.")
    def events(
        ctx: typer.Context,
        run_id: str,
        json_lines: bool = typer.Option(False, "--json-lines"),
        follow: bool = typer.Option(False, "--follow"),
        poll_interval: float = typer.Option(0.5, "--poll-interval", min=0.1, max=10.0),
        timeout: int = typer.Option(600, "--timeout", min=0, max=7200),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output or json_lines)
        if follow:
            deadline = time.monotonic() + timeout
            seen = 0
            run_dir = Path(state.settings.report_root).expanduser().resolve() / run_id
            while True:
                rows = browser.events(run_id)
                for row in rows[seen:]:
                    if json_lines or state.json_output:
                        typer.echo(json.dumps(row, separators=(",", ":")))
                    else:
                        state.console.print(
                            f"{row.get('sequence')} {row.get('phase')} "
                            f"{row.get('action')} {row.get('status')}"
                        )
                seen = len(rows)
                adaptive_state = run_dir / "adaptive_state.json"
                if adaptive_state.is_file():
                    try:
                        status = json.loads(
                            adaptive_state.read_text(encoding="utf-8")
                        ).get("status")
                    except (OSError, json.JSONDecodeError):
                        status = None
                    if status in {"complete", "failed", "cancelled"}:
                        break
                elif (run_dir / "manifest.json").is_file():
                    break
                if timeout == 0 or time.monotonic() >= deadline:
                    break
                time.sleep(poll_interval)
            return
        rows = browser.events(run_id)
        if json_lines:
            for row in rows:
                typer.echo(json.dumps(row, separators=(",", ":")))
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

    @reports_app.command("build", help="Build canonical JSON, Markdown, HTML, or optional PDF reports.")
    def reports_build(
        ctx: typer.Context,
        run_id: str,
        format: Optional[str] = typer.Option(None, "--format"),
        all_formats: bool = typer.Option(False, "--all"),
        safe_share: bool = typer.Option(False, "--safe-share"),
        overwrite: bool = typer.Option(False, "--overwrite"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, service = _reporting(ctx)
        _json(state, json_output)
        normalized = {"md": "markdown"}.get(str(format).lower(), str(format).lower()) if format else None
        formats = ["json", "markdown", "html", "pdf"] if all_formats else ([normalized] if normalized else None)
        data = service.build(
            run_id,
            formats=formats,
            mode=ReportMode.SAFE_SHARE if safe_share else ReportMode.INTERNAL,
            overwrite=overwrite,
        )
        payload = {
            "run_id": run_id,
            "mode": data["mode"],
            "outputs": data["outputs"],
        }
        if state.json_output or json_output:
            emit_envelope(state, "reports.build", payload, warnings=data["warnings"])
        else:
            state.console.print(details_table("Reports built", payload.items()))
            for warning_data in data["warnings"]:
                state.console.print(f"Warning: {warning_data['message']}")

    @reports_app.command("export", help="Export an existing report or build a safe-share report set.")
    def reports_export(
        ctx: typer.Context,
        run_id: str,
        format: str = typer.Option("markdown", "--format"),
        destination: Optional[Path] = typer.Option(None, "--destination"),
        safe_share: bool = typer.Option(False, "--safe-share"),
        overwrite: bool = typer.Option(False, "--overwrite"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, browser = _browser(ctx)
        _json(state, json_output)
        if safe_share:
            service = ReportingService(state.settings.report_root)
            target = destination or (Path.cwd() / f"{run_id}-safe-share")
            normalized = {"md": "markdown"}.get(format.lower(), format.lower())
            path = service.export(
                run_id,
                target,
                formats=[normalized],
                safe_share=True,
                overwrite=overwrite,
            )
        else:
            path = browser.export(run_id, format=format, destination=destination, overwrite=overwrite)
        data = {
            "run_id": run_id,
            "format": format,
            "mode": "safe_share" if safe_share else "internal",
            "path": str(path),
        }
        if state.json_output or json_output:
            emit_envelope(state, "reports.export", data)
        else:
            state.console.print(details_table("Report exported", data.items()))

    @reports_app.command("verify", help="Verify assessment and report manifests.")
    def reports_verify(
        ctx: typer.Context,
        run_id: str,
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, service = _reporting(ctx)
        _json(state, json_output)
        data = service.verify(run_id)
        if state.json_output or json_output:
            emit_envelope(
                state,
                "reports.verify",
                data,
                success=data["status"] == "ok",
                errors=[] if data["status"] == "ok" else ["Manifest verification failed."],
            )
        else:
            state.console.print(details_table("Report integrity", data.items()))
        if data["status"] != "ok":
            raise typer.Exit(code=int(ExitCode.ARTIFACT_FAILURE))

    @reports_app.command("compare", help="Compare two runs using stable finding fingerprints.")
    def reports_compare(
        ctx: typer.Context,
        old_run_id: str,
        new_run_id: str,
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, service = _reporting(ctx)
        _json(state, json_output)
        comparison = service.compare(old_run_id, new_run_id)
        if state.json_output or json_output:
            emit_envelope(state, "reports.compare", comparison)
        else:
            state.console.print(
                details_table(
                    "Report comparison",
                    [
                        ("old_run_id", old_run_id),
                        ("new_run_id", new_run_id),
                        ("new_findings", len(comparison.new_findings)),
                        ("resolved_findings", len(comparison.resolved_findings)),
                        ("persistent_findings", len(comparison.persistent_findings)),
                        ("changed_findings", len(comparison.changed_findings)),
                        ("coverage_change", comparison.coverage_change),
                        ("probe_count_change", comparison.probe_count_change),
                    ],
                )
            )

    @reports_app.command("retest", help="Classify a new run as a retest without treating skipped probes as resolved.")
    def reports_retest(
        ctx: typer.Context,
        old_run_id: str,
        new_run_id: str,
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, service = _reporting(ctx)
        _json(state, json_output)
        comparison = service.retest(old_run_id, new_run_id)
        if state.json_output or json_output:
            emit_envelope(state, "reports.retest", comparison)
        else:
            state.console.print(
                details_table(
                    "Retest summary",
                    [
                        ("old_run_id", old_run_id),
                        ("new_run_id", new_run_id),
                        ("new", len(comparison.new_findings)),
                        ("resolved", len(comparison.resolved_findings)),
                        ("persistent_or_not_retested", len(comparison.persistent_findings)),
                        ("changed", len(comparison.changed_findings)),
                    ],
                )
            )

    @reports_app.command("findings", help="List normalized findings with severity and status filters.")
    def reports_findings(
        ctx: typer.Context,
        run_id: str,
        severity: Optional[str] = typer.Option(None, "--severity"),
        status: Optional[str] = typer.Option(None, "--status"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, service = _reporting(ctx)
        _json(state, json_output)
        findings = service.canonical(run_id).findings
        if severity:
            findings = [item for item in findings if str(item.severity).lower() == severity.lower()]
        if status:
            findings = [item for item in findings if str(item.status).lower() == status.lower()]
        if state.json_output or json_output:
            emit_envelope(state, "reports.findings", findings)
        elif not findings:
            empty(state, "No findings match the selected filters.")
        else:
            state.console.print(
                data_table(
                    f"Findings — {run_id}",
                    ["ID", "Severity", "Confidence", "Status", "Category", "Title"],
                    [
                        (
                            item.finding_id,
                            item.severity,
                            item.confidence,
                            item.status,
                            item.category,
                            item.title,
                        )
                        for item in findings
                    ],
                )
            )

    @reports_app.command("coverage", help="Show normalized coverage and non-pass outcomes.")
    def reports_coverage(
        ctx: typer.Context,
        run_id: str,
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state, service = _reporting(ctx)
        _json(state, json_output)
        coverage = service.canonical(run_id).coverage
        if state.json_output or json_output:
            emit_envelope(state, "reports.coverage", coverage)
        else:
            state.console.print(
                data_table(
                    f"Coverage — {run_id}",
                    ["Category", "State", "Planned", "Completed", "Passed", "Findings", "Unavailable", "Errors", "Timeouts", "%"],
                    [
                        (
                            item.category,
                            item.state,
                            item.planned,
                            item.completed,
                            item.passed,
                            item.findings,
                            item.unavailable,
                            item.errors,
                            item.timeouts,
                            item.percentage,
                        )
                        for item in coverage.categories
                    ],
                )
            )
            state.console.print(f"Overall coverage: {coverage.overall_percentage:.1f}%")
