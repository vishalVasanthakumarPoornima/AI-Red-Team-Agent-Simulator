"""Typer/Rich command-line interface for the local assessment platform."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from redteam_platform.benchmark import benchmark_model
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import AgentDescriptor, ItemType, KaliReadiness, OllamaModel
from redteam_platform.schemas import AssessmentBudget, AssessmentProfile
from redteam_platform.scope_policy import ScopeDeniedError
from redteam_platform.service import ApplicationService
from redteam_platform.settings import Settings, load_settings, sanitized_settings


app = typer.Typer(no_args_is_help=False, help="Authorized local-first AI agent red-team platform.")
assess_app = typer.Typer(help="Plan and run bounded assessments.")
runs_app = typer.Typer(help="Inspect persisted assessment runs.")
model_app = typer.Typer(help="Inspect and benchmark local models.")
config_app = typer.Typer(help="Inspect effective configuration.")
api_app = typer.Typer(help="Run the optional loopback API.")
app.add_typer(assess_app, name="assess")
app.add_typer(runs_app, name="runs")
app.add_typer(model_app, name="model")
app.add_typer(config_app, name="config")
app.add_typer(api_app, name="api")

console = Console()


class Context:
    settings: Settings
    json_output: bool


def _emit(payload: Any, json_output: bool = False) -> None:
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump(mode="json")
    if json_output:
        console.print_json(data=payload)
    else:
        console.print(payload)


def _ctx(ctx: typer.Context) -> Context:
    return ctx.obj


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    config: Optional[Path] = typer.Option(None, "--config", help="TOML configuration file."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    state = Context()
    state.settings = load_settings(config)
    state.json_output = json_output
    ctx.obj = state
    if ctx.invoked_subcommand is None:
        interactive_menu(state)


def interactive_menu(state: Context) -> None:
    console.print("[bold cyan]AI Agent Red Team Simulator[/bold cyan]")
    console.print("Authorized local and lab assessment only. Use Ctrl-C to exit.")
    while True:
        console.print("\n1. Doctor  2. Inventory  3. Targets  4. Runs  5. Exit")
        choice = typer.prompt("Select", default="1")
        if choice == "1":
            _doctor(state)
        elif choice == "2":
            _inventory(state, refresh=True, include_docker=False)
        elif choice == "3":
            _targets(state, refresh=False)
        elif choice == "4":
            _emit(ApplicationService(state.settings).list_runs(), state.json_output)
        elif choice == "5":
            return
        else:
            console.print("Unknown choice.")


@app.command("init")
def init_config(
    ctx: typer.Context,
    destination: Path = typer.Option(Path("redteam.toml"), "--destination"),
) -> None:
    if destination.exists():
        raise typer.BadParameter(f"Refusing to overwrite {destination}")
    token = secrets.token_urlsafe(32)
    content = (
        "[redteam]\n"
        'bind_host = "127.0.0.1"\n'
        "api_port = 18150\n"
        'report_root = "reports/runs"\n'
        'allowed_cidrs = ["127.0.0.0/8", "::1/128"]\n'
        "allowed_domains = []\n"
        "allow_public = false\n"
        f'# API token generated for local use; protect this file.\napi_token = "{token}"\n'
    )
    destination.write_text(content, encoding="utf-8")
    destination.chmod(0o600)
    _emit({"created": str(destination), "mode": "0600"}, _ctx(ctx).json_output)


def _doctor(state: Context) -> dict[str, Any]:
    import shutil
    import sys

    service = ApplicationService(state.settings)
    checks = {
        "python": sys.version.split()[0],
        "python_supported": sys.version_info[:2] == (3, 13),
        "loopback_bind": state.settings.bind_host in {"127.0.0.1", "::1", "localhost"},
        "ollama_cli": bool(shutil.which("ollama")),
        "docker_cli": bool(shutil.which("docker")),
        "ssh_cli": bool(shutil.which("ssh")),
        "cached_inventory": service.inventory_service.cached() is not None,
        "report_root": str(state.settings.report_root),
    }
    _emit(checks, state.json_output)
    return checks


@app.command()
def doctor(ctx: typer.Context) -> None:
    _doctor(_ctx(ctx))


def _inventory(
    state: Context,
    refresh: bool,
    include_docker: bool,
    include_kali: bool = False,
    live_ollama: bool = False,
    cached: bool = False,
    json_output: bool = False,
    strict: bool = False,
):
    inventory_settings = state.settings.model_copy(
        update={"ollama_live_check": live_ollama}
    )
    snapshot = InventoryService(inventory_settings).collect(
        include_docker=include_docker,
        include_kali=include_kali,
        refresh=not cached,
        cached_only=cached,
        force_refresh=refresh,
    )
    machine_output = state.json_output or json_output
    if machine_output:
        _emit(snapshot, True)
        if strict and snapshot.errors:
            raise typer.Exit(1)
        return snapshot
    if cached and not snapshot.items:
        console.print("[yellow]No usable inventory cache is available.[/yellow]")
    table = Table(title=f"Inventory ({'stale cache' if snapshot.stale else 'cache' if snapshot.cached else 'fresh'})")
    for column in ("Name", "Type", "Status", "Source", "Scope", "Endpoint"):
        table.add_column(column)
    for item in snapshot.items:
        table.add_row(
            item.name,
            item.type,
            str(item.status),
            str(item.discovery_source),
            str(item.scope_classification),
            item.endpoint or item.local_path or "",
        )
    console.print(table)
    console.print(snapshot.summary.model_dump(mode="json"))
    for error in snapshot.errors:
        console.print(f"[yellow]Limited:[/yellow] {error.source}/{error.code}: {error.message}")
    if strict and snapshot.errors:
        raise typer.Exit(1)
    return snapshot


@app.command()
def inventory(
    ctx: typer.Context,
    refresh: bool = typer.Option(False, "--refresh"),
    cached: bool = typer.Option(False, "--cached"),
    docker: bool = typer.Option(False, "--include-docker", "--docker"),
    kali: bool = typer.Option(False, "--include-kali"),
    live_ollama: bool = typer.Option(
        False,
        "--live-ollama",
        help="Opt in to bounded metadata requests to configured Ollama endpoints.",
    ),
    json_output: bool = typer.Option(False, "--json"),
    strict: bool = typer.Option(False, "--strict"),
) -> None:
    _inventory(
        _ctx(ctx),
        refresh,
        docker,
        kali,
        live_ollama,
        cached,
        json_output,
        strict,
    )


def _targets(state: Context, refresh: bool) -> None:
    snapshot = InventoryService(state.settings).collect(
        include_ollama=False,
        include_listeners=False,
        include_targets=True,
        include_http=False,
        include_docker=False,
        include_kali=False,
        force_refresh=refresh,
    )
    rows = [
        item
        for item in snapshot.items
        if isinstance(item, AgentDescriptor) and item.item_type == ItemType.PYTHON_TARGET
    ]
    _emit([item.model_dump(mode="json") for item in rows], state.json_output)


@app.command()
def targets(ctx: typer.Context, refresh: bool = typer.Option(False, "--refresh")) -> None:
    _targets(_ctx(ctx), refresh)


@app.command()
def models(
    ctx: typer.Context,
    refresh: bool = typer.Option(False, "--refresh"),
    live: bool = typer.Option(
        False,
        "--live",
        help="Opt in to bounded metadata requests to configured Ollama endpoints.",
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    state = _ctx(ctx)
    settings = state.settings.model_copy(update={"ollama_live_check": live})
    snapshot = InventoryService(settings).collect(
        include_listeners=False,
        include_targets=False,
        include_http=False,
        include_docker=False,
        include_kali=False,
        force_refresh=refresh,
    )
    rows = [
        item.model_dump(mode="json")
        for item in snapshot.items
        if isinstance(item, OllamaModel)
    ]
    _emit(rows, state.json_output or json_output)


@app.command()
def agents(
    ctx: typer.Context,
    refresh: bool = typer.Option(False, "--refresh"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    state = _ctx(ctx)
    snapshot = InventoryService(state.settings).collect(
        include_ollama=False,
        include_listeners=True,
        include_targets=True,
        include_http=True,
        include_docker=False,
        include_kali=False,
        force_refresh=refresh,
    )
    rows = [
        item.model_dump(mode="json")
        for item in snapshot.items
        if isinstance(item, AgentDescriptor)
    ]
    _emit(rows, state.json_output or json_output)


@app.command()
def services(
    ctx: typer.Context,
    refresh: bool = typer.Option(False, "--refresh"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    state = _ctx(ctx)
    snapshot = InventoryService(state.settings).collect(
        include_ollama=False,
        include_listeners=True,
        include_targets=False,
        include_http=True,
        include_docker=False,
        include_kali=False,
        force_refresh=refresh,
    )
    rows = [
        item.model_dump(mode="json")
        for item in snapshot.items
        if item.item_type in {ItemType.LISTENER, ItemType.SERVICE}
    ]
    _emit(rows, state.json_output or json_output)


@app.command("kali-status")
def kali_status(
    ctx: typer.Context,
    live: bool = typer.Option(False, "--live", help="Opt in to a bounded SSH readiness check."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    state = _ctx(ctx)
    settings = state.settings.model_copy(
        update={"include_kali_readiness": True, "kali_live_check": live}
    )
    snapshot = InventoryService(settings).collect(
        include_ollama=False,
        include_listeners=False,
        include_targets=False,
        include_http=False,
        include_docker=False,
        include_kali=True,
        force_refresh=True,
    )
    rows = [
        item.model_dump(mode="json")
        for item in snapshot.items
        if isinstance(item, KaliReadiness)
    ]
    _emit(rows, state.json_output or json_output)


def _budget(rounds: int, probes: int, model_calls: int, duration: int) -> AssessmentBudget:
    return AssessmentBudget(
        max_rounds=rounds,
        max_probes=probes,
        max_model_calls=model_calls,
        max_duration_seconds=duration,
    )


def _request_from_options(
    state: Context,
    kind: str,
    target: str,
    statement: str,
    profile: AssessmentProfile,
    categories: list[str] | None,
    planner_model: str | None,
    target_model: str | None,
    rounds: int,
    probes: int,
    model_calls: int,
    duration: int,
    public: bool,
    yes: bool,
):
    if public and not yes:
        yes = typer.confirm("Confirm this allowlisted public target is explicitly authorized")
    return ApplicationService(state.settings).make_request(
        kind=kind,
        value=target,
        statement=statement,
        source="human-cli",
        profile=profile,
        categories=categories,
        planner_model=planner_model,
        target_model=target_model,
        budget=_budget(rounds, probes, model_calls, duration),
        public_mode=public,
        interactive_confirmation=yes,
    )


COMMON_KIND = typer.Option("python", "--kind", help="python|http|openai|ollama|host|web|dexter")


@assess_app.command("plan")
def assess_plan(
    ctx: typer.Context,
    target: str = typer.Option(..., "--target"),
    authorization: str = typer.Option(..., "--authorization", help="Human scope authorization statement."),
    kind: str = COMMON_KIND,
    profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD),
    category: Optional[list[str]] = typer.Option(None, "--category"),
    planner_model: Optional[str] = typer.Option(None, "--planner-model"),
    target_model: Optional[str] = typer.Option(None, "--target-model"),
    rounds: int = typer.Option(8, min=1, max=50),
    probes: int = typer.Option(100, min=1, max=1000),
    model_calls: int = typer.Option(24, min=0, max=500),
    duration: int = typer.Option(1200, min=1, max=86400),
    public: bool = typer.Option(False, "--public"),
    yes: bool = typer.Option(False, "--yes"),
) -> None:
    state = _ctx(ctx)
    try:
        request = _request_from_options(state, kind, target, authorization, profile, category, planner_model, target_model, rounds, probes, model_calls, duration, public, yes)
    except (ScopeDeniedError, ValueError) as exc:
        console.print(f"[red]Scope denied:[/red] {exc}")
        raise typer.Exit(2) from exc
    _emit(request, state.json_output)


@assess_app.command("run")
def assess_run(
    ctx: typer.Context,
    target: str = typer.Option(..., "--target"),
    authorization: str = typer.Option(..., "--authorization"),
    kind: str = COMMON_KIND,
    profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD),
    category: Optional[list[str]] = typer.Option(None, "--category"),
    planner_model: Optional[str] = typer.Option(None, "--planner-model"),
    target_model: Optional[str] = typer.Option(None, "--target-model"),
    rounds: int = typer.Option(8, min=1, max=50),
    probes: int = typer.Option(100, min=1, max=1000),
    model_calls: int = typer.Option(24, min=0, max=500),
    duration: int = typer.Option(1200, min=1, max=86400),
    public: bool = typer.Option(False, "--public"),
    yes: bool = typer.Option(False, "--yes"),
) -> None:
    state = _ctx(ctx)
    service = ApplicationService(state.settings)
    try:
        request = _request_from_options(state, kind, target, authorization, profile, category, planner_model, target_model, rounds, probes, model_calls, duration, public, yes)
        summary, findings, reports = service.run(
            request,
            event_callback=(None if state.json_output else lambda event: console.print(f"[dim]{event.phase}[/dim] {event.action}: {event.status}")),
        )
    except (ScopeDeniedError, ValueError) as exc:
        console.print(f"[red]Scope denied:[/red] {exc}")
        raise typer.Exit(2) from exc
    _emit({"summary": summary.model_dump(mode="json"), "findings": [f.model_dump(mode="json") for f in findings], "reports": reports}, state.json_output)


@runs_app.command("list")
def runs_list(ctx: typer.Context) -> None:
    state = _ctx(ctx)
    _emit(ApplicationService(state.settings).list_runs(), state.json_output)


@runs_app.command("show")
def runs_show(ctx: typer.Context, run_id: str, artifact: str = typer.Option("summary.json")) -> None:
    state = _ctx(ctx)
    path = ApplicationService(state.settings).run_file(run_id, artifact)
    if path.suffix == ".json":
        _emit(json.loads(path.read_text(encoding="utf-8")), state.json_output)
    else:
        console.print(path.read_text(encoding="utf-8"))


@model_app.command("benchmark")
def model_benchmark(ctx: typer.Context, model: list[str] = typer.Option(..., "--model")) -> None:
    _emit([benchmark_model(name).model_dump(mode="json") for name in model], _ctx(ctx).json_output)


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    state = _ctx(ctx)
    _emit(sanitized_settings(state.settings), state.json_output)


@api_app.command("serve")
def api_serve(ctx: typer.Context) -> None:
    import uvicorn
    from redteam_platform.api import create_app

    state = _ctx(ctx)
    if state.settings.bind_host not in {"127.0.0.1", "::1", "localhost"}:
        console.print("[red]API bind denied: only loopback addresses are accepted.[/red]")
        raise typer.Exit(2)
    uvicorn.run(create_app(state.settings), host=state.settings.bind_host, port=state.settings.api_port)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
