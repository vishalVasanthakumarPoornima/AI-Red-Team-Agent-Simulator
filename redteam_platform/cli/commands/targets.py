"""Typed target parsing, resolution, inspection, and health commands."""

from __future__ import annotations

import typer

from redteam_platform.assessments import UnifiedAssessmentService
from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import AgentDescriptor, ItemType
from redteam_platform.targets.models import ResolutionState, TargetKind

KIND_ALIASES = {
    "python": TargetKind.PYTHON_AGENT,
    "http": TargetKind.HTTP_AGENT,
    "openai": TargetKind.OPENAI_COMPATIBLE,
    "ollama": TargetKind.OLLAMA_ENDPOINT,
    "ip": TargetKind.IP_ADDRESS,
    "web": TargetKind.WEB_APPLICATION,
    "service": TargetKind.LOCAL_SERVICE,
}
KIND_HELP = (
    "Target kind. Friendly aliases: python, http, openai, ollama, ip, web, service. "
    "Canonical values such as python_agent and web_application are also accepted."
)


def _state(ctx: typer.Context) -> CLIContext:
    return ctx.find_root().obj


def _service(ctx: typer.Context) -> UnifiedAssessmentService:
    return UnifiedAssessmentService(_state(ctx).settings)


def _kind(value: str | None):
    if not value:
        return None
    normalized = value.strip().lower().replace("-", "_")
    if normalized in KIND_ALIASES:
        return KIND_ALIASES[normalized]
    try:
        return TargetKind(normalized)
    except ValueError as exc:
        aliases = ", ".join(sorted(KIND_ALIASES))
        canonical = ", ".join(item.value for item in TargetKind if item != TargetKind.UNKNOWN)
        raise typer.BadParameter(
            f"Unsupported target kind '{value}'. Aliases: {aliases}. Canonical values: {canonical}.",
            param_hint="--kind",
        ) from exc


def register(root: typer.Typer, targets_app: typer.Typer) -> None:
    root.add_typer(targets_app, name="targets")

    @targets_app.callback(invoke_without_command=True)
    def targets_root(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        state = _state(ctx)
        state.json_output = state.json_output or json_output
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
            if isinstance(item, AgentDescriptor)
            and item.item_type == ItemType.PYTHON_TARGET
        ]
        if state.json_output:
            emit_envelope(state, "targets", rows)
        else:
            state.console.print(
                data_table(
                    "Enrolled Python targets",
                    ["Stable ID", "Name", "Path", "Health"],
                    [(row.stable_id, row.name, row.local_path, row.health) for row in rows],
                )
            )

    @targets_app.command("parse", help="Parse and normalize a target without network access.")
    def parse(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        kind: str | None = typer.Option(None, "--kind", help=KIND_HELP),
        model: str | None = typer.Option(None, "--model"),
        port: list[int] | None = typer.Option(None, "--port"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        parsed = _service(ctx).parse(
            target, kind_hint=_kind(kind), model_name=model, ports=port
        )
        if state.json_output:
            emit_envelope(state, "targets.parse", parsed)
        else:
            state.console.print(details_table("Parsed target", parsed.model_dump(mode="json").items()))

    def resolve_value(ctx, target, kind, model, ports, refresh):
        return _service(ctx).resolve(
            target,
            kind_hint=_kind(kind),
            model_name=model,
            ports=ports,
            refresh=refresh,
        )

    @targets_app.command("resolve", help="Resolve a target against Phase 2 inventory and configuration.")
    def resolve(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        kind: str | None = typer.Option(None, "--kind", help=KIND_HELP),
        model: str | None = typer.Option(None, "--model"),
        port: list[int] | None = typer.Option(None, "--port"),
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        result = resolve_value(ctx, target, kind, model, port, refresh)
        if state.json_output:
            emit_envelope(
                state,
                "targets.resolve",
                result,
                success=result.state == ResolutionState.RESOLVED,
                warnings=[] if result.state == ResolutionState.RESOLVED else [result.explanation],
            )
        else:
            state.console.print(details_table("Target resolution", result.model_dump(mode="json").items()))

    @targets_app.command("show", help="Show the fully resolved typed target.")
    def show(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        kind: str | None = typer.Option(None, "--kind", help=KIND_HELP),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        descriptor = _service(ctx).require_target(target, kind_hint=_kind(kind))
        if state.json_output:
            emit_envelope(state, "targets.show", descriptor)
        else:
            state.console.print(details_table("Resolved target", descriptor.model_dump(mode="json").items()))

    @targets_app.command("capabilities", help="Show resolved target and adapter capabilities.")
    def capabilities(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        kind: str | None = typer.Option(None, "--kind", help=KIND_HELP),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        service = _service(ctx)
        descriptor = service.require_target(target, kind_hint=_kind(kind))
        adapter = service.registry.resolve(descriptor)
        payload = {"target": descriptor, "adapter": adapter}
        if state.json_output:
            emit_envelope(state, "targets.capabilities", payload)
        else:
            state.console.print(details_table("Adapter", adapter.model_dump(mode="json").items()))
            state.console.print(
                data_table(
                    "Capabilities",
                    ["Name", "Available", "Passive", "Active", "Source"],
                    [
                        (item.name, item.available, item.passive, item.active, item.source)
                        for item in descriptor.capabilities
                    ],
                )
            )

    @targets_app.command("health", help="Show inventory-derived health without active probes.")
    def health(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        kind: str | None = typer.Option(None, "--kind", help=KIND_HELP),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        result = _service(ctx).health(target, kind_hint=_kind(kind))
        if state.json_output:
            emit_envelope(state, "targets.health", result)
        else:
            state.console.print(details_table("Target health", result.model_dump(mode="json").items()))
