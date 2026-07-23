"""Inventory, model, agent, and service command groups."""

from __future__ import annotations

from typing import Optional

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import (
    data_table,
    details_table,
    emit_envelope,
    emit_json,
    empty,
    format_bytes,
    title,
    warning,
)
from redteam_platform.cli.progress import operation
from redteam_platform.cli.queries import InventoryQuery, validate_confidence
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import (
    AgentDescriptor,
    InventoryItem,
    InventorySnapshot,
    ItemType,
    Listener,
    OllamaModel,
)


def _state(ctx: typer.Context) -> CLIContext:
    return ctx.find_root().obj


def _machine(state: CLIContext, local: bool) -> bool:
    return state.json_output or local


def _snapshot(
    state: CLIContext,
    *,
    refresh: bool = False,
    cached: bool = False,
    include_ollama: bool = True,
    include_listeners: bool = True,
    include_targets: bool = True,
    include_http: bool = True,
    include_docker: bool = False,
    include_kali: bool = False,
    live_ollama: bool = False,
    live_kali: bool = False,
) -> InventorySnapshot:
    settings = state.settings.model_copy(
        update={"ollama_live_check": live_ollama, "kali_live_check": live_kali}
    )
    with operation(state, "Reading local environment…"):
        return InventoryService(settings).collect(
            include_ollama=include_ollama,
            include_listeners=include_listeners,
            include_targets=include_targets,
            include_http=include_http,
            include_docker=include_docker,
            include_kali=include_kali,
            refresh=not cached,
            cached_only=cached,
            force_refresh=refresh,
            persist_cache=(
                include_ollama
                and include_listeners
                and include_targets
                and include_http
            ),
        )


def _summary_data(snapshot: InventorySnapshot) -> dict:
    return {
        "generated_at": snapshot.generated_at,
        "expires_at": snapshot.expires_at,
        "cache_state": "stale" if snapshot.stale else ("cached" if snapshot.cached else "fresh"),
        "stale": snapshot.stale,
        "adapter_success_count": sum(str(run.state) == "success" for run in snapshot.adapter_runs),
        "adapter_failure_count": sum(str(run.state) not in {"success", "skipped"} for run in snapshot.adapter_runs),
        **snapshot.summary.model_dump(mode="json"),
        "tcp_listeners": sum(isinstance(item, Listener) and item.transport == "tcp" for item in snapshot.items),
        "udp_listeners": sum(isinstance(item, Listener) and item.transport == "udp" for item in snapshot.items),
        "typed_errors": [error.model_dump(mode="json") for error in snapshot.errors],
    }


def _render_summary(state: CLIContext, snapshot: InventorySnapshot) -> None:
    data = _summary_data(snapshot)
    title(state, "Environment inventory", f"Snapshot {snapshot.generated_at.isoformat()}")
    state.console.print(
        details_table(
            "Summary",
            [
                ("Cache", data["cache_state"]),
                ("Adapters", f"{data['adapter_success_count']} successful / {data['adapter_failure_count']} limited"),
                ("Installed models", data["installed_ollama_models"]),
                ("Running models", data["running_ollama_models"]),
                ("Enrolled Python targets", data["enrolled_python_targets"]),
                ("Active compatible agents", data["active_compatible_agents"]),
                ("TCP / UDP listeners", f"{data['tcp_listeners']} / {data['udp_listeners']}"),
                ("Wildcard listeners", data["wildcard_bound_services"]),
                ("Docker", data["docker_status"]),
                ("Kali", data["kali_status"]),
                ("Typed errors", data["error_count"]),
            ],
        )
    )
    for error in snapshot.errors:
        warning(state, f"{error.source}/{error.code}: {error.message}")


def _render_agents(state: CLIContext, items: list[AgentDescriptor]) -> None:
    if not items:
        empty(state, "No enrolled or compatible agents were found.")
        return
    state.console.print(
        data_table(
            "AI agents",
            ["Status", "Name", "Type", "Endpoint / path", "Model", "Confidence", "Health", "Last seen", "Stable ID"],
            [
                (
                    item.status,
                    item.name,
                    item.agent_kind or item.item_type,
                    item.endpoint or item.local_path,
                    item.model_name,
                    item.discovery_confidence,
                    item.health,
                    item.last_seen,
                    item.stable_id,
                )
                for item in items
            ],
        )
    )


def _render_models(state: CLIContext, items: list[OllamaModel]) -> None:
    if not items:
        empty(state, "No Ollama models are present in the selected inventory.")
        return
    state.console.print(
        data_table(
            "Ollama models",
            ["Name", "Installed", "Running", "Parameters", "Quantization", "Disk / loaded", "VRAM", "Endpoint", "Last seen"],
            [
                (
                    item.model_name,
                    item.installed,
                    item.running,
                    item.parameter_size,
                    item.quantization,
                    f"{format_bytes(item.size_bytes)} / {format_bytes(item.loaded_size_bytes)}",
                    format_bytes(item.vram_bytes),
                    item.endpoint,
                    item.last_seen,
                )
                for item in items
            ],
        )
    )


def _render_services(state: CLIContext, items: list[InventoryItem]) -> None:
    if not items:
        empty(state, "No services or listeners matched the filters.")
        return
    state.console.print(
        data_table(
            "Services and listeners",
            ["Status", "Address", "Port", "Protocol", "Process", "Type", "Binding", "Agent", "Container", "Stable ID"],
            [
                (
                    item.status,
                    getattr(item, "address", None) or item.host or item.endpoint,
                    item.port,
                    getattr(item, "transport", None) or item.protocol,
                    item.process_name,
                    getattr(item, "service_kind", None) or item.item_type,
                    "wildcard" if getattr(item, "wildcard_bound", False) else ("loopback" if getattr(item, "loopback_only", False) else "specific"),
                    ", ".join(item.related_ids) if item.related_ids else None,
                    getattr(item, "possible_container_id", None),
                    item.stable_id,
                )
                for item in items
            ],
        )
    )


def register(
    root: typer.Typer,
    inventory_app: typer.Typer,
    models_app: typer.Typer,
    agents_app: typer.Typer,
    services_app: typer.Typer,
) -> None:
    root.add_typer(inventory_app, name="inventory")
    root.add_typer(models_app, name="models")
    root.add_typer(agents_app, name="agents")
    root.add_typer(services_app, name="services")

    @inventory_app.callback(invoke_without_command=True)
    def inventory_legacy(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh", help="Force a new passive snapshot."),
        cached: bool = typer.Option(False, "--cached", help="Use cache only, including stale cache."),
        docker: bool = typer.Option(False, "--include-docker", "--docker"),
        kali: bool = typer.Option(False, "--include-kali"),
        live_ollama: bool = typer.Option(False, "--live-ollama"),
        json_output: bool = typer.Option(False, "--json"),
        strict: bool = typer.Option(False, "--strict"),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        state = _state(ctx)
        snapshot = _snapshot(
            state,
            refresh=refresh,
            cached=cached,
            include_docker=docker,
            include_kali=kali,
            live_ollama=live_ollama,
        )
        if _machine(state, json_output):
            emit_json(state, snapshot)
        else:
            _render_summary(state, snapshot)
            _render_services(state, snapshot.items)
        if strict and snapshot.errors:
            raise SystemExit(8)

    @inventory_app.command("refresh", help="Passively refresh local discovery. May contact configured local endpoints.")
    def inventory_refresh(
        ctx: typer.Context,
        docker: bool = typer.Option(False, "--include-docker"),
        kali: bool = typer.Option(False, "--include-kali"),
        live_ollama: bool = typer.Option(False, "--live-ollama"),
        json_output: bool = typer.Option(False, "--json"),
        strict: bool = typer.Option(False, "--strict"),
    ) -> None:
        state = _state(ctx)
        snapshot = _snapshot(
            state,
            refresh=True,
            include_docker=docker,
            include_kali=kali,
            live_ollama=live_ollama,
        )
        if _machine(state, json_output):
            emit_envelope(state, "inventory.refresh", snapshot, errors=snapshot.errors)
        else:
            _render_summary(state, snapshot)
        if strict and snapshot.errors:
            raise SystemExit(8)

    @inventory_app.command("summary", help="Show the latest inventory summary. Passive; no attacks.")
    def inventory_summary(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh"),
        cached: bool = typer.Option(False, "--cached"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, refresh=refresh, cached=cached)
        data = _summary_data(snapshot)
        if _machine(state, json_output):
            emit_envelope(state, "inventory.summary", data, errors=snapshot.errors)
        else:
            _render_summary(state, snapshot)

    @inventory_app.command("show", help="Browse inventory items with reusable filters. Passive.")
    def inventory_show(
        ctx: typer.Context,
        status: Optional[str] = typer.Option(None, "--status"),
        item_type: Optional[str] = typer.Option(None, "--type"),
        port: Optional[int] = typer.Option(None, "--port"),
        protocol: Optional[str] = typer.Option(None, "--protocol"),
        loopback: Optional[bool] = typer.Option(None, "--loopback/--no-loopback"),
        wildcard: Optional[bool] = typer.Option(None, "--wildcard/--no-wildcard"),
        confidence: Optional[str] = typer.Option(None, "--confidence"),
        stale: Optional[bool] = typer.Option(None, "--stale/--fresh"),
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        query = InventoryQuery(
            status=status,
            item_type=item_type,
            port=port,
            protocol=protocol,
            loopback=loopback,
            wildcard=wildcard,
            confidence=validate_confidence(confidence),
            stale=stale,
        )
        snapshot = _snapshot(state, refresh=refresh)
        rows = query.apply(snapshot.items)
        if _machine(state, json_output):
            emit_envelope(state, "inventory.show", rows, errors=snapshot.errors)
        else:
            _render_services(state, rows)

    @models_app.callback(invoke_without_command=True)
    def models_legacy(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh"),
        live: bool = typer.Option(False, "--live"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        state = _state(ctx)
        snapshot = _snapshot(
            state,
            refresh=refresh,
            include_listeners=False,
            include_targets=False,
            include_http=False,
            live_ollama=live,
        )
        rows = [item for item in snapshot.items if isinstance(item, OllamaModel)]
        if _machine(state, json_output):
            emit_json(state, rows)
        else:
            _render_models(state, rows)

    def model_list_impl(
        ctx: typer.Context,
        running: Optional[bool],
        installed: Optional[bool],
        refresh: bool,
        live: bool,
        json_output: bool,
        command: str,
    ) -> None:
        state = _state(ctx)
        snapshot = _snapshot(
            state,
            refresh=refresh,
            include_listeners=False,
            include_targets=False,
            include_http=False,
            live_ollama=live,
        )
        rows = [
            item
            for item in InventoryQuery(running=running, installed=installed).apply(snapshot.items)
            if isinstance(item, OllamaModel)
        ]
        if _machine(state, json_output):
            emit_envelope(state, command, rows, errors=snapshot.errors)
        else:
            _render_models(state, rows)

    @models_app.command("list", help="List installed and running Ollama models. Passive metadata only.")
    def models_list(
        ctx: typer.Context,
        running: Optional[bool] = typer.Option(None, "--running/--not-running"),
        installed: Optional[bool] = typer.Option(None, "--installed/--not-installed"),
        refresh: bool = typer.Option(False, "--refresh"),
        live: bool = typer.Option(False, "--live"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        model_list_impl(ctx, running, installed, refresh, live, json_output, "models.list")

    @models_app.command("running", help="List models currently loaded by Ollama.")
    def models_running(ctx: typer.Context, live: bool = typer.Option(False, "--live"), json_output: bool = typer.Option(False, "--json")) -> None:
        model_list_impl(ctx, True, None, False, live, json_output, "models.running")

    @models_app.command("installed", help="List installed Ollama models.")
    def models_installed(ctx: typer.Context, live: bool = typer.Option(False, "--live"), json_output: bool = typer.Option(False, "--json")) -> None:
        model_list_impl(ctx, None, True, False, live, json_output, "models.installed")

    @models_app.command("show", help="Show one model by stable ID or exact model name.")
    def models_show(ctx: typer.Context, model_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, include_listeners=False, include_targets=False, include_http=False)
        found = next(
            (item for item in snapshot.items if isinstance(item, OllamaModel) and model_id in {item.stable_id, item.model_name}),
            None,
        )
        if not found:
            raise typer.BadParameter(f"Model not found: {model_id}")
        if _machine(state, json_output):
            emit_envelope(state, "models.show", found)
        else:
            state.console.print(details_table("Model", found.model_dump(mode="json").items()))

    @agents_app.callback(invoke_without_command=True)
    def agents_legacy(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        state = _state(ctx)
        snapshot = _snapshot(state, refresh=refresh, include_ollama=False)
        rows = [item for item in snapshot.items if isinstance(item, AgentDescriptor)]
        if _machine(state, json_output):
            emit_json(state, rows)
        else:
            _render_agents(state, rows)

    @agents_app.command("list", help="List confirmed and enrolled AI agents. Passive discovery.")
    def agents_list(
        ctx: typer.Context,
        status: Optional[str] = typer.Option(None, "--status"),
        item_type: Optional[str] = typer.Option(None, "--type"),
        confidence: Optional[str] = typer.Option(None, "--confidence"),
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, refresh=refresh, include_ollama=False)
        rows = [
            item
            for item in InventoryQuery(status=status, item_type=item_type, confidence=validate_confidence(confidence)).apply(snapshot.items)
            if isinstance(item, AgentDescriptor)
        ]
        if _machine(state, json_output):
            emit_envelope(state, "agents.list", rows, errors=snapshot.errors)
        else:
            _render_agents(state, rows)

    @agents_app.command("show", help="Show one enrolled or discovered agent.")
    def agents_show(ctx: typer.Context, agent_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, include_ollama=False)
        found = next(
            (item for item in snapshot.items if isinstance(item, AgentDescriptor) and agent_id in {item.stable_id, item.name}),
            None,
        )
        if not found:
            raise typer.BadParameter(f"Agent not found: {agent_id}")
        if _machine(state, json_output):
            emit_envelope(state, "agents.show", found)
        else:
            state.console.print(details_table("Agent", found.model_dump(mode="json").items()))

    @agents_app.command("health", help="Display health already observed during passive discovery; does not invoke an agent.")
    def agents_health(ctx: typer.Context, agent_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, include_ollama=False)
        found = next(
            (item for item in snapshot.items if isinstance(item, AgentDescriptor) and agent_id in {item.stable_id, item.name}),
            None,
        )
        if not found:
            raise typer.BadParameter(f"Agent not found: {agent_id}")
        data = {"stable_id": found.stable_id, "name": found.name, "health": found.health, "health_details": found.health_details, "last_seen": found.last_seen}
        if _machine(state, json_output):
            emit_envelope(state, "agents.health", data)
        else:
            state.console.print(details_table("Observed health", data.items()))

    @services_app.callback(invoke_without_command=True)
    def services_legacy(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        state = _state(ctx)
        snapshot = _snapshot(state, refresh=refresh, include_ollama=False, include_targets=False)
        rows = [item for item in snapshot.items if item.item_type in {ItemType.LISTENER, ItemType.SERVICE}]
        if _machine(state, json_output):
            emit_json(state, rows)
        else:
            _render_services(state, rows)

    @services_app.command("list", help="List local listeners and compatible services. Passive.")
    def services_list(
        ctx: typer.Context,
        port: Optional[int] = typer.Option(None, "--port"),
        protocol: Optional[str] = typer.Option(None, "--protocol"),
        loopback: Optional[bool] = typer.Option(None, "--loopback/--no-loopback"),
        wildcard: Optional[bool] = typer.Option(None, "--wildcard/--no-wildcard"),
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, refresh=refresh, include_ollama=False, include_targets=False)
        rows = [
            item
            for item in InventoryQuery(port=port, protocol=protocol, loopback=loopback, wildcard=wildcard).apply(snapshot.items)
            if item.item_type in {ItemType.LISTENER, ItemType.SERVICE}
        ]
        if _machine(state, json_output):
            emit_envelope(state, "services.list", rows, errors=snapshot.errors)
        else:
            _render_services(state, rows)

    @services_app.command("listeners", help="List listening TCP/UDP sockets without probing them.")
    def services_listeners(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, include_ollama=False, include_targets=False, include_http=False)
        rows = [item for item in snapshot.items if isinstance(item, Listener)]
        if _machine(state, json_output):
            emit_envelope(state, "services.listeners", rows, errors=snapshot.errors)
        else:
            _render_services(state, rows)

    @services_app.command("show", help="Show one service or listener by stable ID.")
    def services_show(ctx: typer.Context, service_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
        state = _state(ctx)
        snapshot = _snapshot(state, include_ollama=False, include_targets=False)
        found = next(
            (
                item
                for item in snapshot.items
                if item.item_type in {ItemType.LISTENER, ItemType.SERVICE}
                and service_id in {item.stable_id, item.name}
            ),
            None,
        )
        if not found:
            raise typer.BadParameter(f"Service not found: {service_id}")
        if _machine(state, json_output):
            emit_envelope(state, "services.show", found)
        else:
            state.console.print(details_table("Service", found.model_dump(mode="json").items()))
