"""Cached and explicitly live Kali readiness presentation."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import typer

from redteam_platform.artifacts import sanitize
from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope, emit_json, empty, title, warning
from redteam_platform.inventory.kali import KaliDiscovery
from redteam_platform.inventory.models import DiscoveryError, KaliReadiness
from redteam_platform.schemas import SCHEMA_VERSION, utc_now


def _readiness_cache_path(state: CLIContext) -> Path:
    return Path(state.settings.inventory_cache).with_name("kali-readiness.json")


def _write_readiness_cache(
    state: CLIContext,
    rows: list[KaliReadiness],
    errors: list[DiscoveryError],
) -> None:
    path = _readiness_cache_path(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = sanitize(
        {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "rows": [row.model_dump(mode="json") for row in rows],
            "errors": [error.model_dump(mode="json") for error in errors],
        }
    )
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
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_readiness_cache(
    state: CLIContext,
) -> tuple[list[KaliReadiness], list[DiscoveryError]] | None:
    configured_alias = state.settings.kali_ssh_host
    if not configured_alias:
        return None
    path = _readiness_cache_path(state)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != SCHEMA_VERSION:
            return None
        rows = [
            KaliReadiness.model_validate(row) for row in payload.get("rows", [])
        ]
        if not rows or any(row.ssh_alias != configured_alias for row in rows):
            return None
        return (
            rows,
            [DiscoveryError.model_validate(error) for error in payload.get("errors", [])],
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _collect(state: CLIContext, live: bool) -> tuple[list[KaliReadiness], list]:
    if not live:
        cached = _read_readiness_cache(state)
        if cached is not None:
            return cached
    settings = state.settings.model_copy(
        update={"include_kali_readiness": True, "kali_live_check": live}
    )
    rows, errors = KaliDiscovery(settings).collect(live=live)
    if live:
        _write_readiness_cache(state, rows, errors)
    return rows, errors


def _render(state: CLIContext, rows: list[KaliReadiness], errors: list) -> None:
    title(state, "Kali readiness", "Readiness only; no scan, tunnel, or arbitrary command")
    if not rows:
        empty(state, "Kali is not present in the inventory. Configure an allowlisted SSH alias.")
    for row in rows:
        data = {
            "configured": row.configured,
            "ssh_binary": shutil.which("ssh") or "not found",
            "alias": row.ssh_alias or "not configured",
            "reachable": row.reachable if row.live_check_performed else "not checked",
            "operating_system": row.os_identity,
            "live_check_performed": row.live_check_performed,
            "timeout_seconds": state.settings.kali_readiness_timeout,
            "reverse_tunnel_capability": row.reverse_tunnel_capability,
            "errors": [error.message for error in row.errors],
        }
        state.console.print(details_table(row.name, data.items()))
        if row.tools:
            state.console.print(
                data_table(
                    "Fixed readiness tool inventory",
                    ["Tool", "State", "Version", "Evidence"],
                    [(tool.name, tool.state, tool.version, tool.evidence) for tool in row.tools],
                )
            )
    for error in errors:
        warning(state, f"{error.code}: {error.message}")


def register(root: typer.Typer, kali_app: typer.Typer) -> None:
    root.add_typer(kali_app, name="kali")

    @kali_app.command("status", help="Show cached/configuration-only Kali readiness by default.")
    def status(
        ctx: typer.Context,
        live: bool = typer.Option(False, "--live", help="Run the fixed, bounded SSH readiness script."),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state: CLIContext = ctx.find_root().obj
        rows, errors = _collect(state, live)
        if state.json_output or json_output:
            emit_envelope(state, "kali.status", rows, errors=errors)
        else:
            _render(state, rows, errors)

    @kali_app.command("tools", help="Show tool availability from cached readiness data.")
    def tools(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
        state: CLIContext = ctx.find_root().obj
        rows, errors = _collect(state, False)
        data = [
            {"readiness_id": row.stable_id, "tools": row.tools}
            for row in rows
        ]
        if state.json_output or json_output:
            emit_envelope(state, "kali.tools", data, errors=errors)
        else:
            _render(state, rows, errors)

    @kali_app.command("check", help="Run a fixed Kali readiness check only when --live is supplied.")
    def check(
        ctx: typer.Context,
        live: bool = typer.Option(False, "--live", help="Required explicit opt-in."),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        if not live:
            raise typer.BadParameter("Kali check requires explicit --live opt-in.")
        state: CLIContext = ctx.find_root().obj
        rows, errors = _collect(state, True)
        if state.json_output or json_output:
            emit_envelope(state, "kali.check", rows, errors=errors)
        else:
            _render(state, rows, errors)

    @root.command("kali-status", help="Compatibility alias for `kali status`.")
    def legacy_status(
        ctx: typer.Context,
        live: bool = typer.Option(False, "--live"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state: CLIContext = ctx.find_root().obj
        rows, errors = _collect(state, live)
        if state.json_output or json_output:
            emit_json(state, rows)
        else:
            _render(state, rows, errors)
