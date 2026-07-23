"""Configuration inspection, validation, and path reporting."""

from __future__ import annotations

import os
from pathlib import Path

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope, title
from redteam_platform.diagnostics import configuration_validation
from redteam_platform.settings import ENV_FIELD_MAP, sanitized_settings


def _sources(state: CLIContext) -> dict[str, str]:
    sources: dict[str, str] = {}
    environment_fields = {
        field
        for variable, field in ENV_FIELD_MAP.items()
        if variable in os.environ
    }
    for key in sanitized_settings(state.settings):
        if key in environment_fields:
            sources[key] = "environment"
        elif state.config_path and state.config_path.exists():
            sources[key] = "config/default"
        else:
            sources[key] = "default"
    return sources


def register(root: typer.Typer, config_app: typer.Typer) -> None:
    root.add_typer(config_app, name="config")

    @config_app.command("show", help="Show effective non-secret typed settings. Offline.")
    def show(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
        state: CLIContext = ctx.find_root().obj
        values = sanitized_settings(state.settings)
        data = {"values": values, "sources": _sources(state)}
        if state.json_output or json_output:
            emit_envelope(state, "config.show", data)
        else:
            title(state, "Effective configuration", "Secrets and key paths are redacted")
            state.console.print(
                data_table(
                    "Settings",
                    ["Setting", "Value", "Source"],
                    [(key, value, data["sources"][key]) for key, value in values.items()],
                )
            )

    @config_app.command("validate", help="Validate typed settings and configured paths without network access.")
    def validate(
        ctx: typer.Context,
        strict: bool = typer.Option(False, "--strict"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state: CLIContext = ctx.find_root().obj
        results = configuration_validation(state.settings)
        failed = any(item.status == "FAIL" for item in results)
        warned = any(item.status == "WARN" for item in results)
        if state.json_output or json_output:
            emit_envelope(state, "config.validate", [item.dump() for item in results], success=not failed)
        else:
            title(state, "Configuration validation", "Offline; no integrations contacted")
            state.console.print(
                data_table(
                    "Checks",
                    ["Status", "Check", "Explanation", "Remediation"],
                    [(item.status, item.name, item.explanation, item.remediation) for item in results],
                )
            )
        if failed:
            raise SystemExit(3)
        if strict and warned:
            raise SystemExit(8)

    @config_app.command("paths", help="Show configuration, cache, reports, log, and environment-file paths.")
    def paths(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
        state: CLIContext = ctx.find_root().obj
        rows = []
        for name, path in (
            ("config", state.config_path or state.settings.user_config),
            ("cache", state.settings.inventory_cache),
            ("reports", state.settings.report_root),
            ("log", state.settings.report_root / "redteam.log"),
            ("environment", state.env_file or Path(".env")),
        ):
            target = Path(path).expanduser()
            parent = target if target.is_dir() else target.parent
            rows.append(
                {
                    "name": name,
                    "path": str(target),
                    "exists": target.exists(),
                    "writable": parent.exists() and os.access(parent, os.W_OK),
                }
            )
        if state.json_output or json_output:
            emit_envelope(state, "config.paths", rows)
        else:
            title(state, "Application paths")
            state.console.print(
                data_table(
                    "Paths",
                    ["Name", "Path", "Exists", "Writable"],
                    [(row["name"], row["path"], row["exists"], row["writable"]) for row in rows],
                )
            )
