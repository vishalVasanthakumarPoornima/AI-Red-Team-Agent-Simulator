"""Reusable Rich presentation and stable JSON envelopes."""

from __future__ import annotations

import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel
from rich import box
from rich.panel import Panel
from rich.table import Table

from redteam_platform.artifacts import sanitize
from redteam_platform.cli.context import CLIContext
from redteam_platform.schemas import SCHEMA_VERSION


STYLES = {
    "success": "green",
    "warning": "yellow",
    "failure": "red",
    "info": "cyan",
    "passive": "blue",
    "active": "magenta",
    "denied": "bold red",
    "confirmed": "bold green",
    "inferred": "yellow",
}


def jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): jsonable(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(item) for item in value]
    return value


def envelope(
    command: str,
    data: Any = None,
    *,
    success: bool = True,
    warnings: Iterable[Any] = (),
    errors: Iterable[Any] = (),
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "success": success,
        "data": sanitize(jsonable(data)),
        "warnings": sanitize(jsonable(list(warnings))),
        "errors": sanitize(jsonable(list(errors))),
    }


def emit_json(state: CLIContext, payload: Any) -> None:
    # Rich deliberately wraps long output for terminals. Machine output must not
    # be wrapped because a newline inserted inside a JSON string is invalid JSON.
    state.console.file.write(
        json.dumps(sanitize(jsonable(payload)), separators=(",", ":"), ensure_ascii=False)
        + "\n"
    )
    state.console.file.flush()


def emit_envelope(
    state: CLIContext,
    command: str,
    data: Any = None,
    *,
    warnings: Iterable[Any] = (),
    errors: Iterable[Any] = (),
    success: bool = True,
) -> None:
    emit_json(
        state,
        envelope(
            command,
            data,
            success=success,
            warnings=warnings,
            errors=errors,
        ),
    )


def title(state: CLIContext, text: str, subtitle: str | None = None) -> None:
    body = f"[bold]{text}[/bold]"
    if subtitle:
        body += f"\n[dim]{subtitle}[/dim]"
    state.console.print(Panel(body, border_style="cyan", padding=(0, 1)))


def warning(state: CLIContext, message: str) -> None:
    state.console.print(Panel(message, title="Warning", border_style=STYLES["warning"]))


def error_panel(state: CLIContext, message: str, remediation: str = "") -> None:
    body = message + (f"\n\n[dim]Next: {remediation}[/dim]" if remediation else "")
    state.error_console.print(Panel(body, title="Error", border_style=STYLES["failure"]))


def empty(state: CLIContext, message: str) -> None:
    state.console.print(Panel(message, border_style="dim", title="No results"))


def details_table(title_text: str, rows: Iterable[tuple[str, Any]]) -> Table:
    table = Table(title=title_text, box=box.SIMPLE, show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value", overflow="fold")
    for key, value in rows:
        table.add_row(str(key), _display(value))
    return table


def data_table(title_text: str, columns: list[str], rows: Iterable[Iterable[Any]]) -> Table:
    table = Table(title=title_text, box=box.ROUNDED, header_style="bold cyan")
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*(_display(value) for value in row))
    return table


def _display(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(jsonable(value), ensure_ascii=False)
    return str(value)


def format_bytes(value: int | None) -> str:
    if value is None:
        return "—"
    number = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if number < 1024 or unit == "TiB":
            return f"{number:.1f} {unit}"
        number /= 1024
    return str(value)
