"""Prompt helpers that fail closed outside interactive use."""

from __future__ import annotations

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.errors import NonInteractivePromptError


def require_interactive(state: CLIContext) -> None:
    if state.non_interactive:
        raise NonInteractivePromptError()


def text(state: CLIContext, label: str, *, default: str | None = None, hide: bool = False) -> str:
    require_interactive(state)
    return typer.prompt(label, default=default, hide_input=hide)


def confirm(
    state: CLIContext,
    message: str,
    *,
    default: bool = False,
    allow_yes: bool = True,
) -> bool:
    if allow_yes and state.assume_yes:
        return True
    require_interactive(state)
    return typer.confirm(message, default=default)


def select_number(
    state: CLIContext,
    label: str,
    valid: set[str],
    *,
    default: str | None = None,
) -> str:
    while True:
        value = text(state, label, default=default).strip()
        if value in valid:
            return value
        state.error_console.print(
            f"[yellow]Choose one of: {', '.join(sorted(valid))}.[/yellow]"
        )
