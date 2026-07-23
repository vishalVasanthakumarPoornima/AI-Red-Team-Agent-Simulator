"""Progress presentation kept separate from execution services."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from rich.progress import Progress, SpinnerColumn, TextColumn

from redteam_platform.cli.context import CLIContext


@contextmanager
def operation(state: CLIContext, description: str) -> Iterator[None]:
    if state.json_output or state.quiet:
        yield
        return
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=state.console,
        transient=True,
    ) as progress:
        progress.add_task(description, total=None)
        yield
