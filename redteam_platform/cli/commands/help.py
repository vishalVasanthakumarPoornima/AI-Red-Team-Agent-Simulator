"""Generic command help plus short onboarding and safety topics."""

from __future__ import annotations

import typer
import typer._click as click
from rich.markdown import Markdown

from redteam_platform.cli.context import CLIContext

TOPICS = {
    "getting-started": """# Getting started
1. Run `redteam config validate`.
2. Run `redteam inventory refresh`.
3. Browse `redteam agents list`.
4. Use `redteam assess start` only for a target you own or are authorized to test.
""",
    "authorization": """# Authorization
Every active assessment requires a human-written statement tied to the exact normalized target.
`--yes` confirms a reviewed low-risk UI step; it never supplies or bypasses authorization.
""",
    "inventory": """# Inventory
Inventory is passive discovery. A refresh reads local process/listener state and may make bounded
metadata requests only to configured local endpoints. Docker and Kali are opt-in.
""",
    "assessments": """# Assessments
Phase 3 launches only registered assessment adapters and probe categories. Scope is validated
before execution, the target and budgets are shown, and cancellation before confirmation has no side effects.
""",
}


def _command_help(ctx: typer.Context, path: list[str]) -> str:
    current_command = ctx.find_root().command
    current_context = click.Context(current_command, info_name="redteam")
    resolved: list[str] = []
    for part in path:
        get_command = getattr(current_command, "get_command", None)
        if not callable(get_command):
            command_name = " ".join(("redteam", *resolved))
            raise click.exceptions.UsageError(
                f"'{command_name}' has no subcommand '{part}'. "
                f"Run '{command_name} --help'."
            )
        next_command = get_command(current_context, part)
        if next_command is None:
            attempted = " ".join(path)
            raise click.exceptions.UsageError(
                f"No such command path '{attempted}'. Run 'redteam help' to list topics "
                "or 'redteam --help' to list commands."
            )
        resolved.append(part)
        current_command = next_command
        current_context = click.Context(
            current_command,
            info_name=part,
            parent=current_context,
            color=current_context.color,
        )
    return current_command.get_help(current_context)


def register(root: typer.Typer) -> None:
    @root.command(
        "help",
        help="Show onboarding guidance or help for any command path.",
    )
    def help_command(
        ctx: typer.Context,
        command: list[str] = typer.Argument(
            None,
            metavar="[COMMAND]...",
            help="Command path or onboarding topic, for example 'assess run'.",
        ),
    ) -> None:
        state: CLIContext = ctx.find_root().obj
        path = list(command or [])
        if not path:
            state.console.print(Markdown(TOPICS["getting-started"]))
            state.console.print("Topics: getting-started, authorization, inventory, assessments")
            state.console.print("Command help: redteam help COMMAND [SUBCOMMAND]")
            return
        if len(path) == 1 and path[0] in TOPICS:
            state.console.print(Markdown(TOPICS[path[0]]))
            return
        state.console.print(_command_help(ctx, path))
