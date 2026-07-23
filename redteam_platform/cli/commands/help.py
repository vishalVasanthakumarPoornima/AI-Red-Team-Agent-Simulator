"""Short onboarding and safety help topics."""

from __future__ import annotations

import typer
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


def register(root: typer.Typer, help_app: typer.Typer) -> None:
    root.add_typer(help_app, name="help")

    @help_app.callback(invoke_without_command=True)
    def help_root(ctx: typer.Context) -> None:
        if ctx.invoked_subcommand is not None:
            return
        state: CLIContext = ctx.find_root().obj
        state.console.print(Markdown(TOPICS["getting-started"]))
        state.console.print("Topics: getting-started, authorization, inventory, assessments")

    def topic_command(content: str):
        def command(ctx: typer.Context) -> None:
            state: CLIContext = ctx.find_root().obj
            state.console.print(Markdown(content))

        return command

    for topic, content in TOPICS.items():
        help_app.command(topic, help=f"Read {topic} guidance.")(
            topic_command(content)
        )
