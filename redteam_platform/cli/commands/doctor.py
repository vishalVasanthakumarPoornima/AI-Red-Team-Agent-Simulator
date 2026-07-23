"""Doctor command presentation."""

from __future__ import annotations

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, emit_envelope, title
from redteam_platform.diagnostics import DoctorService


def register(root: typer.Typer) -> None:
    @root.command("doctor", help="Diagnose the local CLI without running attacks or contacting public systems.")
    def doctor(
        ctx: typer.Context,
        live: bool = typer.Option(False, "--live", help="Opt into bounded configured-local readiness checks."),
        strict: bool = typer.Option(False, "--strict", help="Treat warnings as a partial failure."),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state: CLIContext = ctx.find_root().obj
        results = DoctorService(state.settings).run(live=live)
        failed = any(item.status == "FAIL" for item in results)
        warned = any(item.status == "WARN" for item in results)
        if state.json_output or json_output:
            emit_envelope(
                state,
                "doctor",
                [item.dump() for item in results],
                success=not failed and not (strict and warned),
            )
        else:
            title(state, "Diagnostics", "No attacks; live integration checks require --live")
            state.console.print(
                data_table(
                    "System checks",
                    ["Status", "Check", "Explanation", "Suggested remediation"],
                    [(item.status, item.name, item.explanation, item.remediation) for item in results],
                )
            )
        if failed:
            raise SystemExit(3)
        if strict and warned:
            raise SystemExit(8)
