"""Top-level Typer application assembly and process boundary."""

from __future__ import annotations

import json
import secrets
import sys
import traceback
from pathlib import Path

import typer
import typer._click as click
from typer.core import TyperGroup

from redteam_platform import __version__
from redteam_platform.artifacts import sanitize
from redteam_platform.benchmark import benchmark_model
from redteam_platform.cli.commands import adaptive as adaptive_commands
from redteam_platform.cli.commands import assess as assess_commands
from redteam_platform.cli.commands import config as config_commands
from redteam_platform.cli.commands import dexter as dexter_commands
from redteam_platform.cli.commands import doctor as doctor_commands
from redteam_platform.cli.commands import help as help_commands
from redteam_platform.cli.commands import inventory as inventory_commands
from redteam_platform.cli.commands import kali as kali_commands
from redteam_platform.cli.commands import menu as menu_commands
from redteam_platform.cli.commands import model_benchmark as model_benchmark_commands
from redteam_platform.cli.commands import runs as runs_commands
from redteam_platform.cli.commands import scope as scope_commands
from redteam_platform.cli.commands import targets as targets_commands
from redteam_platform.cli.context import CLIContext, build_context
from redteam_platform.cli.errors import CLIError, normalize_error
from redteam_platform.cli.examples import apply_help_epilogs
from redteam_platform.cli.exit_codes import ExitCode
from redteam_platform.cli.formatting import emit_json, error_panel


class SafeTyperGroup(TyperGroup):
    """Convert expected domain failures into stable, traceback-free exits."""

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except click.exceptions.Exit:
            raise
        except click.ClickException:
            raise
        except (KeyboardInterrupt, EOFError) as exc:
            raise click.exceptions.Exit(ExitCode.INTERRUPTED) from exc
        except BrokenPipeError as exc:
            raise click.exceptions.Exit(ExitCode.SUCCESS) from exc
        except Exception as exc:
            error = normalize_error(exc)
            remediation = error.remediation or "Review the command input and local configuration."
            remediation = (
                f"{remediation.rstrip()} Run `redteam help COMMAND` or "
                "`redteam COMMAND --help` for usage."
            )
            state = ctx.find_root().obj
            if isinstance(state, CLIContext):
                if state.json_output:
                    emit_json(
                        state,
                        {
                            "schema_version": "1.0",
                            "command": ctx.command_path.replace(" ", "."),
                            "success": False,
                            "data": None,
                            "warnings": [],
                            "errors": [
                                {
                                    "type": error.error_type,
                                    "message": str(sanitize(error.message)),
                                    "remediation": remediation,
                                }
                            ],
                        },
                    )
                else:
                    error_panel(state, str(sanitize(error.message)), remediation)
                    if state.debug:
                        state.error_console.print(
                            str(sanitize("".join(traceback.format_exception(exc))))
                        )
            else:
                if bool(ctx.params.get("json_output")):
                    sys.stdout.write(
                        json.dumps(
                            {
                                "schema_version": "1.0",
                                "command": ctx.command_path.replace(" ", "."),
                                "success": False,
                                "data": None,
                                "warnings": [],
                                "errors": [
                                    {
                                        "type": error.error_type,
                                        "message": str(sanitize(error.message)),
                                        "remediation": remediation,
                                    }
                                ],
                            },
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                else:
                    click.echo(
                        f"Error: {sanitize(error.message)}\nNext: {remediation}",
                        err=True,
                    )
            raise SystemExit(int(error.code)) from exc


CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 120}
app = typer.Typer(
    cls=SafeTyperGroup,
    context_settings=CONTEXT_SETTINGS,
    invoke_without_command=True,
    no_args_is_help=False,
    rich_markup_mode="rich",
    help="Authorized local-first AI agent red-team platform. No command weakens scope policy.",
)

inventory_app = typer.Typer(help="Browse and refresh passive environment inventory.", invoke_without_command=True)
models_app = typer.Typer(help="Browse installed and running local models.", invoke_without_command=True)
agents_app = typer.Typer(help="Browse enrolled and compatible AI agents.", invoke_without_command=True)
services_app = typer.Typer(help="Browse listening services and ports.", invoke_without_command=True)
targets_app = typer.Typer(help="Parse, resolve, inspect, and health-check typed targets.", invoke_without_command=True)
assess_app = typer.Typer(help="Plan or run bounded authorized assessments.", invoke_without_command=True)
dexter_app = typer.Typer(help="Discover, inspect, plan, and assess Dexter deployments.", invoke_without_command=True)
runs_app = typer.Typer(help="Browse persisted run artifacts.")
reports_app = typer.Typer(help="Build, verify, compare, retest, and export enterprise reports.")
kali_app = typer.Typer(help="Inspect Kali readiness without scanning targets.")
scope_app = typer.Typer(help="Inspect and validate scope policy.")
config_app = typer.Typer(help="Inspect and validate non-secret configuration.")
adaptive_app = typer.Typer(
    help="Plan, run, resume, and stop bounded adaptive assessments.",
    invoke_without_command=True,
)

inventory_commands.register(app, inventory_app, models_app, agents_app, services_app)
model_benchmark_commands.register(models_app)
adaptive_commands.register(app, adaptive_app)
targets_commands.register(app, targets_app)
assess_commands.register(app, assess_app)
dexter_commands.register(app, dexter_app)
runs_commands.register(app, runs_app, reports_app)
kali_commands.register(app, kali_app)
scope_commands.register(app, scope_app)
config_commands.register(app, config_app)
doctor_commands.register(app)
help_commands.register(app)
menu_commands.register(app)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    config: Path | None = typer.Option(None, "--config", help="TOML configuration file."),
    env_file: Path | None = typer.Option(None, "--env-file", help="Environment file; defaults to .env."),
    json_output: bool = typer.Option(False, "--json", help="Emit only machine-readable JSON to stdout."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color."),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress nonessential human output."),
    verbose: bool = typer.Option(False, "--verbose", help="Show additional safe operational detail."),
    debug: bool = typer.Option(False, "--debug", help="Show sanitized tracebacks for unexpected errors."),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Reject missing prompt input."),
    yes: bool = typer.Option(False, "--yes", help="Confirm eligible UI prompts; never supplies authorization."),
    profile: str | None = typer.Option(None, "--profile", help="Named configuration profile metadata."),
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."),
) -> None:
    if quiet and verbose:
        raise typer.BadParameter("--quiet and --verbose cannot be combined.")
    state = build_context(
        config_path=config,
        env_file=env_file,
        json_output=json_output,
        no_color=no_color,
        quiet=quiet,
        verbose=verbose,
        debug=debug,
        non_interactive=non_interactive,
        assume_yes=yes,
        profile=profile,
    )
    ctx.obj = state
    if ctx.invoked_subcommand is None:
        if state.interactive:
            from redteam_platform.cli.commands.menu import interactive_menu

            interactive_menu(state)
        else:
            state.console.print(ctx.get_help())


@app.command("version", help="Show the installed application version.")
def version_command(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
    state: CLIContext = ctx.find_root().obj
    if state.json_output or json_output:
        emit_json(
            state,
            {
                "schema_version": "1.0",
                "command": "version",
                "success": True,
                "data": {"version": __version__},
                "warnings": [],
                "errors": [],
            },
        )
    else:
        state.console.print(__version__)


@app.command("init", help="Create a protected starter config; refuses overwrite.")
def init_config(
    ctx: typer.Context,
    destination: Path = typer.Option(Path("redteam.toml"), "--destination"),
) -> None:
    state: CLIContext = ctx.find_root().obj
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite {destination}")
    token = secrets.token_urlsafe(32)
    content = (
        "[redteam]\n"
        'bind_host = "127.0.0.1"\n'
        "api_port = 18150\n"
        'report_root = "reports/runs"\n'
        'allowed_cidrs = ["127.0.0.0/8", "::1/128"]\n'
        "allowed_domains = []\n"
        "allow_public = false\n"
        f'api_token = "{token}"\n'
    )
    destination.write_text(content, encoding="utf-8")
    destination.chmod(0o600)
    if state.json_output:
        emit_json(state, {"created": str(destination), "mode": "0600"})
    else:
        state.console.print(f"Created {destination} with mode 0600.")


model_app = typer.Typer(help="Compatibility model utilities.")
app.add_typer(model_app, name="model")


@model_app.command("benchmark", help="Benchmark explicitly named local models.")
def model_benchmark(ctx: typer.Context, model: list[str] = typer.Option(..., "--model")) -> None:
    state: CLIContext = ctx.find_root().obj
    rows = [benchmark_model(name).model_dump(mode="json") for name in model]
    if state.json_output:
        emit_json(state, rows)
    else:
        state.console.print_json(data=rows)


api_app = typer.Typer(help="Optional authenticated loopback API.")
app.add_typer(api_app, name="api")


@api_app.command("serve", help="Serve the authenticated API on loopback only.")
def api_serve(ctx: typer.Context) -> None:
    import uvicorn

    from redteam_platform.api import create_app

    state: CLIContext = ctx.find_root().obj
    if state.settings.bind_host not in {"127.0.0.1", "::1", "localhost"}:
        raise CLIError(
            "API bind denied: only loopback addresses are accepted.",
            ExitCode.SCOPE_OR_AUTHORIZATION_DENIED,
            "api_bind_denied",
        )
    uvicorn.run(
        create_app(state.settings),
        host=state.settings.bind_host,
        port=state.settings.api_port,
    )


apply_help_epilogs(app)


def _propagate_exit_code(result: object) -> None:
    """Preserve nonzero ``typer.Exit`` codes in console-script mode."""

    if isinstance(result, int) and result != int(ExitCode.SUCCESS):
        raise SystemExit(result)


def main() -> None:
    try:
        result = app(standalone_mode=False)
        _propagate_exit_code(result)
    except click.ClickException as exc:
        exc.show()
        raise SystemExit(exc.exit_code) from exc
    except click.exceptions.Exit as exc:
        raise SystemExit(exc.exit_code) from exc
    except click.exceptions.Abort as exc:
        raise SystemExit(ExitCode.INTERRUPTED) from exc
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            raise SystemExit(ExitCode.SUCCESS)


if __name__ == "__main__":
    main()
