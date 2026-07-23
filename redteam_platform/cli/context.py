"""Global CLI state and safe console construction."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from redteam_platform.settings import Settings, load_settings


@dataclass
class CLIContext:
    settings: Settings
    console: Console
    error_console: Console
    config_path: Path | None = None
    env_file: Path | None = None
    json_output: bool = False
    no_color: bool = False
    quiet: bool = False
    verbose: bool = False
    debug: bool = False
    non_interactive: bool = False
    assume_yes: bool = False
    profile: str | None = None

    @property
    def interactive(self) -> bool:
        return (
            not self.non_interactive
            and bool(getattr(sys.stdin, "isatty", lambda: False)())
            and bool(getattr(sys.stdout, "isatty", lambda: False)())
        )


def build_context(
    *,
    config_path: Path | None,
    env_file: Path | None,
    json_output: bool,
    no_color: bool,
    quiet: bool,
    verbose: bool,
    debug: bool,
    non_interactive: bool,
    assume_yes: bool,
    profile: str | None,
) -> CLIContext:
    color_disabled = no_color or "NO_COLOR" in os.environ or json_output
    settings = load_settings(config_path, env_file=env_file)
    return CLIContext(
        settings=settings,
        console=Console(
            no_color=color_disabled,
            force_terminal=False if color_disabled else None,
            highlight=False,
        ),
        error_console=Console(
            stderr=True,
            no_color=color_disabled,
            force_terminal=False if color_disabled else None,
            highlight=False,
        ),
        config_path=config_path,
        env_file=env_file,
        json_output=json_output,
        no_color=color_disabled,
        quiet=quiet,
        verbose=verbose,
        debug=debug,
        non_interactive=non_interactive,
        assume_yes=assume_yes,
        profile=profile,
    )
