"""Centralized, tested CLI help examples."""

from __future__ import annotations

import typer

ROOT_EPILOG = """Configuration:
  --config PATH loads TOML settings. --env-file PATH loads environment values (default: .env).
  Safe local defaults work without a config file; run `redteam init` to create a protected starter file.

Environment:
  No environment variable is required for the deterministic local demo.
  REDTEAM_API_TOKEN is required only for `api serve`. OLLAMA_URL and OLLAMA_MODEL select a live
  local model. Kali and provider settings are optional and documented in `.env.example`.

Common workflow:
  doctor -> inventory refresh -> targets resolve -> assess plan -> assess run -> reports show

Examples:
  redteam --help
  redteam doctor
  redteam assess plan python://tool_agent --profile passive
  redteam assess run python://tool_agent --profile standard --authorization "I own this local synthetic target and authorize bounded testing."
  redteam reports list

Command help:
  redteam COMMAND --help
  redteam help COMMAND
  redteam help GROUP COMMAND
"""


COMMAND_EXAMPLES: dict[str, str] = {
    "adaptive models": "redteam adaptive models --live",
    "adaptive plan": "redteam adaptive plan tool_agent --kind python --adaptive-mode guided",
    "adaptive resume": "redteam adaptive resume RUN_ID --authorization \"I own this local synthetic target and authorize bounded testing.\"",
    "adaptive run": "redteam adaptive run tool_agent --authorization \"I own this local synthetic target and authorize bounded testing.\" --adaptive-mode guided",
    "adaptive status": "redteam adaptive status",
    "adaptive stop": "redteam adaptive stop RUN_ID",
    "agents health": "redteam agents health python_target_tool_agent",
    "agents list": "redteam agents list --refresh",
    "agents show": "redteam agents show python_target_tool_agent",
    "api serve": "redteam --config redteam.toml api serve",
    "assess agent": "redteam assess agent http://127.0.0.1:18080 --authorization \"I own this local synthetic target and authorize bounded testing.\"",
    "assess host": "redteam assess host 127.0.0.1 --port 8000 --authorization \"I own this local lab host and authorize bounded testing.\"",
    "assess local-agent": "redteam assess local-agent tool_agent --category prompt_disclosure --authorization \"I own this local synthetic target and authorize bounded testing.\"",
    "assess ollama": "redteam assess ollama http://127.0.0.1:11434 --model llama3.2:1b --authorization \"I own this local model endpoint and authorize bounded testing.\"",
    "assess plan": "redteam assess plan python://tool_agent --profile passive",
    "assess python": "redteam assess python tool_agent --authorization \"I own this local synthetic target and authorize bounded testing.\"",
    "assess python-target": "redteam assess python-target tool_agent --category prompt_disclosure --authorization \"I own this local synthetic target and authorize bounded testing.\"",
    "assess run": "redteam assess run python://tool_agent --authorization \"I own this local synthetic target and authorize bounded testing.\"",
    "assess start": "redteam assess start --kind python --target tool_agent --category prompt_disclosure --authorization \"I own this local synthetic target and authorize bounded testing.\"",
    "assess web": "redteam assess web http://127.0.0.1:8000 --path /health --authorization \"I own this local web app and authorize bounded testing.\"",
    "config paths": "redteam config paths",
    "config show": "redteam config show --json",
    "config validate": "redteam config validate --strict",
    "dexter assess": "redteam dexter assess DEXTER_ID --profile standard --authorization \"I own this local Dexter lab and authorize bounded testing.\"",
    "dexter discover": "redteam dexter discover --refresh",
    "dexter health": "redteam dexter health DEXTER_ID",
    "dexter list": "redteam dexter list",
    "dexter plan": "redteam dexter plan DEXTER_ID --profile standard",
    "dexter show": "redteam dexter show DEXTER_ID",
    "doctor": "redteam doctor --strict",
    "help": "redteam help assess run",
    "init": "redteam init --destination redteam.toml",
    "inventory refresh": "redteam inventory refresh --live-ollama",
    "inventory show": "redteam inventory show --item-type python_target --refresh",
    "inventory summary": "redteam inventory summary --json",
    "kali check": "redteam kali check --live",
    "kali status": "redteam kali status --live",
    "kali tools": "redteam kali tools",
    "kali-status": "redteam kali-status --live",
    "menu": "redteam menu",
    "model benchmark": "redteam model benchmark --model llama3.2:1b",
    "models benchmark": "redteam models benchmark --model llama3.2:1b",
    "models benchmark-list": "redteam models benchmark-list",
    "models benchmark-show": "redteam models benchmark-show BENCHMARK_ID",
    "models installed": "redteam models installed --live",
    "models list": "redteam models list --live",
    "models recommend": "redteam models recommend",
    "models running": "redteam models running --live",
    "models show": "redteam models show llama3.2:1b",
    "reports build": "redteam reports build RUN_ID --all",
    "reports compare": "redteam reports compare OLD_RUN_ID NEW_RUN_ID",
    "reports coverage": "redteam reports coverage RUN_ID",
    "reports export": "redteam reports export RUN_ID --safe-share --destination ./shared-report",
    "reports findings": "redteam reports findings RUN_ID --severity High",
    "reports list": "redteam reports list",
    "reports retest": "redteam reports retest OLD_RUN_ID NEW_RUN_ID",
    "reports show": "redteam reports show RUN_ID",
    "reports verify": "redteam reports verify RUN_ID",
    "runs artifacts": "redteam runs artifacts RUN_ID",
    "runs events": "redteam runs events RUN_ID --follow --timeout 30",
    "runs list": "redteam runs list --limit 10",
    "runs show": "redteam runs show RUN_ID",
    "scope explain": "redteam scope explain http://127.0.0.1:18080",
    "scope show": "redteam scope show",
    "scope validate": "redteam scope validate http://127.0.0.1:18080",
    "services list": "redteam services list --loopback true --refresh",
    "services listeners": "redteam services listeners",
    "services show": "redteam services show listener_tcp_127_0_0_1_18080",
    "targets capabilities": "redteam targets capabilities tool_agent --kind python",
    "targets health": "redteam targets health tool_agent --kind python",
    "targets parse": "redteam targets parse tool_agent --kind python",
    "targets resolve": "redteam targets resolve tool_agent --kind python --refresh",
    "targets show": "redteam targets show tool_agent --kind python",
    "version": "redteam version",
}


GROUP_EXAMPLES: dict[str, str] = {
    "adaptive": "redteam adaptive status",
    "agents": "redteam agents list --refresh",
    "api": "redteam --config redteam.toml api serve",
    "assess": "redteam assess plan python://tool_agent --profile passive",
    "config": "redteam config validate",
    "dexter": "redteam dexter discover",
    "inventory": "redteam inventory summary",
    "kali": "redteam kali status",
    "model": "redteam model benchmark --model llama3.2:1b",
    "models": "redteam models list",
    "reports": "redteam reports list",
    "runs": "redteam runs list",
    "scope": "redteam scope show",
    "services": "redteam services list",
    "targets": "redteam targets resolve tool_agent --kind python",
}


def _example_epilog(example: str) -> str:
    return f"Example:\n  {example}"


def apply_help_epilogs(root: typer.Typer) -> None:
    """Attach one tested example to every command and useful command group."""

    root.info.epilog = ROOT_EPILOG
    missing: list[str] = []

    def visit(application: typer.Typer, prefix: tuple[str, ...]) -> None:
        for command in application.registered_commands:
            name = command.name
            if not name and command.callback is not None:
                name = command.callback.__name__.replace("_", "-")
            path = " ".join((*prefix, str(name)))
            example = COMMAND_EXAMPLES.get(path)
            if example is None:
                missing.append(path)
                continue
            command.epilog = _example_epilog(example)

        for group in application.registered_groups:
            name = str(group.name)
            path_tuple = (*prefix, name)
            path = " ".join(path_tuple)
            example = GROUP_EXAMPLES.get(path)
            if example is not None:
                group.epilog = _example_epilog(example)
            visit(group.typer_instance, path_tuple)

    visit(root, ())
    if missing:
        joined = ", ".join(sorted(missing))
        raise RuntimeError(f"CLI commands are missing help examples: {joined}")
