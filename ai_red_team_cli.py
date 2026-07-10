#!/usr/bin/env python3
"""Command-line entry point for the local AI red-team simulator."""

import argparse
import json
import os
import shutil
import subprocess
import sys

from local_red_team.run_local_red_team_scan import run_scan as run_local_red_team_scan
from scanner.attack_runner import run_all_attacks, status_counts
from scanner.target_loader import discover_targets


DEFAULT_KALI_HOST = os.environ.get("KALI_SSH_HOST", "kali-redteam")
DEFAULT_KALI_KEY = "~/.ssh/kali_ai_red_team"


class CliError(RuntimeError):
    """Raised for expected user-facing CLI failures."""


def _print_target_table(targets):
    if not targets:
        print("No targets discovered.")
        return

    name_width = max(len("Target"), *(len(target["name"]) for target in targets))
    print(f"{'Target'.ljust(name_width)}  Path")
    print(f"{'-' * name_width}  {'-' * 4}")
    for target in sorted(targets, key=lambda item: item["name"]):
        print(f"{target['name'].ljust(name_width)}  {target['path']}")


def cmd_targets(args):
    targets = discover_targets()
    if args.json:
        print(json.dumps(sorted(targets, key=lambda item: item["name"]), indent=2))
    else:
        _print_target_table(targets)
    return 0


def cmd_scan(args):
    run_result = run_all_attacks(target_name=args.target, attack_name=args.attack)
    counts = status_counts(run_result["results"])
    print(
        "Scan complete: "
        f"{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['ERROR']} ERROR."
    )
    print(f"Combined report: {run_result['combined_report']}")

    if args.fail_on_findings and (counts["FAIL"] or counts["ERROR"]):
        return 1
    return 0


def cmd_local_red_team(args):
    payload = run_local_red_team_scan(
        selected_target=args.target,
        max_payloads=max(1, args.max_payloads),
    )
    summary = payload["summary"]
    if args.fail_on_findings and (summary["fail"] or summary["error"]):
        return 1
    return 0


def _remote_status_script():
    return """
printf 'SSH OK: %s@%s\\n' "$(whoami)" "$(hostname)"
printf 'Kernel: '
uname -srmo
printf 'Python: '
python3 --version 2>&1 || true
printf 'Git: '
git --version 2>&1 || true
printf 'SSH daemon: '
command -v sshd || true
printf 'Port 22 listener: '
if command -v ss >/dev/null 2>&1 && ss -tln | awk '{print $4}' | grep -Eq '(^|:)22$'; then
    echo yes
else
    echo unknown
fi
""".strip()


def cmd_kali_status(args):
    if shutil.which("ssh") is None:
        raise CliError("ssh was not found on this machine.")

    host = args.host or DEFAULT_KALI_HOST
    timeout = max(1, args.timeout)
    identity_file = resolve_identity_file(args.identity_file)

    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout}",
    ]
    if identity_file:
        command.extend(
            [
                "-i",
                os.path.expanduser(identity_file),
                "-o",
                "IdentitiesOnly=yes",
            ]
        )

    command.extend(
        [
            host,
            _remote_status_script(),
        ]
    )
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode != 0:
        raise CliError(
            f"Could not reach Kali host '{host}' with key-based SSH "
            f"(exit code {result.returncode})."
        )
    return 0


def cmd_serve_agents(args):
    from agent_lab_server import DEFAULT_TARGETS, serve

    target_names = tuple(args.targets or DEFAULT_TARGETS)
    try:
        serve(args.host, args.port, target_names)
    except KeyboardInterrupt:
        print("\nAgent lab server stopped.")
    return 0


def cmd_serve_agent(args):
    from agent_service import serve

    try:
        serve(args.target, args.host, args.port)
    except KeyboardInterrupt:
        print("\nAgent service stopped.")
    return 0


def cmd_agents_list(args):
    from agent_registry import load_registry

    registry = load_registry(args.registry)
    agents = registry["agents"]
    if args.json:
        print(json.dumps(agents, indent=2))
        return 0
    if not agents:
        print("No registered agents.")
        return 0
    name_width = max(len("Agent"), *(len(agent.get("name", "")) for agent in agents))
    print(f"{'Agent'.ljust(name_width)}  Health URL")
    print(f"{'-' * name_width}  {'-' * 10}")
    for agent in agents:
        print(f"{agent.get('name', '').ljust(name_width)}  {agent.get('health_url', '')}")
    return 0


def cmd_agents_health(args):
    from agent_registry import check_agent_health, load_registry

    registry = load_registry(args.registry)
    results = [check_agent_health(agent, timeout=args.timeout) for agent in registry["agents"]]
    if args.json:
        print(json.dumps(results, indent=2))
        return 0
    if not results:
        print("No registered agents.")
        return 0
    for result in results:
        detail = result.get("error") or result.get("http_status", "")
        print(f"{result.get('name')}: {result.get('status')} {detail}")
    if args.fail_on_down and any(result.get("status") != "up" for result in results):
        return 1
    return 0


def cmd_agents_discover(args):
    from agent_registry import discover_local_agents, local_discovery_ports

    ports = local_discovery_ports(args.ports, registry_path=args.registry)
    agents = discover_local_agents(args.host, ports=ports, timeout=args.timeout)
    if args.json:
        print(json.dumps(agents, indent=2))
        return 0
    if not agents:
        print(f"No active local agents found on {args.host}.")
        return 1 if args.fail_on_none else 0

    name_width = max(len("Agent"), *(len(str(agent.get("name", ""))) for agent in agents))
    kind_width = max(len("Kind"), *(len(str(agent.get("kind", ""))) for agent in agents))
    print(f"{'Agent'.ljust(name_width)}  {'Kind'.ljust(kind_width)}  Base URL  Targets")
    print(f"{'-' * name_width}  {'-' * kind_width}  {'-' * 8}  {'-' * 7}")
    for agent in agents:
        targets = ", ".join(agent.get("targets") or [])
        print(
            f"{str(agent.get('name', '')).ljust(name_width)}  "
            f"{str(agent.get('kind', '')).ljust(kind_width)}  "
            f"{agent.get('base_url', '')}  {targets}"
        )
    return 0


def resolve_identity_file(value=None):
    identity_file = value or os.environ.get("KALI_SSH_KEY")
    if identity_file is None and os.path.exists(os.path.expanduser(DEFAULT_KALI_KEY)):
        identity_file = DEFAULT_KALI_KEY
    return identity_file


def cmd_kali_attack_agents(args):
    from kali_agent_attack import run_kali_agent_attack

    report = run_kali_agent_attack(
        host=args.host,
        identity_file=resolve_identity_file(args.identity_file),
        ssh_timeout=args.ssh_timeout,
        local_port=args.local_port,
        remote_port=args.remote_port,
        targets=args.targets,
        ollama_model=args.ollama_model,
        ollama_timeout=args.ollama_timeout,
        report_path=args.report,
        skip_web_recon=args.skip_web_recon,
    )
    summary = report["summary"]
    if args.fail_on_findings and (summary["fail"] or summary["error"] or summary["unparsed"]):
        return 1
    return 0


def cmd_kali_attack_url(args):
    from kali_url_attack import run_kali_url_attack

    report = run_kali_url_attack(
        host=args.host,
        url=args.url,
        identity_file=resolve_identity_file(args.identity_file),
        ssh_timeout=args.ssh_timeout,
        report_path=args.report,
        skip_web_recon=args.skip_web_recon,
    )
    summary = report["summary"]
    if args.fail_on_findings and (summary["fail"] or summary["error"] or summary["unparsed"]):
        return 1
    return 0


def cmd_chat(args):
    from red_team_assistant import run_chat

    run_chat(
        message=args.message,
        prefer_local_model=args.local_model,
        kali_host=args.kali_host,
    )
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ai-red-team",
        description="Run local AI red-team scans and check the connected Kali lab host.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    targets_parser = subparsers.add_parser("targets", help="List discovered Python targets.")
    targets_parser.add_argument("--json", action="store_true", help="Print targets as JSON.")
    targets_parser.set_defaults(func=cmd_targets)

    scan_parser = subparsers.add_parser("scan", help="Run static payload attacks.")
    scan_parser.add_argument("--target", help="Target module name, for example: tool_agent.")
    scan_parser.add_argument("--attack", help="Attack name, for example: prompt_disclosure.")
    scan_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 when the scan records FAIL or ERROR results.",
    )
    scan_parser.set_defaults(func=cmd_scan)

    chat_parser = subparsers.add_parser(
        "chat",
        help="Talk to the red-team assistant in natural language.",
    )
    chat_parser.add_argument(
        "--message",
        "-m",
        help="Run one natural-language request instead of opening interactive chat.",
    )
    chat_parser.add_argument(
        "--local-model",
        action="store_true",
        help="Use REDTEAM_NL_MODEL through local Ollama for intent parsing when available.",
    )
    chat_parser.add_argument(
        "--kali-host",
        default=DEFAULT_KALI_HOST,
        help=f"Kali SSH host for natural-language Kali requests. Default: {DEFAULT_KALI_HOST}",
    )
    chat_parser.set_defaults(func=cmd_chat)

    local_parser = subparsers.add_parser(
        "local-red-team",
        help="Use the local Ollama red-team planner before scanning targets.",
    )
    local_parser.add_argument("--target", help="Run one target only, for example: travel_agent.")
    local_parser.add_argument(
        "--max-payloads",
        type=int,
        default=2,
        help="Payloads to ask the local planner for per target.",
    )
    local_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 when the scan records FAIL or ERROR results.",
    )
    local_parser.set_defaults(func=cmd_local_red_team)

    serve_parser = subparsers.add_parser(
        "serve-agents",
        help="Expose selected local agents on loopback for Kali tunnel testing.",
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host.")
    serve_parser.add_argument("--port", type=int, default=18080, help="Bind port.")
    serve_parser.add_argument(
        "--target",
        action="append",
        dest="targets",
        help="Target name to expose. Can be repeated.",
    )
    serve_parser.set_defaults(func=cmd_serve_agents)

    serve_one_parser = subparsers.add_parser(
        "serve-agent",
        help="Serve one target agent over HTTP for local demos or Render deployment.",
    )
    serve_one_parser.add_argument("--target", default="weather_insight_agent")
    serve_one_parser.add_argument("--host", default="127.0.0.1")
    serve_one_parser.add_argument("--port", type=int, default=18101)
    serve_one_parser.set_defaults(func=cmd_serve_agent)

    agents_parser = subparsers.add_parser("agents", help="Discover registered agent services.")
    agents_subparsers = agents_parser.add_subparsers(dest="agents_command", required=True)
    agents_list_parser = agents_subparsers.add_parser("list", help="List registered agents.")
    agents_list_parser.add_argument("--registry", default="agent_registry.json")
    agents_list_parser.add_argument("--json", action="store_true")
    agents_list_parser.set_defaults(func=cmd_agents_list)

    agents_health_parser = agents_subparsers.add_parser(
        "health", help="Check health URLs for registered agents."
    )
    agents_health_parser.add_argument("--registry", default="agent_registry.json")
    agents_health_parser.add_argument("--timeout", type=int, default=5)
    agents_health_parser.add_argument("--json", action="store_true")
    agents_health_parser.add_argument("--fail-on-down", action="store_true")
    agents_health_parser.set_defaults(func=cmd_agents_health)

    agents_discover_parser = agents_subparsers.add_parser(
        "discover",
        help="Actively scan localhost for running compatible agent services.",
    )
    agents_discover_parser.add_argument("--host", default="127.0.0.1")
    agents_discover_parser.add_argument(
        "--ports",
        help="Comma-separated ports and ranges, for example: 18080,18101-18110.",
    )
    agents_discover_parser.add_argument("--registry", default="agent_registry.json")
    agents_discover_parser.add_argument("--timeout", type=float, default=0.35)
    agents_discover_parser.add_argument("--json", action="store_true")
    agents_discover_parser.add_argument("--fail-on-none", action="store_true")
    agents_discover_parser.set_defaults(func=cmd_agents_discover)

    kali_parser = subparsers.add_parser("kali", help="Interact with the connected Kali lab host.")
    kali_subparsers = kali_parser.add_subparsers(dest="kali_command", required=True)

    status_parser = kali_subparsers.add_parser("status", help="Check SSH and basic Kali tooling.")
    status_parser.add_argument(
        "--host",
        default=DEFAULT_KALI_HOST,
        help=f"SSH host or alias to check. Default: {DEFAULT_KALI_HOST}",
    )
    status_parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="SSH connect timeout in seconds.",
    )
    status_parser.add_argument(
        "--identity-file",
        help=(
            "SSH private key to use. Defaults to KALI_SSH_KEY or "
            f"{DEFAULT_KALI_KEY} when that file exists."
        ),
    )
    status_parser.set_defaults(func=cmd_kali_status)

    attack_parser = kali_subparsers.add_parser(
        "attack-agents",
        help="Run bounded Kali recon and prompt probes against local lab agents.",
    )
    attack_parser.add_argument(
        "--host",
        default=DEFAULT_KALI_HOST,
        help=f"SSH host or alias to use. Default: {DEFAULT_KALI_HOST}",
    )
    attack_parser.add_argument(
        "--identity-file",
        help=(
            "SSH private key to use. Defaults to KALI_SSH_KEY or "
            f"{DEFAULT_KALI_KEY} when that file exists."
        ),
    )
    attack_parser.add_argument("--ssh-timeout", type=int, default=8)
    attack_parser.add_argument("--local-port", type=int, default=18080)
    attack_parser.add_argument("--remote-port", type=int, default=18080)
    attack_parser.add_argument(
        "--target",
        action="append",
        dest="targets",
        help="Target name to assess. Can be repeated.",
    )
    attack_parser.add_argument(
        "--ollama-model",
        help="Override OLLAMA_MODEL for ollama_agent during this run.",
    )
    attack_parser.add_argument(
        "--ollama-timeout",
        type=int,
        help="Override OLLAMA_TIMEOUT_SECONDS for local agent calls during this run.",
    )
    attack_parser.add_argument(
        "--report",
        default="reports/kali_agent_scan.json",
        help="Path for the JSON report.",
    )
    attack_parser.add_argument(
        "--skip-web-recon",
        action="store_true",
        help="Skip nmap, whatweb, and nikto; run endpoint and prompt probes only.",
    )
    attack_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 when prompt probes record FAIL, ERROR, or unparsed results.",
    )
    attack_parser.set_defaults(func=cmd_kali_attack_agents)

    url_attack_parser = kali_subparsers.add_parser(
        "attack-url",
        help="Run Kali recon and prompt probes against a hosted agent URL.",
    )
    url_attack_parser.add_argument("--url", required=True, help="Base URL, for example Render URL.")
    url_attack_parser.add_argument(
        "--host",
        default=DEFAULT_KALI_HOST,
        help=f"SSH host or alias to use. Default: {DEFAULT_KALI_HOST}",
    )
    url_attack_parser.add_argument(
        "--identity-file",
        help=(
            "SSH private key to use. Defaults to KALI_SSH_KEY or "
            f"{DEFAULT_KALI_KEY} when that file exists."
        ),
    )
    url_attack_parser.add_argument("--ssh-timeout", type=int, default=8)
    url_attack_parser.add_argument(
        "--report",
        default="reports/kali_url_scan.json",
        help="Path for the JSON report.",
    )
    url_attack_parser.add_argument(
        "--skip-web-recon",
        action="store_true",
        help="Skip nmap, whatweb, and nikto; run endpoint and prompt probes only.",
    )
    url_attack_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 when prompt probes record FAIL, ERROR, or unparsed results.",
    )
    url_attack_parser.set_defaults(func=cmd_kali_attack_url)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CliError, FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
