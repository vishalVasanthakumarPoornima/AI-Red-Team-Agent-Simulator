"""Typed, deterministic optional Kali plan with owned tunnel cleanup."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from urllib.parse import urlparse

from redteam_platform.artifacts import sanitize
from redteam_platform.dexter.models import DexterKaliPlan, DexterTarget
from redteam_platform.inventory.kali import KaliDiscovery
from redteam_platform.inventory.models import ToolState
from redteam_platform.schemas import AuthorizationRecord
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


ALLOWED_TOOLS = {"nmap", "whatweb", "nikto", "curl"}


def _owned_reverse_tunnel(
    host: str,
    local_port: int,
    remote_port: int,
    timeout: int,
    identity_file: str | None = None,
) -> subprocess.Popen:
    command = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "RequestTTY=no",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        f"ConnectTimeout={max(1, timeout)}",
    ]
    if identity_file:
        command.extend(["-i", identity_file, "-o", "IdentitiesOnly=yes"])
    command.extend(
        [
            "-N",
            "-R",
            f"127.0.0.1:{remote_port}:127.0.0.1:{local_port}",
            host,
        ]
    )
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _stop_owned_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


class DexterKaliService:
    def __init__(
        self,
        settings: Settings,
        *,
        policy: ScopePolicy | None = None,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        tunnel_factory: Callable[..., subprocess.Popen] = _owned_reverse_tunnel,
        tunnel_stopper: Callable[[subprocess.Popen | None], None] = _stop_owned_process,
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.runner = runner
        self.tunnel_factory = tunnel_factory
        self.tunnel_stopper = tunnel_stopper

    def plan(self, target: DexterTarget, *, enabled: bool) -> DexterKaliPlan:
        parsed = urlparse(target.main_endpoint)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not enabled:
            return DexterKaliPlan(
                target_id=target.stable_id,
                enabled=False,
                exact_host=parsed.hostname or "",
                exact_ports=[port],
                requires_tunnel=target.configuration.requires_kali_tunnel,
                skip_reason="Kali was not requested.",
            )
        if not self.settings.kali_ssh_host:
            return DexterKaliPlan(
                target_id=target.stable_id,
                enabled=False,
                exact_host=parsed.hostname or "",
                exact_ports=[port],
                requires_tunnel=target.configuration.requires_kali_tunnel,
                skip_reason="Kali is not configured.",
            )
        return DexterKaliPlan(
            target_id=target.stable_id,
            enabled=True,
            ssh_alias=self.settings.kali_ssh_host,
            tools=["nmap", "whatweb", "curl"],
            exact_host=parsed.hostname or "",
            exact_ports=[port],
            requires_tunnel=target.configuration.requires_kali_tunnel,
        )

    def execute(
        self,
        target: DexterTarget,
        plan: DexterKaliPlan,
        authorization: AuthorizationRecord,
    ) -> list[dict]:
        if not plan.enabled or not plan.ssh_alias:
            return [{"status": "unavailable", "reason": plan.skip_reason}]
        decision = self.policy.decide(
            target.main_endpoint,
            active=True,
            authorization_statement=authorization.statement,
            public_mode=authorization.public_mode,
            interactive_confirmation=authorization.confirmed_interactively,
        )
        if not decision.allowed:
            raise ScopeDeniedError(decision.reason)
        ssh_decision = self.policy.decide(f"ssh://{plan.ssh_alias}", active=False)
        if not ssh_decision.allowed:
            raise ScopeDeniedError(ssh_decision.reason)
        readiness, errors = KaliDiscovery(self.settings).collect(live=True)
        if errors or not readiness or not readiness[0].reachable:
            return [
                {
                    "status": "unavailable",
                    "reason": "; ".join(error.message for error in errors)
                    or "Kali readiness failed.",
                }
            ]
        available = {
            tool.name
            for tool in readiness[0].tools
            if tool.state == ToolState.AVAILABLE
        }
        selected = [tool for tool in plan.tools if tool in ALLOWED_TOOLS and tool in available]
        if not selected:
            return [{"status": "unavailable", "reason": "No registered Kali tools are available."}]
        parsed = urlparse(target.main_endpoint)
        local_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        remote_port = target.configuration.kali_remote_port
        tunnel = None
        effective_host = parsed.hostname or "127.0.0.1"
        effective_port = local_port
        results: list[dict] = []
        try:
            if plan.requires_tunnel:
                tunnel = self.tunnel_factory(
                    plan.ssh_alias,
                    local_port,
                    remote_port,
                    int(self.settings.kali_readiness_timeout),
                    str(self.settings.kali_ssh_key) if self.settings.kali_ssh_key else None,
                )
                effective_host = "127.0.0.1"
                effective_port = remote_port
                health_command = self._ssh_prefix(plan.ssh_alias) + [
                    "--",
                    "curl",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "10",
                    f"http://127.0.0.1:{remote_port}{urlparse(target.health_endpoint).path or '/'}",
                ]
                health = self.runner(
                    health_command,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if health.returncode != 0:
                    return [
                        {
                            "status": "unavailable",
                            "reason": "Kali tunnel health verification failed.",
                            "returncode": health.returncode,
                        }
                    ]
            base_url = f"http://{effective_host}:{effective_port}"
            for tool in selected[:3]:
                remote_args = self._tool_args(tool, effective_host, effective_port, base_url)
                command = self._ssh_prefix(plan.ssh_alias) + ["--", *remote_args]
                try:
                    completed = self.runner(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    results.append(
                        {
                            "tool": tool,
                            "status": "complete" if completed.returncode == 0 else "error",
                            "returncode": completed.returncode,
                            "stdout": str(sanitize(completed.stdout[:65536])),
                            "stderr": str(sanitize(completed.stderr[:65536])),
                            "command": [part if part != str(self.settings.kali_ssh_key) else "<key-path>" for part in command],
                        }
                    )
                except subprocess.TimeoutExpired:
                    results.append({"tool": tool, "status": "timeout", "returncode": 124})
        finally:
            self.tunnel_stopper(tunnel)
        return results

    def _ssh_prefix(self, alias: str) -> list[str]:
        command = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            f"ConnectTimeout={max(1, int(self.settings.kali_readiness_timeout))}",
        ]
        if self.settings.kali_ssh_key:
            command.extend(
                [
                    "-i",
                    os.path.expanduser(str(self.settings.kali_ssh_key)),
                    "-o",
                    "IdentitiesOnly=yes",
                ]
            )
        command.append(alias)
        return command

    @staticmethod
    def _tool_args(tool: str, host: str, port: int, base_url: str) -> list[str]:
        if tool == "nmap":
            return ["nmap", "-sV", "--version-light", "-Pn", "-p", str(port), host]
        if tool == "whatweb":
            return ["whatweb", "--no-errors", "--color=never", base_url]
        if tool == "nikto":
            return ["nikto", "-nointeractive", "-maxtime", "20s", "-h", base_url]
        if tool == "curl":
            return ["curl", "--silent", "--show-error", "--max-time", "10", "--head", base_url]
        raise ValueError("Unregistered Kali tool.")
