"""Passive, opt-in Kali readiness inventory with fixed allowlisted commands."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable

from redteam_platform.inventory.models import (
    DiscoveryConfidence,
    DiscoveryError,
    DiscoveryEvidence,
    DiscoverySource,
    HealthState,
    InventoryStatus,
    KaliReadiness,
    ToolAvailability,
    ToolState,
)
from redteam_platform.inventory.platform import stable_id
from redteam_platform.schemas import ScopeClassification
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


KALI_TOOLS = ("nmap", "whatweb", "nikto", "curl", "python3", "sqlmap", "nuclei")
READINESS_SCRIPT = r"""
python3 - <<'PY'
import json
import os
import platform
import shutil
import subprocess

tools = {}
for name in ("nmap", "whatweb", "nikto", "curl", "python3", "sqlmap", "nuclei"):
    path = shutil.which(name)
    version = None
    if path:
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
            version = (result.stdout or result.stderr).splitlines()[0][:200]
        except Exception:
            version = None
    tools[name] = {"available": bool(path), "version": version}
print(json.dumps({
    "os": platform.platform(),
    "tools": tools,
    "reverse_tunnel_capability": None,
}))
PY
""".strip()


class KaliDiscovery:
    def __init__(
        self,
        settings: Settings,
        policy: ScopePolicy | None = None,
        *,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
    ):
        self.settings = settings
        self.policy = policy or ScopePolicy(settings)
        self.runner = runner
        self.which = which

    def collect(
        self, *, live: bool | None = None
    ) -> tuple[list[KaliReadiness], list[DiscoveryError]]:
        host = self.settings.kali_ssh_host
        if not host:
            return [
                KaliReadiness(
                    stable_id=stable_id("kali", "not-configured"),
                    name="Kali",
                    status=InventoryStatus.NOT_CONFIGURED,
                    discovery_source=DiscoverySource.CONFIGURATION,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="No Kali SSH host or alias is configured.",
                    health=HealthState.NOT_CHECKED,
                    scope_classification=ScopeClassification.UNKNOWN,
                    configured=False,
                )
            ], []
        target = f"ssh://{host}"
        try:
            decision = self.policy.decide(target, active=False)
        except ScopeDeniedError as exc:
            decision = None
            reason = str(exc)
        else:
            reason = decision.reason
        if decision is None or not decision.allowed:
            error = DiscoveryError(
                source="kali",
                code="kali_scope_denied",
                message=f"Configured Kali alias was denied: {reason}",
            )
            return [
                KaliReadiness(
                    stable_id=stable_id("kali", host),
                    name="Kali",
                    status=InventoryStatus.UNAVAILABLE,
                    discovery_source=DiscoverySource.CONFIGURATION,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Kali host is configured but not allowlisted.",
                    health=HealthState.UNAVAILABLE,
                    scope_classification=ScopeClassification.BLOCKED,
                    configured=True,
                    ssh_alias=host,
                    ssh_state=ToolState.UNAVAILABLE,
                    errors=[error],
                )
            ], [error]
        if not self.which("ssh"):
            error = DiscoveryError(
                source="kali",
                code="ssh_missing",
                message="SSH executable is unavailable.",
            )
            return [
                KaliReadiness(
                    stable_id=stable_id("kali", host),
                    name="Kali",
                    status=InventoryStatus.UNAVAILABLE,
                    endpoint=decision.normalized_target,
                    discovery_source=DiscoverySource.CONFIGURATION,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Kali alias is configured, but SSH is unavailable.",
                    health=HealthState.UNAVAILABLE,
                    scope_classification=decision.classification,
                    configured=True,
                    ssh_alias=host,
                    ssh_state=ToolState.MISSING,
                    errors=[error],
                )
            ], [error]
        perform_live = self.settings.kali_live_check if live is None else live
        if not perform_live:
            return [
                KaliReadiness(
                    stable_id=stable_id("kali", host),
                    name="Kali",
                    status=InventoryStatus.INACTIVE,
                    endpoint=decision.normalized_target,
                    discovery_source=DiscoverySource.CONFIGURATION,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Kali alias and local SSH binary are configured; live readiness was not requested.",
                    capabilities=["live_readiness_opt_in"],
                    health=HealthState.NOT_CHECKED,
                    scope_classification=decision.classification,
                    evidence=[
                        DiscoveryEvidence(
                            source=DiscoverySource.CONFIGURATION,
                            fact="allowlisted_ssh_alias",
                            value=True,
                            confidence=DiscoveryConfidence.CONFIRMED,
                        )
                    ],
                    configured=True,
                    ssh_alias=host,
                    ssh_state=ToolState.AVAILABLE,
                    tools=[
                        ToolAvailability(name=name, state=ToolState.NOT_CHECKED)
                        for name in KALI_TOOLS
                    ],
                    live_check_performed=False,
                )
            ], []
        return self._live(host, decision)

    def _live(
        self, host: str, decision
    ) -> tuple[list[KaliReadiness], list[DiscoveryError]]:
        command = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            f"ConnectTimeout={int(self.settings.kali_readiness_timeout)}",
        ]
        if self.settings.kali_ssh_key:
            command.extend(
                [
                    "-i",
                    os.fspath(self.settings.kali_ssh_key),
                    "-o",
                    "IdentitiesOnly=yes",
                ]
            )
        command.extend([host, "sh", "-s"])
        try:
            result = self.runner(
                command,
                input=READINESS_SCRIPT,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.settings.kali_readiness_timeout + 5,
            )
        except subprocess.TimeoutExpired:
            error = DiscoveryError(
                source="kali",
                code="kali_timeout",
                message="Kali readiness check timed out.",
            )
            return [self._failed(host, decision, error)], [error]
        except OSError as exc:
            error = DiscoveryError(
                source="kali",
                code="kali_unavailable",
                message=f"Kali readiness could not start: {type(exc).__name__}.",
            )
            return [self._failed(host, decision, error)], [error]
        if result.returncode != 0:
            error = DiscoveryError(
                source="kali",
                code=(
                    "kali_permission_denied"
                    if "permission denied" in str(result.stderr).lower()
                    else "kali_unreachable"
                ),
                message="Kali SSH readiness check failed.",
                details={"returncode": result.returncode},
            )
            return [self._failed(host, decision, error)], [error]
        try:
            payload = json.loads(result.stdout.splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            error = DiscoveryError(
                source="kali",
                code="kali_invalid_response",
                message="Kali readiness returned invalid JSON.",
            )
            return [self._failed(host, decision, error)], [error]
        raw_tools = payload.get("tools") if isinstance(payload, dict) else {}
        tools = [
            ToolAvailability(
                name=name,
                state=(
                    ToolState.AVAILABLE
                    if isinstance(raw_tools, dict)
                    and isinstance(raw_tools.get(name), dict)
                    and raw_tools[name].get("available")
                    else ToolState.MISSING
                ),
                version=(
                    str(raw_tools[name].get("version"))[:200]
                    if isinstance(raw_tools, dict)
                    and isinstance(raw_tools.get(name), dict)
                    and raw_tools[name].get("version")
                    else None
                ),
            )
            for name in KALI_TOOLS
        ]
        return [
            KaliReadiness(
                stable_id=stable_id("kali", host),
                name="Kali",
                status=InventoryStatus.READY,
                endpoint=decision.normalized_target,
                discovery_source=DiscoverySource.KALI_SSH,
                discovery_confidence=DiscoveryConfidence.CONFIRMED,
                confidence_reason="Allowlisted SSH readiness command returned valid metadata.",
                capabilities=["tool_inventory"],
                health=HealthState.HEALTHY,
                scope_classification=decision.classification,
                evidence=[
                    DiscoveryEvidence(
                        source=DiscoverySource.KALI_SSH,
                        fact="readiness_response",
                        value=True,
                        confidence=DiscoveryConfidence.CONFIRMED,
                    )
                ],
                configured=True,
                ssh_alias=host,
                ssh_state=ToolState.AVAILABLE,
                reachable=True,
                os_identity=str(payload.get("os") or "")[:300],
                reverse_tunnel_capability=payload.get("reverse_tunnel_capability"),
                tools=tools,
                live_check_performed=True,
            )
        ], []

    @staticmethod
    def _failed(host: str, decision, error: DiscoveryError) -> KaliReadiness:
        return KaliReadiness(
            stable_id=stable_id("kali", host),
            name="Kali",
            status=InventoryStatus.UNAVAILABLE,
            endpoint=decision.normalized_target,
            discovery_source=DiscoverySource.KALI_SSH,
            discovery_confidence=DiscoveryConfidence.CONFIRMED,
            confidence_reason="Kali alias was allowlisted, but readiness failed.",
            health=HealthState.UNAVAILABLE,
            scope_classification=decision.classification,
            configured=True,
            ssh_alias=host,
            ssh_state=ToolState.AVAILABLE,
            reachable=False,
            live_check_performed=True,
            errors=[error],
        )

