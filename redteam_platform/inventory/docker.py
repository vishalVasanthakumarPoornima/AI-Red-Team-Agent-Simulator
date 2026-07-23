"""Optional read-only Docker CLI inventory."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable

from redteam_platform.artifacts import sanitize
from redteam_platform.inventory.models import (
    DiscoveryConfidence,
    DiscoveryError,
    DiscoveryEvidence,
    DiscoverySource,
    DockerContainer,
    HealthState,
    InventoryStatus,
)
from redteam_platform.inventory.platform import stable_id
from redteam_platform.schemas import ScopeClassification
from redteam_platform.settings import Settings


PORT_RE = re.compile(
    r"(?:(?P<host>[^:, ]+):)?(?P<host_port>\d+)?->(?P<container_port>\d+)/(?:tcp|udp)"
)


def _port_mappings(value: str) -> list[dict]:
    mappings: list[dict] = []
    for part in str(value or "").split(","):
        match = PORT_RE.search(part.strip())
        if not match:
            continue
        mappings.append(
            {
                "host": match.group("host"),
                "host_port": (
                    int(match.group("host_port"))
                    if match.group("host_port")
                    else None
                ),
                "container_port": int(match.group("container_port")),
                "protocol": "udp" if part.strip().endswith("/udp") else "tcp",
            }
        )
    return mappings


def _safe_labels(value: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for entry in str(value or "").split(","):
        if "=" not in entry:
            continue
        key, raw_value = entry.split("=", 1)
        if any(
            marker in key.lower()
            for marker in ("redteam", "agent", "com.docker.compose.project", "service")
        ):
            labels[key] = str(sanitize(raw_value))[:200]
    return labels


class DockerDiscovery:
    def __init__(
        self,
        settings: Settings,
        *,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
    ):
        self.settings = settings
        self.runner = runner
        self.which = which

    def collect(self) -> tuple[list[DockerContainer], list[DiscoveryError]]:
        if not self.which("docker"):
            return [], [
                DiscoveryError(
                    source="docker",
                    code="docker_unavailable",
                    message="Docker CLI is not installed.",
                )
            ]
        command = ["docker", "ps"]
        if self.settings.include_stopped_containers:
            command.append("--all")
        command.extend(["--format", "{{json .}}"])
        try:
            result = self.runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.settings.docker_timeout,
            )
        except subprocess.TimeoutExpired:
            return [], [
                DiscoveryError(
                    source="docker",
                    code="docker_timeout",
                    message="Docker inventory timed out.",
                )
            ]
        except OSError as exc:
            return [], [
                DiscoveryError(
                    source="docker",
                    code="docker_unavailable",
                    message=f"Docker inventory failed: {type(exc).__name__}.",
                )
            ]
        if result.returncode != 0:
            stderr = str(result.stderr or "").lower()
            code = (
                "docker_permission_denied"
                if "permission denied" in stderr
                else "docker_daemon_unavailable"
            )
            return [], [
                DiscoveryError(
                    source="docker",
                    code=code,
                    message=(
                        "Docker permission was denied."
                        if code == "docker_permission_denied"
                        else "Docker daemon is unavailable."
                    ),
                    details={"returncode": result.returncode},
                )
            ]
        items: list[DockerContainer] = []
        errors: list[DiscoveryError] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                errors.append(
                    DiscoveryError(
                        source="docker",
                        code="docker_invalid_response",
                        message="Docker returned an invalid JSON row.",
                    )
                )
                continue
            container_id = str(row.get("ID") or "")
            if not container_id:
                continue
            state = str(row.get("State") or "").lower()
            running = state == "running" or str(row.get("Status") or "").lower().startswith("up ")
            health = None
            status_text = str(row.get("Status") or "")
            if "(healthy)" in status_text:
                health = "healthy"
            elif "(unhealthy)" in status_text:
                health = "unhealthy"
            items.append(
                DockerContainer(
                    stable_id=stable_id("docker_container", container_id),
                    name=str(row.get("Names") or container_id[:12]),
                    status=(
                        InventoryStatus.RUNNING if running else InventoryStatus.STOPPED
                    ),
                    discovery_source=DiscoverySource.DOCKER_CLI,
                    discovery_confidence=DiscoveryConfidence.CONFIRMED,
                    confidence_reason="Container was reported by read-only docker ps metadata.",
                    capabilities=["container_metadata"],
                    health=(
                        HealthState.UNHEALTHY
                        if health == "unhealthy"
                        else HealthState.HEALTHY
                        if health == "healthy"
                        else HealthState.NOT_CHECKED
                    ),
                    scope_classification=ScopeClassification.UNKNOWN,
                    evidence=[
                        DiscoveryEvidence(
                            source=DiscoverySource.DOCKER_CLI,
                            fact="docker_ps_entry",
                            value=container_id[:12],
                            confidence=DiscoveryConfidence.CONFIRMED,
                        )
                    ],
                    container_id=container_id,
                    image=str(sanitize(row.get("Image") or "")),
                    container_status=status_text[:300],
                    port_mappings=_port_mappings(row.get("Ports") or ""),
                    networks=sorted(
                        value
                        for value in str(row.get("Networks") or "").split(",")
                        if value
                    ),
                    labels=_safe_labels(row.get("Labels") or ""),
                    container_health=health,
                )
            )
        return items, errors

