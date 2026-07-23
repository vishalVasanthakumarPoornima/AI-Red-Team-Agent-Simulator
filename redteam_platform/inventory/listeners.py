"""Passive TCP/UDP listener and owning-process discovery for macOS and Linux."""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from collections.abc import Callable
from typing import Any

import psutil

from redteam_platform.artifacts import sanitize, sanitize_url
from redteam_platform.inventory.models import (
    DiscoveryConfidence,
    DiscoveryError,
    DiscoveryEvidence,
    DiscoverySource,
    HealthState,
    InventoryStatus,
    Listener,
    ProcessInfo,
)
from redteam_platform.inventory.platform import (
    listener_id,
    normalize_address,
    platform_name,
    stable_id,
)
from redteam_platform.schemas import ScopeClassification
from redteam_platform.settings import Settings


SECRET_FLAG_RE = re.compile(
    r"(?i)^(--?(?:password|passwd|token|api[-_]?key|secret|authorization))(?:=(.*))?$"
)
URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def redact_command_arguments(arguments: list[str], limit: int = 500) -> str:
    cleaned: list[str] = []
    redact_next = False
    for raw in arguments:
        argument = str(raw)
        if redact_next:
            cleaned.append("<REDACTED>")
            redact_next = False
            continue
        match = SECRET_FLAG_RE.match(argument)
        if match:
            flag = match.group(1)
            if match.group(2) is None:
                cleaned.append(flag)
                redact_next = True
            else:
                cleaned.append(f"{flag}=<REDACTED>")
            continue
        if URL_RE.match(argument):
            argument = sanitize_url(argument)
        cleaned.append(str(sanitize(argument)))
    text = " ".join(cleaned)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def classify_address(address: str) -> tuple[bool, bool, str, ScopeClassification]:
    normalized = normalize_address(address)
    if normalized in {"0.0.0.0", "::", "*"}:
        return False, True, "wildcard", ScopeClassification.UNKNOWN
    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return False, False, "unknown", ScopeClassification.UNKNOWN
    if parsed.is_loopback:
        return True, False, "loopback", ScopeClassification.LOOPBACK
    if parsed.is_private:
        return False, False, "private_interface", ScopeClassification.PRIVATE_DENIED
    if parsed.is_global:
        return False, False, "public_interface", ScopeClassification.PUBLIC
    return False, False, "unknown", ScopeClassification.UNKNOWN


def _split_address_port(value: str) -> tuple[str, int] | None:
    text = value.strip()
    if text.startswith("[") and "]:" in text:
        host, port_text = text[1:].rsplit("]:", 1)
    elif ":" in text:
        host, port_text = text.rsplit(":", 1)
    else:
        return None
    if port_text == "*" or not port_text.isdigit():
        return None
    return normalize_address(host), int(port_text)


class ListenerDiscovery:
    def __init__(
        self,
        settings: Settings,
        *,
        psutil_module: Any = psutil,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        system: str | None = None,
    ):
        self.settings = settings
        self.psutil = psutil_module
        self.runner = runner
        self.system = (system or platform_name()).lower()

    def collect(self) -> tuple[list[Listener], list[DiscoveryError]]:
        method = self.settings.listener_discovery_method
        if method in {"auto", "psutil"}:
            try:
                return self._collect_psutil()
            except (self.psutil.AccessDenied, OSError) as exc:
                error = DiscoveryError(
                    source="listeners",
                    code="psutil_unavailable",
                    message=f"psutil listener inventory unavailable: {type(exc).__name__}.",
                )
                if method == "psutil":
                    return [], [error]
                listeners, fallback_errors = self._collect_native()
                return listeners, [error, *fallback_errors]
        return self._collect_native()

    def _collect_psutil(self) -> tuple[list[Listener], list[DiscoveryError]]:
        listeners: list[Listener] = []
        errors: list[DiscoveryError] = []
        for connection in self.psutil.net_connections(kind="inet"):
            transport = (
                "udp" if connection.type == socket.SOCK_DGRAM else "tcp"
            )
            if transport == "udp":
                if not self.settings.include_udp or connection.raddr:
                    continue
            elif connection.status != self.psutil.CONN_LISTEN:
                continue
            if not connection.laddr:
                continue
            if hasattr(connection.laddr, "ip"):
                address = normalize_address(connection.laddr.ip)
                port = int(connection.laddr.port)
            else:
                address = normalize_address(connection.laddr[0])
                port = int(connection.laddr[1])
            process, process_errors = self._process_info(connection.pid)
            errors.extend(process_errors)
            listeners.append(
                self._listener(
                    address=address,
                    port=port,
                    transport=transport,
                    state=connection.status or ("UNCONN" if transport == "udp" else None),
                    pid=connection.pid,
                    process=process,
                    source=DiscoverySource.PSUTIL,
                    confidence=DiscoveryConfidence.CONFIRMED,
                    family=(
                        "ipv6"
                        if connection.family == socket.AF_INET6
                        else "ipv4"
                    ),
                )
            )
        return listeners, errors

    def _process_info(
        self, pid: int | None
    ) -> tuple[ProcessInfo | None, list[DiscoveryError]]:
        if not pid:
            return None, []
        try:
            process = self.psutil.Process(pid)
            name = process.name()
            executable = process.exe() or None
            user = process.username()
            command = redact_command_arguments(process.cmdline())
            return (
                ProcessInfo(
                    stable_id=stable_id("process", name, executable or "", pid),
                    process_id=pid,
                    process_name=name,
                    executable=executable,
                    process_user=user,
                    command_summary=command,
                ),
                [],
            )
        except self.psutil.AccessDenied:
            error = DiscoveryError(
                source="listeners",
                code="process_access_denied",
                message=f"Process metadata access denied for PID {pid}.",
                details={"process_id": pid},
            )
            return (
                ProcessInfo(
                    stable_id=stable_id("process", pid),
                    process_id=pid,
                    access_denied=True,
                    errors=[error],
                ),
                [error],
            )
        except (self.psutil.NoSuchProcess, OSError) as exc:
            error = DiscoveryError(
                source="listeners",
                code="process_unavailable",
                message=f"Process metadata unavailable for PID {pid}: {type(exc).__name__}.",
                details={"process_id": pid},
            )
            return None, [error]

    def _collect_native(self) -> tuple[list[Listener], list[DiscoveryError]]:
        if self.system == "darwin":
            if not shutil.which("lsof"):
                return [], [
                    DiscoveryError(
                        source="listeners",
                        code="lsof_missing",
                        message="lsof is unavailable on macOS.",
                    )
                ]
            command = ["lsof", "-nP", "-iTCP", "-iUDP"]
            parser = self.parse_lsof
            source = DiscoverySource.LSOF
        elif self.system == "linux":
            if not shutil.which("ss"):
                return [], [
                    DiscoveryError(
                        source="listeners",
                        code="ss_missing",
                        message="ss is unavailable on Linux.",
                    )
                ]
            command = ["ss", "-H", "-lntup"]
            parser = self.parse_ss
            source = DiscoverySource.SS
        else:
            return [], [
                DiscoveryError(
                    source="listeners",
                    code="unsupported_platform",
                    message=f"Listener discovery is unsupported on {self.system}.",
                )
            ]
        try:
            result = self.runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [], [
                DiscoveryError(
                    source="listeners",
                    code="native_listener_failed",
                    message=f"Native listener command failed: {type(exc).__name__}.",
                )
            ]
        if result.returncode != 0:
            return [], [
                DiscoveryError(
                    source="listeners",
                    code="native_listener_error",
                    message="Native listener command returned a nonzero status.",
                    details={"returncode": result.returncode},
                )
            ]
        return parser(result.stdout, source), []

    def parse_lsof(
        self, output: str, source: DiscoverySource = DiscoverySource.LSOF
    ) -> list[Listener]:
        listeners: list[Listener] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.upper().startswith("COMMAND"):
                continue
            parts = stripped.split()
            if len(parts) < 4 or not parts[1].isdigit():
                continue
            protocol_index = next(
                (
                    index
                    for index, part in enumerate(parts)
                    if part.upper() in {"TCP", "UDP"}
                ),
                None,
            )
            if protocol_index is None or protocol_index + 1 >= len(parts):
                continue
            transport = parts[protocol_index].lower()
            if transport == "udp" and not self.settings.include_udp:
                continue
            if transport == "tcp" and "(LISTEN)" not in parts:
                continue
            parsed = _split_address_port(parts[protocol_index + 1])
            if not parsed:
                continue
            address, port = parsed
            state = "LISTEN" if "(LISTEN)" in parts else ("UNCONN" if transport == "udp" else None)
            process = ProcessInfo(
                stable_id=stable_id("process", parts[0], parts[1]),
                process_id=int(parts[1]),
                process_name=parts[0],
                process_user=parts[2],
            )
            listeners.append(
                self._listener(
                    address,
                    port,
                    transport,
                    state,
                    int(parts[1]),
                    process,
                    source,
                    DiscoveryConfidence.HIGH,
                    "ipv6" if ":" in address else "ipv4",
                )
            )
        return listeners

    def parse_ss(
        self, output: str, source: DiscoverySource = DiscoverySource.SS
    ) -> list[Listener]:
        listeners: list[Listener] = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            transport = parts[0].lower()
            if transport not in {"tcp", "udp"}:
                continue
            if transport == "udp" and not self.settings.include_udp:
                continue
            parsed = _split_address_port(parts[4])
            if not parsed:
                continue
            address, port = parsed
            process_match = re.search(r'\(\("([^"]+)".*?pid=(\d+)', line)
            process = None
            pid = None
            if process_match:
                pid = int(process_match.group(2))
                process = ProcessInfo(
                    stable_id=stable_id("process", process_match.group(1), pid),
                    process_id=pid,
                    process_name=process_match.group(1),
                )
            listeners.append(
                self._listener(
                    address,
                    port,
                    transport,
                    parts[1],
                    pid,
                    process,
                    source,
                    DiscoveryConfidence.HIGH,
                    "ipv6" if ":" in address else "ipv4",
                )
            )
        return listeners

    def _listener(
        self,
        address: str,
        port: int,
        transport: str,
        state: str | None,
        pid: int | None,
        process: ProcessInfo | None,
        source: DiscoverySource,
        confidence: DiscoveryConfidence,
        family: str,
    ) -> Listener:
        loopback, wildcard, reachability, scope = classify_address(address)
        name = (
            process.process_name
            if process and process.process_name
            else f"{transport}-listener-{port}"
        )
        process_name = process.process_name if process else None
        executable = process.executable if process else None
        process_user = process.process_user if process else None
        normalized = normalize_address(address)
        rendered = f"[{normalized}]" if ":" in normalized else normalized
        return Listener(
            stable_id=listener_id(
                transport,
                normalized,
                port,
                process_name,
                executable,
            ),
            name=name,
            status=InventoryStatus.ACTIVE,
            endpoint=f"{transport}://{rendered}:{port}",
            host=normalized,
            port=port,
            protocol=transport,
            process_id=pid,
            process_name=process_name,
            executable=executable,
            process_user=process_user,
            discovery_source=source,
            discovery_confidence=confidence,
            confidence_reason="Observed in the host listener table.",
            capabilities=["accept_connections"],
            health=HealthState.NOT_CHECKED,
            scope_classification=scope,
            evidence=[
                DiscoveryEvidence(
                    source=source,
                    fact="listener_table_entry",
                    value=f"{transport}:{normalized}:{port}",
                    confidence=confidence,
                )
            ],
            address=normalized,
            transport=transport,
            listen_state=state,
            loopback_only=loopback,
            wildcard_bound=wildcard,
            reachability=reachability,
            address_family=family,
            process=process,
        )
