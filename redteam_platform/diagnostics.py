"""Reusable non-attacking application diagnostics."""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from redteam_platform.artifacts import RunArtifacts
from redteam_platform.inventory import InventoryService
from redteam_platform.run_browser import RunBrowser
from redteam_platform.settings import Settings, sanitized_settings


CheckStatus = Literal["PASS", "WARN", "FAIL", "SKIP"]


@dataclass
class DiagnosticResult:
    name: str
    status: CheckStatus
    explanation: str
    remediation: str = ""

    def dump(self) -> dict[str, str]:
        return asdict(self)


class DoctorService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def run(self, *, live: bool = False) -> list[DiagnosticResult]:
        results: list[DiagnosticResult] = []
        supported_python = sys.version_info[:2] == (3, 13)
        results.append(
            DiagnosticResult(
                "Python version",
                "PASS" if supported_python else "FAIL",
                platform.python_version(),
                "Use the repository Python 3.13 environment." if not supported_python else "",
            )
        )
        results.append(
            DiagnosticResult("Platform", "PASS", f"{platform.system()} {platform.machine()}")
        )
        for dependency, required in (
            ("typer", True),
            ("rich", True),
            ("pydantic", True),
            ("psutil", True),
            ("docker", False),
        ):
            installed = importlib.util.find_spec(dependency) is not None
            results.append(
                DiagnosticResult(
                    f"Python dependency: {dependency}",
                    "PASS" if installed else ("FAIL" if required else "WARN"),
                    "installed" if installed else "not installed",
                    f"Install the {dependency} package." if not installed else "",
                )
            )
        results.extend(self._path_checks())
        cache = InventoryService(self.settings).cached()
        results.append(
            DiagnosticResult(
                "Inventory cache",
                "WARN" if cache is None or cache.stale else "PASS",
                "not available" if cache is None else ("stale" if cache.stale else "available"),
                "Run `redteam inventory refresh`." if cache is None or cache.stale else "",
            )
        )
        for executable, optional in (("ssh", False), ("docker", True), ("ollama", True)):
            available = shutil.which(executable)
            results.append(
                DiagnosticResult(
                    f"{executable} executable",
                    "PASS" if available else ("WARN" if optional else "FAIL"),
                    available or "not found",
                    f"Install {executable} or update PATH." if not available else "",
                )
            )
        results.append(
            DiagnosticResult(
                "Kali configuration",
                "PASS" if self.settings.kali_ssh_host else "WARN",
                "configured" if self.settings.kali_ssh_host else "not configured",
                "Set KALI_SSH_HOST and allowlist the alias when Kali is required."
                if not self.settings.kali_ssh_host
                else "",
            )
        )
        runs = RunBrowser(self.settings.report_root).list(limit=10_000)
        corrupt = sum(bool(item["integrity_warnings"]) for item in runs)
        results.append(
            DiagnosticResult(
                "Existing run integrity",
                "WARN" if corrupt else "PASS",
                f"{len(runs)} run(s), {corrupt} with incomplete or corrupt core artifacts",
                "Inspect affected runs with `redteam runs show RUN_ID`." if corrupt else "",
            )
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                artifact = RunArtifacts(Path(directory))
                artifact.write_json("doctor.json", {"status": "ok"})
                artifact.build_manifest()
            artifact_status: CheckStatus = "PASS"
            artifact_text = "temporary write, hash, and manifest succeeded"
        except Exception as exc:
            artifact_status = "FAIL"
            artifact_text = f"{type(exc).__name__}: {exc}"
        results.append(
            DiagnosticResult(
                "Artifact writer smoke",
                artifact_status,
                artifact_text,
                "Check temporary-directory permissions and filesystem health."
                if artifact_status == "FAIL"
                else "",
            )
        )
        results.append(
            DiagnosticResult(
                "Terminal capabilities",
                "PASS",
                f"stdin_tty={sys.stdin.isatty()} stdout_tty={sys.stdout.isatty()} color={'disabled' if 'NO_COLOR' in os.environ else 'available'}",
            )
        )
        if live:
            results.extend(self._live_checks())
        else:
            results.append(
                DiagnosticResult(
                    "Live integrations",
                    "SKIP",
                    "not requested",
                    "Use `redteam doctor --live` for bounded local readiness checks.",
                )
            )
        return results

    def _path_checks(self) -> list[DiagnosticResult]:
        results: list[DiagnosticResult] = []
        for name, path in (
            ("Reports directory", self.settings.report_root),
            ("Inventory cache directory", self.settings.inventory_cache.parent),
        ):
            target = Path(path).expanduser()
            probe = target if target.exists() else target.parent
            writable = probe.exists() and os.access(probe, os.W_OK)
            results.append(
                DiagnosticResult(
                    name,
                    "PASS" if writable else "FAIL",
                    f"{target} ({'writable' if writable else 'not writable'})",
                    "Create the directory and correct its permissions." if not writable else "",
                )
            )
        return results

    def _live_checks(self) -> list[DiagnosticResult]:
        settings = self.settings.model_copy(
            update={
                "ollama_live_check": True,
                "include_kali_readiness": bool(self.settings.kali_ssh_host),
                "kali_live_check": bool(self.settings.kali_ssh_host),
            }
        )
        snapshot = InventoryService(settings).collect(
            include_listeners=False,
            include_targets=False,
            include_http=False,
            include_docker=False,
            include_kali=bool(settings.kali_ssh_host),
            force_refresh=True,
            persist_cache=False,
        )
        return [
            DiagnosticResult(
                "Live local readiness",
                "WARN" if snapshot.errors else "PASS",
                f"{len(snapshot.items)} item(s), {len(snapshot.errors)} typed error(s)",
                "Review inventory adapter errors." if snapshot.errors else "",
            )
        ]


def configuration_validation(settings: Settings) -> list[DiagnosticResult]:
    payload = sanitized_settings(settings)
    results = [
        DiagnosticResult("Typed settings", "PASS", f"{len(payload)} validated settings"),
        DiagnosticResult(
            "Public targets",
            "WARN" if settings.allow_public else "PASS",
            "enabled with allowlist requirements" if settings.allow_public else "disabled",
            "Keep disabled unless explicitly needed." if settings.allow_public else "",
        ),
    ]
    for name, path in (
        ("report_root", settings.report_root),
        ("inventory_cache", settings.inventory_cache),
    ):
        parent = Path(path).expanduser().parent
        results.append(
            DiagnosticResult(
                f"Path: {name}",
                "PASS" if parent.exists() else "WARN",
                str(path),
                f"Create parent directory {parent}." if not parent.exists() else "",
            )
        )
    return results
