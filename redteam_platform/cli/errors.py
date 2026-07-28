"""Expected CLI failures and centralized exit-code mapping."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_platform.cli.exit_codes import ExitCode
from redteam_platform.adapters import AdapterError
from redteam_platform.scope_policy import ScopeDeniedError
from redteam_platform.settings import ConfigurationError


@dataclass
class CLIError(Exception):
    message: str
    code: ExitCode = ExitCode.GENERAL_FAILURE
    error_type: str = "cli_error"
    remediation: str = ""

    def __str__(self) -> str:
        return self.message


class NonInteractivePromptError(CLIError):
    def __init__(self, message: str = "This operation requires interactive input."):
        super().__init__(
            message,
            ExitCode.INVALID_USAGE,
            "non_interactive_prompt",
            "Provide every required option or run from an interactive terminal.",
        )


class ArtifactCLIError(CLIError):
    def __init__(self, message: str):
        super().__init__(
            message,
            ExitCode.ARTIFACT_FAILURE,
            "artifact_error",
            "Verify the run ID, artifact name, destination, and permissions.",
        )


def normalize_error(exc: Exception) -> CLIError:
    if isinstance(exc, CLIError):
        return exc
    if isinstance(exc, ConfigurationError):
        return CLIError(
            str(exc),
            ExitCode.INVALID_CONFIGURATION,
            "invalid_configuration",
            "Run `redteam config validate` after correcting the configuration.",
        )
    if isinstance(exc, ScopeDeniedError):
        return CLIError(
            str(exc),
            ExitCode.SCOPE_OR_AUTHORIZATION_DENIED,
            "scope_or_authorization_denied",
            "Review `redteam scope explain TARGET` and provide human authorization.",
        )
    if isinstance(exc, AdapterError):
        denied = "outside passive inventory scope" in str(exc).lower()
        return CLIError(
            str(exc),
            (
                ExitCode.SCOPE_OR_AUTHORIZATION_DENIED
                if denied
                else ExitCode.TARGET_UNAVAILABLE
            ),
            "scope_or_authorization_denied" if denied else "target_unavailable",
            (
                "Review `redteam scope explain TARGET`."
                if denied
                else "Verify the target exists and is currently supported."
            ),
        )
    if isinstance(exc, LookupError):
        return CLIError(
            str(exc),
            ExitCode.TARGET_UNAVAILABLE,
            "target_unavailable",
            "Run `redteam dexter discover` and use the exact stable ID.",
        )
    if isinstance(exc, FileNotFoundError):
        return ArtifactCLIError(str(exc))
    if isinstance(exc, PermissionError):
        return CLIError(
            str(exc),
            ExitCode.ARTIFACT_FAILURE,
            "permission_denied",
            "Check ownership and filesystem permissions.",
        )
    return CLIError(str(exc) or type(exc).__name__)
