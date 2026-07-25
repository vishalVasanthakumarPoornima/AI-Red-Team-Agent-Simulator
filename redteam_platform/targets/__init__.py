"""Unified deterministic target parsing, resolution, and adapter registry."""

from redteam_platform.targets.models import (
    TargetDescriptor,
    TargetDiscoveryResult,
    TargetInput,
    TargetKind,
    TargetResolution,
)
from redteam_platform.targets.parser import TargetParser
from redteam_platform.targets.registry import TargetAdapterRegistry
from redteam_platform.targets.resolver import TargetResolver

__all__ = [
    "TargetAdapterRegistry",
    "TargetDescriptor",
    "TargetDiscoveryResult",
    "TargetInput",
    "TargetKind",
    "TargetParser",
    "TargetResolution",
    "TargetResolver",
]
