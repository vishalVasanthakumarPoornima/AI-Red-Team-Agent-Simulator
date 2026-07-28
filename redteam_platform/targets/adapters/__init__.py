"""Unified target adapter contracts and built-in deterministic adapters."""

from redteam_platform.targets.adapters.base import UnifiedTargetAdapter
from redteam_platform.targets.adapters.builtin import (
    DexterBridgeAdapter,
    RegisteredTargetAdapter,
)

__all__ = ["DexterBridgeAdapter", "RegisteredTargetAdapter", "UnifiedTargetAdapter"]
