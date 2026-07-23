"""Typed, reusable inventory query utilities used by CLI and future API clients."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_platform.inventory.models import (
    AgentDescriptor,
    DiscoveryConfidence,
    InventoryItem,
    Listener,
    OllamaModel,
)


@dataclass(frozen=True)
class InventoryQuery:
    status: str | None = None
    item_type: str | None = None
    running: bool | None = None
    installed: bool | None = None
    agent: str | None = None
    port: int | None = None
    protocol: str | None = None
    loopback: bool | None = None
    wildcard: bool | None = None
    confidence: str | None = None
    stale: bool | None = None

    def apply(self, items: list[InventoryItem]) -> list[InventoryItem]:
        return [item for item in items if self.matches(item)]

    def matches(self, item: InventoryItem) -> bool:
        if self.status and _value(item.status) != self.status:
            return False
        if self.item_type and _value(item.item_type) != self.item_type:
            return False
        if self.running is not None and (
            not isinstance(item, OllamaModel) or item.running != self.running
        ):
            return False
        if self.installed is not None and (
            not isinstance(item, OllamaModel) or item.installed != self.installed
        ):
            return False
        if self.agent and (
            not isinstance(item, AgentDescriptor)
            or self.agent.lower() not in f"{item.name} {item.agent_kind}".lower()
        ):
            return False
        if self.port is not None and item.port != self.port:
            return False
        if self.protocol and (item.protocol or "").lower() != self.protocol.lower():
            return False
        if self.loopback is not None and (
            not isinstance(item, Listener) or item.loopback_only != self.loopback
        ):
            return False
        if self.wildcard is not None and (
            not isinstance(item, Listener) or item.wildcard_bound != self.wildcard
        ):
            return False
        if self.confidence and _value(item.discovery_confidence) != self.confidence:
            return False
        if self.stale is not None and item.stale != self.stale:
            return False
        return True


def validate_confidence(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.lower()
    allowed = {item.value for item in DiscoveryConfidence}
    if normalized not in allowed:
        raise ValueError(f"confidence must be one of: {', '.join(sorted(allowed))}")
    return normalized


def _value(value: object) -> str:
    return str(getattr(value, "value", value))
