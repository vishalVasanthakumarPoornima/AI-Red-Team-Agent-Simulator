"""Thin common adapters; execution remains centralized in registered tools."""

from __future__ import annotations

from redteam_platform.targets.adapters.base import UnifiedTargetAdapter
from redteam_platform.targets.models import TargetHealth, TargetState


class RegisteredTargetAdapter(UnifiedTargetAdapter):
    def __init__(self, metadata):
        self.metadata = metadata

    def health(self, target):
        available = [item.name for item in target.capabilities if item.available]
        unavailable = [item.name for item in target.capabilities if not item.available]
        protected = [
            item.name for item in target.capabilities
            if target.authentication.required and item.active
        ]
        overall = target.health
        if overall == TargetState.UNKNOWN:
            overall = TargetState.PROTECTED if protected and not available else TargetState.READY
        return TargetHealth(
            target_id=target.stable_id,
            overall=overall,
            available_capabilities=sorted(set(available) - set(protected)),
            unavailable_capabilities=sorted(set(unavailable)),
            protected_capabilities=sorted(set(protected)),
            errors=target.errors,
        )

    def execute_step(self, step, context):
        if not step.required_tool:
            return None
        tool = context.tools.get(step.required_tool)
        if tool is None:
            raise LookupError(f"Registered tool {step.required_tool} is unavailable.")
        return tool.execute(
            context.tool_request(step), context.target, context.authorization
        )


class DexterBridgeAdapter(RegisteredTargetAdapter):
    """Marker adapter: Dexter execution is delegated to Phase 4 services."""

    def execute_step(self, step, context):
        return context.execute_dexter_step(step)
