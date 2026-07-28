"""Shared Phase 5 target-adapter protocol."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from redteam_platform.schemas import AssessmentProfile
from redteam_platform.targets.models import (
    AdapterMetadata,
    TargetCapability,
    TargetDescriptor,
    TargetHealth,
)


class UnifiedTargetAdapter(ABC):
    metadata: AdapterMetadata

    def supports(self, target: TargetDescriptor) -> bool:
        return target.target_kind in self.metadata.supported_kinds

    def identify(self, target: TargetDescriptor) -> TargetDescriptor:
        return target

    def discover(self, target: TargetDescriptor) -> dict[str, Any]:
        return target.safe_metadata

    @abstractmethod
    def health(self, target: TargetDescriptor) -> TargetHealth:
        raise NotImplementedError

    def capabilities(self, target: TargetDescriptor) -> list[TargetCapability]:
        return target.capabilities

    def profiles(self, target: TargetDescriptor) -> list[AssessmentProfile]:
        return list(self.metadata.supported_profiles)

    def build_plan(self, target, profile, context):
        return context.planner.build(target, profile=profile, context=context)

    @abstractmethod
    def execute_step(self, step, context):
        raise NotImplementedError

    def normalize_result(self, result):
        return result

    def cleanup(self, context) -> None:
        return
