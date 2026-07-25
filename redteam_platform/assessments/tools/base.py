"""Common tool helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from redteam_platform.assessments.models import ToolRequest, ToolResult


class RegisteredTool(ABC):
    name: str

    @abstractmethod
    def execute(self, request: ToolRequest, target, authorization) -> ToolResult:
        raise NotImplementedError

    def cleanup(self) -> None:
        return
