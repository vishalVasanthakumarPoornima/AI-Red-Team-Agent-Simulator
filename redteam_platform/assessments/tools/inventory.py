"""Side-effect-free typed inventory evidence tool."""

from __future__ import annotations

from datetime import datetime, timezone

from redteam_platform.artifacts import sanitize
from redteam_platform.assessments.models import ResultState, ToolResult
from redteam_platform.assessments.tools.base import RegisteredTool


class InventoryEvidenceTool(RegisteredTool):
    name = "inventory"

    def execute(self, request, target, authorization):
        data = {
            "stable_id": target.stable_id,
            "kind": str(target.target_kind),
            "discovery_source": target.discovery_source,
            "discovery_confidence": target.discovery_confidence,
            "related_inventory_ids": target.related_inventory_ids,
            "safe_metadata": target.safe_metadata,
        }
        return ToolResult(
            request_id=request.request_id,
            tool=self.name,
            status=ResultState.INFORMATIONAL,
            started_at=datetime.now(timezone.utc),
            data=sanitize(data),
            evidence_content=str(sanitize(data)),
        )
