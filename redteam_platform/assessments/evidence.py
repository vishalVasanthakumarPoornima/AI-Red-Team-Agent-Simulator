"""Sanitized, content-addressed evidence construction."""

from __future__ import annotations

import hashlib

from redteam_platform.artifacts import sanitize
from redteam_platform.assessments.models import EvidenceRecord, ProbeDefinition, ToolResult


def evidence_from_result(probe: ProbeDefinition, target_id: str, result: ToolResult) -> EvidenceRecord:
    content = str(sanitize(result.evidence_content or result.data or result.error or ""))
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return EvidenceRecord(
        evidence_id=f"evidence_{digest[:20]}",
        probe_id=probe.probe_id,
        target_id=target_id,
        kind=probe.expected_evidence,
        summary=f"{probe.name}: {str(result.status)}",
        content=content,
        sha256=digest,
    )
