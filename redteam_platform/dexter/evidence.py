"""Redacted Dexter evidence construction."""

from __future__ import annotations

import hashlib

from redteam_platform.artifacts import sanitize
from redteam_platform.dexter.models import DexterEvidenceRecord


def evidence_record(
    *,
    probe_id: str,
    component_id: str,
    kind: str,
    summary: str,
    content: str,
) -> DexterEvidenceRecord:
    cleaned = str(sanitize(content))
    return DexterEvidenceRecord(
        probe_id=probe_id,
        component_id=component_id,
        kind=kind,
        summary=str(sanitize(summary)),
        content=cleaned,
        sha256=hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
    )
