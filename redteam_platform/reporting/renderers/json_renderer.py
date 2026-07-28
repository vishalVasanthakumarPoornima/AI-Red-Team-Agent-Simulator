"""Stable machine-readable JSON renderer."""

import json

from redteam_platform.reporting.models import CanonicalReport


class JsonRenderer:
    media_type = "application/json"
    suffix = ".json"

    def render(self, report: CanonicalReport) -> str:
        validated = CanonicalReport.model_validate(report)
        return json.dumps(
            validated.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ) + "\n"
