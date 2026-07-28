"""Compatibility reporter for the original adaptive service."""

from __future__ import annotations

import html
import json
from pathlib import Path


class EnterpriseReporter:
    """Retains the Phase 1-4 writer contract while Phase 7 becomes canonical."""

    def build_markdown(self, metadata, request, summary, findings, inventory, events) -> str:
        lines = [
            f"# {metadata.title}",
            "",
            f"Run ID: {metadata.run_id}",
            f"Target: {metadata.target_name}",
            "",
            "## Executive Summary",
            "",
            f"- Run status: {summary.status}",
            f"- Findings: {len(findings)}",
            f"- Total probes: {summary.probes}",
            "",
            "## Scope and Authorization",
            "",
            f"- Scope: {metadata.scope}",
            f"- Authorization record: {metadata.authorization_id}",
            "",
            "## Findings Summary",
            "",
        ]
        lines.extend(
            f"- **{item.severity}** `{item.id}` — {item.title}" for item in findings
        )
        lines.extend(
            [
                "",
                "## Coverage",
                "",
                f"- Attempted: {', '.join(summary.coverage.categories_attempted) or 'none'}",
                f"- Completed: {', '.join(summary.coverage.categories_completed) or 'none'}",
                "",
                "## Limitations",
                "",
                "- This bounded assessment provides evidence, not proof of security or compliance certification.",
                "",
            ]
        )
        return "\n".join(lines)

    def write(self, artifacts, metadata, request, summary, findings, inventory, events) -> dict[str, str]:
        markdown = self.build_markdown(metadata, request, summary, findings, inventory, events)
        artifacts._write_text("report.md", markdown + "\n")
        artifacts._write_text(
            "report.html",
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>{html.escape(metadata.title)}</title></head><body><pre>"
            f"{html.escape(markdown)}</pre></body></html>",
        )
        artifacts.write_json(
            "report.json",
            {
                "metadata": metadata,
                "request": request,
                "summary": summary,
                "findings": findings,
                "inventory": inventory,
                "events": events,
            },
        )
        return {
            "markdown": str(artifacts.run_dir / "report.md"),
            "html": str(artifacts.run_dir / "report.html"),
            "json": str(artifacts.run_dir / "report.json"),
        }
