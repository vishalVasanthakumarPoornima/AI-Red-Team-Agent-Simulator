"""High-level report generation, export, verification, comparison, and retest."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from redteam_platform.reporting.builder import ReportBuilder
from redteam_platform.reporting.comparison import compare_reports
from redteam_platform.reporting.integrity import verify_manifest, write_report_manifest
from redteam_platform.reporting.models import (
    CanonicalReport,
    ReportComparison,
    ReportMode,
    ReportingWarning,
)
from redteam_platform.reporting.renderers import (
    HtmlRenderer,
    JsonRenderer,
    MarkdownRenderer,
    PdfRenderer,
)
from redteam_platform.reporting.renderers.pdf_renderer import PdfUnavailable
from redteam_platform.reporting.retest import classify_retest


FORMATS = {"json", "markdown", "html", "pdf"}


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class ReportingService:
    def __init__(self, report_root: str | Path):
        self.report_root = Path(report_root).expanduser().resolve()
        self.builder = ReportBuilder()

    def run_dir(self, run_id: str) -> Path:
        if not run_id.startswith("run_") or Path(run_id).name != run_id:
            raise ValueError("Invalid run ID.")
        path = (self.report_root / run_id).resolve()
        if path.parent != self.report_root or not path.is_dir():
            raise FileNotFoundError(f"Run not found: {run_id}")
        return path

    def canonical(self, run_id: str, *, mode: ReportMode = ReportMode.INTERNAL) -> CanonicalReport:
        return self.builder.build(self.run_dir(run_id), mode=mode)

    def build(
        self,
        run_id: str,
        *,
        formats: list[str] | None = None,
        mode: ReportMode = ReportMode.INTERNAL,
        overwrite: bool = False,
        standard_names: bool = True,
    ) -> dict[str, Any]:
        selected = list(dict.fromkeys(formats or ["json", "markdown", "html"]))
        invalid = sorted(set(selected) - FORMATS)
        if invalid:
            raise ValueError("Unsupported report format(s): " + ", ".join(invalid))
        run_dir = self.run_dir(run_id)
        report = self.builder.build(run_dir, mode=mode)
        prefix = "safe_share_report" if mode == ReportMode.SAFE_SHARE else "report"
        if mode == ReportMode.INTERNAL and not standard_names:
            prefix = "report_v7"
        elif mode == ReportMode.INTERNAL and not overwrite:
            if any((run_dir / f"report{suffix}").exists() for suffix in (".json", ".md", ".html")):
                prefix = "report_v7"
        outputs: dict[str, Path] = {}
        if "pdf" in selected:
            path = run_dir / f"{prefix}.pdf"
            if path.exists() and not overwrite:
                raise FileExistsError(f"Refusing to overwrite existing report: {path.name}")
            try:
                PdfRenderer().render_to_path(report, path)
                outputs["pdf"] = path
            except PdfUnavailable as exc:
                report.reporting_warnings.append(
                    ReportingWarning(
                        code="pdf_unavailable",
                        message=str(exc),
                        recovery_command=f"redteam reports build {run_id} --format pdf --overwrite",
                    )
                )
        renderers = {
            "json": (JsonRenderer(), ".json"),
            "markdown": (MarkdownRenderer(), ".md"),
            "html": (HtmlRenderer(), ".html"),
        }
        for format_name in selected:
            if format_name == "pdf":
                continue
            renderer, suffix = renderers[format_name]
            path = run_dir / f"{prefix}{suffix}"
            if path.exists() and not overwrite:
                raise FileExistsError(f"Refusing to overwrite existing report: {path.name}")
            _atomic_text(path, renderer.render(report))
            outputs[format_name] = path
        summaries = {
            "report_summary.json": {
                "schema_version": report.schema_version,
                "report_id": report.report_id,
                "run_id": report.run_id,
                "status": report.assessment_status,
                "profile": report.profile,
                "finding_count": len(report.findings),
                "coverage_percentage": report.coverage.overall_percentage,
                "errors": len(report.errors),
                "timeouts": len(report.timeouts),
                "warnings": [item.model_dump(mode="json") for item in report.reporting_warnings],
            },
            "findings_summary.json": {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "findings": [
                    {
                        "finding_id": item.finding_id,
                        "fingerprint": item.fingerprint,
                        "severity": item.severity,
                        "confidence": item.confidence,
                        "status": item.status,
                        "title": item.title,
                    }
                    for item in report.findings
                ],
            },
            "coverage_summary.json": report.coverage.model_dump(mode="json"),
            "remediation_plan.json": {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "items": [item.model_dump(mode="json") for item in report.recommendations],
            },
        }
        if mode == ReportMode.SAFE_SHARE:
            summaries = {f"safe_share_{name}": value for name, value in summaries.items()}
        for filename, payload in summaries.items():
            path = run_dir / filename
            if path.exists() and not overwrite:
                continue
            _atomic_text(path, json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
            outputs[filename.removesuffix(".json")] = path
        manifest = write_report_manifest(run_dir, list(outputs.values()))
        outputs["manifest"] = manifest
        return {
            "run_id": run_id,
            "mode": mode,
            "report": report,
            "outputs": {key: str(path) for key, path in outputs.items()},
            "warnings": [item.model_dump(mode="json") for item in report.reporting_warnings],
        }

    def export(
        self,
        run_id: str,
        destination: str | Path,
        *,
        formats: list[str] | None = None,
        safe_share: bool = False,
        overwrite: bool = False,
    ) -> Path:
        destination_path = Path(destination).expanduser()
        if destination_path.exists():
            if not destination_path.is_dir():
                raise ValueError("Export destination must be a directory.")
            if not overwrite and any(destination_path.iterdir()):
                raise FileExistsError(f"Refusing to overwrite existing export: {destination_path}")
        else:
            destination_path.mkdir(parents=True, mode=0o700)
        mode = ReportMode.SAFE_SHARE if safe_share else ReportMode.INTERNAL
        report = self.builder.build(self.run_dir(run_id), mode=mode)
        selected = formats or ["json", "markdown", "html"]
        invalid = sorted(set(selected) - FORMATS)
        if invalid:
            raise ValueError("Unsupported report format(s): " + ", ".join(invalid))
        renderers = {
            "json": (JsonRenderer(), "report.json"),
            "markdown": (MarkdownRenderer(), "report.md"),
            "html": (HtmlRenderer(), "report.html"),
        }
        paths: list[Path] = []
        for format_name in selected:
            if format_name == "pdf":
                target = destination_path / "report.pdf"
                PdfRenderer().render_to_path(report, target)
            else:
                renderer, filename = renderers[format_name]
                target = destination_path / filename
                _atomic_text(target, renderer.render(report))
            paths.append(target)
        write_report_manifest(destination_path, paths)
        return destination_path

    def verify(self, run_id: str) -> dict[str, Any]:
        run_dir = self.run_dir(run_id)
        assessment = verify_manifest(run_dir, "manifest.json")
        reports = verify_manifest(run_dir, "report_manifest.json")
        return {
            "run_id": run_id,
            "assessment": assessment.model_dump(mode="json"),
            "reports": reports.model_dump(mode="json"),
            "status": (
                "ok"
                if assessment.status in {"ok", "unavailable"} and reports.status == "ok"
                else "failed"
            ),
        }

    def compare(self, old_run_id: str, new_run_id: str) -> ReportComparison:
        return compare_reports(self.canonical(old_run_id), self.canonical(new_run_id))

    def retest(self, old_run_id: str, new_run_id: str) -> ReportComparison:
        return classify_retest(self.canonical(old_run_id), self.canonical(new_run_id))


def generate_automatic_reports(report_root: str | Path, run_id: str) -> dict[str, Any]:
    """Generate required reports without changing assessment success semantics."""
    service = ReportingService(report_root)
    try:
        return service.build(
            run_id,
            formats=["json", "markdown", "html", "pdf"],
            overwrite=True,
            standard_names=True,
        )
    except Exception as exc:  # reporting failures are persisted, never hidden or promoted
        run_dir = service.run_dir(run_id)
        payload = {
            "schema_version": "7.0",
            "errors": [
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "recovery_command": f"redteam reports build {run_id} --all --overwrite",
                }
            ],
        }
        _atomic_text(
            run_dir / "reporting_errors.json",
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
        )
        return {"run_id": run_id, "outputs": {}, "warnings": [], "errors": payload["errors"]}
