"""Safe, fault-tolerant browsing and export of Phase 1 run artifacts."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from redteam_platform.artifacts import sanitize


TEXT_ARTIFACTS = {
    "authorization.json",
    "events.jsonl",
    "findings.json",
    "inventory.json",
    "manifest.json",
    "report.html",
    "report.json",
    "report.md",
    "summary.json",
}
REPORT_FORMATS = {
    "markdown": "report.md",
    "md": "report.md",
    "json": "report.json",
    "html": "report.html",
}


def _display_status(value: str) -> str:
    normalized = str(value or "").lower()
    if normalized in {"pass", "confirmed", "likely", "informational", "complete"}:
        return "complete"
    if normalized in {"error", "timeout", "failed", "failure"}:
        return "failed"
    if normalized in {"cancelled", "canceled"}:
        return "cancelled"
    if normalized in {"active", "running", "queued", "created"}:
        return "active"
    if normalized in {"partial", "unreadable", "unparsed"}:
        return "partial"
    return normalized or "partial"


class RunBrowser:
    def __init__(self, report_root: str | Path):
        self.root = Path(report_root).expanduser()

    def _run_dir(self, run_id: str) -> Path:
        if not run_id.startswith("run_") or Path(run_id).name != run_id:
            raise ValueError("Invalid run ID.")
        root = self.root.resolve()
        run_dir = (root / run_id).resolve()
        if run_dir.parent != root:
            raise ValueError("Run path escapes the configured reports root.")
        if not run_dir.is_dir():
            raise FileNotFoundError(f"Run not found: {run_id}")
        return run_dir

    @staticmethod
    def _read_json(path: Path, default: Any = None) -> tuple[Any, str | None]:
        if not path.is_file():
            return default, f"missing {path.name}"
        try:
            return json.loads(path.read_text(encoding="utf-8")), None
        except (OSError, json.JSONDecodeError) as exc:
            return default, f"corrupt {path.name}: {type(exc).__name__}"

    def list(
        self,
        *,
        limit: int = 20,
        status: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        sort: str = "newest",
    ) -> list[dict[str, Any]]:
        if not self.root.is_dir():
            return []
        rows: list[dict[str, Any]] = []
        for path in self.root.glob("run_*"):
            if not path.is_dir():
                continue
            summary, summary_error = self._read_json(path / "summary.json", {})
            manifest, manifest_error = self._read_json(path / "manifest.json", {})
            findings, findings_error = self._read_json(path / "findings.json", [])
            summary = summary if isinstance(summary, dict) else {}
            manifest = manifest if isinstance(manifest, dict) else {}
            findings = findings if isinstance(findings, list) else []
            run_status = _display_status(
                str(summary.get("status") or manifest.get("status") or "partial")
            )
            started = summary.get("started_at") or manifest.get("started_at")
            target_value = summary.get("target_id") or manifest.get("scope") or ""
            errors = list(summary.get("errors") or manifest.get("errors") or [])
            integrity = [item for item in (summary_error, manifest_error, findings_error) if item]
            row = {
                "run_id": path.name,
                "start_time": started,
                "end_time": summary.get("ended_at") or manifest.get("ended_at"),
                "status": run_status,
                "target": target_value,
                "profile": summary.get("profile"),
                "scope": manifest.get("scope"),
                "finding_count": sum(summary.get("finding_counts", {}).values())
                if isinstance(summary.get("finding_counts"), dict)
                else len(findings),
                "error_count": len(errors) + len(integrity),
                "stop_reason": summary.get("stop_reason") or manifest.get("stop_reason"),
                "integrity_warnings": integrity,
            }
            if status and run_status.lower() != status.lower():
                continue
            if target and target.lower() not in str(target_value).lower():
                continue
            if since and started:
                try:
                    parsed = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
                    comparison = since
                    if parsed.tzinfo and comparison.tzinfo is None:
                        comparison = comparison.replace(tzinfo=parsed.tzinfo)
                    if parsed < comparison:
                        continue
                except ValueError:
                    row["integrity_warnings"].append("invalid start timestamp")
            rows.append(row)
        reverse = sort not in {"oldest", "asc"}
        rows.sort(key=lambda item: str(item.get("start_time") or item["run_id"]), reverse=reverse)
        return rows[: max(0, limit)]

    def show(self, run_id: str) -> dict[str, Any]:
        run_dir = self._run_dir(run_id)
        result: dict[str, Any] = {"run_id": run_id, "warnings": []}
        for filename, key, default in (
            ("summary.json", "summary", {}),
            ("manifest.json", "manifest", {}),
            ("findings.json", "findings", []),
            ("inventory.json", "inventory", None),
        ):
            value, problem = self._read_json(run_dir / filename, default)
            result[key] = value
            if problem:
                result["warnings"].append(problem)
        authorization, problem = self._read_json(run_dir / "authorization.json", {})
        if isinstance(authorization, dict) and authorization:
            statement = authorization.pop("statement", None)
            authorization.pop("human_authorization_statement", None)
            authorization["statement_present"] = bool(statement)
            authorization["statement_length"] = len(str(statement or ""))
        result["authorization_summary"] = authorization
        if problem:
            result["warnings"].append(problem)
        result["artifacts"] = self.artifacts(run_id)
        result["hash_state"] = self.verify_hashes(run_id)
        return sanitize(result)

    def events(self, run_id: str) -> list[dict[str, Any]]:
        path = self._run_dir(run_id) / "events.jsonl"
        if not path.is_file():
            raise FileNotFoundError(f"Missing events artifact for {run_id}")
        events: list[dict[str, Any]] = []
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                item = {"line": number, "status": "corrupt", "raw": "<unreadable>"}
            events.append(sanitize(item))
        return events

    def artifacts(self, run_id: str) -> list[dict[str, Any]]:
        run_dir = self._run_dir(run_id)
        rows: list[dict[str, Any]] = []
        for path in sorted(run_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(run_dir)
            rows.append(
                {
                    "path": str(relative),
                    "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        return rows

    def reports(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for run in self.list(limit=10_000):
            try:
                run_dir = self._run_dir(run["run_id"])
            except (ValueError, FileNotFoundError):
                continue
            formats = [
                name
                for name, filename in (("markdown", "report.md"), ("json", "report.json"), ("html", "report.html"))
                if (run_dir / filename).is_file()
            ]
            if formats:
                rows.append({**run, "formats": formats})
        return rows

    def report_text(self, run_id: str) -> tuple[str, str]:
        run_dir = self._run_dir(run_id)
        for filename in ("report.md", "report.json", "report.html"):
            path = run_dir / filename
            if path.is_file():
                return filename, str(sanitize(path.read_text(encoding="utf-8")))
        raise FileNotFoundError(f"No current report artifact exists for {run_id}")

    def export(
        self,
        run_id: str,
        *,
        format: str,
        destination: str | Path | None = None,
        overwrite: bool = False,
    ) -> Path:
        normalized = format.lower()
        filename = REPORT_FORMATS.get(normalized)
        if not filename:
            raise ValueError("Supported export formats are markdown, json, and existing html.")
        source = self._run_dir(run_id) / filename
        if not source.is_file():
            raise FileNotFoundError(
                f"{normalized} report is unavailable; Phase 3 does not fabricate report formats."
            )
        target = Path(destination) if destination else Path.cwd() / f"{run_id}-{filename}"
        target = target.expanduser()
        if target.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing export: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.suffix.lower() in {".json", ".md", ".html", ".txt"}:
            target.write_text(str(sanitize(source.read_text(encoding="utf-8"))), encoding="utf-8")
        else:
            shutil.copy2(source, target)
        return target

    def verify_hashes(self, run_id: str) -> dict[str, Any]:
        run_dir = self._run_dir(run_id)
        manifest, error = self._read_json(run_dir / "manifest.json", {})
        if error or not isinstance(manifest, dict):
            return {"status": "unavailable", "reason": error}
        checked = 0
        mismatches: list[str] = []
        missing: list[str] = []
        for artifact in manifest.get("artifacts") or []:
            relative = artifact.get("path") if isinstance(artifact, dict) else None
            expected = artifact.get("sha256") if isinstance(artifact, dict) else None
            if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
                mismatches.append(str(relative or "<invalid>"))
                continue
            path = (run_dir / relative).resolve()
            if not path.is_relative_to(run_dir.resolve()):
                mismatches.append(str(relative))
                continue
            if not path.is_file():
                missing.append(str(relative))
                continue
            checked += 1
            if expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                mismatches.append(str(relative))
        return {
            "status": "ok" if not mismatches and not missing else "warning",
            "checked": checked,
            "mismatches": mismatches,
            "missing": missing,
        }
