"""Assessment event tracing for natural-language red-team runs."""

from datetime import datetime, timezone
from pathlib import Path
import json

from scanner.attack_runner import REPORTS_DIR, truncate_text
from scanner.detectors import redact_configured_secrets


DEFAULT_EVENTS_PATH = REPORTS_DIR / "assessment_events.jsonl"
DEFAULT_TIMELINE_PATH = REPORTS_DIR / "assessment_timeline.md"


def _redact_value(value):
    if isinstance(value, str):
        return redact_configured_secrets(value)
    if isinstance(value, dict):
        return {str(key): _redact_value(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(inner) for inner in value]
    return value


def _escape_table(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def _details_excerpt(details, limit=420):
    if not details:
        return ""
    text = json.dumps(details, sort_keys=True, default=str)
    return truncate_text(text, limit=limit)


class AssessmentMonitor:
    """Collects an auditable trace of observable assessment actions."""

    def __init__(
        self,
        request="",
        intent=None,
        events_path=DEFAULT_EVENTS_PATH,
        timeline_path=DEFAULT_TIMELINE_PATH,
    ):
        self.request = request
        self.intent = _redact_value(intent or {})
        self.events_path = Path(events_path)
        self.timeline_path = Path(timeline_path)
        self.events = []

    def event(self, phase, action, status="info", details=None):
        entry = {
            "sequence": len(self.events) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": str(phase),
            "action": str(action),
            "status": str(status),
            "details": _redact_value(details or {}),
        }
        self.events.append(entry)
        return entry

    def write(self):
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeline_path.parent.mkdir(parents=True, exist_ok=True)
        self.events_path.write_text(
            "\n".join(json.dumps(event, default=str) for event in self.events) + "\n",
            encoding="utf-8",
        )
        self.timeline_path.write_text(self.to_markdown(), encoding="utf-8")
        return {
            "events_jsonl": str(self.events_path),
            "timeline_markdown": str(self.timeline_path),
            "events_recorded": len(self.events),
        }

    def to_markdown(self):
        generated_at = datetime.now(timezone.utc).isoformat()
        lines = [
            "# Assessment Timeline",
            "",
            f"Generated: {generated_at}",
            f"Assessment request: {redact_configured_secrets(self.request)}",
            "",
            "This trace records observable assessment activity: discovered services, generated probes,",
            "HTTP calls, Kali tool commands, return codes, and result status. It does not expose hidden",
            "model chain-of-thought.",
            "",
            "## Interpreted Intent",
            "",
            "```json",
            json.dumps(self.intent, indent=2, sort_keys=True, default=str),
            "```",
            "",
            "## Events",
            "",
            "| # | Time UTC | Phase | Action | Status | Details |",
            "| ---: | --- | --- | --- | --- | --- |",
        ]
        for event in self.events:
            lines.append(
                f"| {event['sequence']} | {_escape_table(event['timestamp'])} | "
                f"{_escape_table(event['phase'])} | {_escape_table(event['action'])} | "
                f"{_escape_table(event['status'])} | "
                f"{_escape_table(_details_excerpt(event.get('details', {})))} |"
            )
        return "\n".join(lines) + "\n"
