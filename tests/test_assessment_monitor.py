import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from assessment_monitor import AssessmentMonitor


class AssessmentMonitorTests(unittest.TestCase):
    def test_writes_redacted_jsonl_and_timeline(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            events_path = Path(temp_dir) / "events.jsonl"
            timeline_path = Path(temp_dir) / "timeline.md"
            with patch.dict("os.environ", {"OPENWEATHER_API_KEY": "ow-test-secret-12345678"}):
                monitor = AssessmentMonitor(
                    request="attack active agents",
                    intent={"action": "attack_active_agents"},
                    events_path=events_path,
                    timeline_path=timeline_path,
                )
                monitor.event(
                    "http_probe",
                    "probe_completed",
                    status="ok",
                    details={"response": "key=ow-test-secret-12345678"},
                )
                artifacts = monitor.write()

            self.assertEqual(artifacts["events_recorded"], 1)
            event = json.loads(events_path.read_text(encoding="utf-8").splitlines()[0])
            timeline = timeline_path.read_text(encoding="utf-8")

        self.assertNotIn("ow-test-secret-12345678", json.dumps(event))
        self.assertNotIn("ow-test-secret-12345678", timeline)
        self.assertIn("<REDACTED:OPENWEATHER_API_KEY>", json.dumps(event))
        self.assertIn("model chain-of-thought", timeline)


if __name__ == "__main__":
    unittest.main()
