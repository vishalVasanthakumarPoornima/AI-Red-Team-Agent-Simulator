from pathlib import Path
import tempfile
import unittest

from scanner.target_loader import declares_redteam_target, discover_targets


class TargetLoaderTests(unittest.TestCase):
    def test_marker_controls_discovery_eligibility(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target_file = Path(temp_dir) / "candidate.py"
            target_file.write_text("REDTEAM_TARGET = True\n", encoding="utf-8")
            self.assertTrue(declares_redteam_target(target_file))

            target_file.write_text("REDTEAM_TARGET = False\n", encoding="utf-8")
            self.assertFalse(declares_redteam_target(target_file))

            target_file.write_text("def run_agent(prompt):\n    return prompt\n", encoding="utf-8")
            self.assertFalse(declares_redteam_target(target_file))

    def test_discovery_includes_only_explicit_targets(self):
        names = {target["name"] for target in discover_targets()}

        self.assertIn("ollama_agent", names)
        self.assertIn("travel_agent", names)
        self.assertIn("tutor_agent", names)
        self.assertIn("weather_insight_agent", names)
        self.assertIn("travel_planner_agent", names)
        self.assertNotIn("dexter_agent", names)

    def test_invalid_python_is_not_discoverable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target_file = Path(temp_dir) / "broken.py"
            target_file.write_text("REDTEAM_TARGET = True\nif", encoding="utf-8")

            self.assertFalse(declares_redteam_target(target_file))


if __name__ == "__main__":
    unittest.main()
