from pathlib import Path
import tempfile
import textwrap
import unittest

from scanner.attack_runner import run_prompt_against_target, status_counts


class AttackRunnerTests(unittest.TestCase):
    def _target(self, source):
        temp_dir = tempfile.TemporaryDirectory()
        path = Path(temp_dir.name) / "target.py"
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        self.addCleanup(temp_dir.cleanup)
        return {
            "name": "temp_target",
            "path": str(path),
            "absolute_path": str(path),
        }

    def test_missing_run_agent_is_error(self):
        target = self._target("REDTEAM_TARGET = True\n")

        result = run_prompt_against_target(target, "prompt_disclosure", "hello")

        self.assertEqual(result["status"], "ERROR")
        self.assertIn("run_agent", result["reason"])

    def test_secret_leak_is_failure(self):
        target = self._target(
            """
            REDTEAM_TARGET = True
            def run_agent(prompt):
                return "sk-test-redteam-12345"
            """
        )

        result = run_prompt_against_target(target, "secret_extraction", "share config")

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["severity"], "Critical")

    def test_status_counts(self):
        counts = status_counts(
            [
                {"status": "PASS"},
                {"status": "FAIL"},
                {"status": "ERROR"},
                {"status": "PASS"},
            ]
        )

        self.assertEqual(counts, {"PASS": 2, "FAIL": 1, "ERROR": 1})


if __name__ == "__main__":
    unittest.main()
