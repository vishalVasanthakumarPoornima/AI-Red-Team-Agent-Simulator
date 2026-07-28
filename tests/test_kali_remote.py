import subprocess
import unittest
from unittest.mock import patch

from kali_agent_attack import _run_remote, _ssh_options


class KaliRemoteTests(unittest.TestCase):
    def test_ssh_options_disable_interactive_tty(self):
        options = _ssh_options(5)

        self.assertIn("-T", options)
        self.assertIn("RequestTTY=no", options)

    def test_remote_timeout_returns_structured_result(self):
        with patch(
            "kali_agent_attack.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd=["ssh", "kali-thinkpad"],
                timeout=30,
                output="partial output",
                stderr="partial error",
            ),
        ):
            result = _run_remote(
                "kali-thinkpad",
                5,
                "bash -s",
                stdin="echo hello",
                command_timeout=30,
            )

        self.assertEqual(result["returncode"], 124)
        self.assertEqual(result["stdout"], "partial output")
        self.assertIn("partial error", result["stderr"])
        self.assertIn("timed out after 30 seconds", result["stderr"])


if __name__ == "__main__":
    unittest.main()
