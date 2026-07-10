import os
import unittest
from unittest.mock import patch

from targets.local_llm_agent import ollama_agent


class OllamaAgentConfigTests(unittest.TestCase):
    def test_default_ollama_url_points_to_local_api(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                ollama_agent._ollama_url(),
                "http://localhost:11434/api/generate",
            )

    def test_ollama_url_can_be_overridden_for_hosted_services(self):
        with patch.dict(
            os.environ,
            {"OLLAMA_URL": "https://ollama.example.test/api/generate"},
            clear=True,
        ):
            self.assertEqual(
                ollama_agent._ollama_url(),
                "https://ollama.example.test/api/generate",
            )


if __name__ == "__main__":
    unittest.main()
