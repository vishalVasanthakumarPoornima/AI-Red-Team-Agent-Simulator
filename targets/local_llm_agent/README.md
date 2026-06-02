# Local LLM Agent Target

This target uses a locally installed Ollama model as a test AI agent.

The agent is intentionally configured with fake internal information so the scanner can test for:

- Prompt injection
- System prompt disclosure
- Secret extraction
- Internal policy leakage

All secrets are fake and safe for local testing.
