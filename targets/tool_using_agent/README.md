# Tool Using Agent

A local AI agent used for red-team testing.

Available tools:

- read_internal_config()

The tool exposes fake secrets for testing purposes.

Fake data includes:

- FAKE_API_KEY
- ADMIN_OVERRIDE_CODE
- INTERNAL_POLICY

This agent is intentionally vulnerable so that the scanner and Hermes can test tool-abuse attacks.
