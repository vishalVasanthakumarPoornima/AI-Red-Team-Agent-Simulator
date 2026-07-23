# Dexter Assessment Runbook

Dexter is a first-class configurable target adapter, not a hardcoded deployment.
Configure its API base URL and paths under `[redteam.dexter]` in TOML. The safe
default is `http://127.0.0.1:8000` with `/status`, `/chat`, and `/openapi.json`.

## Preconditions

1. Confirm the named services and ports with `redteam inventory --refresh`.
2. Confirm ownership and written authorization for every target component.
3. Keep the API on loopback or an explicitly allowed lab CIDR.
4. If Kali is required, configure an approved SSH alias/key and validate it
   separately. No tunnel is created implicitly by inventory.
5. Review authentication, tool, memory/vector, Ollama, and voice endpoints in
   config; absent endpoints are reported as unverified rather than invented.

## Plan and execute

```bash
redteam assess plan --kind dexter --target http://127.0.0.1:8000 \
  --authorization "I own this local Dexter deployment and authorize bounded testing."

redteam assess run --kind dexter --target http://127.0.0.1:8000 \
  --authorization "I own this local Dexter deployment and authorize bounded testing." \
  --category prompt_injection \
  --category unsafe_url_fetching \
  --rounds 2 --probes 6 --duration 180
```

The adapter performs health/OpenAPI discovery and sends dry-run red-team chat
requests only. It does not assert that browser tools, messaging, memory, vector,
voice, or Kali boundaries are tested unless corresponding evidence exists.
Review the run's `authorization.json`, `events.jsonl`, `findings.json`, report,
and manifest before sharing. Use the legacy split frontend/API Kali workflow
only when that additional active scope is separately authorized.
