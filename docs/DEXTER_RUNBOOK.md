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
redteam dexter discover
redteam dexter health DEXTER_ID
redteam dexter plan DEXTER_ID --profile standard
redteam dexter assess DEXTER_ID \
  --profile standard \
  --authorization "I own this local Dexter deployment and authorize bounded testing."
```

The complete plan is deterministic and visible before execution. Standard
mode performs bounded AI, API, fake-tool, synthetic memory/retrieval, service,
rate-limit, evaluation, coverage, and report steps only where capabilities are
configured. Missing capabilities remain explicit unavailable coverage.
Review `authorization.json`, `assessment_plan.json`, `events.jsonl`,
`findings.json`, `coverage.json`, the reports, and the manifest before sharing.
See [Dexter assessment](dexter-assessment.md) for the full safety model.
