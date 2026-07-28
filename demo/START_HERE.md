
## Emergency preflight correction

This build fixes the brittle `Unexpected structured Ollama response` gate. The preliminary call now verifies local model availability and a real completed response, while the actual adaptive engine remains responsible for strict proposal-schema validation.

# Full Live Adaptive Dexter Demo

## Run this file

Double-click:

```text
RUN_FULL_ADAPTIVE_DEMO.command
```

The other live launchers are aliases to the same strict workflow.

## What this version fixes

Earlier launchers reached the baseline but failed before adaptive execution because blank `.env` values were parsed as invalid numbers for:

- `adaptive_max_model_calls`
- `adaptive_provider_timeout_seconds`
- `adaptive_provider_retries`
- `adaptive_provider_repairs`

This launcher:

1. removes stale shell values;
2. introspects the installed Pydantic `Settings` model;
3. supplies nonempty typed process-level overrides;
4. verifies the effective adaptive settings;
5. makes a small structured local Ollama call;
6. builds the adaptive plan **before** starting the baseline.

It does not modify the project `.env`.

## What happens

1. Apply memory-safe Ollama limits.
2. Unload any non-Dexter loaded model.
3. Verify Dexter is local-only and using the expected model.
4. Verify Kali SSH and registered tools.
5. Verify the adaptive provider and planner.
6. Display the adaptive plan.
7. Display and run the standard Dexter + Kali plan.
8. Ask you to type `AUTHORIZE` once.
9. Validate the baseline and retry it at most once if a transient coverage error occurred.
10. Run true `adaptive` mode with local Ollama.
11. Require `model_calls > 0`, rounds, probes, proposal decisions, a deterministic stop reason, and valid artifact hashes.
12. Build a separate sanitized demo package and verify its SHA-256 file.
13. Request model unload during cleanup.

## Safety boundary

The local model may propose only registered typed probes. Deterministic code controls:

- authorization;
- exact target and loopback scope;
- Kali adapters;
- tools and ports;
- budgets;
- duplicate detection;
- finding evaluation;
- stopping.

The demo does not run subnet scans, full-port scans, brute force, SQLMap, unrestricted Nuclei, Metasploit, reverse shells, persistence, or arbitrary model-generated commands.

## What counts as success

The launcher exits successfully only when:

- the baseline has no failed steps or unexpected errors;
- at least one registered Kali check completed;
- adaptive mode is `adaptive`;
- the provider is Ollama;
- the planner model is recorded;
- model calls, rounds, probes, and proposal decisions are greater than zero;
- a deterministic stop reason exists;
- the adaptive manifest verifies;
- the final presentation package verifies.

A vulnerability is not required. A valid bounded assessment may stop without a new finding.

## Output

```text
demo/output/demo_<timestamp>/
├── presentation/
│   ├── OPEN_ME_FIRST.html
│   ├── ATTACK_WALKTHROUGH.html
│   ├── DYNAMIC_RESULT.md
│   ├── DYNAMIC_RESULT.json
│   └── sanitized reports and summaries
├── evidence/
│   ├── baseline/
│   └── adaptive/
├── logs/
└── INTEGRITY.sha256
```

The latest package is linked at `demo/output/latest`.

## Input required

Type exactly:

```text
AUTHORIZE
```

Anything else cancels active testing.

## July 28 provider-resolution hotfix

The installed Phase 6 builds do not all expose the provider under an
`adaptive_*` Settings field. This release no longer treats that absence as an
error. It resolves the real contract by testing only the non-executing
`redteam assess plan` command with:

- explicit local-Ollama provider aliases;
- exact Settings aliases discovered at runtime;
- provider-qualified planner model identifiers;
- stable model identifiers returned by the installed model inventory;
- CLI provider/model flags when the installed build exposes them.

The baseline does not start until one adaptive plan succeeds. The selected
arguments are recorded in `logs/adaptive-resolution.json`.
