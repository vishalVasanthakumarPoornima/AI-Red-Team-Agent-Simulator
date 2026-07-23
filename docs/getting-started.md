# Getting started

## Install

Use the repository Python 3.13 environment:

```bash
./scripts/bootstrap_dev.sh
source .venv/bin/activate
redteam --version
```

## Safe first run

```bash
redteam config validate
redteam inventory refresh
redteam inventory summary
redteam agents list
redteam models list
redteam services list
```

The menu offers this same sequence without automatically starting an
assessment. It reads cached status before any refresh. Generic listeners remain
services; they are not promoted to confirmed AI agents.

## First authorized assessment

Choose a synthetic enrolled Python target:

```bash
redteam assess plan \
  --kind python \
  --target tool_agent \
  --category prompt_disclosure \
  --authorization "I own this local synthetic target and authorize bounded testing."
```

Review the normalized target, scope, expected operations, and budget. Replace
`plan` with `start` only when the exact target is authorized. Cancellation
before the final interactive confirmation creates no run.

## Browse results

```bash
redteam runs list
redteam runs show RUN_ID
redteam runs events RUN_ID
redteam runs artifacts RUN_ID
redteam reports list
redteam reports show RUN_ID
```

Phase 3 exports Markdown, JSON, or HTML only when that artifact already exists.
It does not fabricate PDF or silently convert incomplete reports.

## Troubleshooting

Run `redteam doctor`. Warnings keep exit status 0 when the application remains
usable; `--strict` returns 8 for recommended-check warnings. Use `--live` only
when bounded configured-local Ollama/Kali readiness checks are intended.
