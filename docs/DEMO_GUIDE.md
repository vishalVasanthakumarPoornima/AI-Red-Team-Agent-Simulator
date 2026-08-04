# Demo Guide

This guide records the safest repeatable portfolio path: a deterministic assessment of the repository's enrolled synthetic `tool_agent`. It needs no external service and produces a real run, finding, coverage record, report, and verified manifest.

## Prerequisites

- macOS or Linux terminal
- Git
- Python 3.13 (the supported version is pinned in `.python-version`)
- Repository cloned locally
- Authorization to execute this repository's synthetic target
- About two minutes for setup after dependencies are installed

Ollama, Docker, Kali, an API key, a database, and internet access are not required for the main recording.

## One-time setup

```bash
cd AI-Red-Team-Agent-Simulator
./scripts/bootstrap_dev.sh
source .venv/bin/activate
cp .env.example .env
redteam --version
```

Expected result: bootstrap reports `Development environment ready` and `redteam --version` prints `0.7.0`.

## Reset before recording

```bash
./scripts/reset_demo.sh
```

Expected result: any existing `reports/` tree is moved to a timestamped temporary backup. Nothing is permanently deleted, and the recovery location is printed.

Then verify the baseline:

```bash
RUN_SERVICE_SMOKE=1 ./scripts/validate.sh
```

Expected result: unit tests, compilation, CLI doctor smoke, target discovery, deterministic scanner smoke, three loopback service fixtures, and `git diff --check` complete successfully. Static analysis is a separate explicit audit; see `docs/FINAL_STATUS.md`.

## Recommended demo sequence

The automated recording path is:

```bash
./scripts/run_demo.sh
```

The script prints a short viewer-facing explanation before each operation and finishes with `RUN_ID=...`. Its eight steps are listed below so you can narrate them manually if preferred.

### 1. Show the professional CLI

```bash
redteam --help
redteam help assess run
```

Expected: the main page shows the command tree, global configuration/environment guidance, workflows, examples, and command-help syntax. The second command shows required/optional assessment arguments, defaults, and a real example.

What it proves: the project is packaged as a discoverable tool rather than a collection of undocumented scripts.

Suggested narration: “The installed Typer CLI is the supported entry point. Every command has validated arguments, a stable help path, JSON output support, and consistent exit behavior.”

### 2. Diagnose readiness

```bash
redteam doctor
redteam config validate
```

Expected: required Python/runtime/path checks pass. Optional integrations may appear as warnings or skips without being described as successful.

What it proves: failures are surfaced before an assessment starts, and configuration is typed and secret-safe.

Suggested narration: “Doctor distinguishes required readiness from optional integrations. Configuration validation is offline and never prints secret values.”

### 3. Refresh passive inventory

```bash
redteam inventory refresh
redteam inventory summary
```

Expected: a typed local snapshot is cached under `reports/cache/inventory.json`; enrolled Python targets are included. No target is invoked.

What it proves: discovery is separate from active testing.

Suggested narration: “Inventory reads local listeners, enrolled modules, configured endpoints, and cached metadata. Live Ollama, Docker, and Kali checks require explicit opt-in.”

### 4. Resolve one exact target

```bash
redteam targets resolve tool_agent --kind python
```

Expected: `tool_agent` resolves to `python://tool_agent`, reports loopback scope, enrollment evidence, capabilities, and a stable ID.

What it proves: user input becomes a normalized typed target before planning.

Suggested narration: “The resolver correlates explicit enrollment with inventory and scope policy; it does not guess that every open port is an AI agent.”

### 5. Preview the plan

```bash
redteam assess plan python://tool_agent --profile standard
```

Expected: ordered phases, registered probes, safety constraints, request limits, and time budgets are shown. No run directory is created.

What it proves: the user can review every operation before execution.

Suggested narration: “Plans are deterministic and capability-aware. There are no hidden steps, arbitrary model-generated commands, or unbounded targets.”

### 6. Execute with human authorization

```bash
redteam assess run python://tool_agent \
  --profile standard \
  --authorization "I own this local synthetic target and authorize bounded testing."
```

Expected: the run completes, coverage is reported, the deliberately simple target produces a real synthetic-secret finding, and the CLI prints artifact locations. Save the displayed run ID as `RUN_ID`.

What it proves: authorization, registered tools, deterministic evaluation, and run-scoped evidence work end to end.

Suggested narration: “The human statement is bound to the normalized target. The synthetic canary is safe test data; the evaluator creates a finding from observed evidence, not from model opinion.”

### 7. Inspect the result

```bash
redteam runs show RUN_ID
redteam runs events RUN_ID
redteam reports findings RUN_ID
redteam reports coverage RUN_ID
```

Expected: summary, sanitized lifecycle events, finding details, and explicit coverage are displayed.

What it proves: results remain inspectable and unavailable coverage is never converted into a pass.

Suggested narration: “Coverage means planned surface exercised, not a security score. Findings point to sanitized evidence and retest guidance.”

### 8. Build and verify the report

```bash
redteam reports build RUN_ID --format html
redteam reports verify RUN_ID
redteam reports show RUN_ID
```

Expected: HTML generation succeeds, manifest verification reports no missing or modified files, and the report can be reviewed in the terminal. The HTML file is under `reports/runs/RUN_ID/`.

What it proves: reporting is reproducible and evidence integrity is checked.

Suggested narration: “Canonical reporting normalizes legacy and current artifacts, redacts unsafe values, and hashes every report output for tamper detection.”

## Copy-paste recording block

```bash
source .venv/bin/activate
./scripts/reset_demo.sh
redteam --help
redteam help assess run
./scripts/run_demo.sh
# Copy RUN_ID from the last line, then:
redteam runs show RUN_ID
redteam reports show RUN_ID
```

## Optional live-model segment

Use this only after the deterministic segment succeeds.

Terminal 1:

```bash
ollama serve
```

Terminal 2:

```bash
ollama pull llama3.2:1b
redteam models list --live
redteam adaptive status
redteam adaptive plan tool_agent --kind python --adaptive-mode guided
```

This proves local model discovery and bounded adaptive planning. Do not make the optional segment the only demo path; model load time and local resource pressure are outside the deterministic application contract.

## Common demo failures and quick recovery

| Failure | Likely reason | Recovery |
| --- | --- | --- |
| `redteam: command not found` | Virtual environment is inactive | `source .venv/bin/activate` or use `.venv/bin/redteam` |
| Installed version is not `0.7.0` | Editable package metadata is stale | `./scripts/bootstrap_dev.sh` |
| `reports/` contains old runs | Reset was skipped | `./scripts/reset_demo.sh`; the old tree is moved, not deleted |
| Target cannot resolve | Wrong name/kind or stale environment | `redteam inventory refresh` then `redteam targets resolve tool_agent --kind python` |
| Authorization error | Missing/short statement | Use the exact human statement shown above; `--yes` never supplies authorization |
| Port warning in doctor | Optional local service already uses a port | The main demo does not need that service; stop it in its owning terminal or continue if doctor marks it optional |
| HTML build fails | Run ID was copied incorrectly or run is incomplete | `redteam runs list --limit 5`, copy the exact ID, then retry |
| Manifest verification fails | Artifact changed after creation | Preserve the run for explanation; reset and rerun rather than editing evidence |
| Ollama unavailable | Optional model service is stopped/model absent | Skip the optional segment or run `ollama serve` and `ollama pull llama3.2:1b` |
| Kali/Docker unavailable | Optional lab integration is not configured | Continue with the deterministic path; the platform records incomplete optional coverage truthfully |

## Stop all services cleanly

The main demo starts no persistent service. `run_demo.sh` returns to the shell when complete.

- Stop `ollama serve`, `redteam api serve`, `agent_service.py`, or `agent_lab_server.py` with `Ctrl-C` in the terminal that started it.
- `scripts/service_smoke.sh` and the validation gate install exit traps and terminate only their own fixture processes.
- Do not use broad `pkill` commands during a recording; they can terminate unrelated user processes.

## Final recording checklist

- `git status --short` contains no secret or generated report files intended for commit.
- `.env` contains only local values and is ignored.
- `redteam --version` prints `0.7.0`.
- `RUN_SERVICE_SMOKE=1 ./scripts/validate.sh` passes.
- `./scripts/reset_demo.sh` has been run.
- The deterministic demo completes before any optional integration segment.
- The final `RUN_ID` and HTML report path are visible on screen.
- The explanation uses “authorized assessment,” “synthetic target,” and “coverage,” not claims of production certification.
