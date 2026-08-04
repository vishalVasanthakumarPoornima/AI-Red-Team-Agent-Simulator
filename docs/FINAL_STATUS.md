# Final Project Status

Final engineering pass: 2026-08-03

Release version: `0.7.0`

Supported runtime: Python 3.13

Primary interface: `redteam`

This document distinguishes verified behavior from optional integrations that
were not available on the final validation host.

## Completed

- Reworked the Typer CLI help system so `--help`, `-h`, `help`,
  `help COMMAND`, and `help GROUP COMMAND` are consistent and useful.
- Added command-specific examples to all 74 leaf command help pages and a root
  guide covering configuration, environment variables, workflows, and support.
- Made invalid commands, target kinds, missing authorization, and expected
  failures return actionable messages and consistent nonzero exit codes without
  normal-user tracebacks.
- Added friendly target-kind aliases such as `python`, `http`, `ollama`, `ip`,
  and `web` while retaining canonical URI kinds.
- Fixed console-entry-point exit-code propagation.
- Fixed report verification after rebuilding `report_manifest.json`; new core
  manifests no longer pin that replaceable nested manifest.
- Removed the API's stale hard-coded version; OpenAPI now reports the package
  version.
- Added an end-to-end narrated demo script and a recoverable reset script.
- Replaced the README with a clean-install quick start, CLI reference,
  architecture and directory maps, troubleshooting, output guidance, and safe
  stop/reset instructions.
- Added the demo guide and project walkthrough, and clearly labeled the older
  repository audit and phase log as historical artifacts.
- Added regression tests for help routing, invalid inputs, aliases, exit-code
  propagation, version consistency, and report-manifest replacement.

## Verified workflows

| Workflow | Verification |
| --- | --- |
| Clean developer setup | `./scripts/bootstrap_dev.sh` completed under Python 3.13 |
| Clean package install | Fresh venv installed `0.7.0`; root help rendered and doctor returned success across 18 checks (optional checks may warn or skip) |
| Root and command help | `--help`, `-h`, generic help, nested help, and invalid-command behavior passed |
| Complete help inventory | 74 leaf help pages rendered; every page contained an example |
| Deterministic validation | Unit tests, compilation, doctor, discovery, six scanner cases, agent discovery, and three loopback service smokes passed |
| Main demo | `./scripts/run_demo.sh` completed through report build and manifest verification |
| Report integrity | Assessment manifest 27/27 and report manifest 1/1 verified for the final demo run |
| Optional loopback API | Health returned 200, unauthenticated inventory 401, authenticated inventory 200, OpenAPI version `0.7.0` |
| Distribution build | Wheel `ai_agent_red_team_simulator-0.7.0-py3-none-any.whl` built successfully |
| Installed dependencies | `pip check` passed; `pip-audit` found no known vulnerabilities |

Final demo run: `run_20260804T000711Z_dc42db97c2f64bc1` (UTC run ID),
complete with 100% probe coverage, one deterministic finding, and zero errors.

## Test results

| Check | Result |
| --- | --- |
| `RUN_SERVICE_SMOKE=1 ./scripts/validate.sh` | PASS — 297 tests, compile, doctor, 6 scanner checks, discovery, and 3 service fixtures |
| `.venv/bin/coverage run -m unittest discover -s tests` | PASS — 297 tests; 72% total coverage (65% minimum) |
| Changed-file Ruff check | PASS |
| `.venv/bin/python -m build` equivalent wheel build | PASS via `pip wheel . --no-deps` |
| `.venv/bin/python -m pip check` | PASS |
| `.venv/bin/pip-audit --cache-dir /tmp/ai-red-team-pip-audit-cache` | PASS — no known vulnerabilities |
| `.venv/bin/python -m ruff check . --statistics` | FAIL — 319 existing repository-wide style findings, 299 auto-fixable |
| `.venv/bin/python -m mypy redteam_platform` | FAIL — 174 existing typing findings in 42 files |
| Docker image build | NOT RUN — Docker CLI installed; Docker Desktop daemon unavailable |

`scripts/validate.sh` keeps Ruff and mypy as explicit opt-ins with
`RUN_RUFF=1`, `RUN_MYPY=1`, or `RUN_STATIC_CHECKS=1`. This makes the default
gate honest and deterministic while the remaining legacy static-analysis debt
is visible rather than hidden.

## Remaining limitations

- Repository-wide Ruff and mypy debt remains as quantified above. Files changed
  during this pass pass the focused Ruff check.
- Live Ollama, Kali/SSH, Docker, and external-provider workflows need their
  actual local-lab services and explicit authorization; they were not exercised
  and are not part of the dependency-free demo claim.
- The optional API is intended for authenticated loopback use, not public
  internet deployment.
- There is no frontend in this repository. Reports and the optional API are the
  non-CLI interfaces.
- Legacy entry points remain for compatibility; `redteam` is authoritative.

## Demo commands

From a clean clone:

```bash
cd AI-Red-Team-Agent-Simulator
./scripts/bootstrap_dev.sh
source .venv/bin/activate
cp .env.example .env
redteam --help
./scripts/run_demo.sh
```

Before recording, archive existing generated reports without deleting them:

```bash
./scripts/reset_demo.sh
./scripts/run_demo.sh
```

Inspect a run again using the ID printed by the script:

```bash
redteam runs show RUN_ID
redteam reports show RUN_ID
redteam reports verify RUN_ID
redteam reports findings RUN_ID
redteam reports coverage RUN_ID
```

No background process is required for this demo. If the optional API is shown,
start it with `redteam api serve` after setting a non-demo
`REDTEAM_API_TOKEN`, and stop it with `Ctrl-C`.

## Architecture study order

1. `README.md` and `docs/DEMO_GUIDE.md`
2. `redteam_platform/cli/app.py` and `redteam_platform/cli/commands/`
3. `redteam_platform/config.py`, `scope.py`, `authorization.py`, and `targets.py`
4. `redteam_platform/assessments/service.py` and `assessments/`
5. `redteam_platform/evaluators/` and `findings.py`
6. `redteam_platform/artifacts.py`, `reporting/`, and `run_store.py`
7. `redteam_platform/api.py` and `tests/`
8. Optional integrations: `adaptive_engine/`, `dexter/`, and Kali adapters

## Important files

| File | Purpose | Why it matters |
| --- | --- | --- |
| `README.md` | Setup and operator guide | Defines the supported first experience |
| `pyproject.toml` | Package, entry point, and tool configuration | Source of install and version behavior |
| `redteam_platform/cli/app.py` | Root CLI assembly and error boundary | All supported commands enter here |
| `redteam_platform/cli/examples.py` | Central help examples | Keeps 74 command pages consistent |
| `redteam_platform/targets.py` | Typed target parsing/resolution | Normalizes what will be assessed |
| `redteam_platform/scope.py` | Scope enforcement | Prevents unintended target expansion |
| `redteam_platform/authorization.py` | Authorization validation | Separates consent from convenience flags |
| `redteam_platform/assessments/service.py` | Main workflow orchestration | Connects target, plan, execution, and artifacts |
| `redteam_platform/assessments/` | Planning, bounded tools, evaluation, and coverage | Implements the deterministic assessment lifecycle |
| `redteam_platform/reporting/` | Normalization and report generation | Produces and verifies portfolio artifacts |
| `redteam_platform/api.py` | Optional authenticated API | Exposes loopback automation without changing policy |
| `scripts/run_demo.sh` | Narrated demonstration | Reproduces the main portfolio story |
| `scripts/validate.sh` | Deterministic quality gate | Records what is actually supported |
| `tests/` | Regression suite | Protects safety and demo behavior |

## Environment requirements

| Requirement | Value |
| --- | --- |
| Python | 3.13 (`.python-version`) |
| Base setup | `./scripts/bootstrap_dev.sh` |
| Required environment variables | None for the deterministic local demo |
| Demo target | Enrolled `python://tool_agent` fixture |
| Generated state | `reports/<run-id>/` and `.redteam/` |
| Optional API | Loopback `127.0.0.1:8000`; requires `REDTEAM_API_TOKEN` |
| Optional Ollama | `OLLAMA_URL` (default `http://127.0.0.1:11434`) and installed model |
| Optional Kali | Authorized SSH lab plus Kali configuration from `.env.example` |
| Optional Docker | Running Docker Desktop daemon |
