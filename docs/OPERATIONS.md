# Operations Runbook

## Setup

Prerequisites are Python 3.13 and Git. Ollama, Docker, SSH, and Kali are optional.

```bash
./scripts/bootstrap_dev.sh
source .venv/bin/activate
cp config.example.toml redteam.toml
redteam --config redteam.toml doctor
```

For an exact runtime-only environment, create a Python 3.13 virtual environment,
install `requirements.lock`, then install this repository with `--no-deps`.

## Inventory and assessment

```bash
redteam inventory --json --refresh
redteam models --json
redteam agents --json
redteam services --json
redteam assess run --kind python --target tool_agent \
  --authorization "I own this local synthetic target and authorize bounded testing." \
  --rounds 3 --probes 10 --model-calls 0 --duration 120
redteam runs list
redteam runs show RUN_ID --artifact report.md
```

For Ollama/OpenAI-compatible targets, pass both the endpoint and explicit target
model with `--target-model`. `--planner-model` separately selects the local
model used to propose registered assessment prompts.

## API

Generate a token into a protected local config with `redteam init`, or export
`REDTEAM_API_TOKEN`. Start with `redteam api serve`. The default address is
`127.0.0.1:18150`; non-loopback binds are rejected. API runs are asynchronous;
use the returned ID with the status and SSE event endpoints.

## Validation

```bash
./scripts/validate.sh
RUN_SERVICE_SMOKE=1 ./scripts/validate.sh
ruff check redteam_platform tests
ruff format --check redteam_platform tests
mypy redteam_platform
coverage run -m unittest discover -s tests
coverage report
pip-audit -r requirements.lock
```

External checks are opt-in. Do not run Kali, Docker, public network, provider,
or Dexter actions unless the target is explicitly authorized and configured.
Live Ollama metadata uses `redteam models --json --live`; Kali SSH readiness
uses `redteam kali-status --json --live`. Both remain off by default.

## Docker

The image is primarily for reproducible CLI/API packaging. Its API remains
bound to loopback inside the container; operate it with `docker exec` or an
explicitly reviewed network design. Host listener/process inventory reflects
the container, not the macOS host. Never bake API tokens or SSH keys into an
image.

## Troubleshooting

- `Target is outside scope`: inspect `allowed_cidrs`/`allowed_domains`; do not
  broaden them unless authorization exists.
- `resolution changed`: DNS answers changed after authorization; create a new
  plan only after reviewing the destination.
- `API token is not configured`: set `REDTEAM_API_TOKEN` or use `redteam init`.
- `planner output invalid`: confirm Ollama is reachable and the selected model
  can return strict JSON; deterministic planning remains available.
- incomplete inventory: run `redteam inventory --refresh`; individual Docker,
  process, model, or agent errors are reported without hiding other sources.
