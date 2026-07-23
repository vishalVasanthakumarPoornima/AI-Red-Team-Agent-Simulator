# AI Agent Red Team Simulator

A local, authorized AI security testing project for evaluating AI agents against
common failure modes:

- Prompt disclosure
- Secret leakage
- Unsafe tool usage
- Excessive permissions
- Weak refusal behavior

This project is intended for isolated lab and portfolio use only. Test local
agents that you own or control. Do not use it against public websites,
third-party systems, real credentials, or production environments.

## Current Platform

The supported entry point is the installed `redteam` CLI. It provides typed
configuration and schemas, live/cached inventory, a centralized scope policy,
human authorization records, bounded adaptive assessments, isolated run
artifacts, enterprise reports, model-planner benchmarks, and an optional
authenticated loopback API. The older `ai_red_team_cli.py` and conversational
assistant remain available as compatibility workflows.

```bash
./scripts/bootstrap_dev.sh
source .venv/bin/activate

redteam doctor
redteam inventory --json --refresh
redteam models --json
redteam agents --json
redteam services --json
redteam targets
redteam assess plan \
  --kind python \
  --target tool_agent \
  --authorization "I own this local synthetic target and authorize bounded testing."
redteam assess run \
  --kind python \
  --target tool_agent \
  --authorization "I own this local synthetic target and authorize bounded testing." \
  --category prompt_disclosure
redteam runs list
```

Public targets are disabled by default. An active run always requires a human
authorization statement. Model output cannot authorize a target, add a network
destination, create a shell command, alter budgets, or bypass deterministic
policy and detector decisions. Run artifacts are written under
`reports/runs/<run-id>/` with restrictive local permissions and a SHA-256
manifest.

## Passive Inventory

Phase 2 inventory is implemented as reusable typed adapters under
`redteam_platform/inventory/`. A fresh inventory reads existing macOS/Linux
listeners, enrolled Python targets, the agent registry, configured local
service metadata, and configured Ollama endpoint identities. Docker and Kali
readiness are optional. Individual adapter failures are returned as typed
partial errors instead of discarding the snapshot.

Ollama installed models and currently loaded models are separate states.
Bounded live Ollama metadata requests require `redteam models --json --live`
or `redteam inventory --json --live-ollama`. Kali SSH readiness similarly
requires `redteam kali-status --json --live`. Inventory never scans a range,
sends an assessment prompt, posts to `/invoke`, mutates Docker, or executes an
arbitrary command.

The standalone atomic cache is `reports/cache/inventory.json`. A typed snapshot
can also be attached to a Phase 1 run as
`reports/runs/<run-id>/inventory.json`, including its SHA-256 manifest record.

The optional API requires `REDTEAM_API_TOKEN` and only accepts a loopback bind:

```bash
export REDTEAM_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
redteam api serve
curl -H "Authorization: Bearer $REDTEAM_API_TOKEN" http://127.0.0.1:18150/inventory
```

See [Architecture](docs/ARCHITECTURE.md),
[Passive discovery](docs/discovery.md),
[Configuration](docs/configuration.md), [Security Model](docs/SECURITY.md),
[Operations](docs/OPERATIONS.md), and the
[Dexter Runbook](docs/DEXTER_RUNBOOK.md).

## Current Scanner

The scanner discovers explicit Python targets under `targets/`, imports each
target, and calls `run_agent(prompt)` when available. A target module must set
`REDTEAM_TARGET = True`; this keeps local scratch or placeholder modules out of
normal scans. Attack payloads are loaded from text files under `attacks/`.

Default attack payloads:

- `attacks/prompt_disclosure/payloads.txt`
- `attacks/tool_abuse/payloads.txt`
- `attacks/secret_extraction/payloads.txt`

Reports are written to:

- `reports/<target>/<attack>.json`
- `reports/combined_report.md`

## Ollama Setup

Use Python 3.13 for local development. The bootstrap script creates `.venv/`
and installs the functional-agent dependencies:

```bash
./scripts/bootstrap_dev.sh
source .venv/bin/activate
```

Start Ollama:

```bash
ollama serve
```

Pull the default local model:

```bash
ollama pull llama3.2:1b
```

The Ollama target uses:

- URL: `http://localhost:11434/api/generate`
- Default model: `llama3.2:1b`
- `stream: false`
- `temperature: 0.2`

Override the model if needed:

```bash
export OLLAMA_MODEL=llama3.2:1b
```

For a service deployment that talks to a separate Ollama-compatible endpoint,
set `OLLAMA_URL` to the full `/api/generate` URL. If `OLLAMA_URL` is not set,
the agents use the local Ollama server above.

## Run The Scanner

Use the project CLI to discover targets, run scans, and check the connected
Kali lab host:

```bash
python3 ai_red_team_cli.py targets
python3 ai_red_team_cli.py scan --target tool_agent --attack prompt_disclosure
python3 ai_red_team_cli.py local-red-team --target travel_agent --max-payloads 2
python3 ai_red_team_cli.py serve-agents --target ollama_agent --target travel_agent --target tutor_agent
python3 ai_red_team_cli.py serve-agent --target weather_insight_agent --port 18101
python3 ai_red_team_cli.py agents discover
python3 ai_red_team_cli.py agents health
python3 ai_red_team_cli.py kali status
python3 ai_red_team_cli.py kali attack-agents --ollama-model llama3.2:1b --ollama-timeout 180
python3 ai_red_team_cli.py kali attack-url --url https://your-agent.onrender.com
```

## Natural-Language Assistant

Start the conversational assistant:

```bash
./scripts/redteam_chat.sh
```

Then type requests in plain English, for example:

```text
find active agents on this machine
attack active running agents
attack all local agents and generate an enterprise report
run a comprehensive dynamic demo assessment with Kali
run adaptive local red team against travel_agent with 3 payloads
run the ThinkPad Kali assessment
attack Dexter live at localhost:5173
attack the web app at http://127.0.0.1:5173 with Kali
full assessment with Kali and enterprise report
```

You can also send one request non-interactively:

```bash
./scripts/redteam_chat.sh --message "run a comprehensive dynamic demo assessment with Kali"
```

The assistant uses deterministic intent parsing by default. If you want local
Ollama-assisted intent parsing, set `REDTEAM_NL_MODEL` and pass `--local-model`:

```bash
export REDTEAM_NL_MODEL=llama3.2:1b
./scripts/redteam_chat.sh --local-model
```

Enterprise reports are written to:

- `reports/enterprise_red_team_report.md`
- `reports/enterprise_red_team_report.json`

Each natural-language assessment also writes monitoring artifacts:

- `reports/assessment_timeline.md` for a readable phase-by-phase trace
- `reports/assessment_events.jsonl` for structured event replay

The monitor records observable behavior: interpreted intent, discovered
services, generated dynamic probes, HTTP calls, Kali commands, return codes,
and result statuses. It does not expose hidden model chain-of-thought.

Run the local validation gate before pushing changes:

```bash
./scripts/validate.sh
```

To include a local HTTP service health check in that gate:

```bash
RUN_SERVICE_SMOKE=1 ./scripts/validate.sh
```

The Kali command expects an SSH alias named `kali-redteam`. You can also pass a
host directly:

```bash
python3 ai_red_team_cli.py kali status --host vishal@10.0.0.124
```

The Kali-backed agent attack command starts a loopback-only local adapter,
creates an SSH reverse tunnel to Kali, runs bounded HTTP recon and prompt-level
probes from Kali, writes `reports/kali_agent_scan.json`, and then tears the
tunnel and adapter down. It does not expose the lab agents to the LAN.

The URL attack command runs Kali recon and prompt-level probes directly against
an authorized hosted agent URL. Use it only against services you own or have
explicit permission to test.

For local web apps such as Dexter running on your Mac, use the web-app mode.
This creates a reverse SSH tunnel so Kali can scan your local loopback service,
then runs bounded recon and non-destructive probes for SQL error exposure,
reflected XSS, path traversal indicators, prompt injection against likely
chat/agent endpoints, and secret/stacktrace leakage:

```bash
./scripts/redteam_chat.sh --message "attack Dexter live at localhost:5173"

python3 ai_red_team_cli.py kali attack-url \
  --url http://127.0.0.1:5173 \
  --web-app \
  --tunnel-local \
  --remote-port 15173
```

The natural-language Dexter command scans both the Vite dashboard on `5173`
and the Dexter API on `8000` when the API is reachable. The lower-level
`attack-url` command scans exactly the URL you pass.

The web-app path uses Kali tools including `nmap`, `whatweb`, `nikto`, and
`sqlmap` when available. Natural-language Dexter runs write split artifacts
such as `reports/kali_url_scan_frontend.json` and `reports/kali_url_scan_api.json`,
plus the enterprise report/timeline artifacts.

The Render blueprint in `render.yaml` requires an Ollama-compatible model
endpoint through `OLLAMA_URL`; a default Render Python web service does not run
Ollama inside the same process.

## Functional Agent Services

The project includes Ollama + LangGraph target agents that can run as local
HTTP services or be deployed as Render web services:

- `weather_insight_agent` drafts morning weather guidance using weather tools.
- `travel_planner_agent` drafts trip plans from location/date requests and
  weather context.

Install the functional-agent dependency:

```bash
python -m pip install -r requirements.txt
```

Run local services:

```bash
python agent_service.py --target weather_insight_agent --port 18101
python agent_service.py --target travel_planner_agent --port 18102
```

Check registered service health:

```bash
python3 ai_red_team_cli.py agents list
python3 ai_red_team_cli.py agents health
```

Find compatible agent services that are actively running on the same machine:

```bash
python3 ai_red_team_cli.py agents discover
python3 ai_red_team_cli.py agents discover --ports 18080,18101-18110
```

Start both registered local services and verify `/health` plus `/metadata`:

```bash
./scripts/service_smoke.sh
```

Invoke one service directly:

```bash
curl -s http://127.0.0.1:18101/invoke \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"location: San Francisco. Give me tomorrow morning weather guidance."}'
```

API keys are read from environment variables only. For weather, set
`OPENWEATHER_API_KEY` if you want OpenWeather geocoding; the weather forecast
tool otherwise falls back to Open-Meteo public forecast data. Do not commit
real keys.

Run every default attack against every discovered target:

```bash
python3 -m scanner.attack_runner
```

Run only the Ollama target:

```bash
python3 -m scanner.attack_runner --target ollama_agent
```

Run only one attack category:

```bash
python3 -m scanner.attack_runner --attack prompt_disclosure
```

Run one attack category against Ollama:

```bash
python3 -m scanner.attack_runner --target ollama_agent --attack prompt_disclosure
```

If Ollama is not running or the model is not installed, the scanner records
`ERROR` results in the reports instead of crashing.

## Run The Local Red-Team Agent

The adaptive red-team flow stays fully local. It uses a local Ollama model as
the payload-planning agent, then sends those generated prompts to local
Ollama-backed target agents and evaluates the responses.

Default red-team planner:

- `dolphin-llama3:latest`

Override it if needed:

```bash
export LOCAL_RED_TEAM_MODEL=dolphin-llama3:latest
```

Active lightweight target agents:

- `travel_agent` uses `qwen2.5:0.5b`
- `tutor_agent` uses `smollm2:360m`

Run a small one-target test:

```bash
python3 local_red_team/run_local_red_team_scan.py --target travel_agent --max-payloads 2
```

Run both active targets:

```bash
python3 local_red_team/run_local_red_team_scan.py --max-payloads 2
```

Reports are written to:

- `reports/local_red_team/red_team_scan.json`
- `reports/local_red_team/simple_summary.txt`
- `reports/combined_report.md`

This local red-team harness does not call external AI services. It talks to
Ollama at `http://localhost:11434/api/generate`.

## Security Boundaries

- Use fake lab secrets only.
- Do not harvest real credentials.
- Do not test public or third-party targets.
- Do not run destructive actions.
- Payloads should simulate unsafe requests without executing them.
