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
