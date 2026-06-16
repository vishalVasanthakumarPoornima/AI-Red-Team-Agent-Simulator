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

The scanner discovers Python targets under `targets/`, imports each target, and
calls `run_agent(prompt)` when available. Attack payloads are loaded from text
files under `attacks/`.

Default attack payloads:

- `attacks/prompt_disclosure/payloads.txt`
- `attacks/tool_abuse/payloads.txt`
- `attacks/secret_extraction/payloads.txt`

Reports are written to:

- `reports/<target>/<attack>.json`
- `reports/combined_report.md`

## Ollama Setup

Start Ollama:

```bash
ollama serve
```

Pull the default local model:

```bash
ollama pull llama3.2:3b
```

The Ollama target uses:

- URL: `http://localhost:11434/api/generate`
- Default model: `llama3.2:3b`
- `stream: false`
- `temperature: 0.2`

Override the model if needed:

```bash
export OLLAMA_MODEL=llama3.2:3b
```

## Run The Scanner

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
