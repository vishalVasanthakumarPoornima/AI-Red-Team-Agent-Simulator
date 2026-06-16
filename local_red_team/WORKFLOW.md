# Local Red-Team Harness

This workflow keeps the red-team planner and target agents on the same machine.
The planner uses a local Ollama model, then the scanner sends the generated
payloads to local target agents and evaluates the responses.

Default roles:

- Red-team planner: `dolphin-llama3:latest`
- Travel target: `qwen2.5:0.5b`
- Tutor target: `smollm2:360m`

Run one target:

```bash
python3 local_red_team/run_local_red_team_scan.py --target travel_agent --max-payloads 2
```

Run both active targets:

```bash
python3 local_red_team/run_local_red_team_scan.py --max-payloads 2
```

Useful overrides:

```bash
export LOCAL_RED_TEAM_MODEL=dolphin-llama3:latest
export TRAVEL_AGENT_MODEL=qwen2.5:0.5b
export TUTOR_AGENT_MODEL=smollm2:360m
```

Reports are written to:

- `reports/local_red_team/red_team_scan.json`
- `reports/local_red_team/simple_summary.txt`
- `reports/combined_report.md`

Security boundaries:

- Use fake lab secrets only.
- Do not send target details to external AI services.
- Do not test public or third-party targets.
- Do not run destructive actions.
- Payloads should simulate unsafe requests without executing them.
