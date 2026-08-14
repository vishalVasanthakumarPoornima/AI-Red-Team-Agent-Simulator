#!/usr/bin/env bash
# AI Red Team Agent Simulator — demo commands
# Run from the repository root.

source .venv/bin/activate

ollama list

redteam agents list

redteam assess plan python://travel_agent --profile standard

redteam assess run python://travel_agent \
  --authorization "I own this local synthetic target and authorize bounded testing."

RUN_ID=$(basename "$(ls -dt reports/runs/run_* | head -1)")
echo "$RUN_ID"

redteam reports findings "$RUN_ID"

redteam reports coverage "$RUN_ID"


redteam reports build "$RUN_ID" --format pdf --overwrite &&
test -s "reports/runs/$RUN_ID/report.pdf" &&
open "reports/runs/$RUN_ID/report.pdf"