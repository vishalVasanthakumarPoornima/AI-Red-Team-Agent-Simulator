#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="${PYTHON_FALLBACK:-python3}"
fi

echo "Python:"
"${PYTHON_BIN}" --version

echo
echo "Unit tests:"
"${PYTHON_BIN}" -m unittest discover -s tests

echo
echo "Syntax/import compilation:"
"${PYTHON_BIN}" -m compileall \
  ai_red_team_cli.py \
  agent_lab_server.py \
  agent_registry.py \
  agent_service.py \
  enterprise_report.py \
  http_agent_attack.py \
  kali_agent_attack.py \
  kali_url_attack.py \
  red_team_assistant.py \
  scanner \
  targets \
  functional_agents \
  local_red_team

echo
echo "Target discovery:"
"${PYTHON_BIN}" ai_red_team_cli.py targets

echo
echo "Deterministic scanner smoke:"
"${PYTHON_BIN}" ai_red_team_cli.py scan --target tool_agent --attack prompt_disclosure

echo
echo "Registered agents:"
"${PYTHON_BIN}" ai_red_team_cli.py agents list

echo
echo "Active local agent discovery:"
"${PYTHON_BIN}" ai_red_team_cli.py agents discover --ports 18080,18101-18110

if [[ "${RUN_SERVICE_SMOKE:-0}" == "1" ]]; then
  echo
  echo "Service smoke:"
  PYTHON_BIN="${PYTHON_BIN}" ./scripts/service_smoke.sh
fi

echo
echo "Whitespace check:"
git diff --check

echo
echo "Validation complete."
