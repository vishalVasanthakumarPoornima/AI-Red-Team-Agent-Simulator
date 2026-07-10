#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"
HOST="${AGENT_SMOKE_HOST:-127.0.0.1}"
LAB_PORT="${AGENT_SMOKE_LAB_PORT:-18080}"
WEATHER_PORT="${AGENT_SMOKE_WEATHER_PORT:-18101}"
TRAVEL_PORT="${AGENT_SMOKE_TRAVEL_PORT:-18102}"
LOG_DIR="${TMPDIR:-/tmp}/ai-red-team-service-smoke"

mkdir -p "${LOG_DIR}"

weather_pid=""
travel_pid=""
lab_pid=""

cleanup() {
  if [[ -n "${lab_pid}" ]]; then
    kill "${lab_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${weather_pid}" ]]; then
    kill "${weather_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${travel_pid}" ]]; then
    kill "${travel_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_json() {
  local url="$1"
  local label="$2"
  "${PYTHON_BIN}" - "$url" "$label" <<'PY'
import json
import sys
import time
import urllib.request

url = sys.argv[1]
label = sys.argv[2]
deadline = time.time() + 15
last_error = None

while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        print(f"{label}: ok {payload}")
        raise SystemExit(0)
    except Exception as exc:
        last_error = exc
        time.sleep(0.5)

raise SystemExit(f"{label}: failed waiting for {url}: {last_error}")
PY
}

"${PYTHON_BIN}" agent_service.py \
  --target weather_insight_agent \
  --host "${HOST}" \
  --port "${WEATHER_PORT}" \
  >"${LOG_DIR}/weather.log" 2>&1 &
weather_pid="$!"

"${PYTHON_BIN}" agent_service.py \
  --target travel_planner_agent \
  --host "${HOST}" \
  --port "${TRAVEL_PORT}" \
  >"${LOG_DIR}/travel.log" 2>&1 &
travel_pid="$!"

"${PYTHON_BIN}" ai_red_team_cli.py serve-agents \
  --host "${HOST}" \
  --port "${LAB_PORT}" \
  --target tool_agent \
  >"${LOG_DIR}/lab.log" 2>&1 &
lab_pid="$!"

wait_for_json "http://${HOST}:${LAB_PORT}/health" "lab health"
wait_for_json "http://${HOST}:${LAB_PORT}/targets" "lab targets"
wait_for_json "http://${HOST}:${WEATHER_PORT}/health" "weather health"
wait_for_json "http://${HOST}:${WEATHER_PORT}/metadata" "weather metadata"
wait_for_json "http://${HOST}:${TRAVEL_PORT}/health" "travel health"
wait_for_json "http://${HOST}:${TRAVEL_PORT}/metadata" "travel metadata"

"${PYTHON_BIN}" ai_red_team_cli.py agents discover \
  --host "${HOST}" \
  --ports "${LAB_PORT},${WEATHER_PORT},${TRAVEL_PORT}" \
  --fail-on-none

echo "Service smoke complete."
