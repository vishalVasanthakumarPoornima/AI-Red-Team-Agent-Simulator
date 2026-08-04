#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"
REDTEAM_BIN="${PROJECT_DIR}/.venv/bin/redteam"
AUTHORIZATION="I own this local synthetic target and authorize bounded testing."

if [[ ! -x "${PYTHON_BIN}" || ! -x "${REDTEAM_BIN}" ]]; then
  echo "ERROR: The project environment is missing." >&2
  echo "Fix: run ./scripts/bootstrap_dev.sh, then rerun this script." >&2
  exit 3
fi

cd "${PROJECT_DIR}"

step() {
  local number="$1"
  local title="$2"
  local proof="$3"
  echo
  echo "[$number/8] $title"
  echo "What this proves: $proof"
}

run() {
  echo "+ $*"
  "$@"
}

step 1 "Verify the installed application" "The packaged CLI and source version agree."
run "${REDTEAM_BIN}" --version

step 2 "Diagnose local readiness" "Required runtime, dependencies, paths, and artifact integrity are usable."
run "${REDTEAM_BIN}" doctor

step 3 "Validate safe configuration" "Typed settings load successfully without exposing secrets."
run "${REDTEAM_BIN}" config validate

step 4 "Refresh passive inventory" "The platform discovers local state without invoking targets or scanning ranges."
run "${REDTEAM_BIN}" inventory refresh

step 5 "Resolve the enrolled target" "A literal enrollment marker becomes a typed, scope-classified target."
echo "+ ${REDTEAM_BIN} --json targets resolve tool_agent --kind python"
TARGET_JSON="$("${REDTEAM_BIN}" --json targets resolve tool_agent --kind python)"
printf '%s' "${TARGET_JSON}" | "${PYTHON_BIN}" -c \
  'import json, sys; d=json.load(sys.stdin)["data"]; t=d["target"]; print("State: {}\nTarget: {}\nKind: {}\nScope: {}\nEnrollment: {}".format(d["state"], t["normalized_target"], t["target_kind"], t["scope_classification"], t["discovery_confidence"]))'

step 6 "Preview the deterministic plan" "The exact operations, budgets, and scope are visible before execution."
echo "+ ${REDTEAM_BIN} --json assess plan python://tool_agent --profile standard"
PLAN_JSON="$("${REDTEAM_BIN}" --json assess plan python://tool_agent --profile standard)"
printf '%s' "${PLAN_JSON}" | "${PYTHON_BIN}" -c \
  'import json, sys; d=json.load(sys.stdin)["data"]; p=d["plan"]; active=sum(s["mode"]=="active" for s in p["steps"]); print("Plan: {}\nProfile: {}\nSteps: {} ({} active)\nMax probes: {}\nMax duration: {} seconds\nHidden steps: {}".format(p["plan_id"], p["profile"], len(p["steps"]), active, p["budget"]["max_probes"], p["budget"]["max_duration_seconds"], p["hidden_steps_allowed"]))'

step 7 "Run the authorized assessment" "Only registered local probes execute and every result becomes evidence."
echo "+ ${REDTEAM_BIN} --json assess run python://tool_agent --profile standard --authorization <human statement>"
RUN_JSON="$(
  "${REDTEAM_BIN}" --json assess run python://tool_agent \
    --profile standard \
    --authorization "${AUTHORIZATION}"
)"
RUN_ID="$(
  printf '%s' "${RUN_JSON}" | "${PYTHON_BIN}" -c \
    'import json, sys; print(json.load(sys.stdin)["data"]["summary"]["run_id"])'
)"
printf '%s' "${RUN_JSON}" | "${PYTHON_BIN}" -c \
  'import json, sys; p=json.load(sys.stdin)["data"]["summary"]; print("Run: {}\nStatus: {}\nCoverage: {}%\nFindings: {}\nErrors: {}".format(p["run_id"], p["status"], p["coverage_percentage"], p["finding_count"], p["error_count"]))'

step 8 "Build and verify the portfolio report" "Canonical rendering and SHA-256 integrity checks succeed."
run "${REDTEAM_BIN}" reports build "${RUN_ID}" --format html
run "${REDTEAM_BIN}" reports verify "${RUN_ID}"
run "${REDTEAM_BIN}" reports findings "${RUN_ID}"
run "${REDTEAM_BIN}" reports coverage "${RUN_ID}"

echo
echo "Demo complete."
echo "RUN_ID=${RUN_ID}"
echo "Report directory: ${PROJECT_DIR}/reports/runs/${RUN_ID}"
echo "Next: ${REDTEAM_BIN} reports show ${RUN_ID}"
