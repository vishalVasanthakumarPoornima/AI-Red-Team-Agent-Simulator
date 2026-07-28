#!/bin/zsh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${AI_REDTEAM_REPO:-/Users/vishal/Career/Projects/AI-Red-Team-Agent-Simulator}"
DEXTER_REPO="${DEXTER_REPO:-/Users/vishal/Career/Projects/Dexter}"
DEXTER_ID="${DEXTER_ID:-dexter_5d3449a61e3bc03a0895}"
DEXTER_MODEL="${DEXTER_MODEL:-llama3.1:8b-instruct-q4_K_M}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
MAX_ROUNDS="${DEMO_MAX_ROUNDS:-4}"
MAX_TOTAL_PROBES="${DEMO_MAX_TOTAL_PROBES:-30}"
MAX_PROBES_PER_ROUND="${DEMO_MAX_PROBES_PER_ROUND:-8}"
MAX_MODEL_CALLS="${DEMO_MAX_MODEL_CALLS:-8}"
MAX_DURATION="${DEMO_MAX_DURATION:-600}"
PROVIDER_TIMEOUT="${DEMO_PROVIDER_TIMEOUT:-120}"
PROVIDER_RETRIES="${DEMO_PROVIDER_RETRIES:-1}"
PROVIDER_REPAIRS="${DEMO_PROVIDER_REPAIRS:-2}"
REPORT_ROOT="$REPO/reports/runs"
PYTHON="$REPO/.venv/bin/python"
AUTHORIZATION="I own this local Dexter deployment and authorize bounded non-destructive testing of the exact configured scope."
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT="$REPO/demo/output/demo_$TIMESTAMP"
LOGS="$OUTPUT/logs"
EVIDENCE="$OUTPUT/evidence"
PRESENTATION="$OUTPUT/presentation"

mkdir -p "$LOGS" "$EVIDENCE" "$PRESENTATION"
CONSOLE_LOG="/private/tmp/ai-redteam-demo-console-$TIMESTAMP-$$.txt"
DEXTER_HEALTH_TMP="/private/tmp/ai-redteam-dexter-health-$TIMESTAMP-$$.json"
PACKAGE_FINALIZED=0
exec > >(tee "$CONSOLE_LOG") 2>&1

OLLAMA_BIN="$(command -v ollama 2>/dev/null || true)"
if [[ -z "$OLLAMA_BIN" && -x "/Applications/Ollama.app/Contents/Resources/ollama" ]]; then
  OLLAMA_BIN="/Applications/Ollama.app/Contents/Resources/ollama"
fi

section() {
  printf '\n\033[1;36m%s\033[0m\n' "$1"
  printf '%s\n' '------------------------------------------------------------------------'
}
warn() { printf '\033[1;33mWarning:\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31mError:\033[0m %s\n' "$1"; }

cleanup() {
  local status=$?
  if [[ "$PACKAGE_FINALIZED" != "1" && -f "$CONSOLE_LOG" ]]; then
    cp "$CONSOLE_LOG" "$LOGS/demo-console.txt" 2>/dev/null || true
  fi
  if [[ -n "$OLLAMA_BIN" ]]; then
    "$OLLAMA_BIN" stop "$DEXTER_MODEL" >/dev/null 2>&1 || true
  elif [[ -x "$PYTHON" ]]; then
    "$PYTHON" "$SCRIPT_DIR/unload_ollama_models.py" \
      --base-url "$OLLAMA_BASE_URL" --all >/dev/null 2>&1 || true
  fi
  rm -f "$CONSOLE_LOG" "$DEXTER_HEALTH_TMP" 2>/dev/null || true
  return $status
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

abort_demo() {
  fail "$1"
  printf '\nThe full adaptive demo is marked FAILED.\n'
  printf 'Diagnostics were preserved under:\n  %s\n' "$LOGS"
  printf 'No replay result was substituted.\n'
  printf '\nPress Return to close this window.'
  read -r _
  exit 1
}

latest_baseline() {
  local dir
  for dir in $(ls -td "$REPORT_ROOT"/run_* 2>/dev/null); do
    if [[ -f "$dir/report.json" && -f "$dir/report.md" ]]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

latest_adaptive() {
  local dir
  for dir in $(ls -td "$REPORT_ROOT"/run_* 2>/dev/null); do
    if [[ -f "$dir/adaptive_summary.json" ]]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

copy_tree() {
  local source="$1"
  local destination="$2"
  rm -rf "$destination"
  if command -v ditto >/dev/null 2>&1; then
    ditto "$source" "$destination"
  else
    cp -R "$source" "$destination"
  fi
}

clear 2>/dev/null || true
section "AI AGENT RED TEAM SIMULATOR — FULL LIVE ADAPTIVE DEMO"
printf 'This launcher requires a real baseline, real Kali checks, and a real local-model adaptive run.\n'
printf 'It never silently falls back to replay and it exits nonzero when adaptive execution fails.\n'
printf 'The model may propose only registered probes; deterministic policy controls execution.\n'

if [[ ! -d "$REPO" || ! -x "$REPO/.venv/bin/python" ]]; then
  abort_demo "Red-team repository or virtual environment was not found at $REPO"
fi

cd "$REPO" || abort_demo "Could not enter the red-team repository."
source .venv/bin/activate

section "1. Project and runtime checkpoint"
PLATFORM_VERSION="$(redteam --version 2>/dev/null | tail -1 || printf 'unknown')"
SOURCE_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
printf 'Platform: %s\n' "$PLATFORM_VERSION"
printf 'Commit:   %s\n' "$SOURCE_COMMIT"
printf 'Target:   %s\n' "$DEXTER_ID"
printf 'Planner:  %s through local Ollama\n' "$DEXTER_MODEL"
git status --short | tee "$LOGS/git-status.txt" || true

section "2. Memory-safe local model configuration"
if command -v launchctl >/dev/null 2>&1; then
  launchctl setenv OLLAMA_CONTEXT_LENGTH 2048 || true
  launchctl setenv OLLAMA_NUM_PARALLEL 1 || true
  launchctl setenv OLLAMA_MAX_LOADED_MODELS 1 || true
  launchctl setenv OLLAMA_KEEP_ALIVE 30s || true
  launchctl setenv OLLAMA_FLASH_ATTENTION 1 || true
  launchctl setenv OLLAMA_KV_CACHE_TYPE q8_0 || true
fi
printf 'Context=2048, parallel=1, maximum loaded models=1, keep-alive=30s, KV cache=q8_0.\n'
"$PYTHON" "$SCRIPT_DIR/unload_ollama_models.py" \
  --base-url "$OLLAMA_BASE_URL" --except "$DEXTER_MODEL" \
  | tee "$LOGS/ollama-cleanup-before.txt" || abort_demo "Could not inspect and unload non-Dexter Ollama models."

section "3. Explicit adaptive environment repair"
# Remove stale shell values. The helper then sets nonempty, typed overrides that
# supersede blank values in the repository's local .env for this process only.
while IFS= read -r name; do
  case "$name" in
    ADAPTIVE_*|REDTEAM_ADAPTIVE_*) unset "$name" 2>/dev/null || true ;;
  esac
done < <(env | sed 's/=.*//')

while IFS=$'\t' read -r env_name env_value; do
  [[ -n "$env_name" && -n "$env_value" ]] && export "$env_name=$env_value"
done < <(
  "$PYTHON" "$SCRIPT_DIR/adaptive_env.py" \
    --model "$DEXTER_MODEL" \
    --base-url "$OLLAMA_BASE_URL" \
    --max-rounds "$MAX_ROUNDS" \
    --max-probes "$MAX_TOTAL_PROBES" \
    --max-probes-per-round "$MAX_PROBES_PER_ROUND" \
    --max-model-calls "$MAX_MODEL_CALLS" \
    --max-duration "$MAX_DURATION" \
    --provider-timeout "$PROVIDER_TIMEOUT" \
    --provider-retries "$PROVIDER_RETRIES" \
    --provider-repairs "$PROVIDER_REPAIRS"
)

if ! "$PYTHON" "$SCRIPT_DIR/adaptive_env.py" \
    --model "$DEXTER_MODEL" \
    --base-url "$OLLAMA_BASE_URL" \
    --max-rounds "$MAX_ROUNDS" \
    --max-probes "$MAX_TOTAL_PROBES" \
    --max-probes-per-round "$MAX_PROBES_PER_ROUND" \
    --max-model-calls "$MAX_MODEL_CALLS" \
    --max-duration "$MAX_DURATION" \
    --provider-timeout "$PROVIDER_TIMEOUT" \
    --provider-retries "$PROVIDER_RETRIES" \
    --provider-repairs "$PROVIDER_REPAIRS" \
    --check >"$LOGS/adaptive-settings.json" 2>&1; then
  cat "$LOGS/adaptive-settings.json"
  abort_demo "Adaptive settings remain invalid after the process-level repair."
fi
cat "$LOGS/adaptive-settings.json"

section "4. Dexter, Ollama, and Kali readiness"
if ! curl -fsS "$OLLAMA_BASE_URL/api/version" >"$LOGS/ollama-version.json" 2>/dev/null; then
  abort_demo "The local Ollama HTTP service is unavailable."
fi

if ! curl -fsS http://127.0.0.1:8000/health >"$DEXTER_HEALTH_TMP" 2>/dev/null; then
  printf 'Dexter is not reachable; requesting a normal start...\n'
  if [[ -d "$DEXTER_REPO" ]] && command -v dexter >/dev/null 2>&1; then
    (cd "$DEXTER_REPO" && dexter start) | tee "$LOGS/dexter-start.txt" || true
    for _ in {1..30}; do
      curl -fsS http://127.0.0.1:8000/health >"$DEXTER_HEALTH_TMP" 2>/dev/null && break
      sleep 1
    done
  fi
fi
if [[ ! -s "$DEXTER_HEALTH_TMP" ]]; then
  abort_demo "Dexter did not become reachable on http://127.0.0.1:8000."
fi

if ! "$PYTHON" "$SCRIPT_DIR/verify_dexter_local.py" \
    "$DEXTER_HEALTH_TMP" "$DEXTER_MODEL" \
    >"$LOGS/dexter-local-verification.txt" 2>&1; then
  cat "$LOGS/dexter-local-verification.txt"
  abort_demo "Dexter is not configured for the expected local-only Ollama model."
fi
cat "$LOGS/dexter-local-verification.txt"

redteam dexter health "$DEXTER_ID" 2>&1 | tee "$LOGS/dexter-readiness.txt" \
  || abort_demo "Dexter readiness failed."
redteam kali check --live 2>&1 | tee "$LOGS/kali-readiness.txt" \
  || abort_demo "Kali SSH readiness failed."
redteam kali tools 2>&1 | tee "$LOGS/kali-tools.txt" \
  || abort_demo "Kali tool inventory failed."

section "5. Real local-model provider preflight"
if ! "$PYTHON" "$SCRIPT_DIR/adaptive_env.py" \
    --model "$DEXTER_MODEL" \
    --base-url "$OLLAMA_BASE_URL" \
    --provider-timeout "$PROVIDER_TIMEOUT" \
    --ollama-preflight >"$LOGS/adaptive-provider-response-safe.json" 2>&1; then
  cat "$LOGS/adaptive-provider-response-safe.json"
  abort_demo "The local model failed the structured adaptive-provider preflight."
fi
cat "$LOGS/adaptive-provider-response-safe.json"

section "6. Adaptive provider/model resolution and plan preflight"
# The installed Phase 6 build may select its provider through a CLI flag,
# a provider-qualified model ID, a role mapping, or an exact Settings alias.
# Resolve the actual contract by running only the non-executing plan command.
if ! "$PYTHON" "$SCRIPT_DIR/resolve_adaptive_cli.py" \
    --target "$DEXTER_ID" \
    --model "$DEXTER_MODEL" \
    --base-url "$OLLAMA_BASE_URL" \
    --profile standard \
    --output "$LOGS/adaptive-resolution.json" \
    --run-args "$LOGS/adaptive-run-args.txt" \
    --env-output "$LOGS/adaptive-resolved-env.tsv" \
    --plan-output "$LOGS/adaptive-plan.txt"; then
  cat "$LOGS/adaptive-resolution.json" 2>/dev/null || true
  cat "$LOGS/adaptive-plan.txt" 2>/dev/null || true
  abort_demo "No explicit local-Ollama adaptive invocation passed the plan preflight."
fi
cat "$LOGS/adaptive-resolution.json"
cat "$LOGS/adaptive-plan.txt"

while IFS=$'\t' read -r env_name env_value; do
  [[ -n "$env_name" && -n "$env_value" ]] && export "$env_name=$env_value"
done < "$LOGS/adaptive-resolved-env.tsv"

ADAPTIVE_ARGS=()
while IFS= read -r arg; do
  [[ -n "$arg" ]] && ADAPTIVE_ARGS+=("$arg")
done < "$LOGS/adaptive-run-args.txt"
ADAPTIVE_ARGS+=(--authorization "$AUTHORIZATION")

# Apply only CLI-supported budget flags to the resolved run invocation.
ASSESS_RUN_HELP="$(redteam assess run --help 2>&1 || true)"
add_run_budget() {
  local flag="$1" value="$2"
  if [[ "$ASSESS_RUN_HELP" == *"$flag"* ]]; then
    ADAPTIVE_ARGS+=("$flag" "$value")
    printf '%s=%s\n' "$flag" "$value" >>"$LOGS/adaptive-budgets.txt"
    return 0
  fi
  return 1
}
: >"$LOGS/adaptive-budgets.txt"
add_run_budget --max-rounds "$MAX_ROUNDS" || true
if ! add_run_budget --max-total-probes "$MAX_TOTAL_PROBES"; then
  add_run_budget --max-probes "$MAX_TOTAL_PROBES" || true
fi
add_run_budget --max-probes-per-round "$MAX_PROBES_PER_ROUND" || true
add_run_budget --max-model-calls "$MAX_MODEL_CALLS" || true
add_run_budget --max-duration "$MAX_DURATION" || true

section "7. What the authorized live demo will execute"
cat <<'TEXT'
BASELINE — every applicable registered standard-profile category
  • deployment and inventory correlation
  • API and OpenAPI surface
  • authentication and authorization observations
  • bounded malformed JSON and error leakage
  • prompt injection, prompt disclosure, protected-instruction checks
  • synthetic canary and context-isolation tests
  • weak-refusal and output-schema checks
  • fake/dry-run tool approval and argument validation
  • memory isolation and bounded rate-limit observations
  • service exposure and HTTP security headers

KALI — restricted, registered, exact-target adapters only
  • loopback-only reverse SSH tunnel
  • exact approved Dexter service port
  • registered Nmap, WhatWeb, bounded Nikto, and curl checks when applicable
  • no subnet scan, brute force, SQLMap, Nuclei, Metasploit, or exploitation

MODEL-DRIVEN ADAPTIVE FOLLOW-UP
  • local Ollama planner proposes typed registered templates
  • safe mutations are validated before execution
  • scope, target, tools, budgets, duplicates, and stopping remain deterministic
  • the model cannot execute shell commands or add hosts, ports, or tools
TEXT
printf '\nHard adaptive limits: rounds=%s, probes=%s, probes/round=%s, model calls=%s, duration=%ss.\n' \
  "$MAX_ROUNDS" "$MAX_TOTAL_PROBES" "$MAX_PROBES_PER_ROUND" "$MAX_MODEL_CALLS" "$MAX_DURATION"

section "8. Live baseline Dexter + Kali assessment"
DEXTER_HELP="$(redteam dexter assess --help 2>&1 || true)"
if [[ "$DEXTER_HELP" != *"--include-kali"* ]]; then
  abort_demo "This build does not expose the required --include-kali baseline option."
fi
BEFORE_BASELINE="$(latest_baseline 2>/dev/null || true)"
if ! "$PYTHON" "$SCRIPT_DIR/interactive_assessment.py" \
    --authorization-mode ask \
    --log "$LOGS/baseline-console.txt" \
    --event-log "$LOGS/baseline-live-events.txt" \
    --report-root "$REPORT_ROOT" \
    --label baseline \
    -- \
    redteam dexter assess "$DEXTER_ID" \
      --profile standard \
      --authorization "$AUTHORIZATION" \
      --include-kali; then
  abort_demo "The baseline Dexter + Kali assessment failed or was not authorized."
fi
BASELINE_SOURCE="$(latest_baseline 2>/dev/null || true)"
if [[ -z "$BASELINE_SOURCE" || "$BASELINE_SOURCE" == "$BEFORE_BASELINE" ]]; then
  abort_demo "The baseline command ended without creating a new report run."
fi
printf 'Baseline run: %s\n' "$(basename "$BASELINE_SOURCE")"

if ! "$PYTHON" "$SCRIPT_DIR/validate_baseline_result.py" \
    --run "$BASELINE_SOURCE" \
    --output "$LOGS/baseline-validation.json" \
    | tee "$LOGS/baseline-validation.txt"; then
  warn "The first baseline did not satisfy the strict demo gate. Retrying the same authorized bounded plan once."
  BEFORE_RETRY="$BASELINE_SOURCE"
  if ! "$PYTHON" "$SCRIPT_DIR/interactive_assessment.py" \
      --authorization-mode approve \
      --log "$LOGS/baseline-retry-console.txt" \
      --event-log "$LOGS/baseline-retry-live-events.txt" \
      --report-root "$REPORT_ROOT" \
      --label baseline-retry \
      -- \
      redteam dexter assess "$DEXTER_ID" \
        --profile standard \
        --authorization "$AUTHORIZATION" \
        --include-kali; then
    abort_demo "The single permitted baseline retry failed."
  fi
  BASELINE_SOURCE="$(latest_baseline 2>/dev/null || true)"
  if [[ -z "$BASELINE_SOURCE" || "$BASELINE_SOURCE" == "$BEFORE_RETRY" ]]; then
    abort_demo "The baseline retry did not create a new run."
  fi
  if ! "$PYTHON" "$SCRIPT_DIR/validate_baseline_result.py" \
      --run "$BASELINE_SOURCE" \
      --output "$LOGS/baseline-validation.json" \
      | tee "$LOGS/baseline-validation-retry.txt"; then
    abort_demo "The baseline remained incomplete after one bounded retry."
  fi
fi

section "9. Live model-driven adaptive follow-up"
BEFORE_ADAPTIVE="$(latest_adaptive 2>/dev/null || true)"
if ! "$PYTHON" "$SCRIPT_DIR/interactive_assessment.py" \
    --authorization-mode approve \
    --log "$LOGS/adaptive-console.txt" \
    --event-log "$LOGS/adaptive-live-events.txt" \
    --report-root "$REPORT_ROOT" \
    --label adaptive \
    -- \
    redteam "${ADAPTIVE_ARGS[@]}"; then
  abort_demo "The real model-driven adaptive assessment failed."
fi
ADAPTIVE_SOURCE="$(latest_adaptive 2>/dev/null || true)"
if [[ -z "$ADAPTIVE_SOURCE" || "$ADAPTIVE_SOURCE" == "$BEFORE_ADAPTIVE" ]]; then
  abort_demo "The adaptive command ended without creating a new adaptive run."
fi
printf 'Adaptive run: %s\n' "$(basename "$ADAPTIVE_SOURCE")"

section "10. Strict adaptive terminal-result validation"
if ! "$PYTHON" "$SCRIPT_DIR/evaluate_dynamic_result.py" \
    --run "$ADAPTIVE_SOURCE" \
    --output "$PRESENTATION" \
    | tee "$LOGS/dynamic-result.txt"; then
  abort_demo "The adaptive run did not satisfy the required real-model demo conditions."
fi

section "11. Isolated sanitized demo package"
BASELINE_COPY="$EVIDENCE/baseline"
ADAPTIVE_COPY="$EVIDENCE/adaptive"
copy_tree "$BASELINE_SOURCE" "$BASELINE_COPY"
copy_tree "$ADAPTIVE_SOURCE" "$ADAPTIVE_COPY"
printf 'Copied baseline evidence: %s\n' "$(basename "$BASELINE_SOURCE")"
printf 'Copied adaptive evidence: %s\n' "$(basename "$ADAPTIVE_SOURCE")"

cat >"$EVIDENCE/PRIVATE_EVIDENCE_DO_NOT_PRESENT.md" <<'PRIVATE'
# Private evidence — do not present without review

This directory contains copied raw assessment artifacts. Show the sanitized files under `../presentation/` during the presentation.
PRIVATE

"$PYTHON" "$SCRIPT_DIR/build_attack_walkthrough.py" \
  --baseline "$BASELINE_COPY" \
  --adaptive "$ADAPTIVE_COPY" \
  --output "$PRESENTATION"

"$PYTHON" "$SCRIPT_DIR/build_demo_summary.py" \
  --output "$OUTPUT" \
  --mode "live full adaptive" \
  --baseline "$BASELINE_COPY" \
  --adaptive "$ADAPTIVE_COPY" \
  --phase7-status "experimental/uncommitted; not auto-invoked" \
  --platform-version "$PLATFORM_VERSION" \
  --source-commit "$SOURCE_COMMIT"

"$PYTHON" - "$PRESENTATION/ATTACK_WALKTHROUGH.json" "$PRESENTATION/kali_activity_safe.json" <<'PY'
import json, sys
src, dst = sys.argv[1:]
data = json.load(open(src, encoding='utf-8'))
json.dump(data.get('kali', {}), open(dst, 'w', encoding='utf-8'), indent=2, sort_keys=True)
open(dst, 'a', encoding='utf-8').write('\n')
PY

cp "$CONSOLE_LOG" "$LOGS/demo-console.txt" 2>/dev/null || true

section "12. Explicit model cleanup"
if ! "$PYTHON" "$SCRIPT_DIR/unload_ollama_models.py" \
    --base-url "$OLLAMA_BASE_URL" --all \
    >"$LOGS/model-cleanup.json" 2>&1; then
  cat "$LOGS/model-cleanup.json"
  abort_demo "Could not unload the local model after the assessment."
fi
sleep 2
if ! "$PYTHON" - "$OLLAMA_BASE_URL" "$DEXTER_MODEL" >"$LOGS/model-state-after-cleanup.json" <<'PY'
import json, sys, urllib.request
base, expected = sys.argv[1].rstrip('/'), sys.argv[2]
with urllib.request.urlopen(base + '/api/ps', timeout=10) as response:
    payload = json.loads(response.read(1024 * 1024))
loaded = [str(item.get('name') or item.get('model')) for item in payload.get('models', []) if isinstance(item, dict)]
result = {'loaded_models': loaded, 'dexter_model_unloaded': expected not in loaded}
print(json.dumps(result, indent=2))
raise SystemExit(0 if expected not in loaded else 2)
PY
then
  cat "$LOGS/model-state-after-cleanup.json"
  abort_demo "The Dexter model remained loaded after explicit cleanup."
fi
printf 'The Dexter model was unloaded successfully.\n'

printf 'The final package is verified with shasum -a 256 -c INTEGRITY.sha256.\n' >"$LOGS/package-integrity.txt"

# Recompute integrity after adding every presentation and log file.
"$PYTHON" - "$OUTPUT" <<'PY'
import hashlib, sys
from pathlib import Path
root=Path(sys.argv[1])
rows=[]
for path in sorted(root.rglob('*')):
    if path.is_file() and path.name != 'INTEGRITY.sha256':
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
(root/'INTEGRITY.sha256').write_text('\n'.join(rows)+'\n', encoding='utf-8')
PY

section "13. Package integrity verification"
INTEGRITY_TMP="/private/tmp/ai-redteam-demo-integrity-$$.txt"
if ! (cd "$OUTPUT" && shasum -a 256 -c INTEGRITY.sha256) >"$INTEGRITY_TMP" 2>&1; then
  cat "$INTEGRITY_TMP"
  rm -f "$INTEGRITY_TMP"
  abort_demo "The generated presentation package failed SHA-256 verification."
fi
rm -f "$INTEGRITY_TMP"
printf 'Package SHA-256 verification passed.\n'
PACKAGE_FINALIZED=1

mkdir -p "$REPO/demo/output"
(
  cd "$REPO/demo/output" || exit 1
  rm -f latest
  ln -s "$(basename "$OUTPUT")" latest
)

section "FULL ADAPTIVE DEMO COMPLETE"
printf 'Baseline run:  %s\n' "$(basename "$BASELINE_SOURCE")"
printf 'Adaptive run:  %s\n' "$(basename "$ADAPTIVE_SOURCE")"
printf 'Output:        %s\n' "$OUTPUT"
printf 'Summary:       %s\n' "$PRESENTATION/OPEN_ME_FIRST.html"
printf 'Walkthrough:   %s\n' "$PRESENTATION/ATTACK_WALKTHROUGH.html"
printf 'Dynamic proof: %s\n' "$PRESENTATION/DYNAMIC_RESULT.md"
printf 'Integrity:     %s\n' "$OUTPUT/INTEGRITY.sha256"
printf '\nThis result contains a real local-model adaptive run with strict validation.\n'

open "$PRESENTATION/OPEN_ME_FIRST.html" >/dev/null 2>&1 || true
open "$PRESENTATION/ATTACK_WALKTHROUGH.html" >/dev/null 2>&1 || true
open "$OUTPUT" >/dev/null 2>&1 || true

printf '\nPress Return to close this window.'
read -r _
exit 0
