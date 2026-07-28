#!/bin/zsh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${AI_REDTEAM_REPO:-/Users/vishal/Career/Projects/AI-Red-Team-Agent-Simulator}"
DEXTER_REPO="${DEXTER_REPO:-/Users/vishal/Career/Projects/Dexter}"
DEXTER_ID="${DEXTER_ID:-dexter_5d3449a61e3bc03a0895}"
DEXTER_MODEL="${DEXTER_MODEL:-llama3.1:8b-instruct-q4_K_M}"
ADAPTIVE_MODE="${DEMO_ADAPTIVE_MODE:-guided}"
DYNAMIC_BOUNDED="${DEMO_DYNAMIC_BOUNDED:-0}"
MAX_ROUNDS="${DEMO_MAX_ROUNDS:-4}"
MAX_TOTAL_PROBES="${DEMO_MAX_TOTAL_PROBES:-30}"
MAX_PROBES_PER_ROUND="${DEMO_MAX_PROBES_PER_ROUND:-8}"
MAX_MODEL_CALLS="${DEMO_MAX_MODEL_CALLS:-8}"
MAX_DURATION="${DEMO_MAX_DURATION:-600}"
REPORT_ROOT="$REPO/reports/runs"
OLLAMA_BIN="$(command -v ollama 2>/dev/null || true)"
if [[ -z "$OLLAMA_BIN" && -x "/Applications/Ollama.app/Contents/Resources/ollama" ]]; then
  OLLAMA_BIN="/Applications/Ollama.app/Contents/Resources/ollama"
fi
DEMO_MODE="live"
[[ "${1:-}" == "--replay" ]] && DEMO_MODE="replay"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT="$REPO/demo/output/demo_$TIMESTAMP"
LOGS="$OUTPUT/logs"
EVIDENCE="$OUTPUT/evidence"
PRESENTATION="$OUTPUT/presentation"
mkdir -p "$LOGS" "$EVIDENCE" "$PRESENTATION"

exec > >(tee "$LOGS/demo-console.txt") 2>&1

section() {
  printf '\n\033[1;36m%s\033[0m\n' "$1"
  printf '%s\n' '------------------------------------------------------------------------'
}

warn() { printf '\033[1;33mWarning:\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31mError:\033[0m %s\n' "$1"; }

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

finish_window() {
  printf '\nPress Return to close this window.'
  read -r _
}

abort_live() {
  fail "$1"
  printf '\nThis launcher is intentionally strict: it will not silently replace a failed live demo with replayed evidence.\n'
  printf 'Use REPLAY_DEMO.command separately when you deliberately want replay mode.\n'
  if [[ -n "$OLLAMA_BIN" ]]; then
    "$OLLAMA_BIN" stop "$DEXTER_MODEL" >/dev/null 2>&1 || true
  fi
  finish_window
  exit 1
}

clear 2>/dev/null || true
section "AI AGENT RED TEAM SIMULATOR — AUTOMATED DEMO"
printf 'Live mode runs a new authorized assessment and streams safe high-level events.\n'
printf 'Replay mode only packages existing evidence and performs no SSH or testing.\n'
printf 'No shell commands are required during the presentation.\n'
if [[ "$DYNAMIC_BOUNDED" == "1" ]]; then
  printf 'Dynamic mode lets the local model propose registered follow-up probes, while deterministic policy controls execution and stopping.\n'
fi

if [[ ! -d "$REPO" || ! -f "$REPO/.venv/bin/activate" ]]; then
  fail "Red-team repository or virtual environment was not found at $REPO"
  finish_window
  exit 1
fi

cd "$REPO" || exit 1
source .venv/bin/activate

PLATFORM_VERSION="$(redteam --version 2>/dev/null | tail -1 || printf 'unknown')"
SOURCE_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
WORKTREE_STATUS="$(git status --porcelain 2>/dev/null || true)"
PHASE7_STATUS="unavailable"
if redteam reports --help >/dev/null 2>&1; then
  if [[ -z "$WORKTREE_STATUS" && "$PLATFORM_VERSION" == *"0.7."* ]]; then
    PHASE7_STATUS="available in a clean 0.7.x worktree; not auto-invoked"
  else
    PHASE7_STATUS="experimental/uncommitted; deliberately not auto-invoked"
  fi
fi

section "1. Project checkpoint"
printf 'Platform: %s\n' "$PLATFORM_VERSION"
printf 'Commit:   %s\n' "$SOURCE_COMMIT"
printf 'Phase 7:  %s\n' "$PHASE7_STATUS"
if [[ -n "$WORKTREE_STATUS" ]]; then
  warn "The repository has uncommitted changes. The demo will not invoke experimental report-building commands or modify existing run evidence."
  git status --short | tee "$LOGS/git-status.txt"
else
  printf 'Worktree: clean\n'
fi

section "2. Memory-safe Ollama configuration"
if command -v launchctl >/dev/null 2>&1; then
  launchctl setenv OLLAMA_CONTEXT_LENGTH 2048 || true
  launchctl setenv OLLAMA_NUM_PARALLEL 1 || true
  launchctl setenv OLLAMA_MAX_LOADED_MODELS 1 || true
  launchctl setenv OLLAMA_KEEP_ALIVE 30s || true
  launchctl setenv OLLAMA_FLASH_ATTENTION 1 || true
  launchctl setenv OLLAMA_KV_CACHE_TYPE q8_0 || true
fi
printf 'Context 2048; one parallel request; one loaded model; 30-second keep-alive.\n'
if [[ -n "$OLLAMA_BIN" ]]; then
  "$OLLAMA_BIN" stop "$DEXTER_MODEL" >/dev/null 2>&1 || true
fi

BASELINE_SOURCE=""
ADAPTIVE_SOURCE=""
FINAL_MODE="$DEMO_MODE"

if [[ "$DEMO_MODE" == "live" ]]; then
  section "3. Live service readiness"
  if ! curl -fsS http://127.0.0.1:11434/api/version >"$LOGS/ollama-version.json" 2>/dev/null; then
    abort_live "Ollama HTTP service is unavailable."
  fi

  if ! curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    printf 'Dexter is not reachable; requesting a normal Dexter start...\n'
    if [[ -d "$DEXTER_REPO" ]] && command -v dexter >/dev/null 2>&1; then
      (cd "$DEXTER_REPO" && dexter start) | tee "$LOGS/dexter-start.txt" || true
      for _ in {1..30}; do
        curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1 && break
        sleep 1
      done
    fi
  fi
  if ! curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    if [[ -f "$DEXTER_REPO/logs/dev/backend.log" ]]; then
      tail -n 100 "$DEXTER_REPO/logs/dev/backend.log" >"$LOGS/dexter-backend-tail.txt" || true
    fi
    abort_live "Dexter did not become reachable."
  fi

  redteam dexter health "$DEXTER_ID" 2>&1 | tee "$LOGS/dexter-readiness.txt" || abort_live "Dexter readiness failed."
  if ! redteam kali check --live >"$LOGS/kali-readiness.txt" 2>&1; then
    cat "$LOGS/kali-readiness.txt"
    abort_live "Kali SSH readiness failed."
  fi
  cat "$LOGS/kali-readiness.txt"

  section "4. What the live assessment will test"
  cat <<'ATTACKS'
BASELINE PROBES
  • API surface and OpenAPI exposure
  • Missing authentication and authorization boundaries
  • Conservative malformed JSON and error leakage
  • Prompt injection and protected-instruction disclosure
  • Weak refusals and unsafe tool claims
  • Synthetic canary isolation across prompt/memory boundaries
  • Dry-run tool approval and argument validation
  • Memory isolation with a fake marker
  • Small bounded rate-limit checks

KALI THROUGH RESTRICTED SSH TUNNEL
  • Exact approved Dexter tunnel port only
  • Registered nmap service fingerprinting
  • WhatWeb / HTTP metadata checks
  • Bounded Nikto and curl checks when registered
  • No subnet scan, brute force, SQLMap, Nuclei, Metasploit, or exploitation
ATTACKS
  if [[ "$ADAPTIVE_MODE" == "guided" ]]; then
    printf '
ADAPTIVE FOLLOW-UP
  • Guided mode dynamically selects additional registered probes.
  • It does not ask a model to invent commands; model_calls may correctly be 0.
'
  else
    printf '
MODEL-PROPOSED ADAPTIVE FOLLOW-UP
'
    printf '  • The local model may propose only typed, registered probe templates.
'
    printf '  • Deterministic code validates authorization, scope, target, tool, duplicate status, and budget.
'
    printf '  • Kali is executed only through registered adapters against the approved tunnel port.
'
    printf '  • The model never emits or executes shell commands and never chooses arbitrary hosts or ports.
'
    printf '  • The engine iterates until coverage/novelty saturates or a hard budget stops it.
'
    printf '  • Budgets: rounds=%s, total probes=%s, probes/round=%s, model calls=%s, duration=%ss.
' \
      "$MAX_ROUNDS" "$MAX_TOTAL_PROBES" "$MAX_PROBES_PER_ROUND" "$MAX_MODEL_CALLS" "$MAX_DURATION"
  fi

  section "5. Live bounded Dexter + Kali assessment"
  AUTHORIZATION="I own this local Dexter deployment and authorize bounded non-destructive testing of the exact configured scope."
  HELP_TEXT="$(redteam dexter assess --help 2>&1 || true)"
  KALI_OPTION=()
  if [[ "$HELP_TEXT" == *"--include-kali"* ]]; then
    KALI_OPTION=(--include-kali)
  fi

  BEFORE_BASELINE="$(latest_baseline 2>/dev/null || true)"
  if python "$SCRIPT_DIR/interactive_assessment.py" \
      --log "$LOGS/baseline-console.txt" \
      --event-log "$LOGS/baseline-live-events.txt" \
      --report-root "$REPORT_ROOT" \
      --label baseline \
      -- \
      redteam dexter assess "$DEXTER_ID" \
      --profile standard \
      --authorization "$AUTHORIZATION" \
      "${KALI_OPTION[@]}"; then
    AFTER_BASELINE="$(latest_baseline 2>/dev/null || true)"
    if [[ -n "$AFTER_BASELINE" && "$AFTER_BASELINE" != "$BEFORE_BASELINE" ]]; then
      BASELINE_SOURCE="$AFTER_BASELINE"
    else
      abort_live "The baseline command completed but no new report run was detected."
    fi
  else
    abort_live "The live baseline assessment did not complete successfully."
  fi

  section "6. Adaptive follow-up"
  BEFORE_ADAPTIVE="$(latest_adaptive 2>/dev/null || true)"

  ADAPTIVE_HELP="$(redteam assess run --help 2>&1 || true)"

  # Adaptive mode intentionally refuses to choose a model provider implicitly.
  # Configure a local Ollama provider without modifying .env, then add the exact
  # CLI option when this installed build exposes one.
  while IFS='=' read -r env_name env_value; do
    [[ -n "$env_name" ]] && export "$env_name=$env_value"
  done < <(python "$SCRIPT_DIR/configure_adaptive_provider.py" \
    --model "$DEXTER_MODEL" \
    --base-url "http://127.0.0.1:11434")

  ADAPTIVE_ARGS=(
    assess run
    --kind dexter
    --target "$DEXTER_ID"
    --profile standard
    --adaptive-mode "$ADAPTIVE_MODE"
    --authorization "$AUTHORIZATION"
  )

  PROVIDER_FLAG=""
  for candidate in --model-provider --adaptive-provider --provider; do
    if [[ "$ADAPTIVE_HELP" == *"$candidate"* ]]; then
      PROVIDER_FLAG="$candidate"
      ADAPTIVE_ARGS+=("$candidate" ollama)
      break
    fi
  done

  MODEL_FLAG=""
  for candidate in --adaptive-model --proposal-model --planner-model --model; do
    if [[ "$ADAPTIVE_HELP" == *"$candidate"* ]]; then
      MODEL_FLAG="$candidate"
      ADAPTIVE_ARGS+=("$candidate" "$DEXTER_MODEL")
      break
    fi
  done

  BASE_URL_FLAG=""
  for candidate in --ollama-base-url --provider-base-url --base-url; do
    if [[ "$ADAPTIVE_HELP" == *"$candidate"* ]]; then
      BASE_URL_FLAG="$candidate"
      ADAPTIVE_ARGS+=("$candidate" "http://127.0.0.1:11434")
      break
    fi
  done

  {
    printf 'Adaptive provider: ollama\n'
    printf 'Adaptive model: %s\n' "$DEXTER_MODEL"
    printf 'Provider CLI flag: %s\n' "${PROVIDER_FLAG:-environment configuration}"
    printf 'Model CLI flag: %s\n' "${MODEL_FLAG:-environment configuration}"
    printf 'Base URL CLI flag: %s\n' "${BASE_URL_FLAG:-environment configuration}"
  } | tee "$LOGS/adaptive-provider.txt"

  redteam adaptive status --json >"$LOGS/adaptive-status.json" 2>/dev/null || true

  add_supported_budget() {
    local flag="$1"
    local value="$2"
    if [[ "$ADAPTIVE_HELP" == *"$flag"* ]]; then
      ADAPTIVE_ARGS+=("$flag" "$value")
      printf 'Using adaptive budget %s=%s
' "$flag" "$value" | tee -a "$LOGS/adaptive-budget.txt"
      return 0
    fi
    return 1
  }

  if [[ "$ADAPTIVE_MODE" == "adaptive" ]]; then
    : >"$LOGS/adaptive-budget.txt"
    add_supported_budget --max-rounds "$MAX_ROUNDS" || true
    if ! add_supported_budget --max-total-probes "$MAX_TOTAL_PROBES"; then
      add_supported_budget --max-probes "$MAX_TOTAL_PROBES" || true
    fi
    add_supported_budget --max-probes-per-round "$MAX_PROBES_PER_ROUND" || true
    add_supported_budget --max-model-calls "$MAX_MODEL_CALLS" || true
    add_supported_budget --max-duration "$MAX_DURATION" || true

    printf '
The engine itself performs multiple adaptive rounds. This launcher does not run an unbounded external attack loop.
'
    printf 'A proper result is a completed run with executed probes, recorded proposal decisions, and a deterministic stop reason.

'

    PLAN_ARGS=(
      assess plan
      --kind dexter
      --target "$DEXTER_ID"
      --profile standard
      --adaptive-mode adaptive
    )
    [[ -n "$PROVIDER_FLAG" ]] && PLAN_ARGS+=("$PROVIDER_FLAG" ollama)
    [[ -n "$MODEL_FLAG" ]] && PLAN_ARGS+=("$MODEL_FLAG" "$DEXTER_MODEL")
    [[ -n "$BASE_URL_FLAG" ]] && PLAN_ARGS+=("$BASE_URL_FLAG" "http://127.0.0.1:11434")

    if ! redteam "${PLAN_ARGS[@]}" >"$LOGS/adaptive-plan.txt" 2>&1; then
      cat "$LOGS/adaptive-plan.txt"
      warn "The adaptive plan preflight failed. The launcher will not pretend that a model-proposed run occurred."
      FINAL_MODE="live baseline; adaptive provider preflight failed"
    else
      printf 'Adaptive provider preflight passed.\n'
    fi
  fi

  ADAPTIVE_PREFLIGHT_OK=1
  if [[ "$ADAPTIVE_MODE" == "adaptive" && ! -s "$LOGS/adaptive-plan.txt" ]]; then
    ADAPTIVE_PREFLIGHT_OK=0
  elif [[ "$ADAPTIVE_MODE" == "adaptive" ]] && grep -qiE 'validation error|explicitly selected model provider|error:' "$LOGS/adaptive-plan.txt"; then
    ADAPTIVE_PREFLIGHT_OK=0
  fi

  if [[ "$ADAPTIVE_PREFLIGHT_OK" == "1" ]] && python "$SCRIPT_DIR/interactive_assessment.py" \
      --log "$LOGS/adaptive-console.txt" \
      --event-log "$LOGS/adaptive-live-events.txt" \
      --report-root "$REPORT_ROOT" \
      --label adaptive \
      -- \
      redteam "${ADAPTIVE_ARGS[@]}"; then
    AFTER_ADAPTIVE="$(latest_adaptive 2>/dev/null || true)"
    if [[ -n "$AFTER_ADAPTIVE" && "$AFTER_ADAPTIVE" != "$BEFORE_ADAPTIVE" ]]; then
      ADAPTIVE_SOURCE="$AFTER_ADAPTIVE"
      if [[ "$ADAPTIVE_MODE" == "adaptive" ]]; then
        if ! python "$SCRIPT_DIR/evaluate_dynamic_result.py" \
            --run "$ADAPTIVE_SOURCE" \
            --output "$PRESENTATION" \
            | tee "$LOGS/dynamic-result.txt"; then
          warn "The adaptive run ended, but it did not satisfy the demo's terminal-result validation. The evidence will still be packaged without overstating success."
          FINAL_MODE="live baseline; adaptive terminal result incomplete"
        fi
      fi
    else
      warn "The adaptive command completed but no separate new adaptive run was detected. The baseline will still be packaged."
    fi
  else
    if [[ "$ADAPTIVE_PREFLIGHT_OK" != "1" ]]; then
      warn "The adaptive provider preflight failed. See logs/adaptive-plan.txt and logs/adaptive-provider.txt."
      FINAL_MODE="live baseline; adaptive provider unavailable"
    else
      warn "The adaptive follow-up failed. The completed baseline assessment will still be packaged honestly."
      FINAL_MODE="live baseline; adaptive unavailable"
    fi
  fi
else
  section "3. Verified-result replay"
  BASELINE_SOURCE="$(latest_baseline 2>/dev/null || true)"
  ADAPTIVE_SOURCE="$(latest_adaptive 2>/dev/null || true)"
  FINAL_MODE="replay"
  if [[ -z "$BASELINE_SOURCE" ]]; then
    fail "No existing baseline report was found under $REPORT_ROOT"
    finish_window
    exit 1
  fi
  printf 'Using existing baseline: %s\n' "$(basename "$BASELINE_SOURCE")"
  if [[ -n "$ADAPTIVE_SOURCE" ]]; then
    printf 'Using existing adaptive: %s\n' "$(basename "$ADAPTIVE_SOURCE")"
    if [[ "$ADAPTIVE_SOURCE" == "$BASELINE_SOURCE" ]]; then
      printf 'This historical run contains both baseline and adaptive artifacts, so both IDs are intentionally the same.\n'
    fi
  else
    warn "No adaptive run was found; the replay package will contain baseline results only."
  fi
fi

section "7. Isolated demo package"
BASELINE_COPY="$EVIDENCE/baseline"
copy_tree "$BASELINE_SOURCE" "$BASELINE_COPY"
printf 'Copied baseline evidence: %s\n' "$(basename "$BASELINE_SOURCE")"

ADAPTIVE_COPY=""
if [[ -n "$ADAPTIVE_SOURCE" ]]; then
  ADAPTIVE_COPY="$EVIDENCE/adaptive"
  copy_tree "$ADAPTIVE_SOURCE" "$ADAPTIVE_COPY"
  printf 'Copied adaptive evidence: %s\n' "$(basename "$ADAPTIVE_SOURCE")"
fi

cat >"$EVIDENCE/PRIVATE_EVIDENCE_DO_NOT_PRESENT.md" <<'PRIVATE'
# Private evidence — do not present without review

This folder contains copied raw assessment artifacts. Raw health, settings, logs, or evidence may contain local paths, user names, operational metadata, or other machine-specific information.

Use the sanitized files under `../presentation/` during the presentation.
PRIVATE

WALKTHROUGH_ARGS=(--baseline "$BASELINE_COPY" --output "$PRESENTATION")
if [[ -n "$ADAPTIVE_COPY" ]]; then
  WALKTHROUGH_ARGS+=(--adaptive "$ADAPTIVE_COPY")
fi
python "$SCRIPT_DIR/build_attack_walkthrough.py" "${WALKTHROUGH_ARGS[@]}"

SUMMARY_ARGS=(
  --output "$OUTPUT"
  --mode "$FINAL_MODE"
  --baseline "$BASELINE_COPY"
  --phase7-status "$PHASE7_STATUS"
  --platform-version "$PLATFORM_VERSION"
  --source-commit "$SOURCE_COMMIT"
)
if [[ -n "$ADAPTIVE_COPY" ]]; then
  SUMMARY_ARGS+=(--adaptive "$ADAPTIVE_COPY")
fi
python "$SCRIPT_DIR/build_demo_summary.py" "${SUMMARY_ARGS[@]}"

mkdir -p "$REPO/demo/output"
(
  cd "$REPO/demo/output" || exit 1
  rm -f latest
  ln -s "$(basename "$OUTPUT")" latest
)

section "8. Cleanup"
if [[ -n "$OLLAMA_BIN" ]]; then
  "$OLLAMA_BIN" stop "$DEXTER_MODEL" >/dev/null 2>&1 || true
fi
printf 'The large Dexter model was requested to unload.\n'
printf 'Managed assessment cleanup remains responsible for the Kali tunnel.\n'

section "DEMO PACKAGE COMPLETE"
printf 'Mode:         %s\n' "$FINAL_MODE"
printf 'Output:       %s\n' "$OUTPUT"
printf 'Summary:      %s\n' "$PRESENTATION/OPEN_ME_FIRST.html"
printf 'Walkthrough:  %s\n' "$PRESENTATION/ATTACK_WALKTHROUGH.html"
printf 'Integrity:    %s\n' "$OUTPUT/INTEGRITY.sha256"
printf '\nThe sanitized summary and attack walkthrough will open now.\n'

open "$PRESENTATION/OPEN_ME_FIRST.html" >/dev/null 2>&1 || true
open "$PRESENTATION/ATTACK_WALKTHROUGH.html" >/dev/null 2>&1 || true
open "$OUTPUT" >/dev/null 2>&1 || true
finish_window
