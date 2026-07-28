#!/bin/zsh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LATEST="$SCRIPT_DIR/output/latest"
if [[ -e "$LATEST/presentation/OPEN_ME_FIRST.html" ]]; then
  open "$LATEST/presentation/OPEN_ME_FIRST.html"
  if [[ -e "$LATEST/presentation/ATTACK_WALKTHROUGH.html" ]]; then
    open "$LATEST/presentation/ATTACK_WALKTHROUGH.html"
  fi
  open "$LATEST"
else
  printf 'No completed demo package was found. Run RUN_LIVE_DEMO.command or REPLAY_DEMO.command first.\n'
  printf 'Press Return to close.'
  read -r _
fi
