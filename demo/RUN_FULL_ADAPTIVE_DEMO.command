#!/bin/zsh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec /bin/zsh -l "$SCRIPT_DIR/run_full_adaptive_demo.zsh"
