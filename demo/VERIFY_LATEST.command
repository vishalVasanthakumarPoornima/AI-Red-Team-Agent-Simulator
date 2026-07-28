#!/bin/zsh
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LATEST="$SCRIPT_DIR/output/latest"

clear 2>/dev/null || true
printf '\nDemo Package Integrity Verification\n'
printf '%s\n' '==================================='

if [[ ! -f "$LATEST/INTEGRITY.sha256" ]]; then
  printf 'No integrity file was found. Run the demo first.\n'
  printf 'Press Return to close.'
  read -r _
  exit 1
fi

cd "$LATEST"
if shasum -a 256 -c INTEGRITY.sha256; then
  printf '\nAll packaged files match their recorded SHA-256 hashes.\n'
else
  printf '\nVerification failed. At least one packaged file changed or is missing.\n'
fi

printf '\nPress Return to close.'
read -r _
