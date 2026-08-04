#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS_DIR="${PROJECT_DIR}/reports"

if [[ ! -d "${REPORTS_DIR}" ]]; then
  echo "No generated reports directory exists; the demo is already reset."
  exit 0
fi

BACKUP_ROOT="${TMPDIR:-/tmp}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT%/}/ai-red-team-reports-${STAMP}"

if [[ -e "${BACKUP_DIR}" ]]; then
  echo "ERROR: Refusing to overwrite existing backup ${BACKUP_DIR}" >&2
  exit 1
fi

mv "${REPORTS_DIR}" "${BACKUP_DIR}"
echo "Demo reports moved safely to: ${BACKUP_DIR}"
echo "Run ./scripts/run_demo.sh to create a clean report tree."
