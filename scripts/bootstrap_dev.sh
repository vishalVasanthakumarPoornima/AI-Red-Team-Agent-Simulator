#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3.13}"
VENV_DIR="${VENV_DIR:-.venv}"
PIP_CACHE_DIR="${PIP_CACHE_DIR:-${TMPDIR:-/tmp}/ai-red-team-pip-cache}"
export PIP_CACHE_DIR

mkdir -p "${PIP_CACHE_DIR}"

"${PYTHON_BIN}" -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
if [[ "${INSTALL_DEV_TOOLS:-1}" == "1" ]]; then
  "${VENV_DIR}/bin/python" -m pip install -e '.[dev]'
else
  "${VENV_DIR}/bin/python" -m pip install -e .
fi

cat <<MSG
Development environment ready.

Activate it with:
  source ${VENV_DIR}/bin/activate

Run validation with:
  ${VENV_DIR}/bin/python -m unittest discover -s tests
  ${VENV_DIR}/bin/redteam --help
MSG
