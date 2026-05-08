#!/usr/bin/env bash
set -euo pipefail

# Run the repository integration test and append output to repo logs.
REPO_DIR="$(cd "$(dirname "$0")/../../" && pwd)"
VENV_DIR="${VENV_DIR:-$REPO_DIR/.venv}"
LOG_DIR="$REPO_DIR/logs"
LOG_FILE="$LOG_DIR/integration_test.log"

mkdir -p "$LOG_DIR"
echo "[$(date -Is)] Running integration_test.py" >> "$LOG_FILE"
PYTHONPATH="$REPO_DIR" "$VENV_DIR/bin/python" "$REPO_DIR/scripts/integration_test.py" >> "$LOG_FILE" 2>&1 || echo "[$(date -Is)] integration_test failed (see log)" >> "$LOG_FILE"
echo "[$(date -Is)] Done" >> "$LOG_FILE"
