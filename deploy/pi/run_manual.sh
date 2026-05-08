#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../../" && pwd)"
VENV_DIR="${VENV_DIR:-$HOME/.venv/sentineledgeai}"

echo "Repository: $REPO_DIR"
echo "Virtualenv: $VENV_DIR"

if [ ! -d "$VENV_DIR" ]; then
  echo "Virtualenv not found at $VENV_DIR. Create it with: python3 -m venv $VENV_DIR" >&2
  exit 1
fi

case "${1:-}" in
  main)
    echo "Running main.py (press Ctrl+C to stop)"
    . "$VENV_DIR/bin/activate"
    python "$REPO_DIR/main.py"
    ;;
  streamlit)
    echo "Running Streamlit dashboard on port 8501"
    . "$VENV_DIR/bin/activate"
    streamlit run "$REPO_DIR/dashboard/streamlit_app.py" --server.port 8501 --server.address 0.0.0.0
    ;;
  *)
    echo "Usage: $0 {main|streamlit}"
    exit 2
    ;;
esac
