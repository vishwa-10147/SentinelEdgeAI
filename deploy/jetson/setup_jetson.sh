#!/usr/bin/env bash
set -euo pipefail

# Create a Python virtualenv for Jetson and install Python deps.
REPO_DIR="$(cd "$(dirname "$0")/../../" && pwd)"
VENV_DIR="${1:-$HOME/.venv/sentineledgeai}"

echo "Repository: $REPO_DIR"
echo "Creating venv at: $VENV_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

if [ -f "$REPO_DIR/requirements.txt" ]; then
  "$VENV_DIR/bin/pip" install -r "$REPO_DIR/requirements.txt"
else
  echo "requirements.txt not found in repo root" >&2
  exit 1
fi

echo "Setup complete. Activate with: source $VENV_DIR/bin/activate"
echo "Run main: python $REPO_DIR/main.py"
