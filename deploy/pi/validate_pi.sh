#!/usr/bin/env bash
set -euo pipefail

# Validate Pi runtime environment and presence of dashboard JSON files.
REPO_DIR="$(cd "$(dirname "$0")/../../" && pwd)"
VENV_DIR="${VENV_DIR:-$HOME/.venv/sentineledgeai}"

echo "Repository: $REPO_DIR"
echo "Checking virtualenv: $VENV_DIR"

if [ ! -d "$VENV_DIR" ]; then
  echo "Virtualenv not found at $VENV_DIR. Create it with: python3 -m venv $VENV_DIR" >&2
  exit 1
fi

echo "Running smoke test..."
PYTHONPATH="$REPO_DIR" "$VENV_DIR/bin/python" "$REPO_DIR/scripts/smoke_test.py"

echo "Ensuring dashboard JSON files exist (alerts.json, live_stats.json, device_profiles.json, risk_timeline.json, health.json)"
for f in alerts.json live_stats.json device_profiles.json risk_timeline.json health.json; do
  if [ ! -f "$REPO_DIR/$f" ]; then
    echo "Creating empty $f"
    case "$f" in
      alerts.json)
        echo "[]" > "$REPO_DIR/$f" ;;
      *)
        echo "{}" > "$REPO_DIR/$f" ;;
    esac
  else
    echo "$f exists"
  fi
done

echo "Validation complete. To run the app manually: source $VENV_DIR/bin/activate && python $REPO_DIR/main.py"
