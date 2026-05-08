#!/usr/bin/env bash
set -euo pipefail

# Idempotent installer wrapper for Pi: safe to re-run
REPO_DIR="$(cd "$(dirname "$0")/../../" && pwd)"

echo "Running idempotent installer from $REPO_DIR"

# Ensure systemd env path exists
sudo mkdir -p /etc/sentinel || true
if [ ! -f /etc/sentinel/integration_alert.env ]; then
  sudo tee /etc/sentinel/integration_alert.env > /dev/null <<EOF
# INTEGRATION_ALERT_WEBHOOK=
INTEGRATION_ALERT_WEBHOOK=
EOF
  sudo chmod 600 /etc/sentinel/integration_alert.env
  echo "Created /etc/sentinel/integration_alert.env (edit to add webhook)"
else
  echo "/etc/sentinel/integration_alert.env already exists"
fi

# Run main setup (creates venv and service units)
chmod +x "$REPO_DIR/scripts/setup_pi.sh"
sudo bash "$REPO_DIR/scripts/setup_pi.sh" "$@"

echo "Idempotent install complete. Check services with: sudo systemctl status sentineledgeai.service"
