#!/usr/bin/env bash
set -euo pipefail

# Toggle atomic enable/disable for the sentinel installer service and keep a backup
# Usage: installer_atomic_toggle.sh enable|disable

ACTION=${1:-}
if [[ "$ACTION" != "enable" && "$ACTION" != "disable" ]]; then
  echo "Usage: $0 enable|disable" >&2
  exit 2
fi

UNIT=sentineledgeai.service
BACKUP_DIR=/var/lib/sentinel/units-backup
mkdir -p "$BACKUP_DIR"

if [[ "$ACTION" == "disable" ]]; then
  echo "Disabling $UNIT and backing up unit files..."
  sudo systemctl stop "$UNIT" || true
  sudo cp -a /etc/systemd/system/$UNIT* "$BACKUP_DIR/" || true
  sudo systemctl disable "$UNIT" || true
  echo "Disabled and backed up to $BACKUP_DIR"
fi

if [[ "$ACTION" == "enable" ]]; then
  echo "Enabling $UNIT and restoring backups if present..."
  if ls "$BACKUP_DIR"/* >/dev/null 2>&1; then
    sudo cp -a "$BACKUP_DIR"/* /etc/systemd/system/ || true
  fi
  sudo systemctl daemon-reload
  sudo systemctl enable --now "$UNIT"
  echo "Enabled $UNIT"
fi
