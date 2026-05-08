#!/usr/bin/env bash
set -euo pipefail

SERVICE_SRC="$(pwd)/deploy/pi/sentinel-local.service"
DROPIN_SRC="$(pwd)/deploy/pi/override.conf"
HARDENING_SRC="$(pwd)/deploy/pi/hardening.conf"
SERVICE_DST="/etc/systemd/system/sentinel-local.service"
DROPIN_DIR="/etc/systemd/system/sentinel-local.service.d"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (sudo)."
  echo "Run: sudo $0"
  exit 2
fi

if [ ! -f "$SERVICE_SRC" ]; then
  echo "Service source not found: $SERVICE_SRC"
  exit 1
fi

echo "Installing sentinel-local.service to $SERVICE_DST"
cp "$SERVICE_SRC" "$SERVICE_DST"
mkdir -p "$DROPIN_DIR"
cp "$DROPIN_SRC" "$DROPIN_DIR/override.conf"
if [ -f "$HARDENING_SRC" ]; then
  cp "$HARDENING_SRC" "$DROPIN_DIR/hardening.conf"
fi

echo "Reloading systemd daemon and enabling service"
systemctl daemon-reload
systemctl enable --now sentinel-local.service

echo "Service installed and started. Check status with: systemctl status sentinel-local.service"
