#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-sentineledgeai.service}"
DROPIN_DIR="/etc/systemd/system/${SERVICE_NAME}.d"
DROPIN_FILE="$DROPIN_DIR/enable_enforcement.conf"
BACKUP_DIR="/var/backups/sentineledgeai"

usage() {
  cat <<EOF
Usage: sudo $0 enable|disable|status

Atomically enable or disable real firewall enforcement for $SERVICE_NAME.
The script writes/removes the FIREWALL_DRY_RUN=0 systemd drop-in, keeps a
timestamped backup, reloads systemd, and restarts the service.
EOF
}

require_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "Run as root (sudo) to modify systemd units" >&2
    exit 2
  fi
}

backup_current() {
  mkdir -p "$BACKUP_DIR"
  if [ -f "$DROPIN_FILE" ]; then
    cp "$DROPIN_FILE" "$BACKUP_DIR/enable_enforcement.conf.$(date +%Y%m%d%H%M%S).bak"
  fi
}

restart_service() {
  systemctl daemon-reload
  if ! systemctl restart "$SERVICE_NAME"; then
    echo "Service restart failed. Inspect: journalctl -u $SERVICE_NAME -n 100 --no-pager" >&2
    exit 3
  fi
}

enable_enforcement() {
  require_root
  mkdir -p "$DROPIN_DIR"
  backup_current
  tmp="$(mktemp "$DROPIN_DIR/.enable_enforcement.XXXXXX")"
  cat > "$tmp" <<'EOF'
[Service]
Environment="FIREWALL_DRY_RUN=0"
EOF
  chmod 0644 "$tmp"
  mv "$tmp" "$DROPIN_FILE"
  restart_service
  echo "Real firewall enforcement enabled for $SERVICE_NAME."
}

disable_enforcement() {
  require_root
  backup_current
  if [ -f "$DROPIN_FILE" ]; then
    rm -f "$DROPIN_FILE"
    restart_service
    echo "Real firewall enforcement disabled for $SERVICE_NAME. Service is back to dry-run unless another environment source overrides it."
  else
    echo "No enforcement drop-in found at $DROPIN_FILE"
  fi
}

status_enforcement() {
  if [ -f "$DROPIN_FILE" ]; then
    echo "enabled: $DROPIN_FILE exists"
    cat "$DROPIN_FILE"
  else
    echo "disabled: no $DROPIN_FILE"
  fi
}

case "${1:-}" in
  enable) enable_enforcement ;;
  disable) disable_enforcement ;;
  status) status_enforcement ;;
  -h|--help|"") usage ;;
  *) usage >&2; exit 2 ;;
esac
