#!/bin/sh
# Installer script for SentinelEdgeAI firewall rollback guard
# Usage: sudo ./install_firewall_guard.sh [--env-file PATH] [--apply]

set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
UNIT_DIR=/etc/systemd/system
INSTALL_SCRIPT=/usr/local/bin/sentinel-firewall-rollback.sh
ENV_DEST=/etc/sentinel/firewall-rollback.env

ENV_FILE="${1:-}" # optional first arg
APPLY=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file) shift; ENV_FILE="$1"; shift;;
    --apply) APPLY=1; shift;;
    -h|--help) echo "Usage: sudo $0 [--env-file PATH] [--apply]"; exit 0;;
    *) shift;;
  esac
done

echo "Installer root: $ROOT_DIR"

if [ "$APPLY" -ne 1 ]; then
  echo "DRY-RUN: no changes will be made. Rerun with --apply to perform installation."
fi

copy_unit(){
  src="$ROOT_DIR/packaging/$1"
  if [ ! -f "$src" ]; then
    echo "Missing $src" >&2; return 1
  fi
  dest="$UNIT_DIR/$1"
  echo "Installing $src -> $dest"
  if [ "$APPLY" -eq 1 ]; then
    cp "$src" "$dest"
  fi
}

install_script(){
  src="$ROOT_DIR/packaging/sentinel-firewall-rollback.sh"
  echo "Installing script $src -> $INSTALL_SCRIPT"
  if [ "$APPLY" -eq 1 ]; then
    cp "$src" "$INSTALL_SCRIPT"
    chmod 755 "$INSTALL_SCRIPT"
  fi
}

install_env(){
  if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
    echo "Installing env file $ENV_FILE -> $ENV_DEST"
    if [ "$APPLY" -eq 1 ]; then
      mkdir -p "$(dirname "$ENV_DEST")"
      cp "$ENV_FILE" "$ENV_DEST"
      chmod 600 "$ENV_DEST"
    fi
  else
    echo "No env file provided or not found; skipping env install. Use --env-file to provide one." 
  fi
}

enable_timer(){
  echo "Reloading systemd and enabling timer"
  if [ "$APPLY" -eq 1 ]; then
    systemctl daemon-reload
    systemctl enable --now sentinel-firewall-rollback.timer
  fi
}

echo "Preparing to install rollback guard (dry-run=$([ $APPLY -eq 0 ] && echo true || echo false))"
copy_unit sentinel-firewall-rollback.service
copy_unit sentinel-firewall-rollback.timer
install_script
install_env
enable_timer

echo "Done."
echo "If you ran without --apply, re-run with --apply to perform installation."
