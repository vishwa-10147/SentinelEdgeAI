#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/opt/sentineledgeai}"
SRC_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ "$EUID" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 2
fi

mkdir -p "$PREFIX"
# --delete removes files dropped from the release; the excludes below are
# runtime state and secrets on the device, which an upgrade must never delete.
rsync -a --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude 'venv' \
  --exclude 'frontend/node_modules' \
  --exclude 'logs' \
  --exclude '*.pyc' \
  --exclude 'data' \
  --exclude '*.db' \
  --exclude '*.key' \
  --exclude '*.env' \
  --exclude 'firewall_rules.json' \
  --exclude 'firewall_policy.json' \
  --exclude 'alerts.json' \
  --exclude 'live_events.jsonl' \
  --exclude 'live_stats.json' \
  --exclude 'health.json' \
  --exclude 'device_profiles.json' \
  --exclude 'risk_timeline.json' \
  --exclude 'flows.csv' \
  "$SRC_DIR/" "$PREFIX/"

chmod +x "$PREFIX/scripts/"*.sh "$PREFIX/deploy/pi/"*.sh || true
echo "Installed SentinelEdgeAI package to $PREFIX"
echo "Next: sudo bash $PREFIX/deploy/pi/install_pi.sh --install-rollback"
