#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/opt/sentineledgeai}"
SRC_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ "$EUID" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 2
fi

mkdir -p "$PREFIX"
rsync -a --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude 'venv' \
  --exclude 'frontend/node_modules' \
  --exclude 'logs' \
  --exclude '*.pyc' \
  "$SRC_DIR/" "$PREFIX/"

chmod +x "$PREFIX/scripts/"*.sh "$PREFIX/deploy/pi/"*.sh || true
echo "Installed SentinelEdgeAI package to $PREFIX"
echo "Next: sudo bash $PREFIX/deploy/pi/install_pi.sh --install-rollback"
