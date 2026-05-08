#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-$(date +%Y%m%d%H%M%S)}"
DIST_DIR="$REPO_DIR/dist"
STAGE_DIR="$(mktemp -d)"
PKG_NAME="sentineledgeai-pi-$VERSION"
PKG_ROOT="$STAGE_DIR/$PKG_NAME"

mkdir -p "$DIST_DIR" "$PKG_ROOT"

rsync -a \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude 'venv' \
  --exclude 'frontend/node_modules' \
  --exclude 'frontend/dist' \
  --exclude 'logs' \
  --exclude '.pytest_cache' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude 'alerts.json' \
  --exclude 'flows.csv' \
  --exclude 'live_events.jsonl' \
  --exclude 'firewall_rules.json' \
  --exclude 'firewall_policy.json' \
  "$REPO_DIR/" "$PKG_ROOT/"

cat > "$PKG_ROOT/MANIFEST.txt" <<EOF
SentinelEdgeAI Pi package
Version: $VERSION
Built: $(date -u +%Y-%m-%dT%H:%M:%SZ)

Install:
  sudo bash packaging/pi/install_from_package.sh
  sudo bash /opt/sentineledgeai/deploy/pi/install_pi.sh --install-rollback
EOF

tar -C "$STAGE_DIR" -czf "$DIST_DIR/$PKG_NAME.tar.gz" "$PKG_NAME"
rm -rf "$STAGE_DIR"

echo "$DIST_DIR/$PKG_NAME.tar.gz"
