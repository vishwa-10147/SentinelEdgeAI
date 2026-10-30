#!/usr/bin/env bash
set -euo pipefail

# Build the Raspberry Pi install tarball.
#
# Package contents come from `git archive HEAD` (committed files only), so
# untracked keys, .env files, virtualenvs and runtime data can never end up in
# a release. The built web console (frontend/dist) is added on top.
#
#   VERSION=1.0.0 bash scripts/build_pi_package.sh
#   SKIP_FRONTEND_BUILD=1 bash scripts/build_pi_package.sh   # reuse frontend/dist

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$REPO_DIR" describe --tags --always --dirty 2>/dev/null || date +%Y%m%d%H%M%S)}"
DIST_DIR="$REPO_DIR/dist"
STAGE_DIR="$(mktemp -d)"
PKG_NAME="sentineledgeai-pi-$VERSION"
PKG_ROOT="$STAGE_DIR/$PKG_NAME"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$DIST_DIR"

if [ -n "$(git -C "$REPO_DIR" status --porcelain)" ]; then
  echo "Warning: uncommitted changes are NOT included; the package is built from HEAD" >&2
fi

if [ "${SKIP_FRONTEND_BUILD:-0}" != "1" ]; then
  echo "Building web console..."
  (cd "$REPO_DIR/frontend" && npm ci --legacy-peer-deps && npm run build)
fi
if [ ! -f "$REPO_DIR/frontend/dist/index.html" ]; then
  echo "frontend/dist/index.html is missing; build the web console first" >&2
  exit 1
fi

git -C "$REPO_DIR" archive --format=tar --prefix="$PKG_NAME/" HEAD | tar -x -C "$STAGE_DIR"
mkdir -p "$PKG_ROOT/frontend"
cp -R "$REPO_DIR/frontend/dist" "$PKG_ROOT/frontend/dist"

# Defence in depth: never ship anything that looks like a secret.
SECRETS="$(find "$PKG_ROOT" -type f \( -name '*.key' -o -name '*.pem' -o -name '*.env' \))"
if [ -n "$SECRETS" ]; then
  echo "Refusing to package secret-like files:" >&2
  echo "$SECRETS" >&2
  exit 1
fi

cat > "$PKG_ROOT/MANIFEST.txt" <<EOF
SentinelEdgeAI Pi package
Version: $VERSION
Commit: $(git -C "$REPO_DIR" rev-parse HEAD)
Built: $(date -u +%Y-%m-%dT%H:%M:%SZ)

Install:
  sudo bash packaging/pi/install_from_package.sh
  sudo bash /opt/sentineledgeai/deploy/pi/install_pi.sh --install-rollback
EOF

TARBALL="$DIST_DIR/$PKG_NAME.tar.gz"
tar -C "$STAGE_DIR" -czf "$TARBALL" "$PKG_NAME"
(cd "$DIST_DIR" && sha256sum "$PKG_NAME.tar.gz" > "$PKG_NAME.tar.gz.sha256")

echo "$TARBALL"
