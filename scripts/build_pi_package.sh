#!/usr/bin/env bash
set -euo pipefail

# Build the Raspberry Pi install tarball.
#
# Package contents come from `git archive HEAD` (committed files only), so
# untracked keys, .env files, virtualenvs and runtime data can never end up in
# a release. The built web console (frontend/dist) and a wheelhouse of every
# runtime dependency for the Pi (linux aarch64, CPython 3.11) are added on top,
# so devices install with no internet access.
#
#   bash scripts/build_pi_package.sh                       # version from VERSION file
#   VERSION=1.1.0-rc1 bash scripts/build_pi_package.sh     # override the version
#   SKIP_FRONTEND_BUILD=1 bash scripts/build_pi_package.sh # reuse frontend/dist
#   INCLUDE_WHEELS=0 bash scripts/build_pi_package.sh      # no wheelhouse (online install)
#
# Reproducible: the same commit and dependency set always produce the same
# tarball bytes (timestamps fixed to the commit time, sorted entries, fixed
# owners and modes, gzip without a timestamp). Check with:
#   bash scripts/build_pi_package.sh && sha256sum dist/*.tar.gz   (twice)

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-$(tr -d '[:space:]' < "$REPO_DIR/VERSION")}"
PYTHON="${PYTHON:-python3}"
# Bookworm ships Python 3.11, trixie 3.13; one package carries wheels for both (space-separated list)
WHEEL_PYTHON_VERSION="${WHEEL_PYTHON_VERSION:-3.11 3.13}"
WHEEL_PLATFORMS="${WHEEL_PLATFORMS:-manylinux2014_aarch64 manylinux_2_17_aarch64 manylinux_2_28_aarch64 manylinux_2_34_aarch64 linux_aarch64}"
DIST_DIR="$REPO_DIR/dist"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_DIR" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
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
printf '%s\n' "$VERSION" > "$PKG_ROOT/VERSION"
mkdir -p "$PKG_ROOT/frontend"
cp -R "$REPO_DIR/frontend/dist" "$PKG_ROOT/frontend/dist"

if [ "${INCLUDE_WHEELS:-1}" = "1" ]; then
  PLATFORM_ARGS=()
  for p in $WHEEL_PLATFORMS; do PLATFORM_ARGS+=(--platform "$p"); done
  MISSING=""
  for pyver in $WHEEL_PYTHON_VERSION; do
    echo "Downloading runtime wheels for Python $pyver on: $WHEEL_PLATFORMS"
    "$PYTHON" -m pip download --quiet --only-binary=:all: \
      --python-version "$pyver" --implementation cp "${PLATFORM_ARGS[@]}" \
      -r "$PKG_ROOT/requirements.txt" -d "$PKG_ROOT/wheels"
    # pip evaluates environment markers on the build host, so make sure every
    # top-level requirement really has a wheel for this target (pure-Python or cpXY)
    tag="cp${pyver/./}"
    while read -r name; do
      norm="$(echo "$name" | tr 'A-Z-.' 'a-z__')"
      ls "$PKG_ROOT/wheels" | tr 'A-Z-.' 'a-z__' | grep "^${norm}_" | grep -qE "(py3|${tag}|abi3)" \
        || MISSING="$MISSING $name($pyver)"
    done < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$PKG_ROOT/requirements.txt" | grep -v '^$' | sed -E 's/[=<>!~;\[].*//')
  done
  if [ -n "$MISSING" ]; then
    echo "No wheel bundled for:$MISSING" >&2
    exit 1
  fi
  echo "Bundled $(ls "$PKG_ROOT/wheels" | wc -l | tr -d ' ') wheels"
fi

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
Built: $(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ) (commit time; reproducible)

Install (first time):
  sha256sum -c $PKG_NAME.tar.gz.sha256
  tar -xzf $PKG_NAME.tar.gz
  sudo bash $PKG_NAME/deploy/pi/provision_key.sh /path/to/model_signing.key
  sudo bash $PKG_NAME/packaging/sentinelctl install $PKG_NAME.tar.gz

Upgrade:
  sudo sentinelctl upgrade $PKG_NAME.tar.gz
Roll back:
  sudo sentinelctl rollback
EOF

TARBALL="$DIST_DIR/$PKG_NAME.tar.gz"
tar -C "$STAGE_DIR" --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' --format=gnu -cf - "$PKG_NAME" | gzip -9 -n > "$TARBALL"
(cd "$DIST_DIR" && sha256sum "$PKG_NAME.tar.gz" > "$PKG_NAME.tar.gz.sha256")

echo "$TARBALL"
