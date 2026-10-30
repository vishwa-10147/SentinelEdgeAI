#!/usr/bin/env bash
set -euo pipefail

# Install SentinelEdgeAI as the Brain on an NVIDIA Jetson (JetPack 6.x).
#
#   sudo bash deploy/jetson/install_brain.sh sentineledgeai-pi-<version>.tar.gz
#
# JetPack 6 ships Python 3.10, but the runtime needs >= 3.11 (numpy 2.4), so
# this script installs a private CPython 3.11 with uv under
# /opt/sentineledgeai/python and builds the release venv from it. The
# release package bundles aarch64 wheels for CPython 3.11, so the install
# itself needs no internet once uv and Python are present.
#
# After it finishes: open https://<jetson>:9000, sign in, choose the Brain
# role in Setup, then enrol sensors from the Sensors panel.
#
# Not yet validated on Jetson hardware; please report anything that differs.

PKG="${1:-}"
UV_VERSION="${UV_VERSION:-0.5.11}"
PY_VERSION="${SENTINEL_JETSON_PYTHON:-3.11}"
PY_DIR="${SENTINEL_PYTHON_DIR:-/opt/sentineledgeai/python}"
HERE="$(cd "$(dirname "$0")" && pwd)"

log() { printf '[install_brain] %s\n' "$*"; }
die() { printf '[install_brain] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -n "$PKG" ] && [ -f "$PKG" ] || die "usage: sudo bash $0 sentineledgeai-pi-<version>.tar.gz"
[ "$(uname -m)" = "aarch64" ] || die "expected an aarch64 Jetson, found $(uname -m)"
if [ -f /etc/nv_tegra_release ]; then
  log "Jetson: $(head -1 /etc/nv_tegra_release)"
else
  log "WARNING: /etc/nv_tegra_release not found; continuing as a generic aarch64 brain"
fi

# 1. uv, pinned, installed for root only
if ! command -v uv >/dev/null 2>&1; then
  log "installing uv $UV_VERSION"
  python3 -m pip install --quiet "uv==$UV_VERSION" || die "could not install uv (needs internet once)"
fi

# 2. private CPython 3.11, never touching the system python3
export UV_PYTHON_INSTALL_DIR="$PY_DIR"
install -d -m 755 "$PY_DIR"
uv python install "$PY_VERSION" >/dev/null || die "uv could not install CPython $PY_VERSION"
PY_BIN="$(uv python find "$PY_VERSION")" || die "CPython $PY_VERSION not found after install"
"$PY_BIN" -c 'import venv, ensurepip, sys; print(sys.version)' >/dev/null \
  || die "$PY_BIN lacks venv/ensurepip"
log "using $("$PY_BIN" -V) at $PY_BIN"

# 3. the normal device installer, pointed at that interpreter
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
tar -xzf "$PKG" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
[ -x "$SRC/packaging/sentinelctl" ] || [ -f "$SRC/packaging/sentinelctl" ] || die "package has no sentinelctl"
SENTINEL_PYTHON="$PY_BIN" bash "$SRC/packaging/sentinelctl" install "$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"

# 4. later 'sentinelctl upgrade' runs read the interpreter from here
echo "$PY_BIN" > /etc/sentinel/python
chmod 644 /etc/sentinel/python
log "recorded $PY_BIN in /etc/sentinel/python for future upgrades"

log "done. Open https://$(hostname -I | awk '{print $1}'):9000, sign in and choose the Brain role in Setup."
log "sensors connect to port 9443; allow it on the management network."
