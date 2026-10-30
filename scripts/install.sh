#!/usr/bin/env bash
set -euo pipefail

# One-command install of SentinelEdgeAI on a Raspberry Pi or Jetson.
#
#   curl -fsSLO https://raw.githubusercontent.com/vishwa-10147/SentinelEdgeAI/main/scripts/install.sh
#   less install.sh                       # read it first
#   sudo bash install.sh --preset office --signing-key /path/to/model_signing.key
#
# Options:
#   --preset home|office|ot|enterprise   response policy to start with (default: home)
#   --signing-key FILE                   model signing key (skip if /etc/sentinel/model_signing.key exists)
#   --package FILE                       install this package instead of downloading the latest release
#   --mirror file:///path                offline mirror containing latest.json, the package and its .sha256
#
# Every download is checked against its SHA-256; the Sigstore signature is
# verified too when cosign is installed (set SENTINEL_REQUIRE_SIGNATURE=1 to
# make that mandatory). The package's bundled wheels decide the Python
# version; if the system python3 differs, a private CPython is installed with
# uv under /opt/sentineledgeai/python (the system python3 is never changed).

PRESET=home; KEY=""; PKG=""; MIRROR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --preset) PRESET="$2"; shift 2 ;;
    --signing-key) KEY="$2"; shift 2 ;;
    --package) PKG="$2"; shift 2 ;;
    --mirror) MIRROR="$2"; shift 2 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash $0 ..."
case "$PRESET" in home|office|ot|enterprise) ;; *) die "--preset must be home, office, ot or enterprise" ;; esac
case "$(uname -m)" in aarch64|x86_64) ;; *) die "unsupported CPU $(uname -m) (aarch64 or x86_64 needed)" ;; esac

missing=""
for cmd in python3 curl nft openssl sha256sum; do command -v "$cmd" >/dev/null || missing="$missing $cmd"; done
python3 -c 'import venv, ensurepip' 2>/dev/null || missing="$missing python3-venv"
if [ -n "$missing" ]; then
  log "installing prerequisites:$missing"
  command -v apt-get >/dev/null || die "install these first:$missing"
  if ! out="$(DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv curl nftables openssl ca-certificates 2>&1)"; then
    printf '%s\n' "$out" | tail -3 >&2
    die "apt-get failed (see above); fix the package manager, then run this installer again"
  fi
else
  log "prerequisites present"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fetch() { if [[ "$1" == file://* ]]; then cp "${1#file://}" "$2"; else curl -fsSL --max-time 900 -o "$2" "$1"; fi; }

if [ -z "$PKG" ]; then
  if [ -n "$MIRROR" ]; then
    read -r VERSION URL < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["version"], d["tarball"])' "${MIRROR#file://}/latest.json")
  else
    read -r VERSION URL < <(curl -fsSL https://api.github.com/repos/vishwa-10147/SentinelEdgeAI/releases/latest | python3 -c '
import json, sys
d = json.load(sys.stdin); v = d["tag_name"].lstrip("v")
print(v, next(a["browser_download_url"] for a in d["assets"] if a["name"] == f"sentineledgeai-pi-{v}.tar.gz"))')
  fi
  log "downloading SentinelEdgeAI $VERSION"
  PKG="$WORK/sentineledgeai-pi-$VERSION.tar.gz"
  fetch "$URL" "$PKG"
  fetch "$URL.sha256" "$PKG.sha256" || die "checksum file missing; refusing to install"
  if fetch "$URL.cosign.bundle" "$PKG.cosign.bundle" 2>/dev/null && command -v cosign >/dev/null; then
    cosign verify-blob --bundle "$PKG.cosign.bundle" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp '^https://github.com/vishwa-10147/SentinelEdgeAI/' "$PKG" >/dev/null 2>&1 \
      || die "Sigstore signature verification failed"
    log "Sigstore signature verified"
  elif [ "${SENTINEL_REQUIRE_SIGNATURE:-0}" = "1" ]; then
    die "signature required but cosign or the signature bundle is missing"
  fi
fi
[ -f "$PKG" ] || die "package not found: $PKG"
[ -f "$PKG.sha256" ] || die "missing $PKG.sha256 next to the package"
(cd "$(dirname "$PKG")" && sha256sum -c "$(basename "$PKG").sha256" >/dev/null) || die "checksum mismatch"
log "checksum OK"

# which Python do the bundled wheels need?
WANT="$(tar -tzf "$PKG" | sed -n 's#.*/wheels/.*-cp3\([0-9][0-9]*\)-cp3[0-9]*-.*#\1#p' | sort -u | head -1)"
HAVE="$(python3 -c 'import sys; print(sys.version_info[1])')"
PYTHON=python3
if [ -n "$WANT" ] && [ "$WANT" != "$HAVE" ]; then
  log "package needs Python 3.$WANT, system has 3.$HAVE: installing a private CPython 3.$WANT with uv"
  command -v uv >/dev/null || python3 -m pip install --quiet --break-system-packages "uv==${UV_VERSION:-0.5.11}" 2>/dev/null \
    || python3 -m pip install --quiet "uv==${UV_VERSION:-0.5.11}" || die "could not install uv"
  export UV_PYTHON_INSTALL_DIR=/opt/sentineledgeai/python
  install -d -m 755 "$UV_PYTHON_INSTALL_DIR"
  uv python install "3.$WANT" >/dev/null || die "uv could not install CPython 3.$WANT"
  PYTHON="$(uv python find "3.$WANT")"
fi

if [ -n "$KEY" ]; then
  install -d -m 750 /etc/sentinel
  install -m 600 -o root -g root "$KEY" /etc/sentinel/model_signing.key
  log "installed the model signing key"
fi
[ -f /etc/sentinel/model_signing.key ] || die "no model signing key: pass --signing-key FILE"

tar -xzf "$PKG" -C "$WORK"
SRC="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d -name 'sentineledgeai-pi-*' | head -1)"
SENTINEL_PYTHON="$PYTHON" bash "$SRC/packaging/sentinelctl" install "$PKG"
[ "$PYTHON" = python3 ] || echo "$PYTHON" > /etc/sentinel/python

sentinelctl preset "$PRESET"
IP="$(hostname -I | awk '{print $1}')"
log "done."
log "  console:            https://$IP:9000"
log "  certificate:        $(openssl x509 -in /etc/sentinel/tls/cert.pem -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
log "  first sign-in:      user 'admin', password: sudo cat /etc/sentinel/initial-admin-password"
log "  policy preset:      $PRESET (change with: sudo sentinelctl preset <name>)"
log "  hardening (review): sudo bash /opt/sentineledgeai/current/deploy/pi/harden_os.sh"
