#!/usr/bin/env bash
set -euo pipefail

# Simple cross-platform installer for SentinelEdgeAI
# Usage:
#   sudo bash scripts/install_on_device.sh --prefix /opt/sentineledgeai --unattended --install-deps --enable-service
# The script detects Raspberry Pi vs Jetson vs x86 and installs minimal system deps,
# creates a Python venv, installs Python requirements, and optionally creates a systemd service.

PREFIX="${PREFIX:-/opt/sentineledgeai}"
UNATTENDED=0
INSTALL_DEPS=0
ENABLE_SERVICE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --unattended) UNATTENDED=1; shift;;
    --install-deps) INSTALL_DEPS=1; shift;;
    --enable-service) ENABLE_SERVICE=1; shift;;
    -h|--help) echo "Usage: $0 [--prefix PATH] [--install-deps] [--unattended] [--enable-service]"; exit 0;;
    *) echo "Unknown arg $1"; exit 2;;
  esac
done

if [[ $(id -u) -ne 0 ]]; then
  echo "This installer requires sudo/root for installing system packages and creating /opt paths. Re-run with sudo." >&2
  exit 3
fi

echo "Installer starting. Prefix=$PREFIX"

# detect platform
ARCH=$(uname -m)
OS_ID="unknown"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID=${ID:-unknown}
fi

echo "Detected OS=$OS_ID ARCH=$ARCH"

apt_install_common() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3-venv python3-dev build-essential git curl ca-certificates \
    libssl-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev \
    libncursesw5-dev pkg-config
}

jetson_check() {
  # basic check for NVIDIA Jetson (presence of /etc/nv_tegra_release or cuda)
  if [ -f /etc/nv_tegra_release ] || [ -d /usr/local/cuda ]; then
    return 0
  fi
  return 1
}

if [ "$INSTALL_DEPS" -eq 1 ]; then
  echo "Installing system dependencies..."
  if command -v apt-get >/dev/null 2>&1; then
    if jetson_check; then
      echo "Jetson detected: please ensure JetPack is installed prior to running this script. Will install base deps only."
      apt_install_common
    else
      apt_install_common
    fi
  else
    echo "Automatic system package installation not supported for this platform. Please install system deps manually." >&2
  fi
fi

# copy files to prefix
mkdir -p "$PREFIX"
rsync -a --delete --exclude '.git' --exclude 'venv' --exclude '.venv' --exclude 'frontend/node_modules' --exclude 'logs' . "$PREFIX/"
chown -R root:root "$PREFIX"

# create python venv
PY_VENV="$PREFIX/venv"
if [ ! -d "$PY_VENV" ]; then
  python3 -m venv "$PY_VENV"
fi
source "$PY_VENV/bin/activate"
pip install --upgrade pip

# use piwheels index for armhf/aarch64 if on Raspberry/arm
if [[ "$ARCH" == "armv7l" || "$ARCH" == "aarch64" ]]; then
  echo "Using piwheels/simple index for faster arm installs"
  pip install --no-cache-dir -r "$PREFIX/requirements.txt" -i https://www.piwheels.org/simple || pip install --no-cache-dir -r "$PREFIX/requirements.txt" || true
else
  pip install --no-cache-dir -r "$PREFIX/requirements.txt" || true
fi

echo "Python packages installed into $PY_VENV"

if [ "$ENABLE_SERVICE" -eq 1 ]; then
  SERVICE_PATH="/etc/systemd/system/sentineledge.service"
  echo "Creating systemd service at $SERVICE_PATH"
  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=SentinelEdgeAI service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PREFIX
Environment=PYTHONUNBUFFERED=1
ExecStart=$PY_VENV/bin/python $PREFIX/dashboard/dashboard_api.py
Restart=always
RestartSec=5
Environment=ENABLE_FILE_FALLBACK=0

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable sentineledge.service
  systemctl start sentineledge.service
  echo "Service started. Check status: systemctl status sentineledge.service"
fi

echo "Install complete. Backend should be available on port 9000 by default." 
echo "To run manually: source $PY_VENV/bin/activate && python $PREFIX/dashboard/dashboard_api.py"

exit 0
