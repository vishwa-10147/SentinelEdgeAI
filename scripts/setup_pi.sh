#!/usr/bin/env bash
set -euo pipefail

# SentinelEdgeAI Pi setup script
# Usage:
#   sudo bash scripts/setup_pi.sh [main|streamlit]
# Default installs the `main.py` service. Pass `streamlit` to install the Streamlit service instead.

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_TYPE="${1:-main}"

# Determine the target (non-root) user to run the service and own the venv.
TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
VENV_DIR="$TARGET_HOME/.venv/sentineledgeai"
SERVICE_NAME="sentineledgeai.service"
if [ "$SERVICE_TYPE" = "streamlit" ]; then
  SERVICE_NAME="sentineledgeai-streamlit.service"
fi
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

echo "Repository dir: $REPO_DIR"
echo "Requested service type: $SERVICE_TYPE"

echo "Updating apt and installing system packages..."
sudo apt update && sudo apt upgrade -y
# Try to install common build and runtime packages. Some packages
# (like libatlas-base-dev) may not be available on all Pi OS variants;
# try a fallback and continue if neither is present.
sudo apt install -y git build-essential libjpeg-dev libssl-dev ffmpeg python3-venv python3-pip libusb-1.0-0-dev rsync || true
if ! dpkg -s libatlas-base-dev >/dev/null 2>&1; then
  echo "libatlas-base-dev not available; attempting libatlas3-base"
  sudo apt install -y libatlas3-base || echo "No atlas package available; numeric performance may be degraded"
fi

# Create venv
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating python virtualenv at $VENV_DIR (owner: $TARGET_USER)"
  sudo -u "$TARGET_USER" python3 -m venv "$VENV_DIR"
fi

echo "Installing/upgrading pip and wheel inside the venv as $TARGET_USER..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
if [ -f "$REPO_DIR/requirements.txt" ]; then
  "$VENV_DIR/bin/pip" install -r "$REPO_DIR/requirements.txt"
else
  echo "Warning: requirements.txt not found in repo — please check $REPO_DIR/requirements.txt"
fi
# Ensure optional helpers are available
"$VENV_DIR/bin/pip" install python-dotenv || true

echo "Creating systemd service at $SERVICE_PATH (requires sudo)"

# Install health agent and logrotate config if present in repo
if [ -f "$REPO_DIR/scripts/sentinel-health-agent.sh" ]; then
  echo "Installing sentinel-health-agent to /usr/local/bin and unit to /etc/systemd/system"
  sudo install -m 755 -o root -g root "$REPO_DIR/scripts/sentinel-health-agent.sh" /usr/local/bin/sentinel-health-agent.sh || true
fi
if [ -f "$REPO_DIR/packaging/sentinel-health-agent.service" ]; then
  sudo install -m 644 -o root -g root "$REPO_DIR/packaging/sentinel-health-agent.service" /etc/systemd/system/sentinel-health-agent.service || true
  sudo systemctl daemon-reload || true
  sudo systemctl enable --now sentinel-health-agent.service || true
fi
if [ -f "$REPO_DIR/packaging/logrotate/sentinel-edgeai.conf" ]; then
  sudo install -m 644 -o root -g root "$REPO_DIR/packaging/logrotate/sentinel-edgeai.conf" /etc/logrotate.d/sentinel-edgeai || true
fi

if [ "$SERVICE_TYPE" = "streamlit" ]; then
  # Streamlit service
  sudo tee "$SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=SentinelEdgeAI Streamlit service
After=network.target

[Service]
  User=$TARGET_USER
WorkingDirectory=$REPO_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_DIR/bin/streamlit run $REPO_DIR/dashboard/streamlit_app.py --server.port 8501 --server.address 0.0.0.0
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
else
  # Main application service
  sudo tee "$SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=SentinelEdgeAI service
After=network.target

[Service]
  User=$TARGET_USER
WorkingDirectory=$REPO_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_DIR/bin/python $REPO_DIR/main.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
fi

sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE_NAME"

echo "--- Setup complete ---"
echo "Please edit your config file(s) as needed:"
echo " - $REPO_DIR/config.yaml"
echo " - $REPO_DIR/alerts.json"

echo "To view logs: sudo journalctl -u $SERVICE_NAME -f"

echo "If you need camera hardware permissions, add your user to the 'video' group:" 
echo "  sudo usermod -aG video $SUDO_USER"

echo "Reboot or re-login may be required after group changes."

echo "If you prefer not to install the systemd service, run the app manually with:"
echo "  source $VENV_DIR/bin/activate && python $REPO_DIR/main.py"
