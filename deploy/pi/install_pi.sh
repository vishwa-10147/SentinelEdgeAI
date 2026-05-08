#!/usr/bin/env bash
set -euo pipefail

# Simple wrapper to run the Pi installer in the repo root.
REPO_DIR="$(cd "$(dirname "$0")/../../" && pwd)"
ENABLE_ENFORCEMENT=0
DISABLE_ENFORCEMENT=0
INSTALL_ROLLBACK=0
SETUP_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --enable-enforcement) ENABLE_ENFORCEMENT=1 ;;
    --disable-enforcement) DISABLE_ENFORCEMENT=1 ;;
    --install-rollback|--enable-rollback) INSTALL_ROLLBACK=1 ;;
    *) SETUP_ARGS+=("$arg") ;;
  esac
done

if [ "$EUID" -ne 0 ]; then
  echo "This script requires sudo to install systemd units; re-running with sudo..."
  exec sudo bash "$0" "$@"
fi

chmod +x "$REPO_DIR/scripts/setup_pi.sh"
bash "$REPO_DIR/scripts/setup_pi.sh" "${SETUP_ARGS[@]}"

if [ "$INSTALL_ROLLBACK" -eq 1 ]; then
  echo "Installing rollback guard units..."
  chmod +x "$REPO_DIR/scripts/firewall_rollback_guard.sh"
  install -m 644 "$REPO_DIR/deploy/pi/sentinel-firewall-rollback-guard.service.example" /etc/systemd/system/sentinel-firewall-rollback-guard.service
  install -m 644 "$REPO_DIR/deploy/pi/sentinel-firewall-rollback-guard.timer.example" /etc/systemd/system/sentinel-firewall-rollback-guard.timer
  mkdir -p /etc/sentinel
  if [ ! -f /etc/sentinel/firewall-rollback.env ]; then
    install -m 600 "$REPO_DIR/deploy/pi/firewall-rollback.env.example" /etc/sentinel/firewall-rollback.env
  fi
  systemctl daemon-reload
  systemctl enable --now sentinel-firewall-rollback-guard.timer
fi

if [ "$ENABLE_ENFORCEMENT" -eq 1 ] && [ "$DISABLE_ENFORCEMENT" -eq 1 ]; then
  echo "Cannot use both --enable-enforcement and --disable-enforcement" >&2
  exit 2
fi

chmod +x "$REPO_DIR/deploy/pi/enforcement_ctl.sh"
if [ "$ENABLE_ENFORCEMENT" -eq 1 ]; then
  "$REPO_DIR/deploy/pi/enforcement_ctl.sh" enable
elif [ "$DISABLE_ENFORCEMENT" -eq 1 ]; then
  "$REPO_DIR/deploy/pi/enforcement_ctl.sh" disable
fi

# Optional: enable rollback guard by copying deploy/pi/firewall-rollback.env
# Usage: install_pi.sh --enable-rollback
ENABLE_ROLLBACK=0
for arg in "$@"; do
  if [ "$arg" = "--enable-rollback" ]; then
    ENABLE_ROLLBACK=1
  fi
done

if [ "$ENABLE_ROLLBACK" -eq 1 ]; then
  SRC="$REPO_DIR/deploy/pi/firewall-rollback.env"
  DEST="/etc/sentinel/firewall-rollback.env"
  if [ -f "$SRC" ]; then
    echo "Installing rollback env to $DEST"
    mkdir -p /etc/sentinel
    cp "$SRC" "$DEST"
    systemctl daemon-reload || true
    systemctl enable --now sentinel-firewall-rollback-guard.timer || true
    echo "Rollback guard installed and timer enabled"
  else
    echo "Rollback env file not found at $SRC; generate it with scripts/enable_firewall_enforcement.sh --apply and retry" >&2
  fi
fi

# Interactive enforcement drop-in creation
for arg in "$@"; do
  if [ "$arg" = "--create-enforce-dropin" ]; then
    echo "This will create a systemd drop-in to enable real firewall enforcement (FIREWALL_DRY_RUN=0)."
    read -p "Proceed and backup existing drop-in if present? [y/N]: " ans
    case "$ans" in
      [Yy]*)
        mkdir -p /etc/systemd/system/sentineledgeai.service.d
        DROP_IN=/etc/systemd/system/sentineledgeai.service.d/enable_enforcement.conf
        if [ -f "$DROP_IN" ]; then
          cp "$DROP_IN" "$DROP_IN.bak.$(date +%s)"
          echo "Existing drop-in backed up to $DROP_IN.bak.*"
        fi
        cat > "$DROP_IN" <<'EOF'
[Service]
Environment="FIREWALL_DRY_RUN=0"
EOF
        systemctl daemon-reload || true
        systemctl restart sentineledgeai.service || true
        echo "Enforcement drop-in created at $DROP_IN and service restarted."
        ;;
      *)
        echo "Skipping enforcement drop-in creation."
        ;;
    esac
  fi
done

# Post-install sanity checks
echo "Running post-install sanity checks..."
sleep 1
echo "- Checking sentinel-health-agent.service status"
sudo systemctl status sentinel-health-agent.service --no-pager || true
echo "- Checking sentineledgeai.service status"
sudo systemctl status sentineledgeai.service --no-pager || true
echo "If services failed, inspect logs with: sudo journalctl -u sentinel-health-agent.service -xe && sudo journalctl -u sentineledgeai.service -n 200"
