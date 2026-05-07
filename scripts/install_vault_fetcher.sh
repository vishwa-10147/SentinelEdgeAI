#!/bin/sh
set -euo pipefail

# Install the Vault health fetcher script and systemd units, then enable timer
INSTALL_BIN=/usr/local/bin/fetch-health-from-vault.sh
SERVICE_UNIT=/etc/systemd/system/sentinel-health-vault.service
TIMER_UNIT=/etc/systemd/system/sentinel-health-vault.timer

echo "Installing fetcher to $INSTALL_BIN"
sudo install -m 755 scripts/fetch_health_from_vault.sh "$INSTALL_BIN"
echo "Installing systemd service to $SERVICE_UNIT"
sudo install -m 644 packaging/sentinel-health-vault.service "$SERVICE_UNIT"
echo "Installing systemd timer to $TIMER_UNIT"
sudo install -m 644 packaging/sentinel-health-vault.timer "$TIMER_UNIT"

echo "Reloading systemd and enabling timer"
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-health-vault.timer

echo "Installation complete. Timer enabled. Use 'systemctl status sentinel-health-vault.timer' to verify."

# Ensure node_exporter textfile collector directories exist with correct perms so the fetcher can write metrics
TEXTDIRS="/var/lib/node_exporter/textfile_collector /var/run/node_exporter/textfile_collector /var/cache/node_exporter/textfile_collector"
for d in $TEXTDIRS; do
	if [ ! -d "$d" ]; then
		echo "Creating textfile directory $d"
		sudo mkdir -p "$d"
		sudo chown root:root "$d"
		sudo chmod 755 "$d"
	fi
done

echo "Created/verified node_exporter textfile collector directories."
