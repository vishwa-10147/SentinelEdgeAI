#!/usr/bin/env bash
set -euo pipefail
# Rotate the HEALTH_PASS in /etc/sentinel/health.env and restart services that consume it.

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

HEALTH_FILE=/etc/sentinel/health.env
TMP=$(mktemp)

NEWPASS=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9_-' | head -c 20)

cat > "$TMP" <<EOF
HEALTH_USER=health
HEALTH_PASS=${NEWPASS}
HEALTH_BIND_LOCALHOST=false
EOF

chmod 600 "$TMP"
chown root:root "$TMP"
mv "$TMP" "$HEALTH_FILE"

# Ensure the runtime copy is updated (health-agent will copy on restart)
systemctl try-restart sentinel-health-agent.service || true

# Restart main service so it reads new creds if necessary
systemctl try-restart sentineledgeai.service || true

logger -t sentinel-rotate "Rotated health password"
echo "Rotated HEALTH_PASS and wrote to $HEALTH_FILE"
