#!/bin/sh
set -euo pipefail

# Fetch HEALTH_PASS from Vault and write /etc/sentinel/health.env
# Requires: `vault` CLI authenticated (VAULT_ADDR and token via env or agent).

VAULT_SECRET_PATH=${VAULT_SECRET_PATH:-secret/sentineledge/health}
OUT=/etc/sentinel/health.env
TMP=$(mktemp /tmp/health.env.XXXX)

PASS=$(vault kv get -field=HEALTH_PASS "$VAULT_SECRET_PATH") || exit 2
if [ -z "$PASS" ]; then
  echo "vault: no HEALTH_PASS at $VAULT_SECRET_PATH" >&2
  exit 3
fi

# write atomically with strict permissions
umask 177
printf "HEALTH_USER=health\nHEALTH_PASS=%s\n" "$PASS" > "$TMP"
install -o root -g root -m 600 "$TMP" "$OUT"
rm -f "$TMP"

# notify local health agent to pick up the new file
if command -v systemctl >/dev/null 2>&1; then
  systemctl try-restart sentinel-health-agent.service || true
fi

# Emit a timestamp file so Prometheus (or a simple file-based monitor) can detect
# the last successful fetch. The file is written atomically and is world-readable.
RUN_DIR=/var/run/sentinel
TS_FILE=${RUN_DIR}/last_fetch

mkdir -p "$RUN_DIR"
chown root:root "$RUN_DIR" || true
chmod 755 "$RUN_DIR" || true

TMP_TS=$(mktemp /tmp/last_fetch.XXXX)
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$TMP_TS"
install -o root -g root -m 644 "$TMP_TS" "$TS_FILE"
rm -f "$TMP_TS"

exit 0

