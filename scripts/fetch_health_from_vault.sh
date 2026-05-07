#!/bin/sh
set -euo pipefail

# Fetch HEALTH_PASS from Vault and write /etc/sentinel/health.env
# Requires: `vault` CLI authenticated (VAULT_ADDR and token via env or agent).

VAULT_SECRET_PATH=${VAULT_SECRET_PATH:-secret/sentineledge/health}
# Default VAULT_ADDR to localhost HTTP if not provided (Vault dev server uses HTTP by default)
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
export VAULT_ADDR
OUT=/etc/sentinel/health.env
TMP=$(mktemp /tmp/health.env.XXXX)

PASS=$(vault kv get -field=HEALTH_PASS "$VAULT_SECRET_PATH") || exit 2
if [ -z "$PASS" ]; then
  echo "vault: no HEALTH_PASS at $VAULT_SECRET_PATH" >&2
  exit 3
fi

# If the vault CLI failed above (or is unavailable), try HTTP API fallback using VAULT_TOKEN
if [ -z "${PASS:-}" ] && [ -n "${VAULT_TOKEN:-}" ]; then
  # KV v2 data path: /v1/<mount>/data/<path>
  MOUNT=$(echo "$VAULT_SECRET_PATH" | cut -d'/' -f1)
  SUBPATH=$(echo "$VAULT_SECRET_PATH" | cut -d'/' -f2-)
  API_URL="${VAULT_ADDR%/}/v1/${MOUNT}/data/${SUBPATH}"
  JSON=$(curl -sS -H "X-Vault-Token: ${VAULT_TOKEN}" "$API_URL") || true
  PASS=$(echo "$JSON" | python3 -c 'import sys, json
data=json.load(sys.stdin)
print(data.get("data", {}).get("data", {}).get("HEALTH_PASS", ""))' 2>/dev/null || true)
fi

if [ -z "$PASS" ]; then
  echo "vault: failed to obtain HEALTH_PASS via CLI or API" >&2
  exit 4
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

# Also write a Prometheus textfile metric for node_exporter textfile collector
# Try common textfile collector directories and write `sentinel_last_fetch_timestamp` as epoch seconds
TS_EPOCH=$(date -u +%s)
METRIC_NAME=sentinel_last_fetch_timestamp
METRIC_FILE_TMP=$(mktemp /tmp/sentinel_last_fetch.XXXX)
echo "# HELP ${METRIC_NAME} Unix timestamp of last successful Vault fetch" > "$METRIC_FILE_TMP"
echo "# TYPE ${METRIC_NAME} gauge" >> "$METRIC_FILE_TMP"
echo "${METRIC_NAME} ${TS_EPOCH}" >> "$METRIC_FILE_TMP"

TEXTDIRS="/var/lib/node_exporter/textfile_collector /var/run/node_exporter/textfile_collector /var/cache/node_exporter/textfile_collector"
for d in $TEXTDIRS; do
  if [ -d "$d" ]; then
    install -o root -g root -m 644 "$METRIC_FILE_TMP" "$d/sentinel_last_fetch.prom" || true
    FOUND=1 && break
  fi
done
if [ -z "${FOUND:-}" ]; then
  # create a local textfile dir under /var/run and write there
  mkdir -p /var/run/node_exporter/textfile_collector >/dev/null 2>&1 || true
  install -o root -g root -m 644 "$METRIC_FILE_TMP" /var/run/node_exporter/textfile_collector/sentinel_last_fetch.prom || true
fi
rm -f "$METRIC_FILE_TMP"

exit 0

