#!/usr/bin/env bash
set -euo pipefail

# notify_on_failure.sh
# Simple failure notifier: posts the last 200 lines of the failing unit's journal
# to a webhook defined in INTEGRATION_ALERT_WEBHOOK (env). If not set, writes to
# logs/integration_failure_notify.log

UNIT=${1:-integration_test.service}
WEBHOOK=${INTEGRATION_ALERT_WEBHOOK:-}
# Prefer repo logs directory (assumes installed user 'vishwa' home path)
LOGFILE="/home/vishwa/SentinelEdgeAI/logs/integration_failure_notify.log"

JOURNAL=$(journalctl -u "$UNIT" -n 200 -o cat)
PAYLOAD="Integration test unit $UNIT failed on $(hostname)\n\nLast journal lines:\n$JOURNAL"

if [ -n "$WEBHOOK" ]; then
  curl -sS -X POST -H 'Content-type: application/json' --data "{\"text\": \"$(echo "$PAYLOAD" | sed ':a;N;s/"/\\\"/g;ba' )\" }" "$WEBHOOK" || true
else
  mkdir -p "$(dirname "$LOGFILE")"
  echo "[$(date -Is)] $PAYLOAD" >> "$LOGFILE"
fi
