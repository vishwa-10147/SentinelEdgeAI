#!/usr/bin/env bash
set -euo pipefail

# Opt-in rollback guard for real firewall enforcement.
# Intended to run from a systemd timer. It rolls back active SentinelEdgeAI
# blocks only after consecutive local API health failures.

REPO_DIR="${REPO_DIR:-/home/vishwa/SentinelEdgeAI}"
VENV_PYTHON="${VENV_PYTHON:-$REPO_DIR/.venv/bin/python}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:9000/api/health}"
STATE_DIR="${STATE_DIR:-/run/sentinel}"
FAIL_FILE="$STATE_DIR/firewall_rollback_guard.failures"
FAIL_THRESHOLD="${FAIL_THRESHOLD:-3}"
ENABLE_ROLLBACK_GUARD="${ENABLE_ROLLBACK_GUARD:-0}"
DASHBOARD_API_KEY="${DASHBOARD_API_KEY:-}"

mkdir -p "$STATE_DIR"

if [ "$ENABLE_ROLLBACK_GUARD" != "1" ]; then
  echo "rollback guard disabled; set ENABLE_ROLLBACK_GUARD=1 to enable"
  exit 0
fi

if [ ! -x "$VENV_PYTHON" ]; then
  echo "python not executable: $VENV_PYTHON" >&2
  exit 2
fi

if [ ! -d "$REPO_DIR" ]; then
  echo "repo dir not found: $REPO_DIR" >&2
  exit 2
fi

ACTIVE_RULES=$(
  cd "$REPO_DIR"
  "$VENV_PYTHON" - <<'PY'
import core.firewall as firewall
print(len([rule for rule in firewall.list_rules() if rule.get("blocked")]))
PY
)

if [ "${ACTIVE_RULES:-0}" -eq 0 ]; then
  rm -f "$FAIL_FILE"
  echo "no active SentinelEdgeAI firewall rules"
  exit 0
fi

CURL_ARGS=(-fsS --max-time 2)
if [ -n "$DASHBOARD_API_KEY" ]; then
  CURL_ARGS+=(-H "X-API-Key: $DASHBOARD_API_KEY")
fi

if curl "${CURL_ARGS[@]}" "$HEALTH_URL" >/dev/null; then
  rm -f "$FAIL_FILE"
  echo "health check passed with $ACTIVE_RULES active rule(s)"
  exit 0
fi

FAILURES=0
if [ -f "$FAIL_FILE" ]; then
  FAILURES="$(cat "$FAIL_FILE" 2>/dev/null || echo 0)"
fi
FAILURES=$((FAILURES + 1))
printf "%s\n" "$FAILURES" > "$FAIL_FILE"

echo "health check failed ($FAILURES/$FAIL_THRESHOLD) with $ACTIVE_RULES active rule(s)" >&2

if [ "$FAILURES" -lt "$FAIL_THRESHOLD" ]; then
  exit 1
fi

echo "failure threshold reached; rolling back SentinelEdgeAI firewall rules" >&2
cd "$REPO_DIR"
FIREWALL_DRY_RUN=0 "$VENV_PYTHON" - <<'PY'
import core.firewall as firewall
print(firewall.rollback_blocks("systemd_rollback_guard"))
PY
rm -f "$FAIL_FILE"
