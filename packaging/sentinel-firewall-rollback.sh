#!/bin/sh
# SentinelEdgeAI firewall rollback guard helper
# Reads environment from /etc/sentinel/firewall-rollback.env or from environment
# Expects the following variables (see firewall-rollback.env.example):
#  API_URL - base URL for local backend (default: http://127.0.0.1:9000)
#  API_KEY - optional API key header to authenticate requests
#  MIN_UPTIME_SECONDS - minimum acceptable uptime before considering rollback (default: 30)
#  HEALTH_TIMEOUT - curl timeout seconds when fetching health (default: 5)

set -eu

ENVFILE=/etc/sentinel/firewall-rollback.env
[ -f "$ENVFILE" ] && . "$ENVFILE" || true

API_URL=${API_URL:-http://127.0.0.1:9000}
API_KEY=${API_KEY:-}
MIN_UPTIME_SECONDS=${MIN_UPTIME_SECONDS:-30}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-5}

log(){
  logger -t sentinel-firewall-rollback -- "$1"
}

fetch_health(){
  if [ -n "$API_KEY" ]; then
    CURL_OPTS=(-H "X-API-Key: $API_KEY")
  else
    CURL_OPTS=()
  fi
  health=$(curl -sS -m "$HEALTH_TIMEOUT" "${CURL_OPTS[@]}" "$API_URL/api/health" 2>/dev/null || true)
  printf '%s' "$health"
}

extract_uptime(){
  data="$1"
  if command -v python3 >/dev/null 2>&1; then
    uptime=$(printf '%s' "$data" | python3 -c 'import sys,json
try:
    obj=json.load(sys.stdin)
    print(int(obj.get("uptime_seconds") or 0))
except Exception:
    print(0)')
  else
    # fallback: crude grep for uptime_seconds
    uptime=$(printf '%s' "$data" | sed -n 's/.*"uptime_seconds"[[:space:]]*:\s*\([0-9]\+\).*/\1/p' || true)
    uptime=${uptime:-0}
  fi
  printf '%s' "$uptime"
}

do_rollback(){
  if [ -n "$API_KEY" ]; then
    curl -sS -X POST -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d '{"reason":"guard_rollback"}' "$API_URL/api/firewall/rollback" >/dev/null 2>&1 || true
  else
    curl -sS -X POST -H "Content-Type: application/json" -d '{"reason":"guard_rollback"}' "$API_URL/api/firewall/rollback" >/dev/null 2>&1 || true
  fi
  log "Triggered firewall rollback via $API_URL/api/firewall/rollback"
}

main(){
  health_json=$(fetch_health)
  if [ -z "${health_json}" ]; then
    log "health endpoint unreachable, triggering rollback"
    do_rollback
    exit 0
  fi
  uptime=$(extract_uptime "$health_json" 2>/dev/null || echo 0)
  case "$uptime" in
    ''|*[!0-9]*) uptime=0 ;;
  esac
  if [ "$uptime" -lt "$MIN_UPTIME_SECONDS" ]; then
    log "uptime ($uptime)s below threshold ($MIN_UPTIME_SECONDS)s — triggering rollback"
    do_rollback
  else
    log "health OK — uptime ${uptime}s"
  fi
}

main
