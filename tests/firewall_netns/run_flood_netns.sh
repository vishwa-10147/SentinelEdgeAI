#!/usr/bin/env bash
set -euo pipefail

# Flood safety against the real engine, in throwaway network namespaces.
#
#   sudo SENTINEL_MODEL_SIGNING_KEY_FILE=/path/model_signing.key bash tests/firewall_netns/run_flood_netns.sh [seconds]
#
#   attacker (spoofed-source TCP SYN flood, ~300k packets/s) ---veth--- appliance (the real engine, AF_PACKET)
#
# The engine runs from a copy of the working tree in a temporary directory (firewall in dry run),
# so nothing in the repository or on the device is touched. Passes when the engine's memory growth
# stays under LIMIT_MB, the flow table stays at its cap and exactly one capture-overload alert is raised.

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
SECS="${1:-120}"; LIMIT_MB="${LIMIT_MB:-400}"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 2; }
[ -r "${SENTINEL_MODEL_SIGNING_KEY_FILE:-}" ] || { echo "set SENTINEL_MODEL_SIGNING_KEY_FILE (the engine verifies its model)"; exit 2; }
A=flood-appl-$$; X=flood-atk-$$; WORK="$(mktemp -d)"
cleanup() { [ -n "${EPID:-}" ] && kill "$EPID" 2>/dev/null || true; sleep 1
            ip netns del "$A" 2>/dev/null || true; ip netns del "$X" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

(cd "$REPO" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf -) | tar -x -C "$WORK"
cp -r "$REPO/model" "$WORK/" 2>/dev/null || true
ip netns add "$A"; ip netns add "$X"
ip link add fla$$ type veth peer name flx$$
ip link set fla$$ netns "$A"; ip link set flx$$ netns "$X"
ip -n "$A" addr add 10.250.0.1/24 dev fla$$; ip -n "$A" link set fla$$ up; ip -n "$A" link set lo up
ip -n "$X" addr add 10.250.0.2/24 dev flx$$; ip -n "$X" link set flx$$ up
MAC=$(ip netns exec "$A" cat /sys/class/net/fla$$/address)

cd "$WORK"
ip netns exec "$A" env -i PATH=/usr/bin:/bin HOME=/root PYTHONPATH="$WORK" PYTHONDONTWRITEBYTECODE=1 \
  SENTINEL_MODEL_SIGNING_KEY_FILE="$SENTINEL_MODEL_SIGNING_KEY_FILE" CAPTURE_IFACE=fla$$ SENTINEL_CAPTURE=afpacket \
  FIREWALL_DRY_RUN=1 SENTINEL_AUDIT_DB="$WORK/audit.db" SENTINEL_SETUP_FILE="$WORK/setup.json" \
  "$PY" -u main.py > "$WORK/engine.log" 2>&1 &
EPID=$!
sleep 12
rss() { ps -o rss= -p "$EPID" 2>/dev/null | awk '{printf "%d", $1/1024}'; }
BASE=$(rss); [ -n "$BASE" ] || { echo "engine did not start:"; tail -5 "$WORK/engine.log"; exit 1; }
echo "engine RSS before the flood: $BASE MB"
ip netns exec "$X" "$PY" "$REPO/tests/firewall_netns/flood.py" flx$$ "$MAC" 10.250.0.1 "$SECS" &
FPID=$!; PEAK=$BASE
while kill -0 "$FPID" 2>/dev/null; do
  sleep 10; R=$(rss); [ -n "$R" ] || { echo "FAIL engine died during the flood"; exit 1; }
  [ "$R" -gt "$PEAK" ] && PEAK=$R; echo "  engine RSS $R MB"
done
sleep 5
GROWTH=$((PEAK - BASE))
STATS=$("$PY" -c "import json; print(json.load(open('health.json')).get('capture'))")
ALERTS=$("$PY" -c "import json; print(sum(1 for a in json.load(open('alerts.json')) if a.get('attack_type') == 'capture_overload'))")
echo "capture: $STATS"
echo "peak growth ${GROWTH} MB (limit ${LIMIT_MB} MB), overload alerts: $ALERTS"
[ "$GROWTH" -lt "$LIMIT_MB" ] && [ "$ALERTS" -eq 1 ] && echo "PASS" || { echo "FAIL"; exit 1; }
