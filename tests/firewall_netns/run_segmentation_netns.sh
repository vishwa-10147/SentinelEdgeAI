#!/usr/bin/env bash
set -euo pipefail

# Phase 7 OT micro-segmentation against the real kernel, in throwaway network namespaces.
#
#   sudo bash tests/firewall_netns/run_segmentation_netns.sh
#
#   hmi   (10.78.1.2) --+
#                       +-- appliance (routes 10.78.1.0/24 <-> 10.78.2.0/24) --- plc (10.78.2.2)
#   rogue (10.78.3.2) --+
#
# The OT store says the HMI has commanded the PLC over Modbus for longer than
# the learning period. With segmentation enforced, the HMI still reaches
# tcp/502, the rogue host does not (but still reaches ports that are not
# guarded), an Admin exception lets it in, and a rollback turns everything
# off. Nothing outside the namespaces is touched; they are deleted on exit.

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
A=seg-appl-$$; H=seg-hmi-$$; R=seg-rogue-$$; P=seg-plc-$$
STATE="$(mktemp -d)"
PASS=0; FAIL=0

cleanup() { for n in "$A" "$H" "$R" "$P"; do ip netns del "$n" 2>/dev/null || true; done; rm -rf "$STATE"; }
trap cleanup EXIT
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 2; }

for n in "$A" "$H" "$R" "$P"; do ip netns add "$n"; ip -n "$n" link set lo up; done
link() {  # link <ns> <ns-addr> <appliance-addr> <name>
  ip link add "a$4" type veth peer name "o$4"
  ip link set "a$4" netns "$A"; ip link set "o$4" netns "$1"
  ip -n "$A" addr add "$3/24" dev "a$4"; ip -n "$A" link set "a$4" up
  ip -n "$1" addr add "$2/24" dev "o$4"; ip -n "$1" link set "o$4" up
  ip -n "$1" route add default via "$3"
}
link "$H" 10.78.1.2 10.78.1.1 h
link "$R" 10.78.3.2 10.78.3.1 r
link "$P" 10.78.2.2 10.78.2.1 p
ip netns exec "$A" sysctl -qw net.ipv4.ip_forward=1

segpy() {  # run enforcement.segmentation inside the appliance namespace with real enforcement
  ip netns exec "$A" env FIREWALL_DRY_RUN=0 SENTINEL_FIREWALL_BACKEND=nft SENTINEL_BRIDGE=1 \
    SENTINEL_AUDIT_DB="$STATE/audit.db" SENTINEL_RESPONSE_POLICY="$STATE/policy.json" \
    SENTINEL_SETUP_FILE="$STATE/setup.json" SENTINEL_OT_DB="$STATE/ot.db" \
    SENTINEL_OT_SEGMENTATION="$STATE/segmentation.json" \
    "$PY" -c "import sys; sys.path.insert(0, '$REPO'); import core.firewall as fw; fw.ROOT = '$STATE'
from enforcement import segmentation as seg
$1"
}
check() {  # check <description> <expected 0|1> <command...>
  local desc="$1" want="$2"; shift 2
  if "$@" >/dev/null 2>&1; then got=0; else got=1; fi
  if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $desc"; else FAIL=$((FAIL+1)); echo "  FAIL $desc"; fi
}
tcp_ok() { ip netns exec "$1" nc -z -w 2 10.78.2.2 "$2"; }

# the PLC serves Modbus (tcp/502) and something unguarded (tcp/80)
ip netns exec "$P" sh -c 'while true; do nc -l -p 502 -q 0 </dev/null >/dev/null 2>&1; done' & S1=$!
ip netns exec "$P" sh -c 'while true; do nc -l -p 80 -q 0 </dev/null >/dev/null 2>&1; done' & S2=$!
trap 'kill $S1 $S2 2>/dev/null || true; cleanup' EXIT
sleep 0.5

# what the OT detector learned: the HMI has polled the PLC for eight days
segpy "
from detection.ot import OTStore
import time
s = OTStore(); t = time.time() - 8 * 86400
s.add_server('10.78.2.2', 'modbus', t); s.touch('10.78.1.2', '10.78.2.2', 'modbus', '', t)
s.touch('10.78.1.2', '10.78.2.2', 'modbus', 'read holding registers', t)"

echo "baseline"
check "hmi reaches plc tcp/502" 0 tcp_ok "$H" 502
check "rogue reaches plc tcp/502" 0 tcp_ok "$R" 502

echo "enforce"
segpy "print(seg.set_mode('enforce', by='netns')['mode'])"
check "hmi still reaches plc tcp/502" 0 tcp_ok "$H" 502
check "rogue cannot reach plc tcp/502" 1 tcp_ok "$R" 502
check "rogue still reaches the unguarded tcp/80" 0 tcp_ok "$R" 80
check "drops are counted" 0 segpy "assert seg.status()['dropped_packets'] > 0"

echo "exception"
segpy "seg.allow('10.78.3.2', '10.78.2.2', 'modbus', by='netns')"
check "rogue reaches plc tcp/502 after an Admin exception" 0 tcp_ok "$R" 502

echo "rollback"
segpy "seg.set_mode('enforce', by='netns'); seg.refresh(by='netns')"
segpy "fw.rollback_blocks('netns')"
check "segmentation is off after a rollback" 0 segpy "assert seg.status()['mode'] == 'off'"
check "no ot_segment chain left in the kernel" 1 ip netns exec "$A" nft list chain inet sentinel ot_segment

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
