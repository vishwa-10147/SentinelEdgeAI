#!/usr/bin/env bash
set -euo pipefail

# Phase 3 enforcement against the real kernel, in throwaway network namespaces.
#
#   sudo bash tests/firewall_netns/run_enforcement_netns.sh
#
#   client (10.77.0.2) ---veth--- appliance (10.77.0.1)
#
# The appliance namespace runs the real core.firewall code with
# FIREWALL_DRY_RUN=0 and checks real traffic: block, quarantine (only DNS,
# DHCP and the console port allowed), per-source rate limiting, rollback
# timing, and the protected-host refusal. Nothing outside the namespaces is
# touched; they are deleted on exit.

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
A=sentinel-appl-$$; C=sentinel-client-$$
STATE="$(mktemp -d)"
PASS=0; FAIL=0

cleanup() { ip netns del "$A" 2>/dev/null || true; ip netns del "$C" 2>/dev/null || true; rm -rf "$STATE"; }
trap cleanup EXIT
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 2; }

ip netns add "$A"; ip netns add "$C"
ip link add va type veth peer name vc
ip link set va netns "$A"; ip link set vc netns "$C"
ip -n "$A" addr add 10.77.0.1/24 dev va; ip -n "$A" link set va up; ip -n "$A" link set lo up
ip -n "$C" addr add 10.77.0.2/24 dev vc; ip -n "$C" link set vc up; ip -n "$C" link set lo up

fwpy() {  # run core.firewall inside the appliance namespace with real enforcement
  ip netns exec "$A" env FIREWALL_DRY_RUN=0 SENTINEL_FIREWALL_BACKEND=nft SENTINEL_BRIDGE=0 \
    SENTINEL_AUDIT_DB="$STATE/audit.db" SENTINEL_RESPONSE_POLICY="$STATE/policy.json" \
    SENTINEL_SETUP_FILE="$STATE/setup.json" SENTINEL_RATELIMIT_PPS=20 \
    "$PY" -c "import sys; sys.path.insert(0, '$REPO'); import core.firewall as fw; fw.ROOT = '$STATE'; $1"
}
check() {  # check <description> <expected 0|1> <command...>
  local desc="$1" want="$2"; shift 2
  if "$@" >/dev/null 2>&1; then got=0; else got=1; fi
  if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $desc"; else FAIL=$((FAIL+1)); echo "  FAIL $desc"; fi
}
ping_ok() { ip netns exec "$C" ping -c 2 -W 1 -i 0.2 10.77.0.1; }
tcp_ok() { ip netns exec "$C" nc -z -w 2 10.77.0.1 "$1"; }
udp_dns_ok() { echo q | ip netns exec "$C" nc -u -w 2 10.77.0.1 53 | grep -q pong; }

# services on the appliance: TCP 22 (anything), TCP 9000 (console), UDP 53 (DNS)
ip netns exec "$A" sh -c 'while true; do nc -l -p 22 -q 0 </dev/null >/dev/null 2>&1; done' & S1=$!
ip netns exec "$A" sh -c 'while true; do nc -l -p 9000 -q 0 </dev/null >/dev/null 2>&1; done' & S2=$!
ip netns exec "$A" socat -T1 UDP-RECVFROM:53,fork SYSTEM:'echo pong' & S3=$!
trap 'kill $S1 $S2 $S3 2>/dev/null || true; cleanup' EXIT
sleep 0.5

echo "baseline"
check "ping works" 0 ping_ok
check "tcp/22 works" 0 tcp_ok 22

echo "block"
fwpy "fw.add_block('10.77.0.2', ttl=60, reason='netns')"
check "blocked client cannot ping" 1 ping_ok
check "blocked client cannot reach tcp/22" 1 tcp_ok 22
T0=$(date +%s%N); fwpy "fw.rollback_blocks('netns')"; T1=$(date +%s%N)
MS=$(( (T1 - T0) / 1000000 ))
check "rollback restores ping" 0 ping_ok
check "rollback took ${MS} ms (< 2000 ms)" 0 test "$MS" -lt 2000

echo "quarantine"
fwpy "fw.add_restriction('quarantine', '10.77.0.2', ttl=60, reason='netns')"
check "quarantined client cannot ping" 1 ping_ok
check "quarantined client cannot reach tcp/22" 1 tcp_ok 22
check "quarantined client can still reach the console port tcp/9000" 0 tcp_ok 9000
check "quarantined client can still use DNS udp/53" 0 udp_dns_ok
fwpy "fw.remove_restriction('quarantine', '10.77.0.2')"
check "release restores ping" 0 ping_ok
check "release restores tcp/22" 0 tcp_ok 22

echo "rate limit (20 packets/s per source)"
fwpy "fw.add_restriction('ratelimit', '10.77.0.2', ttl=60, reason='netns')"
RECV=$(ip netns exec "$C" ping -c 300 -i 0.005 -W 1 -q 10.77.0.1 2>/dev/null | sed -n 's/.* \([0-9]*\) received.*/\1/p')
check "300 pings at 200/s: ${RECV} answered (limited)" 0 test "${RECV:-300}" -lt 150
check "slow traffic still flows" 0 ping_ok
fwpy "fw.remove_restriction('ratelimit', '10.77.0.2')"

echo "protected hosts"
check "the appliance refuses to block its own address" 1 fwpy "fw.add_block('10.77.0.1')"

echo "rollback removes everything"
fwpy "fw.add_block('10.77.0.2'); fw.add_restriction('quarantine', '10.77.0.3')"
fwpy "fw.rollback_blocks('netns')"
check "no sentinel table left in the kernel" 1 ip netns exec "$A" nft list table inet sentinel

echo "inline bridge: client (10.88.0.2) -- [appliance br0] -- server (10.88.0.3)"
B=sentinel-bridge-$$; L=sentinel-lan-$$; W=sentinel-wan-$$
ip netns add "$B"; ip netns add "$L"; ip netns add "$W"
trap 'kill $S1 $S2 $S3 2>/dev/null || true; ip netns del "$B" 2>/dev/null; ip netns del "$L" 2>/dev/null; ip netns del "$W" 2>/dev/null; cleanup' EXIT
ip link add bl type veth peer name ll; ip link add bw type veth peer name ww
ip link set bl netns "$B"; ip link set bw netns "$B"; ip link set ll netns "$L"; ip link set ww netns "$W"
ip -n "$B" link add br0 type bridge
ip -n "$B" link set bl master br0; ip -n "$B" link set bw master br0
for dev in bl bw br0 lo; do ip -n "$B" link set "$dev" up; done
ip -n "$L" addr add 10.88.0.2/24 dev ll; ip -n "$L" link set ll up
ip -n "$W" addr add 10.88.0.3/24 dev ww; ip -n "$W" link set ww up
bpy() {
  ip netns exec "$B" env FIREWALL_DRY_RUN=0 SENTINEL_FIREWALL_BACKEND=nft SENTINEL_BRIDGE=1 \
    SENTINEL_AUDIT_DB="$STATE/audit.db" SENTINEL_RESPONSE_POLICY="$STATE/policy.json" \
    SENTINEL_SETUP_FILE="$STATE/setup.json" \
    "$PY" -c "import sys; sys.path.insert(0, '$REPO'); import core.firewall as fw; fw.ROOT = '$STATE/b'; import os; os.makedirs(fw.ROOT, exist_ok=True); $1"
}
lan_ping() { ip netns exec "$L" ping -c 2 -W 1 -i 0.2 10.88.0.3; }
check "bridged traffic flows" 0 lan_ping
bpy "fw.add_block('10.88.0.2', ttl=60, reason='netns-bridge')"
check "blocked device cannot cross the bridge" 1 lan_ping
bpy "fw.remove_block('10.88.0.2')"
check "unblock restores bridged traffic" 0 lan_ping
LMAC=$(ip -n "$L" link show ll | awk '/ether/ {print $2}')
bpy "fw.add_restriction('quarantine', '10.88.0.2', ttl=60, mac='$LMAC')"
check "quarantined device (by MAC) cannot cross the bridge" 1 lan_ping
bpy "fw.rollback_blocks('netns-bridge')"
check "rollback restores bridged traffic" 0 lan_ping
check "no bridge table left" 1 ip netns exec "$B" nft list table bridge sentinel

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
