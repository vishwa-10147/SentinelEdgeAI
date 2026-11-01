#!/usr/bin/env bash
set -euo pipefail

# IPv6 parity (Phase 9) against the real kernel, in throwaway network namespaces.
#
#   sudo bash tests/firewall_netns/run_ipv6_netns.sh
#
#   device (fd79:1::2) --- appliance (router, fd79:N::1) ---+--- peer  (fd79:2::2)  tcp/80, tcp/22
#                                                            +--- other (fd79:3::2)  tcp/80, tcp/502
#
# Containment: the device's learned IPv6 profile is "peer tcp/80"; contained, it keeps exactly that.
# Quarantine: the device keeps only the console's quarantine page (and DNS/DHCPv6).
# OT segmentation: only peer may reach other's Modbus port.
# Every check that needs the appliance as a router first flushes the neighbour caches, so IPv6
# neighbour discovery must really work through the rules (without it nothing reaches anything).
# Nothing outside the namespaces is touched.

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
A=v6-appl-$$; D=v6-dev-$$; P=v6-peer-$$; O=v6-other-$$
STATE="$(mktemp -d)"
PASS=0; FAIL=0
CAPTIVE=9000

cleanup() { kill ${PIDS:-} 2>/dev/null || true; for n in "$A" "$D" "$P" "$O"; do ip netns del "$n" 2>/dev/null || true; done; rm -rf "$STATE"; }
trap cleanup EXIT
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 2; }

for n in "$A" "$D" "$P" "$O"; do
  ip netns add "$n"; ip -n "$n" link set lo up
  ip netns exec "$n" sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
done
link() {  # link <ns> <ns-addr> <appliance-addr> <name>
  ip link add "v6$4a" type veth peer name "v6$4o"
  ip link set "v6$4a" netns "$A"; ip link set "v6$4o" netns "$1"
  ip -n "$A" addr add "$3/64" dev "v6$4a" nodad; ip -n "$A" link set "v6$4a" up
  ip -n "$1" addr add "$2/64" dev "v6$4o" nodad; ip -n "$1" link set "v6$4o" up
  ip -n "$1" -6 route add default via "$3"
}
link "$D" fd79:1::2 fd79:1::1 d
link "$P" fd79:2::2 fd79:2::1 p
link "$O" fd79:3::2 fd79:3::1 o
ip netns exec "$A" sysctl -qw net.ipv6.conf.all.forwarding=1

fwpy() {  # run SentinelEdgeAI code inside the appliance namespace with real enforcement
  ip netns exec "$A" env FIREWALL_DRY_RUN=0 SENTINEL_FIREWALL_BACKEND=nft SENTINEL_BRIDGE=0 \
    SENTINEL_PORT=$CAPTIVE SENTINEL_AUDIT_DB="$STATE/audit.db" SENTINEL_RESPONSE_POLICY="$STATE/policy.json" \
    SENTINEL_SETUP_FILE="$STATE/setup.json" SENTINEL_PEERS_DB="$STATE/peers.db" \
    SENTINEL_OT_SEGMENTATION="$STATE/segmentation.json" \
    "$PY" -c "import sys; sys.path.insert(0, '$REPO'); import core.firewall as fw; fw.ROOT = '$STATE'
$1"
}
check() {  # check <description> <expected 0|1> <command...>
  local desc="$1" want="$2"; shift 2
  if "$@" >/dev/null 2>&1; then got=0; else got=1; fi
  if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $desc"; else FAIL=$((FAIL+1)); echo "  FAIL $desc"; fi
}
forget() { for n in "$A" "$D" "$P" "$O"; do ip -n "$n" -6 neigh flush all 2>/dev/null || true; done; }
tcp_ok() { forget; ip netns exec "$1" nc -6 -z -w 2 "$2" "$3"; }
serve() { ip netns exec "$1" sh -c "while true; do nc -6 -l -p $2 -q 0 </dev/null >/dev/null 2>&1; done" & PIDS="${PIDS:-} $!"; }

serve "$P" 80; serve "$P" 22; serve "$O" 80; serve "$O" 502; serve "$D" 8080; serve "$A" "$CAPTIVE"
sleep 0.5

fwpy "
from detection.peers import PeerStore
import time
s = PeerStore(); t = time.time() - 8 * 86400
s.observe({'src': 'fd79:1::2', 'dst': 'fd79:2::2', 'proto': 'TCP', 'dport': 80, 'ts': t})"

echo "baseline"
check "device reaches peer tcp/80" 0 tcp_ok "$D" fd79:2::2 80
check "device reaches peer tcp/22" 0 tcp_ok "$D" fd79:2::2 22
check "device reaches other tcp/80" 0 tcp_ok "$D" fd79:3::2 80

echo "containment (IPv6)"
check "an IPv6 device without a profile is refused" 0 fwpy "
try:
    fw.add_restriction('contain', 'fd79:3::2', ttl=60)
    raise SystemExit(1)
except ValueError as e:
    assert 'no learned peer profile' in str(e)"
fwpy "fw.add_restriction('contain', 'fd79:1::2', ttl=60, reason='netns')"
check "contained device still reaches its learned peer tcp/80 (neighbour discovery passes)" 0 tcp_ok "$D" fd79:2::2 80
check "contained device cannot reach peer tcp/22 (not learned)" 1 tcp_ok "$D" fd79:2::2 22
check "contained device cannot reach other tcp/80 (internal, not learned)" 1 tcp_ok "$D" fd79:3::2 80
check "others can still connect to the contained device (replies pass)" 0 tcp_ok "$O" fd79:1::2 8080
check "the kernel holds the device in contain6" 0 ip netns exec "$A" sh -c "nft list set inet sentinel contain6 | grep -q fd79:1::2"
fwpy "fw.remove_restriction('contain', 'fd79:1::2')"
check "release restores other tcp/80" 0 tcp_ok "$D" fd79:3::2 80

echo "quarantine (IPv6)"
fwpy "fw.add_restriction('quarantine', 'fd79:1::2', ttl=60, reason='netns')"
check "quarantined device cannot reach peer tcp/80" 1 tcp_ok "$D" fd79:2::2 80
check "quarantined device still reaches the quarantine page (neighbour discovery passes)" 0 tcp_ok "$D" fd79:1::1 "$CAPTIVE"
check "nothing new reaches the quarantined device" 1 tcp_ok "$O" fd79:1::2 8080
fwpy "fw.remove_restriction('quarantine', 'fd79:1::2')"
check "release restores peer tcp/80" 0 tcp_ok "$D" fd79:2::2 80

echo "OT segmentation (IPv6)"
fwpy "
from enforcement import segmentation as seg
plan = {'controllers': [{'ip': 'fd79:3::2', 'protocol': 'modbus', 'allowed': ['fd79:2::2']}]}
ok, out = fw._run_nft_script(seg.nft_script(plan, bridge=False))
assert ok, out"
check "the allowed master reaches the PLC's Modbus port" 0 tcp_ok "$P" fd79:3::2 502
check "another host cannot reach the PLC's Modbus port" 1 tcp_ok "$D" fd79:3::2 502
check "other ports of the PLC are not guarded" 0 tcp_ok "$D" fd79:3::2 80
check "the drop counter saw the refused connection" 0 ip netns exec "$A" sh -c "nft list chain inet sentinel ot_segment | grep -Eq 'counter packets [1-9]'"

echo "rollback"
fwpy "fw.add_restriction('contain', 'fd79:1::2', ttl=60, reason='netns')"
check "contained again" 1 tcp_ok "$D" fd79:3::2 80
fwpy "fw.rollback_blocks('netns')"
check "rollback restores other tcp/80" 0 tcp_ok "$D" fd79:3::2 80

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
