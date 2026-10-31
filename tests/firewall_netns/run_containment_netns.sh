#!/usr/bin/env bash
set -euo pipefail

# Phase 7 containment (zero-trust) against the real kernel, in throwaway network namespaces.
#
#   sudo bash tests/firewall_netns/run_containment_netns.sh
#
#   device (10.79.1.2) --- appliance (router) ---+--- peer  (10.79.2.2)  tcp/80 and tcp/22
#                                                +--- other (10.79.3.2)  tcp/80
#
# The device's learned profile is "talks to peer on tcp/80". Contained, it
# keeps exactly that, loses tcp/22 on the same peer and everything on other,
# and still answers connections made to it (conntrack). Release and rollback
# restore it. Nothing outside the namespaces is touched.

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
A=ctn-appl-$$; D=ctn-dev-$$; P=ctn-peer-$$; O=ctn-other-$$
STATE="$(mktemp -d)"
PASS=0; FAIL=0

cleanup() { for n in "$A" "$D" "$P" "$O"; do ip netns del "$n" 2>/dev/null || true; done; rm -rf "$STATE"; }
trap cleanup EXIT
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 2; }

for n in "$A" "$D" "$P" "$O"; do ip netns add "$n"; ip -n "$n" link set lo up; done
link() {  # link <ns> <ns-addr> <appliance-addr> <name>
  ip link add "ctn$4a" type veth peer name "ctn$4o"
  ip link set "ctn$4a" netns "$A"; ip link set "ctn$4o" netns "$1"
  ip -n "$A" addr add "$3/24" dev "ctn$4a"; ip -n "$A" link set "ctn$4a" up
  ip -n "$1" addr add "$2/24" dev "ctn$4o"; ip -n "$1" link set "ctn$4o" up
  ip -n "$1" route add default via "$3"
}
link "$D" 10.79.1.2 10.79.1.1 d
link "$P" 10.79.2.2 10.79.2.1 p
link "$O" 10.79.3.2 10.79.3.1 o
ip netns exec "$A" sysctl -qw net.ipv4.ip_forward=1

fwpy() {  # run core.firewall inside the appliance namespace with real enforcement
  ip netns exec "$A" env FIREWALL_DRY_RUN=0 SENTINEL_FIREWALL_BACKEND=nft SENTINEL_BRIDGE=0 \
    SENTINEL_AUDIT_DB="$STATE/audit.db" SENTINEL_RESPONSE_POLICY="$STATE/policy.json" \
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
tcp_ok() { ip netns exec "$1" nc -z -w 2 "$2" "$3"; }
serve() { ip netns exec "$1" sh -c "while true; do nc -l -p $2 -q 0 </dev/null >/dev/null 2>&1; done" & PIDS="${PIDS:-} $!"; }

serve "$P" 80; serve "$P" 22; serve "$O" 80; serve "$D" 8080
trap 'kill $PIDS 2>/dev/null || true; cleanup' EXIT
sleep 0.5

# eight days ago the device started using peer:80 (and DNS to the internet, kept as udp/53 only)
fwpy "
from detection.peers import PeerStore
import time
s = PeerStore(); t = time.time() - 8 * 86400
s.observe({'src': '10.79.1.2', 'dst': '10.79.2.2', 'proto': 'TCP', 'dport': 80, 'ts': t})"

echo "baseline"
check "device reaches peer tcp/80" 0 tcp_ok "$D" 10.79.2.2 80
check "device reaches peer tcp/22" 0 tcp_ok "$D" 10.79.2.2 22
check "device reaches other tcp/80" 0 tcp_ok "$D" 10.79.3.2 80

echo "contain"
check "a device without a profile is refused" 0 fwpy "
try:
    fw.add_restriction('contain', '10.79.3.2', ttl=60)
    raise SystemExit(1)
except ValueError as e:
    assert 'no learned peer profile' in str(e)"
fwpy "fw.add_restriction('contain', '10.79.1.2', ttl=60, reason='netns')"
check "contained device still reaches its learned peer tcp/80" 0 tcp_ok "$D" 10.79.2.2 80
check "contained device cannot reach peer tcp/22 (not learned)" 1 tcp_ok "$D" 10.79.2.2 22
check "contained device cannot reach other tcp/80" 1 tcp_ok "$D" 10.79.3.2 80
check "others can still connect to the contained device (replies pass)" 0 tcp_ok "$O" 10.79.1.2 8080

echo "release"
fwpy "fw.remove_restriction('contain', '10.79.1.2')"
check "release restores other tcp/80" 0 tcp_ok "$D" 10.79.3.2 80

echo "rollback"
fwpy "fw.add_restriction('contain', '10.79.1.2', ttl=60, reason='netns')"
check "contained again" 1 tcp_ok "$D" 10.79.3.2 80
fwpy "fw.rollback_blocks('netns')"
check "rollback restores other tcp/80" 0 tcp_ok "$D" 10.79.3.2 80

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
