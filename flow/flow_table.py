import os
from collections import OrderedDict
from datetime import datetime, timezone
from features.feature_extractor import FeatureExtractor
from flow.flow_record import FlowRecord

# Flood safety: at most this many active flows (SENTINEL_MAX_FLOWS). The table is kept in
# order of last activity, so when it is full the least recently active flow is evicted
# (under a flood of spoofed addresses, almost always a one-packet flow). Evicted flows are
# still scored, up to EVICT_SCORE_BUDGET per timeout pass; the rest are only counted.
MAX_FLOWS = int(os.environ.get('SENTINEL_MAX_FLOWS', '100000'))
EVICT_SCORE_BUDGET = 500


class FlowTable:
    def __init__(self, idle_timeout: int = 30, max_flows: int = None):
        self.flows = OrderedDict()                # key -> flow, least recently active first
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows or MAX_FLOWS
        self.evicted = 0                          # flows pushed out because the table was full
        self.shed = 0                             # evicted flows not scored (over the budget)
        self.new_flows = 0
        self._evicted_pending = []

    def _generate_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """
        Generate bidirectional key (unordered pair)
        """
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            return (dst_ip, dst_port, src_ip, src_port, protocol)

    def process_packet(self, src_ip, src_port, dst_ip, dst_port, protocol, size):
        now = datetime.now(timezone.utc)
        key = self._generate_key(src_ip, src_port, dst_ip, dst_port, protocol)

        if key not in self.flows:
            # New flow
            self.new_flows += 1
            if len(self.flows) >= self.max_flows:
                _, oldest = self.flows.popitem(last=False)
                self.evicted += 1
                if len(self._evicted_pending) < EVICT_SCORE_BUDGET:
                    self._evicted_pending.append(self._record(oldest, "EVICTED"))
                else:
                    self.shed += 1
            self.flows[key] = {
                "initiator_ip": src_ip,
                "initiator_port": src_port,
                "responder_ip": dst_ip,
                "responder_port": dst_port,
                "protocol": protocol,
                "start_time": now,
                "last_seen": now,
                "forward_bytes": size,
                "backward_bytes": 0,
                "forward_packets": 1,
                "backward_packets": 0,
            }
        else:
            flow = self.flows[key]
            flow["last_seen"] = now
            self.flows.move_to_end(key)           # keeps the table in order of last activity

            if src_ip == flow["initiator_ip"]:
                flow["forward_bytes"] += size
                flow["forward_packets"] += 1
            else:
                flow["backward_bytes"] += size
                flow["backward_packets"] += 1

    @staticmethod
    def _record(flow, state):
        return FlowRecord(
            initiator_ip=flow["initiator_ip"],
            initiator_port=flow["initiator_port"],
            responder_ip=flow["responder_ip"],
            responder_port=flow["responder_port"],
            protocol=flow["protocol"],
            start_time=flow["start_time"],
            end_time=flow["last_seen"],
            duration=(flow["last_seen"] - flow["start_time"]).total_seconds(),
            forward_bytes=flow["forward_bytes"],
            backward_bytes=flow["backward_bytes"],
            forward_packets=flow["forward_packets"],
            backward_packets=flow["backward_packets"],
            flow_state=state,
        )

    def check_timeouts(self):
        """Finished flows: idle ones (oldest first; the scan stops at the first active flow) and evicted ones."""
        now = datetime.now(timezone.utc)
        expired_flows, self._evicted_pending = self._evicted_pending, []
        while self.flows:
            key, flow = next(iter(self.flows.items()))
            # total_seconds(): .seconds drops whole days, so day-old flows never expired
            if (now - flow["last_seen"]).total_seconds() <= self.idle_timeout:
                break
            del self.flows[key]
            expired_flows.append(self._record(flow, "IDLE_TIMEOUT"))
        return expired_flows

    def expire_all(self, flow_state="FORCED_EXPIRE"):
        expired_flows, self._evicted_pending = self._evicted_pending, []
        while self.flows:
            _, flow = self.flows.popitem(last=False)
            expired_flows.append(self._record(flow, flow_state))
        return expired_flows

    def stats(self):
        return {"active": len(self.flows), "max": self.max_flows, "new_total": self.new_flows,
                "evicted_total": self.evicted, "shed_total": self.shed}

feature_extractor = FeatureExtractor()
