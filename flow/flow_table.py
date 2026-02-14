from datetime import datetime
from typing import Dict, Tuple
from features.feature_extractor import FeatureExtractor
from flow.flow_record import FlowRecord


class FlowTable:
    def __init__(self, idle_timeout: int = 30):
        self.flows: Dict[Tuple, dict] = {}
        self.idle_timeout = idle_timeout

    def _generate_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """
        Generate bidirectional key (unordered pair)
        """
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            return (dst_ip, dst_port, src_ip, src_port, protocol)

    def process_packet(self, src_ip, src_port, dst_ip, dst_port, protocol, size):
        now = datetime.utcnow()
        key = self._generate_key(src_ip, src_port, dst_ip, dst_port, protocol)

        if key not in self.flows:
            # New flow
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

            if src_ip == flow["initiator_ip"]:
                flow["forward_bytes"] += size
                flow["forward_packets"] += 1
            else:
                flow["backward_bytes"] += size
                flow["backward_packets"] += 1

    def check_timeouts(self):
        now = datetime.utcnow()
        expired_flows = []

        for key, flow in list(self.flows.items()):
            if (now - flow["last_seen"]).seconds > self.idle_timeout:
                duration = (flow["last_seen"] - flow["start_time"]).total_seconds()

                record = FlowRecord(
                    initiator_ip=flow["initiator_ip"],
                    initiator_port=flow["initiator_port"],
                    responder_ip=flow["responder_ip"],
                    responder_port=flow["responder_port"],
                    protocol=flow["protocol"],
                    start_time=flow["start_time"],
                    end_time=flow["last_seen"],
                    duration=duration,
                    forward_bytes=flow["forward_bytes"],
                    backward_bytes=flow["backward_bytes"],
                    forward_packets=flow["forward_packets"],
                    backward_packets=flow["backward_packets"],
                    flow_state="IDLE_TIMEOUT"
                )

                expired_flows.append(record)
                del self.flows[key]

        return expired_flows

feature_extractor = FeatureExtractor()
