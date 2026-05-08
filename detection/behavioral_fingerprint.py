from collections import defaultdict
from core.product_intelligence import behavior_summary, infer_device_type


class BehavioralFingerprint:

    def __init__(self, drift_threshold=0.5):
        self.profiles = defaultdict(lambda: {
            "flow_count": 0,
            "total_duration": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "protocol_usage": {},
            "risk_score_sum": 0,
            "destination_counts": {},
            "destination_port_counts": {},
            "avg_packets_per_sec": 0,

            # Drift tracking
            "baseline_avg_bytes": 0,
            "baseline_avg_duration": 0,
            "baseline_packets_per_sec": 0
        })
        self.drift_threshold = drift_threshold

    def update(self, flow, threat_score):

        profile = self.profiles[flow.initiator_ip]

        profile["flow_count"] += 1

        total_bytes = flow.forward_bytes + flow.backward_bytes

        profile["total_duration"] += flow.duration
        profile["total_bytes"] += total_bytes
        profile["total_packets"] += flow.forward_packets + flow.backward_packets
        profile["risk_score_sum"] += threat_score
        packet_total = flow.forward_packets + flow.backward_packets
        packets_per_sec = packet_total / max(flow.duration, 0.001)
        profile["avg_packets_per_sec"] = (
            profile["total_packets"] / max(profile["total_duration"], 0.001)
        )

        protocol = flow.protocol
        profile["protocol_usage"][protocol] = \
            profile["protocol_usage"].get(protocol, 0) + 1
        profile["destination_counts"][flow.responder_ip] = \
            profile["destination_counts"].get(flow.responder_ip, 0) + 1
        port_key = str(flow.responder_port)
        profile["destination_port_counts"][port_key] = \
            profile["destination_port_counts"].get(port_key, 0) + 1

        # After 100 flows, lock baseline reference
        if profile["flow_count"] == 100:
            profile["baseline_avg_bytes"] = \
                profile["total_bytes"] / profile["flow_count"]

            profile["baseline_avg_duration"] = \
                profile["total_duration"] / profile["flow_count"]
            profile["baseline_packets_per_sec"] = packets_per_sec

    def detect_deviation(self, flow):
        profile = self.profiles[flow.initiator_ip]

        if profile["flow_count"] < 25:
            return {
                "score": 0,
                "reasons": []
            }

        reasons = []
        packet_total = flow.forward_packets + flow.backward_packets
        packets_per_sec = packet_total / max(flow.duration, 0.001)
        avg_packets_per_sec = profile.get("avg_packets_per_sec") or 0

        if avg_packets_per_sec > 0:
            packet_rate_delta = abs(packets_per_sec - avg_packets_per_sec) / avg_packets_per_sec
            if packet_rate_delta > self.drift_threshold:
                reasons.append("PACKET_RATE_DEVIATION")

        destinations = profile.get("destination_counts", {})
        if len(destinations) >= 3 and flow.responder_ip not in destinations:
            reasons.append("UNUSUAL_DESTINATION")

        port_counts = profile.get("destination_port_counts", {})
        port_key = str(flow.responder_port)
        if len(port_counts) >= 3 and port_key not in port_counts:
            reasons.append("UNUSUAL_DESTINATION_PORT")

        return {
            "score": min(len(reasons), 3),
            "reasons": reasons
        }

    def detect_drift(self, ip):

        profile = self.profiles[ip]

        if profile["flow_count"] < 150:
            return {
                "drift": False,
                "reason": None
            }

        current_avg_bytes = profile["total_bytes"] / profile["flow_count"]
        current_avg_duration = profile["total_duration"] / profile["flow_count"]

        # Drift threshold deviation
        if profile["baseline_avg_bytes"] > 0:
            byte_drift = abs(
                (current_avg_bytes - profile["baseline_avg_bytes"]) /
                profile["baseline_avg_bytes"]
            )

            if byte_drift > self.drift_threshold:
                return {
                    "drift": True,
                    "reason": "BYTE_USAGE_DRIFT"
                }

        if profile["baseline_avg_duration"] > 0:
            duration_drift = abs(
                (current_avg_duration - profile["baseline_avg_duration"]) /
                profile["baseline_avg_duration"]
            )

            if duration_drift > self.drift_threshold:
                return {
                    "drift": True,
                    "reason": "SESSION_DURATION_DRIFT"
                }

        return {
            "drift": False,
            "reason": None
        }

    def get_all_profiles(self):
        output = {}
        for ip, profile in self.profiles.items():
            item = dict(profile)
            item["common_ports"] = self._top_counts(
                profile.get("destination_port_counts", {})
            )
            item["typical_destinations"] = self._top_counts(
                profile.get("destination_counts", {})
            )
            item["type"] = infer_device_type(ip, profile)
            item["behavior_summary"] = behavior_summary(profile)
            output[ip] = item
        return output

    def _top_counts(self, values, limit=10):
        return [
            {"value": value, "count": count}
            for value, count in sorted(
                values.items(),
                key=lambda item: item[1],
                reverse=True
            )[:limit]
        ]
