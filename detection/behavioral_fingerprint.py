from collections import defaultdict


class BehavioralFingerprint:

    def __init__(self, drift_threshold=0.5):
        self.profiles = defaultdict(lambda: {
            "flow_count": 0,
            "total_duration": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "protocol_usage": {},
            "risk_score_sum": 0,

            # Drift tracking
            "baseline_avg_bytes": 0,
            "baseline_avg_duration": 0
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

        protocol = flow.protocol
        profile["protocol_usage"][protocol] = \
            profile["protocol_usage"].get(protocol, 0) + 1

        # After 100 flows, lock baseline reference
        if profile["flow_count"] == 100:
            profile["baseline_avg_bytes"] = \
                profile["total_bytes"] / profile["flow_count"]

            profile["baseline_avg_duration"] = \
                profile["total_duration"] / profile["flow_count"]

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
        return self.profiles
