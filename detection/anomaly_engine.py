class AnomalyEngine:
    def __init__(self, baseline):
        self.baseline = baseline

    def check(self, flow_features):
        score = 0

        # Duration anomaly
        if flow_features["duration"] > 2 * self.baseline["avg_duration"]:
            score += 1

        # Traffic volume anomaly
        if flow_features["total_bytes"] > 2 * self.baseline["avg_total_bytes"]:
            score += 1

        # Packet anomaly
        if flow_features["total_packets"] > 2 * self.baseline["avg_total_packets"]:
            score += 1

        # Directional imbalance anomaly
        if abs(flow_features["byte_ratio"] - self.baseline["avg_byte_ratio"]) > 0.4:
            score += 1

        return score >= 2  # anomaly if 2+ conditions triggered
