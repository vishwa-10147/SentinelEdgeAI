class AnomalyEngine:
    def __init__(self, baseline, warmup_flows=50, z_threshold=3):
        self.baseline = baseline
        self.warmup_flows = warmup_flows
        self.z_threshold = z_threshold

    def z_score(self, value, mean, std):
        if std == 0 or std is None:
            return 0
        return (value - mean) / std

    def analyze(self, features, initiator_ip, protocol):

        if self.baseline.count(initiator_ip, protocol) < self.warmup_flows:
            return {
                "score": 0,
                "triggers": [],
                "confidence": 0
            }

        base = self.baseline.get(initiator_ip, protocol)
        if base is None:
            return {
                "score": 0,
                "triggers": [],
                "confidence": 0
            }

        triggers = []
        score = 0

        metrics = {
            "duration": features["duration"],
            "total_bytes": features["total_bytes"],
            "total_packets": features["total_packets"],
            "byte_ratio": features["byte_ratio"]
        }

        for metric, value in metrics.items():

            mean = base[f"{metric}_mean"]
            std = base[f"{metric}_std"]

            z = self.z_score(value, mean, std)

            if abs(z) > self.z_threshold:
                score += 1
                triggers.append({
                    "metric": metric,
                    "z_score": round(z, 2)
                })

        confidence = min(score / 4, 1)

        return {
            "score": score,
            "triggers": triggers,
            "confidence": round(confidence, 2)
        }
