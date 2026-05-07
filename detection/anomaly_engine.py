import logging


class AnomalyEngine:
    def __init__(self, baseline, warmup_flows=50, z_threshold=3):
        self.baseline = baseline
        self.warmup_flows = warmup_flows
        self.z_threshold = z_threshold
        self.logger = logging.getLogger("sentinel.anomaly")

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
            mean = base.get(f"{metric}_mean")
            std = base.get(f"{metric}_std")

            # Backwards compatibility: some baselines use legacy names
            if mean is None or std is None:
                if metric == "total_bytes":
                    mean = base.get("bytes_mean", mean)
                    std = base.get("bytes_std", std)
                elif metric == "total_packets":
                    mean = base.get("packets_mean", mean)
                    std = base.get("packets_std", std)

            # If baseline still lacks this metric, skip it (defensive)
            if mean is None or std is None:
                self.logger.debug("Baseline missing metric %s for %s/%s; skipping", metric, initiator_ip, protocol)
                continue

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
