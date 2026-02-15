class AnomalyEngine:
    def __init__(self, baseline):
        self.baseline = baseline

    def z_score(self, value, mean, std):
        if std == 0 or std is None:
            return 0
        return abs((value - mean) / std)

    def check(self, features, initiator_ip, protocol):
        # Warm-up protection
        if self.baseline.count(initiator_ip, protocol) < 50:
            return 0  # No score during learning phase

        base = self.baseline.get(initiator_ip, protocol)
        if base is None:
            return 0

        score = 0

        if self.z_score(features["duration"],
                        base["duration_mean"],
                        base["duration_std"]) > 3:
            score += 1

        if self.z_score(features["total_bytes"],
                        base["bytes_mean"],
                        base["bytes_std"]) > 3:
            score += 1

        if self.z_score(features["total_packets"],
                        base["packets_mean"],
                        base["packets_std"]) > 3:
            score += 1

        if self.z_score(features["byte_ratio"],
                        base["byte_ratio_mean"],
                        base["byte_ratio_std"]) > 3:
            score += 1

        return score
