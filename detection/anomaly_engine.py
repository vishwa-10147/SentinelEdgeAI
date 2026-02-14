class AnomalyEngine:
    def __init__(self, baseline):
        self.baseline = baseline

    def z_score(self, value, mean, std):
        if std == 0 or std is None:
            return 0
        return abs((value - mean) / std)

    def check(self, features):
        score = 0

        if self.z_score(features["duration"],
                        self.baseline["duration_mean"],
                        self.baseline["duration_std"]) > 3:
            score += 1

        if self.z_score(features["total_bytes"],
                        self.baseline["bytes_mean"],
                        self.baseline["bytes_std"]) > 3:
            score += 1

        if self.z_score(features["total_packets"],
                        self.baseline["packets_mean"],
                        self.baseline["packets_std"]) > 3:
            score += 1

        if self.z_score(features["byte_ratio"],
                        self.baseline["byte_ratio_mean"],
                        self.baseline["byte_ratio_std"]) > 3:
            score += 1

        # Require multiple anomaly signals
        return score >= 2
