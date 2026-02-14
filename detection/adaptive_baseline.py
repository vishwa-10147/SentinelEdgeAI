from collections import defaultdict, deque
import numpy as np


class AdaptiveBaseline:

    def __init__(self, window_size=500):
        self.window_size = window_size
        self.data = defaultdict(lambda: deque(maxlen=self.window_size))
        self.stats = {}

    def update(self, features, initiator_ip, protocol):
        key = f"{initiator_ip}_{protocol}"

        self.data[key].append(features)

        # Need minimum samples before computing stats
        if len(self.data[key]) < 10:
            return

        durations = [f["duration"] for f in self.data[key]]
        bytes_ = [f["total_bytes"] for f in self.data[key]]
        packets = [f["total_packets"] for f in self.data[key]]
        ratios = [f["byte_ratio"] for f in self.data[key]]

        self.stats[key] = {
            "duration_mean": np.mean(durations),
            "duration_std": np.std(durations),

            "bytes_mean": np.mean(bytes_),
            "bytes_std": np.std(bytes_),

            "packets_mean": np.mean(packets),
            "packets_std": np.std(packets),

            "byte_ratio_mean": np.mean(ratios),
            "byte_ratio_std": np.std(ratios),
        }

    def get(self, initiator_ip, protocol):
        key = f"{initiator_ip}_{protocol}"
        return self.stats.get(key, None)

    def count(self, initiator_ip, protocol):
        key = f"{initiator_ip}_{protocol}"
        return len(self.data[key])
