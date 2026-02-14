import pandas as pd


class BaselineModel:
    def __init__(self, dataset_path="flows.csv"):
        self.dataset_path = dataset_path
        self.stats = {}

    def build(self):
        df = pd.read_csv(self.dataset_path)

        self.stats = {
            "duration_mean": df["duration"].mean(),
            "duration_std": df["duration"].std(),

            "bytes_mean": df["total_bytes"].mean(),
            "bytes_std": df["total_bytes"].std(),

            "packets_mean": df["total_packets"].mean(),
            "packets_std": df["total_packets"].std(),

            "byte_ratio_mean": df["byte_ratio"].mean(),
            "byte_ratio_std": df["byte_ratio"].std(),
        }

        return self.stats
