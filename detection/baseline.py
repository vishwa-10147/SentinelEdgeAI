import pandas as pd


class BaselineModel:
    def __init__(self, dataset_path="flows.csv"):
        self.dataset_path = dataset_path
        self.baseline = {}

    def build(self):
        df = pd.read_csv(self.dataset_path)

        self.baseline = {
            "avg_duration": df["duration"].mean(),
            "avg_total_bytes": df["total_bytes"].mean(),
            "avg_total_packets": df["total_packets"].mean(),
            "avg_byte_ratio": df["byte_ratio"].mean(),
            "avg_packet_ratio": df["packet_ratio"].mean(),
        }

        return self.baseline
