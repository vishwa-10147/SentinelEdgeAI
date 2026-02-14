import csv
from pathlib import Path
from flow.flow_record import FlowRecord


class FeatureExtractor:
    def __init__(self, output_file="flows.csv"):
        self.output_file = Path(output_file)

        if not self.output_file.exists():
            with open(self.output_file, mode="w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "initiator_ip",
                    "responder_ip",
                    "protocol",
                    "duration",
                    "total_bytes",
                    "total_packets",
                    "byte_ratio",
                    "packet_ratio"
                ])

    def extract(self, flow: FlowRecord):
        total_bytes = flow.forward_bytes + flow.backward_bytes
        total_packets = flow.forward_packets + flow.backward_packets

        byte_ratio = (
            flow.forward_bytes / total_bytes if total_bytes > 0 else 0
        )

        packet_ratio = (
            flow.forward_packets / total_packets if total_packets > 0 else 0
        )

        features = {
            "duration": flow.duration,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "byte_ratio": byte_ratio,
            "packet_ratio": packet_ratio,
        }

        # Save to CSV
        with open(self.output_file, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                flow.initiator_ip,
                flow.responder_ip,
                flow.protocol,
                flow.duration,
                total_bytes,
                total_packets,
                byte_ratio,
                packet_ratio
            ])

        return features
