from scapy.all import sniff, IP, TCP, UDP
from flow.flow_table import FlowTable
from features.feature_extractor import FeatureExtractor
from detection.baseline import BaselineModel
from detection.anomaly_engine import AnomalyEngine


flow_table = FlowTable(idle_timeout=30)
feature_extractor = FeatureExtractor()

# Build baseline from collected dataset
baseline_model = BaselineModel()
baseline = baseline_model.build()
anomaly_engine = AnomalyEngine(baseline)


def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        size = len(packet)

        src_port = 0
        dst_port = 0
        protocol_name = "OTHER"

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"

        flow_table.process_packet(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol_name,
            size
        )

        expired = flow_table.check_timeouts()

        for flow in expired:
            features = feature_extractor.extract(flow)

            if anomaly_engine.check(features):
                print("🚨 ALERT: Anomalous flow detected!", flow)
            else:
                print("Normal flow")


def start_sniffing(interface=None):
    sniff(prn=process_packet, iface=interface, store=False)
