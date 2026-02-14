from scapy.all import sniff, IP, TCP, UDP
from flow.flow_table import FlowTable
from features.feature_extractor import FeatureExtractor
from detection.adaptive_baseline import AdaptiveBaseline
from detection.anomaly_engine import AnomalyEngine
from detection.ml_engine import MLEngine


baseline = AdaptiveBaseline(window_size=500)
anomaly_engine = AnomalyEngine(baseline)
ml_engine = MLEngine()

flow_table = FlowTable(idle_timeout=30)
feature_extractor = FeatureExtractor()


def process_packet(packet):

    if IP not in packet:
        return

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

        # Statistical detection
        stat_score = anomaly_engine.analyze(
            features,
            flow.initiator_ip,
            flow.protocol,
            flow
        )

        # ML detection
        ml_score = ml_engine.predict(features)

        final_score = stat_score + ml_score

        if final_score >= 2:
            print(f"🚨 ALERT | Score: {final_score} | {flow}")
        elif final_score == 1:
            print("⚠ Suspicious")
        else:
            print("Normal flow")

        # Learn baseline AFTER detection
        baseline.update(
            features,
            flow.initiator_ip,
            flow.protocol
        )

        # Train ML only on clean flows
        if final_score == 0:
            ml_engine.add_training_sample(features)

        ml_engine.train()


def start_sniffing(interface=None):
    print("Starting SentinelEdge AI Hybrid Engine...")
    sniff(prn=process_packet, iface=interface, store=False)
