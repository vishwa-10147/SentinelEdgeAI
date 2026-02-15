from scapy.all import sniff, IP, TCP, UDP
from flow.flow_table import FlowTable
from features.feature_extractor import FeatureExtractor
from detection.adaptive_baseline import AdaptiveBaseline
from detection.anomaly_engine import AnomalyEngine
from detection.ml_engine import MLEngine
from utils.alert_logger import AlertLogger

# ===============================
# 🔧 Initialize Core Components
# ===============================

baseline = AdaptiveBaseline(window_size=500)
anomaly_engine = AnomalyEngine(baseline)
ml_engine = MLEngine()
alert_logger = AlertLogger()

flow_table = FlowTable(idle_timeout=30)
feature_extractor = FeatureExtractor()


# ===============================
# 📦 Packet Processing
# ===============================

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

    # Update flow table
    flow_table.process_packet(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol_name,
        size
    )

    # Check for expired flows
    expired = flow_table.check_timeouts()

    for flow in expired:

        # Extract features
        features = feature_extractor.extract(flow)

        # ===============================
        # 🧠 Anomaly Detection
        # ===============================

        threat_score = anomaly_engine.check(
            features,
            flow.initiator_ip,
            flow.protocol
        )

        if threat_score >= 3:
            severity = "CRITICAL"
        elif threat_score == 2:
            severity = "HIGH"
        elif threat_score == 1:
            severity = "SUSPICIOUS"
        else:
            severity = "NORMAL"

        print(f"[{severity}] Score={threat_score} | {flow}")

        # ===============================
        # 🚨 Alert Logging (only HIGH+)
        # ===============================

        if threat_score >= 2:
            alert = {
                "timestamp": str(flow.end_time),
                "initiator_ip": flow.initiator_ip,
                "responder_ip": flow.responder_ip,
                "protocol": flow.protocol,
                "score": threat_score,
                "severity": severity
            }

            alert_logger.log(alert)

        # ===============================
        # 🧠 Adaptive Learning
        # ===============================

        baseline.update(
            features,
            flow.initiator_ip,
            flow.protocol
        )


# ===============================
# 🚀 Start Engine
# ===============================

def start_sniffing(interface=None):
    print("Starting SentinelEdge AI Hybrid Engine...")
    sniff(prn=process_packet, iface=interface, store=False)
