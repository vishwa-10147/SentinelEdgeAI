from scapy.all import sniff, IP, TCP, UDP
import json
import time
import logging
import psutil
from flow.flow_table import FlowTable
from features.feature_extractor import FeatureExtractor
from detection.adaptive_baseline import AdaptiveBaseline
from detection.anomaly_engine import AnomalyEngine
from detection.ml_engine import MLEngine
from detection.attack_classifier import AttackClassifier
from detection.behavioral_fingerprint import BehavioralFingerprint
from detection.risk_engine import RiskEscalationEngine
from detection.mitre_mapper import MitreMapper
from core.engine import SentinelEngine
from core.config_loader import Config
from core.health import HealthMonitor
from utils.alert_logger import AlertLogger

# Load configuration
config = Config()

# Get logger
logger = logging.getLogger("sentinel")

# ===============================
# 🔧 Initialize Core Components
# ===============================

baseline = AdaptiveBaseline(
    window_size=config.get("baseline", "window_size")
)
anomaly_engine = AnomalyEngine(
    baseline,
    warmup_flows=config.get("baseline", "warmup_flows"),
    z_threshold=config.get("anomaly", "z_threshold")
)
ml_engine = MLEngine()
attack_classifier = AttackClassifier()
fingerprint_engine = BehavioralFingerprint(
    drift_threshold=config.get("drift", "deviation_threshold")
)
risk_engine = RiskEscalationEngine()
mitre_mapper = MitreMapper()

sentinel_engine = SentinelEngine(
    anomaly_engine=anomaly_engine,
    ml_engine=ml_engine,
    fingerprint_engine=fingerprint_engine,
    attack_classifier=attack_classifier,
    risk_engine=risk_engine,
    mitre_mapper=mitre_mapper
)

alert_logger = AlertLogger()
health_monitor = HealthMonitor()

flow_table = FlowTable(idle_timeout=30)
feature_extractor = FeatureExtractor()


# Live stats file for simple dashboarding / UI
LIVE_STATS_FILE = "live_stats.json"
HEALTH_FILE = "health.json"

# ===============================
# 📊 Performance Metrics
# ===============================
ENGINE_METRICS = {
    "flows_processed": 0,
    "total_processing_time_ms": 0
}

SYSTEM_METRICS = {
    "cpu_usage": 0,
    "memory_usage_mb": 0
}


# ===============================
# 📦 Packet Processing
# ===============================

def process_packet(packet):

    try:
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

            try:
                # Measure processing time
                start_time = time.perf_counter()

                # Extract features
                features = feature_extractor.extract(flow)

                # Process through all detection layers
                result = sentinel_engine.process_flow(flow, features)

                end_time = time.perf_counter()
                processing_time_ms = round((end_time - start_time) * 1000, 3)

                final_risk = result["final_risk"]
                attack_type = result["attack_type"]
                drift_flag = result["drift"]
                drift_reason = result["drift_reason"]
                mitre_info = result["mitre"]
                anomaly_score = result["anomaly_score"]
                ml_score = result["ml_score"]
                confidence = result["confidence"]

                # Update metrics
                ENGINE_METRICS["flows_processed"] += 1
                ENGINE_METRICS["total_processing_time_ms"] += processing_time_ms
                health_monitor.update_flows()

                # Log per-flow processing time at DEBUG level
                logger.debug(
                    f"Flow processed in {processing_time_ms} ms | "
                    f"IP={flow.initiator_ip}"
                )

                # Log average performance every 100 flows
                if ENGINE_METRICS["flows_processed"] % 100 == 0:
                    avg_time = (
                        ENGINE_METRICS["total_processing_time_ms"] /
                        ENGINE_METRICS["flows_processed"]
                    )
                    logger.info(
                        f"Performance | Flows={ENGINE_METRICS['flows_processed']} | "
                        f"AvgProcessingTime={round(avg_time, 3)} ms"
                    )

                    # Collect system resource metrics
                    process = psutil.Process()
                    SYSTEM_METRICS["cpu_usage"] = psutil.cpu_percent(interval=None)
                    SYSTEM_METRICS["memory_usage_mb"] = round(
                        process.memory_info().rss / (1024 * 1024), 2
                    )

                    logger.info(
                        f"System | CPU={SYSTEM_METRICS['cpu_usage']}% | "
                        f"Memory={SYSTEM_METRICS['memory_usage_mb']} MB"
                    )

                # Determine severity based on config thresholds
                critical_threshold = config.get("risk_thresholds", "critical")
                high_threshold = config.get("risk_thresholds", "high")
                medium_threshold = config.get("risk_thresholds", "medium")

                if final_risk >= critical_threshold:
                    severity = "CRITICAL"
                elif final_risk >= high_threshold:
                    severity = "HIGH"
                elif final_risk >= medium_threshold:
                    severity = "MEDIUM"
                elif final_risk > 0:
                    severity = "LOW"
                else:
                    severity = "NORMAL"

                # Log flow analysis
                logger.info(
                    f"[{severity}] Risk={final_risk} | "
                    f"IP={flow.initiator_ip} | "
                    f"Protocol={flow.protocol}"
                )

                # Log drift if detected
                if drift_flag:
                    logger.warning(
                        f"BEHAVIORAL DRIFT DETECTED | "
                        f"IP={flow.initiator_ip} | "
                        f"Reason={drift_reason}"
                    )

                # Persist device profiles
                with open("device_profiles.json", "w") as f:
                    json.dump(fingerprint_engine.get_all_profiles(), f, indent=4)

                # -------- Store Risk Timeline --------
                RISK_TIMELINE_FILE = "risk_timeline.json"

                try:
                    with open(RISK_TIMELINE_FILE, "r") as f:
                        timeline = json.load(f)
                except:
                    timeline = {}

                ip = flow.initiator_ip

                if ip not in timeline:
                    timeline[ip] = []

                timeline[ip].append({
                    "timestamp": time.time(),
                    "risk": final_risk
                })

                # Keep last N entries per device
                history_limit = config.get("persistence", "history_limit")
                timeline[ip] = timeline[ip][-history_limit:]

                with open(RISK_TIMELINE_FILE, "w") as f:
                    json.dump(timeline, f, indent=4)

                # ===============================
                # 🚨 Alert Logging (only HIGH+)
                # ===============================

                alert_threshold = config.get("alerts", "min_risk_score")
                if final_risk >= alert_threshold:
                    alert = {
                        "timestamp": str(flow.end_time),
                        "initiator_ip": flow.initiator_ip,
                        "responder_ip": flow.responder_ip,
                        "protocol": flow.protocol,
                        "final_risk_score": final_risk,
                        "severity": severity,
                        "attack_type": attack_type,
                        "drift": drift_flag,
                        "mitre_tactic": mitre_info["tactic"],
                        "mitre_technique_id": mitre_info["technique_id"],
                        "mitre_technique_name": mitre_info["technique_name"]
                    }

                    alert_logger.log(alert)

                    # Log security events at appropriate level
                    if final_risk >= config.get("risk_thresholds", "critical"):
                        logger.critical(
                            f"CRITICAL ALERT | Risk={final_risk} | "
                            f"IP={flow.initiator_ip} | Attack={attack_type}"
                        )
                    elif final_risk >= config.get("risk_thresholds", "high"):
                        logger.warning(
                            f"ALERT | Risk={final_risk} | "
                            f"IP={flow.initiator_ip} | Attack={attack_type}"
                        )

                # ===============================
                # 🧠 Adaptive Learning
                # ===============================

                baseline.update(
                    features,
                    flow.initiator_ip,
                    flow.protocol
                )

            except Exception as e:
                logger.error(
                    f"Flow processing failed | IP={flow.initiator_ip} | Error={str(e)}",
                    exc_info=True
                )
                continue

            # -------- Update Live Stats --------
            # -------- Update Live Stats --------
            try:
                with open(LIVE_STATS_FILE, "r") as f:
                    stats = json.load(f)
            except:
                stats = {
                    "total_flows": 0,
                    "unique_ips": [],
                    "flow_history": []
                }

            stats["total_flows"] += 1

            if flow.initiator_ip not in stats["unique_ips"]:
                stats["unique_ips"].append(flow.initiator_ip)

            stats["flow_history"].append({
                "timestamp": time.time(),
                "score": final_risk
            })

            # Keep only last N entries
            history_limit = config.get("persistence", "history_limit")
            stats["flow_history"] = stats["flow_history"][-history_limit:]

            with open(LIVE_STATS_FILE, "w") as f:
                json.dump(stats, f)

            # -------- Update Health Status --------
            try:
                with open(HEALTH_FILE, "w") as f:
                    json.dump(health_monitor.get_status(), f, indent=4)
            except Exception as e:
                logger.debug(f"Failed to write health status | Error={str(e)}")

    except Exception as e:
        logger.error(
            f"Packet processing error | Error={str(e)}",
            exc_info=True
        )


# ===============================
# 🚀 Start Engine
# ===============================

def start_sniffing(interface=None):
    logger.info("Starting SentinelEdge AI Hybrid Engine...")
    sniff(prn=process_packet, iface=interface, store=False)
