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
from utils.metrics import FLOWS_COUNTER
from utils.alert_logger import AlertLogger
import core.firewall as firewall
import asyncio
import threading
from core.async_queue import IngestQueue
from core.storage import get_storage

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

# optional in-process event publisher (callable)
event_publisher = None

def set_event_publisher(cb):
    global event_publisher
    event_publisher = cb


# Live stats file for simple dashboarding / UI
LIVE_STATS_FILE = "live_stats.json"
HEALTH_FILE = "health.json"
LIVE_EVENTS_FILE = "live_events.jsonl"
FLOWS_HISTORY_FILE = "flows_history.jsonl"

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
            # enqueue expired flow to async ingestion queue for batched processing
            try:
                if ingest_queue and ingest_loop:
                    # schedule enqueue on background loop
                    asyncio.run_coroutine_threadsafe(ingest_queue.enqueue(flow), ingest_loop)
                else:
                    # fallback: process inline (synchronous)
                    _process_flow_sync(flow)
            except Exception:
                logger.exception("Failed to enqueue flow for processing; falling back to sync")
                try:
                    _process_flow_sync(flow)
                except Exception:
                    logger.exception("Fallback sync processing also failed")

            # -------- Update Live Stats --------
            # -------- Update Live Stats --------
            try:
                with open(LIVE_STATS_FILE, "r") as f:
                    stats = json.load(f)
            except Exception:
                stats = {}

            # Ensure required keys exist
            stats.setdefault("total_flows", 0)
            stats.setdefault("unique_ips", [])
            stats.setdefault("flow_history", [])

            stats["total_flows"] += 1

            if flow.initiator_ip not in stats["unique_ips"]:
                stats["unique_ips"].append(flow.initiator_ip)

            try:
                stats["flow_history"].append({
                    "timestamp": time.time(),
                    "score": final_risk
                })
            except Exception:
                stats["flow_history"] = [{
                    "timestamp": time.time(),
                    "score": final_risk
                }]

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
    # ensure ingest loop is running
    _start_ingest_loop()
    sniff(prn=process_packet, iface=interface, store=False)


# ===============================
# Async ingest queue init and batch processor
# ===============================

ingest_loop = None
ingest_queue = None


def _start_ingest_loop():
    global ingest_loop, ingest_queue
    if ingest_loop is not None:
        return

    ingest_loop = asyncio.new_event_loop()

    def _run_loop():
        asyncio.set_event_loop(ingest_loop)
        ingest_loop.run_forever()

    t = threading.Thread(target=_run_loop, daemon=True)
    t.start()

    # initialize storage (Postgres if DATABASE_URL set, otherwise SQLite)
    try:
        storage = get_storage("data/sentinel.db")
        storage.connect()
        storage.create_tables()
    except Exception:
        logger.exception("Failed to initialize storage")
        storage = None

    async def _process_batch(batch):
        for flow in batch:
            try:
                start_time = time.perf_counter()
                features = feature_extractor.extract(flow)
                result = sentinel_engine.process_flow(flow, features)
                end_time = time.perf_counter()
                processing_time_ms = round((end_time - start_time) * 1000, 3)

                final_risk = result.get("final_risk", 0)
                attack_type = result.get("attack_type")
                drift_flag = result.get("drift")
                drift_reason = result.get("drift_reason")
                mitre_info = result.get("mitre", {})
                anomaly_score = result.get("anomaly_score")
                ml_score = result.get("ml_score")
                confidence = result.get("confidence", 0)
                behavior_score = result.get("behavior_score", 0)
                behavior_reasons = result.get("behavior_reasons", [])

                ENGINE_METRICS["flows_processed"] += 1
                try:
                    if FLOWS_COUNTER is not None:
                        FLOWS_COUNTER.inc()
                except Exception:
                    logger.debug("FLOWS_COUNTER.inc failed", exc_info=True)
                ENGINE_METRICS["total_processing_time_ms"] += processing_time_ms
                health_monitor.update_flows()

                # severity
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

                logger.info(f"[{severity}] Risk={final_risk} | IP={flow.initiator_ip} | Protocol={flow.protocol}")

                if drift_flag:
                    logger.warning(f"BEHAVIORAL DRIFT DETECTED | IP={flow.initiator_ip} | Reason={drift_reason}")

                # Persist basic flow record to SQLite
                try:
                    if storage:
                        storage.insert_flow(
                            int(time.time()),
                            flow.initiator_ip,
                            flow.responder_ip,
                            flow.initiator_port,
                            flow.responder_port,
                            flow.protocol,
                            flow.forward_bytes + flow.backward_bytes,
                            flow.forward_packets + flow.backward_packets,
                            int(flow.end_time.timestamp()) if hasattr(flow.end_time, 'timestamp') else int(time.time())
                        )
                except Exception:
                    logger.debug("Failed to persist flow to SQLite", exc_info=True)

                # Alerts and firewall
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
                        "behavior_score": behavior_score,
                        "behavior_reasons": behavior_reasons,
                        "mitre_tactic": mitre_info.get("tactic"),
                        "mitre_technique_id": mitre_info.get("technique_id"),
                        "mitre_technique_name": mitre_info.get("technique_name")
                    }
                    alert_logger.log(alert)
                    try:
                        if storage:
                            storage.insert_alert(int(time.time()), flow.initiator_ip, flow.responder_ip, flow.initiator_port, flow.responder_port, flow.protocol, final_risk, confidence, str(alert))
                    except Exception:
                        logger.debug("Failed to persist alert to SQLite", exc_info=True)

                    try:
                        policy = firewall.get_policy()
                        if (
                            policy.get("response_mode") == "auto_block"
                            and final_risk >= int(policy.get("auto_block_min_risk", 75))
                        ):
                            firewall.add_block(
                                flow.initiator_ip,
                                ttl=policy.get("default_ttl"),
                                reason=f"auto_response:{attack_type}"
                            )
                    except Exception:
                        logger.debug("Auto-response evaluation failed", exc_info=True)

                # Publish event
                try:
                    evt = {
                        "timestamp": time.time(),
                        "type": "flow",
                        "src": flow.initiator_ip,
                        "dst": flow.responder_ip,
                        "src_port": flow.initiator_port,
                        "dst_port": flow.responder_port,
                        "protocol": flow.protocol,
                        "packets": flow.forward_packets + flow.backward_packets,
                        "bytes": flow.forward_bytes + flow.backward_bytes,
                        "duration": flow.duration,
                        "risk": final_risk,
                        "severity": severity,
                        "attack_type": attack_type,
                        "anomaly_score": anomaly_score,
                        "ml_score": ml_score,
                        "drift": drift_flag,
                        "drift_reason": drift_reason,
                        "behavior_score": behavior_score,
                        "behavior_reasons": behavior_reasons,
                        "features": features
                    }
                    try:
                        if event_publisher:
                            event_publisher(evt)
                    except Exception:
                        logger.debug("event_publisher callback failed", exc_info=True)
                except Exception:
                    logger.debug("Failed to build/publish event", exc_info=True)

                # adaptive baseline update
                try:
                    baseline.update(features, flow.initiator_ip, flow.protocol)
                except Exception:
                    logger.debug("Baseline update failed", exc_info=True)

            except Exception:
                logger.exception("Error processing flow in batch")

    ingest_queue = IngestQueue(_process_batch, batch_size=32, batch_timeout=0.25)
    # start ingest queue
    asyncio.run_coroutine_threadsafe(ingest_queue.start(), ingest_loop)


def _process_flow_sync(flow):
    # fallback synchronous processor (keeps original behavior minimally)
    try:
        start_time = time.perf_counter()
        features = feature_extractor.extract(flow)
        result = sentinel_engine.process_flow(flow, features)
        end_time = time.perf_counter()
        processing_time_ms = round((end_time - start_time) * 1000, 3)
        ENGINE_METRICS["flows_processed"] += 1
        ENGINE_METRICS["total_processing_time_ms"] += processing_time_ms
        health_monitor.update_flows()
    except Exception:
        logger.exception("Synchronous flow processing failed")
