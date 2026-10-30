from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, Raw
import json
import os
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
import core.audit as audit
from enforcement import identity
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
        # device identity (MAC, vendor, DHCP fingerprint) from ARP and DHCP
        if ARP in packet or (UDP in packet and packet[UDP].dport in (67, 68)):
            identity.observe_packet(packet)
        if IP not in packet:
            return
        _observe_dns_tls(packet)

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

        handle_parsed(src_ip, dst_ip, src_port, dst_port, protocol_name, size)

    except Exception as e:
        logger.error(
            f"Packet processing error | Error={str(e)}",
            exc_info=True
        )


_last_timeout_check = 0.0


def handle_parsed(src_ip, dst_ip, src_port, dst_port, protocol_name, size):
    """Flow accounting for one parsed packet; shared by the scapy and AF_PACKET capture paths."""
    try:
        flow_table.process_packet(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol_name,
            size
        )

        # Check for expired flows. The scan walks every active flow, so run it at most
        # once a second instead of on every packet (idle timeouts are 30 s).
        global _last_timeout_check
        now_mono = time.monotonic()
        if now_mono - _last_timeout_check < 1.0:
            return
        _last_timeout_check = now_mono
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
    mode = os.environ.get("SENTINEL_CAPTURE", "auto").lower()
    from capture import afpacket
    if mode == "afpacket" or (mode == "auto" and afpacket.available()):
        from scapy.layers.l2 import Ether
        logger.warning("capture: AF_PACKET fast path on %s", interface or "all interfaces")
        afpacket.run(interface, handle_parsed, lambda frame: process_packet(Ether(frame)))
        return
    logger.warning("capture: scapy on %s", interface or "all interfaces")
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

                fused = None
                try:
                    from common.protocol import flow_record
                    from detection.pipeline import get_pipeline
                    record = flow_record(flow, result, features)
                    fused = get_pipeline().observe_flow(record, result)
                    # raise this flow's risk only when the flow itself produced a finding; earlier
                    # findings for the source still count toward confirmation, without re-alerting
                    if fused['new_findings'] and fused['risk'] > (result.get("final_risk") or 0):
                        result["final_risk"] = fused['risk']
                        if fused['attack_type']:
                            result["attack_type"] = fused['attack_type']
                    result["confidence"] = max(result.get("confidence") or 0, fused['confidence'])
                except Exception:
                    logger.debug("Detection pipeline failed", exc_info=True)

                final_risk = result.get("final_risk", 0)
                try:
                    _record_flow_stats(flow, final_risk)
                except Exception:
                    logger.debug("Failed to update live stats", exc_info=True)
                try:
                    _forward_to_brain(flow, result, features)
                except Exception:
                    logger.exception("Failed to queue flow for the brain")
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
                    from utils import metrics as m
                    if m.FLOWS_COUNTER is not None:
                        m.FLOWS_COUNTER.inc()
                    if m.DECISION_LATENCY is not None:
                        m.DECISION_LATENCY.observe(processing_time_ms / 1000)
                    if m.FINDINGS is not None and fused:
                        for nf in fused.get('new_findings', []):
                            m.FINDINGS.labels(nf['kind']).inc()
                    if m.INGEST_QUEUE is not None and ingest_queue is not None:
                        m.INGEST_QUEUE.set(ingest_queue.queue.qsize())
                    if m.SENSOR_BUFFER is not None and _brain_buffer is not None:
                        m.SENSOR_BUFFER.set(len(_brain_buffer))
                except Exception:
                    logger.debug("metrics update failed", exc_info=True)
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
                        "mitre_technique_name": mitre_info.get("technique_name"),
                        "confidence": result.get("confidence"),
                        "confirmed": bool(fused and fused['confirmed']),
                        "explanation": _alert_explanation(fused),
                        "findings": (fused or {}).get('findings', []),
                    }
                    if fused and fused.get('technique') and not alert.get("mitre_technique_id"):
                        alert["mitre_technique_id"] = fused['technique']
                    alert_logger.log(alert)
                    try:
                        from utils import metrics as m
                        if m.ALERTS is not None:
                            m.ALERTS.labels(severity).inc()
                    except Exception:
                        pass
                    try:
                        if storage:
                            storage.insert_alert(int(time.time()), flow.initiator_ip, flow.responder_ip, flow.initiator_port, flow.responder_port, flow.protocol, final_risk, confidence, str(alert))
                    except Exception:
                        logger.debug("Failed to persist alert to SQLite", exc_info=True)

                    try:
                        policy = firewall.get_policy()
                        # multi-stage confirmation before any automatic enforcement
                        if policy.get("response_mode") == "auto_block" and fused and fused['confirmed']:
                            # graduated: alert -> rate limit -> block -> quarantine, with approval gates
                            from enforcement.playbook import get_playbook
                            get_playbook().evaluate(flow.initiator_ip, final_risk, reason=str(attack_type))
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


_brain_buffer = None
_brain_checked = 0.0


def _alert_explanation(fused):
    """This flow's own evidence first; findings from earlier flows of the source are labelled as such."""
    if not fused:
        return []
    new = {(f['kind'], f['evidence']) for f in fused.get('new_findings', [])}
    out = [f['evidence'] for f in fused.get('findings', []) if (f['kind'], f['evidence']) in new]
    out += [e for e in fused.get('explanation', []) if 'standard deviations' in e]
    out += [f"earlier finding for this source: {f['evidence']}"
            for f in fused.get('findings', []) if (f['kind'], f['evidence']) not in new][:2]
    return out


def _forward_to_brain(flow, result, features):
    """When this device is an enrolled sensor, queue the scored flow for the brain."""
    global _brain_buffer, _brain_checked
    if _brain_buffer is None:
        # re-check enrolment once a minute, so enrolling needs no engine restart
        if time.time() - _brain_checked < 60:
            return
        _brain_checked = time.time()
        from sensor import uplink
        if not uplink.load_identity():
            return
        from sensor.buffer import DiskBuffer
        _brain_buffer = DiskBuffer()
        logger.warning("sensor enrolled; forwarding flows to the brain")
    from common.protocol import flow_record
    _brain_buffer.put(flow_record(flow, result, features))


def _observe_dns_tls(packet):
    """Feed DNS answers and TLS ClientHellos to the Phase 4 detectors; alert on findings."""
    try:
        from detection.pipeline import get_pipeline
        findings = []
        if DNS in packet and packet[DNS].qr == 1 and packet[DNS].qd is not None:
            qname = packet[DNS].qd.qname.decode('ascii', 'replace') if isinstance(packet[DNS].qd.qname, bytes) \
                else str(packet[DNS].qd.qname)
            findings = get_pipeline().observe_dns(packet[IP].dst, qname, nxdomain=packet[DNS].rcode == 3)
        elif TCP in packet and Raw in packet:
            payload = bytes(packet[Raw].load)
            if payload[:1] == b'\x16':
                _, findings = get_pipeline().observe_tls(packet[IP].src, packet[IP].dst, payload)
        for f in findings:
            if f.severity >= config.get("alerts", "min_risk_score"):
                alert_logger.log({
                    "timestamp": str(time.strftime('%Y-%m-%d %H:%M:%S')), "initiator_ip": f.src,
                    "responder_ip": f.details.get('target'), "protocol": 'DNS' if 'dns' in f.kind or f.kind == 'dga' else 'TLS',
                    "final_risk_score": f.severity, "severity": "CRITICAL" if f.severity >= 75 else "HIGH",
                    "attack_type": f.kind, "confidence": f.probability, "mitre_technique_id": f.technique,
                    "explanation": [f.evidence], "findings": [f.as_dict()],
                })
    except Exception:
        logger.debug("DNS/TLS analysis failed", exc_info=True)


def _record_flow_stats(flow, risk):
    """Append a finished flow and its risk score to the live stats file."""
    try:
        with open(LIVE_STATS_FILE, "r") as f:
            stats = json.load(f)
    except Exception:
        stats = {}
    stats.setdefault("total_flows", 0)
    stats.setdefault("unique_ips", [])
    if not isinstance(stats.get("flow_history"), list):
        stats["flow_history"] = []
    stats["total_flows"] += 1
    if flow.initiator_ip not in stats["unique_ips"]:
        stats["unique_ips"].append(flow.initiator_ip)
    stats["flow_history"].append({"timestamp": time.time(), "score": risk})
    history_limit = config.get("persistence", "history_limit")
    stats["flow_history"] = stats["flow_history"][-history_limit:]
    with open(LIVE_STATS_FILE, "w") as f:
        json.dump(stats, f)


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
        _record_flow_stats(flow, result.get("final_risk", 0))
        _forward_to_brain(flow, result, features)
    except Exception:
        logger.exception("Synchronous flow processing failed")
