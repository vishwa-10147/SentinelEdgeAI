"""Centralized Prometheus metrics for SentinelEdgeAI.

This module exposes a shared CollectorRegistry and commonly used
metrics so different modules in the project can import the same
handles without redefining them.
"""
try:
    from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, start_http_server
except Exception:
    CollectorRegistry = None
    Gauge = None
    Counter = None
    Histogram = None
    start_http_server = None

# Registry and metric handles (may be None if prometheus_client not installed)
REGISTRY = None
REQUEST_COUNT = None
WS_EVENTS = None
ML_MODEL_LOADED = None
ML_SIGNATURE_STATUS = None
FLOWS_COUNTER = None
DECISION_LATENCY = None     # seconds to score a finished flow
FINDINGS = None             # detector findings by kind
ALERTS = None               # alerts by severity
INGEST_QUEUE = None         # flows waiting for scoring
DROPPED_PACKETS = None      # kernel receive drops on the capture interfaces
SYSTEM = None               # cpu_percent, memory_percent, temperature_c
INTEGRATION_EVENTS = None   # SIEM / notification deliveries by result
SENSOR_BUFFER = None        # flows buffered for the brain


def init_metrics(registry=None):
    global REGISTRY, REQUEST_COUNT, WS_EVENTS, ML_MODEL_LOADED, ML_SIGNATURE_STATUS, FLOWS_COUNTER
    global DECISION_LATENCY, FINDINGS, ALERTS, INGEST_QUEUE, DROPPED_PACKETS, SYSTEM, INTEGRATION_EVENTS, SENSOR_BUFFER
    if CollectorRegistry is None or Gauge is None or Counter is None:
        return
    if registry is None:
        REGISTRY = CollectorRegistry()
    else:
        REGISTRY = registry
    try:
        REQUEST_COUNT = Counter('sentinel_http_requests_total', 'Total HTTP requests', ['method', 'path', 'status'], registry=REGISTRY)
    except Exception:
        REQUEST_COUNT = None
    try:
        WS_EVENTS = Counter('sentinel_ws_events_total', 'Total websocket events emitted', registry=REGISTRY)
    except Exception:
        WS_EVENTS = None
    try:
        ML_MODEL_LOADED = Gauge('sentinel_ml_model_loaded', '1 if ML model loaded and verified, 0 otherwise', registry=REGISTRY)
    except Exception:
        ML_MODEL_LOADED = None
    try:
        ML_SIGNATURE_STATUS = Gauge('sentinel_ml_signature_status', '0=missing,1=valid,2=invalid', registry=REGISTRY)
    except Exception:
        ML_SIGNATURE_STATUS = None
    try:
        FLOWS_COUNTER = Counter('sentinel_flows_processed_total', 'Total flows processed', registry=REGISTRY)
    except Exception:
        FLOWS_COUNTER = None
    try:
        DECISION_LATENCY = Histogram('sentinel_decision_latency_seconds', 'Time to score a finished flow',
                                     buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5), registry=REGISTRY)
        FINDINGS = Counter('sentinel_findings_total', 'Detector findings', ['kind'], registry=REGISTRY)
        ALERTS = Counter('sentinel_alerts_total', 'Alerts raised', ['severity'], registry=REGISTRY)
        INGEST_QUEUE = Gauge('sentinel_ingest_queue_depth', 'Flows waiting to be scored', registry=REGISTRY)
        DROPPED_PACKETS = Gauge('sentinel_dropped_packets', 'Kernel receive drops', ['interface'], registry=REGISTRY)
        SYSTEM = Gauge('sentinel_system', 'Host resources', ['resource'], registry=REGISTRY)
        INTEGRATION_EVENTS = Gauge('sentinel_integration_events', 'Alert deliveries to SIEM/notification sinks',
                                   ['result'], registry=REGISTRY)
        SENSOR_BUFFER = Gauge('sentinel_sensor_buffered_flows', 'Flows buffered for the brain', registry=REGISTRY)
    except Exception:
        pass


def read_temperature():
    """SoC temperature in degrees C (Raspberry Pi and Jetson expose thermal zones), or None."""
    import glob
    temps = []
    for path in glob.glob('/sys/class/thermal/thermal_zone*/temp'):
        try:
            with open(path) as f:
                temps.append(int(f.read().strip()) / 1000)
        except (OSError, ValueError):
            continue
    return max(temps) if temps else None


def collect_system():
    """Refresh host gauges; called every 15 s by the engine."""
    if SYSTEM is None:
        return
    try:
        import psutil
        SYSTEM.labels('cpu_percent').set(psutil.cpu_percent(interval=None))
        SYSTEM.labels('memory_percent').set(psutil.virtual_memory().percent)
        temp = read_temperature()
        if temp is not None:
            SYSTEM.labels('temperature_c').set(temp)
        for name, c in psutil.net_io_counters(pernic=True).items():
            if name == 'lo' or name.startswith(('veth', 'docker', 'br-')):
                continue
            DROPPED_PACKETS.labels(name).set(c.dropin)
        from integrations.dispatcher import get_dispatcher, write_status
        stats = get_dispatcher().stats
        for key in ('sent', 'failed', 'dropped'):
            INTEGRATION_EVENTS.labels(key).set(stats[key])
        write_status()
    except Exception:
        pass


def start_metrics_server(port=8001):
    if start_http_server is None:
        return False
    try:
        if REGISTRY is None:
            init_metrics()
        # serve this module's registry, not prometheus_client's empty default one
        start_http_server(int(port), registry=REGISTRY)
        return True
    except Exception:
        return False
