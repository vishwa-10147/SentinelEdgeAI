"""Centralized Prometheus metrics for SentinelEdgeAI.

This module exposes a shared CollectorRegistry and commonly used
metrics so different modules in the project can import the same
handles without redefining them.
"""
try:
    from prometheus_client import CollectorRegistry, Gauge, Counter, start_http_server
except Exception:
    CollectorRegistry = None
    Gauge = None
    Counter = None
    start_http_server = None

# Registry and metric handles (may be None if prometheus_client not installed)
REGISTRY = None
REQUEST_COUNT = None
WS_EVENTS = None
ML_MODEL_LOADED = None
ML_SIGNATURE_STATUS = None
FLOWS_COUNTER = None


def init_metrics(registry=None):
    global REGISTRY, REQUEST_COUNT, WS_EVENTS, ML_MODEL_LOADED, ML_SIGNATURE_STATUS, FLOWS_COUNTER
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


def start_metrics_server(port=8001):
    if start_http_server is None:
        return False
    try:
        if REGISTRY is None:
            init_metrics()
        start_http_server(int(port))
        return True
    except Exception:
        return False
