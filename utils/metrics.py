"""Prometheus metrics helpers.

Provides module-level metrics objects if `prometheus_client` is available.
"""
try:
    from prometheus_client import start_http_server, Gauge, Counter
except Exception:
    start_http_server = None
    Gauge = None
    Counter = None

# Exported metric handles (may be None if prometheus_client not installed)
PROCESS_UP = None
FLOWS_COUNTER = None

def init_metrics():
    global PROCESS_UP, FLOWS_COUNTER
    if Counter is None or Gauge is None:
        return
    # create metrics only once
    try:
        PROCESS_UP = Gauge("sentinel_process_up", "Sentinel process up (1/0)")
    except Exception:
        PROCESS_UP = None
    try:
        FLOWS_COUNTER = Counter("sentinel_flows_processed_total", "Total flows processed")
    except Exception:
        FLOWS_COUNTER = None

def start_metrics_server(port=8001):
    if start_http_server is None:
        return False
    try:
        init_metrics()
        start_http_server(int(port))
        return True
    except Exception:
        return False
