This folder contains example monitoring artifacts for SentinelEdgeAI.

Files:

- `prometheus.yml` — a minimal Prometheus scrape config that scrapes the FastAPI `/metrics` endpoint on port 9000 and a `node` job for node exporter on port 9100.
- `grafana_sentinel_dashboard.json` — importable Grafana dashboard showing ML model status, signature status, HTTP request rate, and WebSocket event rate.

Quick start (local):

1. Run the API:

```bash
uvicorn dashboard.dashboard_api:app --host 0.0.0.0 --port 9000
```

2. Start Prometheus with this config (adjust paths as needed):

```bash
prometheus --config.file=deploy/monitoring/prometheus.yml
```

3. Import `deploy/monitoring/grafana_sentinel_dashboard.json` into Grafana (Dashboards → Import).

Notes:
- On a Pi you can run `node_exporter` to expose system metrics on port 9100.
- For production, place `prometheus.yml` into your Prometheus server config and ensure network access between Prometheus and devices.
