# Monitoring (packaging)

The maintained monitoring files are in **`deploy/monitoring/`** (see its README):
- the Prometheus scrape config for the API on `:9000` (with a Viewer API token) and the engine on `:9101`
- alert rules, including engine down, packet drops and capture overload
- the Grafana operations dashboard

`packaging/prometheus/sentinel.yml` and `alerts.yml` are older examples for the legacy health agent and `sentinel-rotate.service`. Engine metrics moved from port 8001 to **9101** in v1.6 (`app__metrics_port`).
