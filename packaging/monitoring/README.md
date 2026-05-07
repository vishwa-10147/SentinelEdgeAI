Monitoring guidance

This repo includes minimal scaffolding for monitoring and scraping.

- `packaging/prometheus/sentinel.yml` - example Prometheus scrape config for scraping the local health endpoint (adjust job/port as needed).

Recommendations:
- Install a node exporter or use Prometheus to scrape `/health` and an exporter that reads logs/metrics.
- For advanced setups, add `prometheus_client` instrumentation inside `main.py` and expose `/metrics` on a dedicated port.

This repo now includes basic Prometheus instrumentation in `main.py`:

- Exposes `/metrics` on port configured by `app.metrics_port` (defaults to `8001`).
- Provides `sentinel_process_up` gauge and `sentinel_flows_processed_total` counter (increment in `capture` when flows are processed).

To enable:

1. Ensure `prometheus-client` is installed (it's now in `requirements.txt`).
2. Configure `app.metrics_port` in `config.yaml` if you want a different port.
3. Add the scrape target to your Prometheus config (example in `packaging/prometheus/sentinel.yml`).

