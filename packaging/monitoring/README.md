Monitoring guidance

This repo includes minimal scaffolding for monitoring and scraping.

- `packaging/prometheus/sentinel.yml` - example Prometheus scrape config for scraping the local health endpoint (adjust job/port as needed).

Recommendations:
- Install a node exporter or use Prometheus to scrape `/health` and an exporter that reads logs/metrics.
- For advanced setups, add `prometheus_client` instrumentation inside `main.py` and expose `/metrics` on a dedicated port.
