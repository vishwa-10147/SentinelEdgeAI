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

Alerting:

- This repo includes simple alert rules in `packaging/prometheus/alerts.yml`:
	- `SentinelHealthDown` fires when Prometheus cannot scrape the `sentinel` job (the health endpoint) for 5 minutes.
	- `SentinelRotateFailed` fires when `sentinel-rotate.service` is not active for 10 minutes. This requires `node_exporter` with the systemd collector enabled (which exposes `systemd_unit_state_active`).

Vault fetcher timer alert:

- `SentinelVaultFetcherTimerInactive` fires when `sentinel-health-vault.timer` is not active for 30 minutes. It requires `node_exporter` with the systemd collector enabled which exposes `systemd_unit_state_active` metrics.

If you don't run `node_exporter`, consider exposing a small metric (file, HTTP, or journald exporter) indicating last successful fetch time and alert on its staleness instead.

Textfile collector (recommended)
-------------------------------

This repo now writes a Prometheus textfile metric when the Vault fetcher succeeds:

- `sentinel_last_fetch_timestamp` (gauge) — Unix epoch seconds of the last successful fetch.

Where the metric is written:

- The fetcher will write `sentinel_last_fetch.prom` to the first existing directory among:
	- `/var/lib/node_exporter/textfile_collector`
	- `/var/run/node_exporter/textfile_collector`
	- `/var/cache/node_exporter/textfile_collector`
- If none exist it will create `/var/run/node_exporter/textfile_collector` and write the file there.

Enable node_exporter textfile collector:

1. Install and run `node_exporter` on the device.
2. Ensure the `--collector.textfile.directory` flag points to one of the paths above (default commonly `/var/lib/node_exporter/textfile_collector`).
3. Restart `node_exporter` and confirm the metric appears in Prometheus by scraping the node_exporter target.

Prometheus rule:

- `SentinelLastFetchStale` alerts when `sentinel_last_fetch_timestamp` is older than 36 hours. Adjust the threshold in `packaging/prometheus/alerts.yml` if your fetch cadence differs.


To enable alerts:

1. Place `packaging/prometheus/alerts.yml` on your Prometheus server and include it in `prometheus.yml` via `rule_files`.
2. Ensure your Prometheus scrape job for the service is named `sentinel` (see `packaging/prometheus/sentinel.yml`).
3. Install and configure `node_exporter` with `--collector.systemd` enabled, or adapt the rotate alert to an alternate metric exposed by your environment.


