# Monitoring

Prometheus scrape configuration, alert rules and a Grafana dashboard for SentinelEdgeAI.

| File | Purpose |
|---|---|
| `prometheus.yml` | Scrapes the API (`https://<device>:9000/metrics`, with a Viewer API token), the engine (`:9101`) and node_exporter (`:9100`) |
| `sentinel_alerts.yml` | Engine down, slow decisions, packet drops, **capture overloaded** (floods), temperature, SIEM delivery failures, sensor buffering, critical alerts |
| `rollback_alerts.yml` | Firewall rollback guard |
| `grafana_sentinel_dashboard.json` | Operations dashboard: flows, decision latency, findings, alerts, queue depth, drops, CPU, memory, temperature, sensor buffer, SIEM deliveries |

## Set up

1. Create a Viewer API token for Prometheus, on the device:

   ```bash
   cd /opt/sentineledgeai/current
   sudo -u sentinel .venv/bin/python -m core.auth create-token --owner admin --name prometheus --role viewer
   ```

   Save it to `/etc/prometheus/sentinel.token`, and copy `/etc/sentinel/tls/cert.pem` to `/etc/prometheus/sentinel-ca.pem`. The certificate is self-signed unless you imported your own.
2. Replace `localhost` in `prometheus.yml` with the device address, and load both rule files.
3. Import `grafana_sentinel_dashboard.json` into Grafana (Dashboards → Import).

## Useful metrics

| Metric | Meaning |
|---|---|
| `sentinel_flows_processed_total` | Flows scored |
| `sentinel_decision_latency_seconds` | Time to score a finished flow |
| `sentinel_findings_total{kind}` / `sentinel_alerts_total{severity}` | Detector findings and alerts |
| `sentinel_capture{item}` | `active`, `max`, `evicted_total`, `shed_total`, `ingest_shed_total`, `overloaded` (flood safety) |
| `sentinel_dropped_packets{interface}` | Kernel receive drops |
| `sentinel_system{resource}` | CPU, memory, temperature |
| `sentinel_sensor_buffered_flows` | Flows waiting for the brain (two-node mode) |
