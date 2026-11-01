# Deployment files

The supported way to install SentinelEdgeAI on a device is the **release package** with `sentinelctl`:

```bash
curl -fsSL https://raw.githubusercontent.com/vishwa-10147/SentinelEdgeAI/main/scripts/install.sh | sudo bash -s -- --preset office
# or, from a downloaded and verified package:
sudo bash sentineledgeai-pi-<version>/packaging/sentinelctl install sentineledgeai-pi-<version>.tar.gz
```

See the [README](../README.md#quick-start) and the [admin guide](../docs/ADMIN_GUIDE.md).

| Folder | Contents |
|---|---|
| [`pi/`](pi/README.md) | OS hardening (`harden_os.sh`), turning enforcement on, a self-hosted CI runner for the privileged tests; legacy development installers |
| [`jetson/`](jetson/README.md) | Brain installer for the Jetson (`install_brain.sh`) |
| [`fleet-hosted/`](fleet-hosted/README.md) | The fleet server and console in Docker Compose for any Linux host or cloud VM |
| [`elastic/`](elastic/filebeat.yml) | A tested Filebeat 8 configuration for alerts into Elasticsearch / Elastic Cloud |
| [`assistant/`](assistant/) | Systemd units for the optional local assistant's model server (Ollama or llama.cpp), with CPU and memory limits |
| [`monitoring/`](monitoring/README.md) | Prometheus scrape configuration and alert rules, Grafana operations dashboard |
| `grafana/` | Grafana with a PostgreSQL datasource, for setups that keep alerts in PostgreSQL ([notes](../dashboard/README_GRAFANA.md)) |
