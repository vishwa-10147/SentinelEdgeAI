# Deployment files

The supported way to install and run SentinelEdgeAI on a device is the **release package** with `sentinelctl`:

```bash
curl -fsSL https://raw.githubusercontent.com/vishwa-10147/SentinelEdgeAI/main/scripts/install.sh | sudo bash -s -- --preset office
# or, from a downloaded package:
sudo bash sentineledgeai-pi-<version>/packaging/sentinelctl install sentineledgeai-pi-<version>.tar.gz
```

See the [README](../README.md#installation) and the [admin guide](../docs/ADMIN_GUIDE.md).

| Folder | Contents |
|---|---|
| `pi/` | OS hardening (`harden_os.sh`), model-key provisioning (`provision_key.sh`), enforcement notes, privileged integration-test helpers; older development installers (legacy) |
| `jetson/` | Brain installer for the Jetson (`install_brain.sh`); an older CPU-only development setup (legacy) |
| `monitoring/` | Prometheus scrape config and alert rules, Grafana operations dashboard |
| `grafana/` | Docker Compose Grafana with a PostgreSQL datasource (for setups that use PostgreSQL) |
