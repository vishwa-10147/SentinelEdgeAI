SentinelEdgeAI Firewall Rollback Guard
------------------------------------

This directory contains systemd unit templates and helper scripts to ensure that when enforcement is enabled on a Pi, an automated rollback guard periodically verifies health and removes accidental blocks if the device becomes unhealthy.

Files
- `sentinel-firewall-rollback.service` — one-shot systemd service that runs the rollback script.
- `sentinel-firewall-rollback.timer` — timer to run the guard periodically (default: every 5 minutes).

Installation (on target Pi)

1. Copy the unit files to `/etc/systemd/system/`:

```bash
sudo cp packaging/sentinel-firewall-rollback.service /etc/systemd/system/
sudo cp packaging/sentinel-firewall-rollback.timer /etc/systemd/system/
```

2. Install the helper script and environment file (example):

```bash
sudo cp packaging/sentinel-firewall-rollback.service /usr/local/bin/sentinel-firewall-rollback.sh
sudo chmod +x /usr/local/bin/sentinel-firewall-rollback.sh
# Create /etc/sentinel/firewall-rollback.env with required variables (see deploy scripts)
```


3. Enable and start the timer (manual):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-firewall-rollback.timer
```

Automated installer

An installer script is provided to simplify deployment from this repository. On the Pi run (as root):

```bash
cd /path/to/SentinelEdgeAI
sudo packaging/install_firewall_guard.sh --env-file packaging/firewall-rollback.env.example --apply
```

This will copy unit files to `/etc/systemd/system`, install the helper script to `/usr/local/bin/sentinel-firewall-rollback.sh`, write the env file to `/etc/sentinel/firewall-rollback.env`, and enable the timer.

The guard script calls the backend `POST /api/firewall/rollback` endpoint when health checks fail. See `scripts/validate_rollback_guard.py` for a test harness.
