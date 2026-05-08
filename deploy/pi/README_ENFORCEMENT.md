Enforcement & Rollback Guard — Pi deployment notes

This document explains how to safely enable real firewall enforcement on a Raspberry Pi
running SentinelEdgeAI and how to use the rollback guard/timer to avoid lockout.

Prerequisites
- Pi with systemd and `docker` installed (for running privileged integration tests during validation).
- Console or out-of-band access (serial/SSH with fallback) in case network is disrupted.

Validation checklist (local, on your workstation)
1. Run health check against the device: `curl -fsS http://<pi_ip>:9000/api/health`
2. Run privileged integration tests on a self-hosted runner (see `.github/workflows/privileged-integration.yml`).
3. Generate `deploy/pi/firewall-rollback.env` locally with `./scripts/enable_firewall_enforcement.sh --apply` and copy it to the Pi.

Deploy rollback guard on the Pi
1. Copy env file to the Pi: `sudo cp firewall-rollback.env /etc/sentinel/firewall-rollback.env`
2. Enable the timer: `sudo systemctl enable --now sentinel-firewall-rollback-guard.timer`

Enable enforcement (safe steps)
1. Keep console access to the Pi.
2. Option A — use installer helper on Pi:

```bash
# on the Pi
sudo bash /opt/sentineledgeai/deploy/pi/install_pi.sh --install-rollback
sudo bash /opt/sentineledgeai/deploy/pi/install_pi.sh --enable-enforcement
```

3. Option B — manual drop-in:

```bash
sudo mkdir -p /etc/systemd/system/sentineledgeai.service.d
cat > /etc/systemd/system/sentineledgeai.service.d/enable_enforcement.conf <<'EOF'
[Service]
Environment="FIREWALL_DRY_RUN=0"
EOF
sudo systemctl daemon-reload
sudo systemctl restart sentineledgeai.service
```

Disable enforcement atomically:

```bash
sudo bash /opt/sentineledgeai/deploy/pi/enforcement_ctl.sh disable
```

Check status:

```bash
sudo bash /opt/sentineledgeai/deploy/pi/enforcement_ctl.sh status
```

Recovering from accidental lockout
- The rollback guard timer will call `core.firewall.rollback_blocks()` after the configured failure threshold if the dashboard health endpoint is unreachable. Keep the rollback guard enabled while testing.
- If you lose network access entirely, use local console to run `python3 -c "import core.firewall as f; print(f.rollback_blocks('manual_recovery'))"` from the venv to clear rules.
