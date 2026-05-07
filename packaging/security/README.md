Security hardening notes

Quick steps applied/available:
- Services run as a non-root user (`vishwa` by default) and the health runtime env is provided from `/run/sentinel/health.env` with 600 perms.
- Systemd units include `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` and `NoNewPrivileges=false` where needed.

Recommendations:
- Lock down SSH and use key-based auth; disable password login.
- Use a centralized secrets store (HashiCorp Vault) for production secrets.
- Enable `systemd` service sandboxes (`PrivateTmp=yes`, `ProtectSystem=full`) where compatible.
- Regularly rotate credentials in `/etc/sentinel/health.env` and consider an automated agent.

Rotation helper:
- This repo contains `scripts/rotate_health.sh` plus a unit and timer under `packaging/` to run daily.
- To install the rotation timer on the device (requires root):
  1. Copy the script and units into place:
	  ```bash
	  sudo install -m 755 scripts/rotate_health.sh /usr/local/bin/rotate-health.sh
	  sudo install -m 644 packaging/sentinel-rotate.service /etc/systemd/system/sentinel-rotate.service
	  sudo install -m 644 packaging/sentinel-rotate.timer /etc/systemd/system/sentinel-rotate.timer
	  ```
  2. Reload systemd, enable and start the timer:
	  ```bash
	  sudo systemctl daemon-reload
	  sudo systemctl enable --now sentinel-rotate.timer
	  ```

Optional: Vault integration
---------------------------

You can replace manual `/etc/sentinel/health.env` maintenance with a Vault-backed fetcher.

Files included:

- `scripts/fetch_health_from_vault.sh` — uses the `vault` CLI to read `HEALTH_PASS` from a KV path (defaults to `secret/sentineledge/health`) and writes `/etc/sentinel/health.env` with `root:root 600` permissions.
- `packaging/sentinel-health-vault.service` — a one-shot systemd unit that runs the fetcher. Install the script to `/usr/local/bin/fetch-health-from-vault.sh` and the unit to `/etc/systemd/system/`.

To enable:

1. Ensure a Vault server is reachable and the machine has a valid Vault token (via environment, agent, or systemd token helper).
2. Optionally set `VAULT_SECRET_PATH` env var to your KV path (defaults to `secret/sentineledge/health`).
3. Install the script and unit:

```sh
sudo install -m 755 scripts/fetch_health_from_vault.sh /usr/local/bin/fetch-health-from-vault.sh
sudo install -m 644 packaging/sentinel-health-vault.service /etc/systemd/system/sentinel-health-vault.service
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-health-vault.service
```

4. Consider adding a timer to rotate or refresh secrets periodically, or invoke the service from your existing rotation workflow.

Providing a Vault token to systemd
--------------------------------

The systemd unit supports reading a Vault token from `/etc/sentinel/vault.env`. Create that file with root-only permissions so systemd can use it when contacting Vault (useful for automated fetches or when running the service as a timer):

```sh
sudo mkdir -p /etc/sentinel
sudo tee /etc/sentinel/vault.env > /dev/null <<'EOF'
VAULT_TOKEN=your-vault-token-here
EOF
sudo chown root:root /etc/sentinel/vault.env
sudo chmod 600 /etc/sentinel/vault.env
```

Replace `your-vault-token-here` with a token that has `kv/get` permission for the path set in `VAULT_SECRET_PATH` (default `secret/sentineledge/health`).

After creating the file, reload systemd and run the service once:

```sh
sudo systemctl daemon-reload
sudo systemctl start --no-block sentinel-health-vault.service
sudo systemctl status sentinel-health-vault.service --no-pager -l
```


Timer (recommended)
-------------------

This repository includes a ready-made systemd timer `packaging/sentinel-health-vault.timer` and an installer helper `scripts/install_vault_fetcher.sh` to install and enable the timer and unit.

Install using the helper (runs installs and enables the timer):

```sh
sh scripts/install_vault_fetcher.sh
```

The timer runs the fetcher shortly after boot and then every 24 hours. Adjust `packaging/sentinel-health-vault.timer` if you need a different cadence.



