# Raspberry Pi

Install with the release package and `sentinelctl` (see the [README](../../README.md#installation)). This folder holds the tools you use around that:

| File | Purpose |
|---|---|
| `harden_os.sh` | Secure OS baseline: SSH keys only (with a lockout guard), management firewall, unattended upgrades, journald limits. Dry run unless `--apply` |
| `provision_key.sh` | Installs the model signing key at `/etc/sentinel/model_signing.key` (see [MODEL_KEY_PROVISIONING.md](MODEL_KEY_PROVISIONING.md)) |
| `README_ENFORCEMENT.md` | Turning real enforcement on safely |
| `SELF_HOSTED_RUNNER.md`, `run_integration.sh`, `integration_test.*.example`, `notify_on_failure.sh` | A self-hosted CI runner on a Pi for the privileged integration tests |
| `provision_vault_kv.sh`, [../pi/VAULT_PROVISION.md](VAULT_PROVISION.md) | Optional: deliver the signing key from HashiCorp Vault |
| `install_pi.sh`, `install_idempotent.sh`, `run_manual.sh`, `enforcement_ctl.sh`, `disable_enforcement.sh`, `override.conf*`, `firewall-rollback.env.example` | **Legacy** development installers and helpers from before `sentinelctl`, for a single `sentineledgeai.service`. Do not use them on a device installed with the package |

Useful commands on an installed Pi:

```bash
sentinelctl status                     # versions and services
sudo sentinelctl update                # over-the-air update (verified, health-checked, rolls back on failure)
sudo sentinelctl backup /root/pi.seab  # encrypted backup
sudo journalctl -u 'sentineledgeai-*' -n 100
```
