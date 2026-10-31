# Turning on real enforcement

A new install records what it *would* do (`FIREWALL_DRY_RUN=1`) and responds in `monitor` mode. Turn enforcement on only after a week or more of watching.

## Before

- Run at least 7 days in monitor mode. Label alerts as real or false alarms in the console, which recalibrates the detectors.
- Check the protected hosts (`sudo -u sentinel .venv/bin/python -m enforcement protected`, from `/opt/sentineledgeai/current`). The gateway, DNS, DHCP and the appliance are found automatically; add management PCs and OT engineering stations to `management_hosts` in the policy.
- Keep a way in that doesn't depend on the network: a keyboard and screen, or a serial console.
- For inline placement, have a hardware bypass or a spare cable ready (see `updates.md`).

## Turn it on

```bash
sudo sed -i 's/^FIREWALL_DRY_RUN=.*/FIREWALL_DRY_RUN=0/' /etc/sentinel/sentinel.env
sudo sentinelctl preset office            # or home / ot / enterprise; ot never acts automatically
sudo systemctl restart sentineledgeai-engine sentineledgeai-api
```

By default, actions at risk 75 and above wait for an Operator's approval (**Operations → Response**) for the first 30 days.

## Safety nets that are always on

- **Protected hosts** can never be blocked, contained, quarantined or segmented.
- **TTLs:** every block and restriction expires on its own.
- **Watchdog** (`sentineledgeai-watchdog.timer`, every 20 s): if the engine or API is down for 3 checks while rules are in force, every rule is removed (fail-open), and it's written to the audit log.
- **Rollback guard** (`sentineledgeai-rollback-guard.timer`, every minute): checks the API's health and removes all blocks after repeated failed checks (`scripts/firewall_rollback_guard.sh`, validated by `scripts/validate_rollback_guard.py`).
- **Emergency rollback:** in the console, click the mode badge in the top bar, then **Remove ALL blocks now**; or `POST /api/firewall/rollback`. It takes about 100 ms.

## Turn it off

```bash
sudo sed -i 's/^FIREWALL_DRY_RUN=.*/FIREWALL_DRY_RUN=1/' /etc/sentinel/sentinel.env
sudo systemctl restart sentineledgeai-engine sentineledgeai-api
```

Rules already in force are removed by the emergency rollback; new ones are only recorded.
