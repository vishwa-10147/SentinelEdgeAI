# Operator runbooks

Short, tested procedures for the situations an operator meets. Commands assume a shell on the appliance; `S=/opt/sentineledgeai/current` and `py="sudo -u sentinel $S/.venv/bin/python"` (run from `$S`).

## Triage a new alert

1. Open the alert: read **explanation** (evidence and the features furthest from normal), **confidence** and **confirmed**.
2. Look at the source's history: console device panel, or `GET /api/devices/<ip>/history` (CSV).
3. Check the identity: `$py -m enforcement devices` (MAC, vendor, DHCP hostname).
4. Decide:
   * Real and active → contain (next section).
   * False positive → label it (`POST /api/alerts/feedback` with `label: fp`). Repeated false positives for a detector lower its confidence, so it stops triggering automatic action.
   * Expected behaviour of a known host → add it to `whitelist` or `management_hosts` in the policy.

## Contain a device

| Goal | Console / API | CLI |
|---|---|---|
| Slow it down | `POST /api/firewall/ratelimit` | `$py -m enforcement ratelimit <ip> --ttl 600` |
| Cut it off | `POST /api/firewall/block` | — |
| Quarantine (DNS/DHCP and the notice page only) | `POST /api/firewall/quarantine` | `$py -m enforcement quarantine <ip> --ttl 3600` |
| Approve a waiting playbook action | `POST /api/playbook/pending/<id>/approve` | `$py -m enforcement approve <id>` |

Protected hosts are refused with a reason (e.g. `gateway`) — this is intended.

## Undo containment

* One device: `POST /api/firewall/unblock`, or `POST /api/firewall/release` with `kind: quarantine|ratelimit`.
* Everything, immediately: **Rollback** (`POST /api/firewall/rollback`). Measured at ~100 ms.

## The network seems broken after enabling enforcement

1. Roll back everything (above). If the console is unreachable: `sudo nft delete table inet sentinel; sudo nft delete table bridge sentinel`.
2. Find the cause in the audit log: `$py -m core.audit tail -n 50` (every block and its actor).
3. Add the affected host to `management_hosts`, re-apply the policy, re-enable.

## The engine or API is down

* `sentinelctl status`, then `sudo journalctl -u sentineledgeai-engine -u sentineledgeai-api -n 100`.
* While down for a minute, the watchdog removes all rules (fail-open); look for `watchdog_failopen` in the audit log.
* `sudo sentinelctl rollback` returns to the previous version if a new one misbehaves.

## The brain is unreachable (two-node mode)

* Sensors keep detecting and buffer flows; check `sudo -u sentinel $S/.venv/bin/python -m sensor status` (buffered, dropped).
* When the brain is back the buffer replays automatically; nothing to do.
* If `dropped` grows, the outage exceeded the buffer (2 million flows by default).

## Audit log integrity alarm

`$py -m core.audit verify` reports the first entry that was changed or removed.
1. Preserve evidence: copy `/var/lib/sentinel/data/audit.db` and the journal (`journalctl -u sentineledgeai-api -u sentineledgeai-engine | grep 'audit '`), which has an independent copy of every entry with its hash.
2. Treat the appliance as possibly compromised: rotate passwords and API tokens, check `/etc/sentinel` and the SSH keys, restore from a known-good backup if needed.

## Certificate expiring

`sentinelctl tls show` prints the expiry. Self-signed: `sudo sentinelctl tls renew` (tell users the new fingerprint). Your CA: `sudo sentinelctl tls import cert.pem key.pem`.

## Restore onto replacement hardware

1. Install the same or a newer version (`install.sh`).
2. `sudo sentinelctl restore /path/to/backup.seab` (verifies the passphrase and every checksum first, stops services, restores, restarts with a health check).
3. Re-enrol sensors only if the brain's keys were not in the backup (they are by default).
