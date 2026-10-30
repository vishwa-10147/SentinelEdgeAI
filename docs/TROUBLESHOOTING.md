# Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| Install fails with `dpkg was interrupted` | the system package manager | `sudo dpkg --configure -a`, then run the installer again |
| `sentinelctl install` says `health check failed` and rolls back | `journalctl -u sentineledgeai-engine -u sentineledgeai-api -n 100` | fix the error shown; a service that restarts in a loop also fails the check |
| `model signature verification failed` in the engine log | `/etc/sentinel/model_signing.key` | install the key that signed the release (`deploy/pi/provision_key.sh`) |
| Browser: certificate warning | `sentinelctl tls show` | compare the fingerprint and accept, or `sentinelctl tls import` your own |
| API refuses to start: `set both SENTINEL_TLS_CERT and SENTINEL_TLS_KEY` | `/etc/sentinel/sentinel.env` | set both or neither |
| `429 rate limit exceeded` | many clients behind one proxy share a limit | raise `SENTINEL_RATE_LIMIT_READ` / `_WRITE` |
| Console shows no traffic | `curl -s localhost:9101/metrics \| grep flows_processed` | wrong capture interface → Setup; no mirror port traffic → check the switch |
| Engine metrics port in use | `ss -ltnp \| grep 9101` | set `app__metrics_port` in `sentinel.env` |
| `refusing to block protected host` | `python -m enforcement protected` | intended; use another response or remove it from `management_hosts` |
| Blocks have no effect | `FIREWALL_DRY_RUN` in `sentinel.env`; `sudo nft list table inet sentinel` | set `FIREWALL_DRY_RUN=0` and restart; inline placement also needs the bridge table |
| Watchdog removed all rules | `python -m core.audit tail` (`watchdog_failopen`) | the engine or API stopped; find out why in the journal |
| Sensor `buffered` keeps growing | `python -m sensor status`, `journalctl -u sentineledgeai-sensor` | brain unreachable or revoked; check port 9443 and `python -m brain sensors` |
| Enrolment: `CA fingerprint does not match` | the fingerprint shown with the code | possible interception — do not enrol; check the network path |
| No alerts in the SIEM | `GET /api/integrations` (status), `POST /api/integrations/test` | wrong host/port, TLS CA, or the sink's `min_severity` |
| Report PDF empty | `alerts.json` has alerts in the period? | widen to `weekly`; check the engine is detecting |
| Audit `BROKEN at entry N` | see RUNBOOKS → audit log integrity | |

Useful commands:

```bash
sentinelctl status                         # versions and services
sentinelctl tls show                       # certificate and fingerprint
sudo journalctl -u 'sentineledgeai-*' -n 200
cd /opt/sentineledgeai/current
sudo -u sentinel .venv/bin/python -m core.audit verify
sudo -u sentinel .venv/bin/python -m enforcement protected
sudo -u sentinel .venv/bin/python -m detection.registry list
```
