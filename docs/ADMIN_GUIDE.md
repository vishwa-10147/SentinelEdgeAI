# SentinelEdgeAI administrator guide

This guide covers installing, configuring and running a SentinelEdgeAI appliance. For day-to-day incident handling see [RUNBOOKS.md](RUNBOOKS.md); for problems see [TROUBLESHOOTING.md](TROUBLESHOOTING.md); every endpoint is listed in [API.md](API.md).

## 1. Install

```bash
curl -fsSLO https://raw.githubusercontent.com/vishwa-10147/SentinelEdgeAI/main/scripts/install.sh
less install.sh
sudo bash install.sh --preset office --signing-key /path/to/model_signing.key
```

The installer downloads the latest release, checks its SHA-256 (and its Sigstore signature when `cosign` is installed), installs a private Python if the package needs a different version than the system's, runs `sentinelctl install` (health-checked) and applies the preset. Air-gapped sites pass `--mirror file:///path` (a directory with `latest.json`, the package and its `.sha256`) or `--package FILE`.

On a Jetson used as the brain, use `deploy/jetson/install_brain.sh` instead.

| Preset | Behaviour |
|---|---|
| `home` | Alerts; every enforcement needs your approval |
| `office` | Graduated automatic response, Operator approval above risk 75 for the first 30 days |
| `ot` | Detect and alert only, never act automatically (availability first) |
| `enterprise` | Faster escalation, approval for 14 days, longer containment |

Change later with `sudo sentinelctl preset <name>`, or edit the policy as YAML (section 6).

## 2. First sign-in

1. `sudo cat /etc/sentinel/initial-admin-password`
2. Open `https://<device>:9000`. The certificate is self-signed: compare the browser's SHA-256 fingerprint with `sentinelctl tls show` before accepting, or import your own certificate (`sudo sentinelctl tls import cert.pem key.pem`).
3. Sign in as `admin`, choose a new password, enrol an authenticator app and store the 10 recovery codes.
4. The setup wizard asks for the network role, placement, capture interface and response mode.
5. `sudo rm /etc/sentinel/initial-admin-password`

## 3. Network placement

* **Passive (recommended first):** connect the capture interface to a switch mirror (SPAN) port. Detection only; blocks apply to traffic to and routed through the appliance.
* **Inline:** the appliance bridges two interfaces (`br0`); blocks and quarantines apply to bridged traffic through a `bridge` nftables table. Use hardware with a bypass relay, or accept that the fail-open watchdog removes all rules if the enforcer dies.
  Step by step for a home or office line (router → appliance → switch): see `updates.md` in the repository.

### Capacity and flood safety

A Pi 5 captures about 120,000 packets/s. Every table the engine keeps has a limit, so a flood of spoofed addresses cannot exhaust its memory. Instead it raises one **capture overloaded** alert and keeps running (RUNBOOKS → "Capture overloaded").

| Setting (`/etc/sentinel/sentinel.env`) | Default | When to change |
|---|---|---|
| `SENTINEL_MAX_FLOWS` | 100,000 active flows (~85 MB) | very busy links that trigger the overload alert without a flood |
| `SENTINEL_MAX_SOURCES` | 20,000 devices per detector | networks with more than 20,000 internal addresses |
| `SENTINEL_MAX_DEVICES` | 20,000 registry rows | the same |

The systemd units also give the engine a lower CPU weight and make it the first process to be killed if memory runs out; systemd restarts it and the watchdog fails open meanwhile. Their `MemoryMax=` limits apply only where the memory cgroup is enabled. Raspberry Pi OS ships with it off: add `cgroup_enable=memory` to `/boot/firmware/cmdline.txt` to enable it.

## 4. Users, MFA and API tokens

* Roles: Viewer (read), Analyst (+ explain and label alerts), Operator (+ block, quarantine, approve playbook actions), Admin (+ policy, users, integrations, setup).
* Operators and Admins must use two-step sign-in. Lost phone: an Admin uses **Reset MFA** in the Users panel.
* Scripts use API tokens (Users panel → API tokens), each with the lowest role it needs and an expiry. The shared `DASHBOARD_API_KEY` in `/etc/sentinel/sentinel.env` is still accepted for health checks; replace it with a scoped token, then remove it (the compliance report flags it).

## 5. Enforcement

The appliance starts in dry run: actions are recorded but not applied. To enforce:

```bash
sudo sed -i 's/^FIREWALL_DRY_RUN=1/FIREWALL_DRY_RUN=0/' /etc/sentinel/sentinel.env
sudo systemctl restart sentineledgeai-engine sentineledgeai-api
```

Safety nets that stay on: protected hosts (gateway, DNS, DHCP, the appliance itself, management hosts) are never blocked; automatic actions need multi-stage confirmation and, during the approval period, an Operator's approval; `sentineledgeai-watchdog.timer` removes all rules if the engine or API stops; **Rollback** in the console (or `POST /api/firewall/rollback`) removes everything in about 100 ms.

## 6. Response policy as code

```bash
cd /opt/sentineledgeai/current
sudo -u sentinel .venv/bin/python -m enforcement policy export > policy.yaml
# edit policy.yaml
sudo -u sentinel .venv/bin/python -m enforcement policy diff policy.yaml    # dry run
sudo -u sentinel .venv/bin/python -m enforcement policy apply policy.yaml
```

Every apply is validated, stored in `data/policy_history/` and written to the audit log. Add administrator workstations and OT controllers to `management_hosts` so they can never be blocked.

### Response tuning

**Operations → Response → Response tuning** shows what the engine has learned: for each kind of incident, how often each response resolved it, meaning the source was not detected again within an hour. In the default **recommend** mode, every playbook decision records what tuning would have chosen, and nothing changes. Switch to **apply** to let it choose a gentler response, within these bounds:

- never stronger than the playbook's step for that risk
- never gentler than `min_action` (default `rate_limit`, so an incident the playbook would act on never gets only an alert)
- after a response fails for a source, its next detection always gets a stronger one
- approvals work as before

```bash
sudo -u sentinel .venv/bin/python -m enforcement tuning status
sudo -u sentinel .venv/bin/python -m enforcement tuning set --mode apply --min-action rate_limit
```

### Device trust and containment

**Trust** in the console (or `GET /api/trust`) lists every device with a score from 0 to 100, least trusted first, and the reasons behind it:

- **Identity:** known MAC, vendor (not for randomised MACs) and hostname raise the score, and no MAC at all lowers it.
- **Tenure:** days seen add to it, up to 10 days.
- **Alerts:** each *kind* of alert in the last 7 days lowers it once, at its strongest, weighted by risk and halved every 24 h. Repeats of the same kind don't stack, and kinds you marked as false positives for that device don't count.
- **Restrictions:** quarantined or blocked devices score 0, and contained devices at most 30.

At 70 or more a device is *trusted*, at 40 or more *watch*, below that *untrusted*.

For an untrusted device that has a 7-day peer profile, the recommendation is **contain**. It keeps the peers and ports it normally uses, plus DNS and DHCP, and loses everything else. That is much less disruptive than quarantine for printers, cameras and other devices people depend on. Containment has a TTL (one hour from the console), is refused for protected hosts, and is cleared by any rollback. Without a profile, quarantine is the fallback.

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://<pi>:9000/api/devices/192.168.1.50/peers   # what containment would keep
```

### OT micro-segmentation

On industrial networks the engine learns, for 7 days per controller, which hosts command each Modbus, DNP3, BACnet or OPC UA device (**OT devices** in the console, `GET /api/ot/assets`). That learning can become an allow-list:

- `monitor` (start here): shows the plan, meaning each learned controller and the hosts allowed to reach its industrial ports. A new host commanding a controller is already alerted (`ot_new_master`).
- `enforce` (Admin, inline placement only): installs nftables rules so only the allowed hosts can open connections to those ports. Replies and other ports are untouched. Management hosts and the whitelist are always allowed, and protected hosts (gateway, DNS, DHCP, the appliance) are never guarded.
- The enforced plan is a snapshot. A host learned afterwards is **not** allowed until you add an exception or take a new snapshot.
- An operator rollback or the watchdog's fail-open turns segmentation **off**, and it stays off until someone turns it on again.

Change modes, add exceptions and take snapshots from **OT devices** in the console (or `POST /api/ot/segmentation*`). The API service holds the firewall capability. The CLI is useful to inspect the plan:

```bash
cd /opt/sentineledgeai/current
sudo -u sentinel .venv/bin/python -m enforcement segment status
```

Every change is in the audit log. The real-kernel test is `sudo bash tests/firewall_netns/run_segmentation_netns.sh`.

## 7. Two-node mode (Pi sensor + brain)

1. On the brain: choose the **Brain** role in Setup (sensors connect to port 9443).
2. Console → `POST /api/brain/codes` (or `python -m brain code --brain-url https://<brain>:9443`) gives a one-time code, the CA fingerprint and the command to run on the sensor.
3. On the sensor: run that `python -m sensor enroll ...` command (or `POST /api/sensor/enroll`). The sensor link service starts by itself.

Sensors buffer flows on disk while the brain is unreachable and replay them afterwards; they never block on their own in that state. Revoke a sensor with `python -m brain revoke <id>`.

### Upgrading sensors through the brain

Sensors often have no internet access. Stage a release on the brain and every sensor picks it up within 15 minutes:

```bash
cd /opt/sentineledgeai/current
sudo -u sentinel .venv/bin/python -m brain upgrade stage --version 2.5.0   # downloads + checks the SHA-256
sudo -u sentinel .venv/bin/python -m brain upgrade status                  # staged release and each sensor's version
```

Each sensor downloads the package over its mutual-TLS link and checks it against the SHA-256 the brain announced. The root `sentineledgeai-fleet-update.timer` then installs it: hourly, with the usual health check and automatic rollback. With no internet on the brain either, use `--file sentineledgeai-pi-X.Y.Z.tar.gz`, with its `.sha256` next to it.

### Brain database

The brain keeps sensors, flows and commands in SQLite. For brains with many sensors, set `SENTINEL_BRAIN_DATABASE_URL=postgresql://user:pass@host/db` in `/etc/sentinel/sentinel.env`, or `DATABASE_URL`, which the engine also uses.

### High availability: a standby brain and dual sensors

**Two brains.** Both brains use the same PostgreSQL (`SENTINEL_BRAIN_DATABASE_URL` in `/etc/sentinel/sentinel.env` on both), and share their key material:

```bash
# on the active brain
sudo -u sentinel .venv/bin/python -m brain ha export /root/brain-pair.seha     # asks for a passphrase
# copy the file to the second device (it is encrypted), then on it:
sudo -u sentinel .venv/bin/python -m brain ha import /root/brain-pair.seha     # choose the Brain role in Setup first
# on every sensor
sudo -u sentinel .venv/bin/python -m sensor add-brain https://brain-b.local:9443
```

Both brains accept flows and command polls, and sensors switch to the other brain on their own when one is unreachable. Because the state is shared, nothing is lost. Only the **active** brain issues new commands: it holds a lease in the database, renewed every 10 s, and the standby takes over within 30 s of the active brain stopping. `python -m brain ha status` (or `GET /api/brain/ha`) shows which brain is active. The PostgreSQL itself should be replicated by your usual means. That is outside SentinelEdgeAI.

**Dual sensors.** Put two sensors that watch the same segment in one segment: `python -m brain segment <sensor-id> floor-2`. A command sent to the segment (`POST /api/brain/segments/floor-2/commands`) goes to whichever of them was heard from most recently. **Bypass:** for inline sensors, use a bypass NIC or switch, so traffic keeps flowing if the sensor loses power. In software, the fail-open watchdog already removes every rule when the engine stops.

## 7a. Fleet manager (many sites, one console)

Any appliance can also be the **fleet server**. Sites report to it over mutual TLS (port 9444, its own CA), and it gives each group of sites a configuration template and a target version.

On the fleet server:

```bash
cd /opt/sentineledgeai/current
sudo -u sentinel .venv/bin/python -m fleet init                  # keys; sentineledgeai-fleet.path starts the service
sudo -u sentinel .venv/bin/python -m fleet code --group default  # one-time code (1 hour) + the command for the site
```

On each site, run the printed command:

```bash
sudo -u sentinel .venv/bin/python -m fleet enroll https://<fleet>:9444 <CODE> <CA-FINGERPRINT>
```

The site pins the fleet CA by fingerprint, and its private key never leaves it. From then on it reports every 5 minutes: version, health, alerts by severity, trust levels, restrictions, OT and segmentation state. Flows and packet data are never sent.

Everything else happens in **Fleet** in the console (or `/api/fleet/*`, or `python -m fleet ...`):

- **Templates:** a response policy (YAML, or one of the presets), validated before it is stored and again on every site before it is applied.
- **Groups:** a template and a target version per group. A new target version rolls out in stages. By default that's 10% of sites at once, 50% after 24 h and 100% after 48 h. The same sites are always the canaries.
- **Rollouts:** sites record the target version, and a root timer (`sentineledgeai-fleet-update.timer`, hourly) installs it with `sentinelctl fleet-update`. That's the normal verified, health-checked update with automatic rollback. A site whose update fails pauses its group's rollout until an Admin resumes it. Downgrades are refused.

`sentinelctl update --to X.Y.Z` installs a specific release by hand.

**Federated learning.** Start a round from **Fleet** (or `python -m fleet federated start --min-sites 3`). On their next report, sites that have at least 500 normal flows sampled train the flow autoencoder locally and send back model parameters only. When enough sites have answered, the fleet server combines the updates. Every site then installs the result as a **shadow** model with its threshold calibrated on its own traffic. Compare it in **Operations → Models & evaluation**, and promote it to canary and then active when it looks right. Each round starts from the previous global model.

## 7b. Compliance evidence

**Operations → Compliance** (Admin) reports what this appliance can show for **ISO/IEC 27001:2022** (Annex A), **IEC 62443-3-3** and **NIS2** (Art. 21(2) and 23). The evidence is read live, so fix a gap and refresh. Each control is *met*, *partial*, *gap* (with how to close it), *manual* (organisational, e.g. training or physical security: evidence comes from elsewhere) or *n/a*. Download the PDF for your auditor, or run:

```bash
sudo -u sentinel .venv/bin/python -m compliance report nis2 --pdf /tmp/nis2-evidence.pdf
```

This is documentation support for an audit, not a certification or an audit opinion.

## 8. Integrations and threat intelligence

* SIEM and notifications: `PUT /api/integrations` with sinks of type `syslog` (RFC 5424 or CEF, UDP/TCP/TLS), `webhook` (HMAC-signed), `jsonl`, `slack`, `teams` or `email`; `POST /api/integrations/test` sends a test alert.
* Threat intelligence: `python -m intel add-feed <name> <https url> --format plain|stix|taxii`, updated daily; or import a file with `python -m intel import`.
* Suricata on the sensor: SentinelEdgeAI follows `/var/log/suricata/eve.json` automatically.
* Monitoring: scrape the engine on `:9101` and the API's `/metrics` (HTTPS, Viewer token); import `deploy/grafana/dashboards/sentinel_operations.json` and `deploy/monitoring/sentinel_alerts.yml`.

## 9. Backups and updates

```bash
sudo sentinelctl backup /root/sentinel-$(date +%F).seab      # asks for a passphrase (12+ characters)
sudo sentinelctl restore /root/sentinel-2026-10-31.seab        # on a fresh device, install first
sudo sentinelctl update --check && sudo sentinelctl update     # verified, health-checked, auto-rollback
sudo sentinelctl rollback                                      # back to the previous version
```

Store backups off the device: they contain the signing keys and the user database (encrypted).

## 10. Hardening the operating system

`sudo bash /opt/sentineledgeai/current/deploy/pi/harden_os.sh` shows the changes; add `--apply` to make them: SSH keys only (refused until a regular user has a key), the management ports restricted to `MGMT_NETS`, automatic security updates and capped logs. Disk encryption and a read-only root are described in the script's output.
