# SentinelEdgeAI — Product Plan and Roadmap

This is the single source of truth for what we are building, in what order, and how we know each step is done. It replaces the older upgrade prompt and build plan, now in `docs/archive/`.

---

## 1. Product vision

**SentinelEdgeAI is an offline network detection and response (NDR) appliance with an adaptive firewall.** It learns the normal behaviour of every device on a network, detects attacks and compromised devices in real time with explainable AI, and responds automatically and safely. It gives small organisations, OT/IoT sites and multi-branch operators enterprise-grade protection without a SOC, a cloud subscription, or sending data off-site.

### Design principles
1. **Never be the outage.** Fail open, dry-run first, every action reversible, every block expires unless made permanent.
2. **Offline by default.** All AI, storage and management run on-premises; any cloud feature is opt-in.
3. **Explainable decisions.** Every alert says *why* (which features, which baseline, which detector, MITRE mapping) and how confident the system is.
4. **Least privilege everywhere.** The sensor only senses and enforces; the brain decides; humans approve high-impact actions until trust is earned.
5. **Measured, not claimed.** Detection quality, latency and throughput are benchmarked and published per release.
6. **Secure supply chain.** Signed models, signed releases, SBOMs, reproducible builds.

### Positioning
| Option | What it is | Where SentinelEdgeAI differs |
|---|---|---|
| Suricata / Snort / Zeek on pfSense/OPNsense | Signature IDS/IPS, expert-operated | Behavioural AI per device; explanations; automated safe response; turnkey appliance |
| Consumer boxes (e.g. Firewalla) | Home/SOHO firewall with alerts | Deeper ML, OT/IoT focus, multi-sensor, SIEM integration, open architecture |
| Enterprise NDR (e.g. Darktrace, Vectra) | Cloud-connected, enterprise-priced | Offline, ~USD 350 hardware, built for sites with no security staff |

---

## 2. Target architecture (v2.0)

```text
           Pi 5 "Sensor" (one per network segment)            Jetson Orin Nano "Brain"
  ┌───────────────────────────────────────────┐        ┌────────────────────────────────────────┐
  │ sentinel-sensor                           │        │ sentinel-brain                         │
  │  capture (AF_PACKET) → flow table          │  mTLS  │  ingest (gRPC) → feature store         │
  │  → features → local fast-path detector    │ ─────► │  → detectors (CPU + GPU/TensorRT)      │
  │  → disk buffer (when brain unreachable)   │        │  → risk fusion + confidence            │
  │                                           │        │  → policy engine → response playbooks  │
  │ sentinel-enforcer                         │ ◄───── │  signed commands (block/quarantine/…)  │
  │  nftables (inet + bridge), TTL, rollback   │        │                                        │
  │  fail-open bypass, local whitelist        │        │  PostgreSQL · model registry           │
  └───────────────────────────────────────────┘        │  API (FastAPI) · console (React, HTTPS) │
                                                       │  users/RBAC/MFA · audit log · SIEM out  │
                                                       └────────────────────────────────────────┘
```

**Contracts between components**
* **Sensor → Brain:** batches of flow-feature records and sensor health, protobuf over gRPC, mutual TLS with per-sensor certificates issued at enrolment.
* **Brain → Sensor:** response commands (`block`, `unblock`, `quarantine`, `rate_limit`, `rollback`), each signed by the brain, with a sequence number and expiry to stop replays. The enforcer re-checks its local whitelist before acting.
* **Degraded mode:** if the brain is unreachable, the sensor keeps its local Z-score detector running, buffers up to N hours to disk, raises a local alert, and **never** auto-blocks on its own unless an admin enabled that.

**Detection stack on the brain**
| Layer | Model | Hardware |
|---|---|---|
| Statistical | Adaptive per-device, per-protocol Z-score baselines | CPU |
| Unsupervised ML | Isolation Forest | CPU |
| Deep anomaly | Autoencoder on flow features (reconstruction error) | GPU (TensorRT) |
| Sequence | Temporal model over a device's flow sequence → multi-stage attacks (recon → exploit → exfiltration) | GPU |
| Graph | Device-to-device communication graph → lateral movement, new peers | GPU |
| Rules & intel | Detectors for scans, brute force, DNS tunnelling and beaconing; offline threat-intel blocklists; optional Suricata alerts as input | CPU |
| Fusion | Weighted, calibrated combination → risk 0–100 + confidence 0–1 + explanation | CPU |

---

## 3. Release plan

| Release | Theme | Phases |
|---|---|---|
| **v1.1** | Correctness, hygiene, release pipeline | 0 |
| **v1.2** | Secure management plane | 1 |
| **v1.3** | Two-node architecture | 2 |
| **v1.4** | Enforcement you can trust | 3 |
| **v1.5** | Detection quality | 4 |
| **v1.6** | Integrations and operations | 5 |
| **v2.0** | Production release | 6 |
| **v2.x+** | Scale and advanced intelligence | 7 |

Each phase ends with a working, tested, merged build. The **exit criteria** must all be met before the phase is called done.

Version numbers continue from the first prototype release, `v1.0.0` (February 2026). Releases follow Semantic Versioning and are published by pushing a `vX.Y.Z` tag that matches the `VERSION` file (see `.github/workflows/release.yml`).

---

## Phase 0 — Correctness and hygiene (v1.1)

**Goal:** fix what is broken or unsafe in the current code before building on it.

- [x] Remove stray files and tracked runtime data, compiled files, the signing key and the credentials file; clean `.gitignore`.
- [x] Rewrite documentation (README, SECURITY, PLAN, EXPLAIN).
- [x] **Rotate the model signing key:** new key, model re-signed, GitHub secret updated (2026-10-30). Remaining per device: install the new key and change the old health-check credentials (SECURITY.md §4).
- [x] **Fix firewall command execution:** `_run_cmd` now runs only allowlisted `nft`/`iptables` binaries directly (the generic subprocess wrapper rejected them, so nothing was ever applied).
- [x] **Fix the nftables backend:** `input` and `forward` chains in `inet sentinel` drop traffic matching `@blacklist`; created idempotently.
- [x] **Fix iptables removal** so it matches the inserted rule (including the comment); cover `INPUT` and `FORWARD`; no duplicate rules on re-block.
- [x] Rollback flushes every SentinelEdgeAI kernel rule, including ones missing from the state file.
- [x] Container integration test checks the kernel ruleset after block, unblock and rollback.
- [x] IPv6 blocking: `blacklist6` (`ipv6_addr`) set and `ip6` rules in nftables, `ip6tables` for the iptables backend; existing v1.1.0 rulesets are upgraded in place.
- [x] Split dependencies: `requirements.txt` (runtime), `requirements-dev.txt` (pytest, bandit, pip-audit), `requirements-streamlit.txt` (legacy dashboard); upgrade `uvicorn` 0.23 → 0.54.
- [x] Pi package is built from `git archive HEAD` (no untracked secrets), includes the built web console, refuses secret-like files, and ships a SHA-256 checksum.
- [x] Package installer no longer deletes the device's database, firewall state or keys on upgrade.
- [x] **Release pipeline:** a `vX.Y.Z` tag runs tests, the model-signature check and a dependency audit, then publishes the Pi package with an offline wheelhouse, checksum, SBOM and build-provenance attestation.
- [x] **Device lifecycle:** `sentinelctl install | upgrade | rollback | status` with versioned releases under `/opt/sentineledgeai/releases`, config in `/etc/sentinel`, state in `/var/lib/sentinel`, automatic rollback when the new version fails its health check, and hardened systemd units running as an unprivileged `sentinel` user.
- [x] Licence: Apache-2.0 (`LICENSE`, `NOTICE`).
- [x] Delete the empty stubs `flow/timeout_manager.py` and `utils/config.py`.
- [x] Move superseded docs (`README_LOCAL.md`, `README_DEPLOY.md`, `BUILD_SUMMARY.md`, `SECURITY_AUDIT.md`, `docs/BUILD_PLAN.md`, `notes.txt`) to `docs/archive/`.

**Exit criteria:** a block issued with `FIREWALL_DRY_RUN=0` drops packets and unblock restores them, on both nft and iptables, proven in CI (the container test now checks this; it must pass on the privileged runner); no secrets in the tree; all tests green.

---

## Phase 1 — Secure management plane (v1.2)

**Goal:** the console and API are safe to expose on a management network.

- [x] Users table (Argon2id hashes), login and logout, short-lived access token plus rotating refresh token in an HttpOnly cookie; console sign-in, forced first-login password change, admin Users panel; `python -m core.auth` CLI; `sentinelctl` creates the first admin.
- [x] Roles: Viewer, Analyst, Operator, Admin; enforced on every endpoint (with tests) and reflected in the UI.
- [x] Account lockout and rate limiting on login.
- [x] WebSocket stream requires authentication (token in the first message).
- [x] CORS locked to configured origins (`SENTINEL_CORS_ORIGINS`); the console calls its own origin in production.
- [x] TOTP two-step sign-in, required for Operator and Admin (`SENTINEL_MFA_ROLES`), with QR enrolment, replay protection, 10 single-use recovery codes and admin reset.
- [x] General API rate limits: 600 reads and 60 writes per client per minute on `/api/*`, configurable, `429` with `Retry-After`.
- [x] API tokens (scoped, expiring) for automation: role capped at the owner's, 1–365 day expiry, hashed at rest, Users panel + API + CLI. The shared key remains for health checks until it is retired.
- [x] HTTPS by default: certificate generated at install, with the option to import an organisation's own certificate; HSTS; secure WebSocket (WSS).
- [x] Security headers: CSP, X-Frame-Options, Referrer-Policy (plus nosniff, Permissions-Policy, COOP); HSTS follows with HTTPS.
- [x] Hash-chained audit log of every login, policy change and response action, viewable by Admins (console panel with integrity check, API, CLI; copy in the system journal).
- [x] First-run setup wizard: set the network role, choose passive or inline mode (plus capture interface and response mode; the engine follows the chosen interface).

**Exit criteria:** every endpoint has a role test; no unauthenticated endpoint except `/healthz`; OWASP ZAP baseline scan clean; login brute force is throttled.

**Status (2026-10-30): met.**
- Every endpoint has a role test: `tests/test_endpoint_roles.py` lists all 44 routes with their minimum role, fails when a route is added without one, and checks the guard wired to each route, 401 for anonymous callers, 403 for the role below the minimum, and access for the minimum role on reads.
- Unauthenticated endpoints: only what sign-in itself needs (`/api/auth/status`, `/login`, `/refresh` with its cookie and CSRF header, `/logout` with its CSRF header) and the console's static files. There is no separate `/healthz`; health is `/api/health` (Viewer).
- OWASP ZAP baseline against the installed console over HTTPS: 0 FAIL, 0 WARN, 66 PASS (`scripts/zap_baseline.sh`; two informational rules ignored with reasons in `security/zap-baseline.conf`).
- Login brute force: 10 attempts per client per 5 minutes and a 15-minute lockout after 5 wrong passwords (`tests/test_auth.py`), plus general API rate limits.

---

## Phase 2 — Two-node architecture (v1.3)

**Goal:** the Pi senses and enforces; the Jetson does all AI work and management.

- Split the codebase into `sensor/`, `brain/` and `common/` packages, each with its own systemd service and installer.
- gRPC protobuf schema for flow batches, health and commands; mTLS with a small built-in certificate authority on the brain; sensor enrolment with a one-time code.
- Command signing (Ed25519) with sequence numbers and expiry; the enforcer verifies commands and re-checks its local whitelist.
- Sensor disk buffer and replay after reconnect; degraded mode with the local detector.
- Event bus inside the brain replacing file polling; WebSocket heartbeat, reconnect with resync cursor, server-side throttling.
- Move storage to PostgreSQL on the Jetson; keep SQLite for the Lite profile.
- Jetson installer (JetPack 6.x) and Pi installer; "Lite" profile keeps everything on one Pi. JetPack 6 ships Python 3.10 while the runtime needs ≥ 3.11 (numpy 2.4), so the brain package must bring its own interpreter (e.g. a `uv`-managed CPython 3.11) or run in an L4T container.
- `sentinelctl` gains a `brain` package type; the brain distributes sensor upgrades to its Pis.

**Exit criteria:** unplugging the Jetson for an hour loses no flow data and causes no network impact; a forged or replayed command is rejected; one Jetson handles 3 sensors at the target load.

**Status (2026-10-31): built and tested in simulation; hardware validation pending.**
- [x] `common/`, `brain/`, `sensor/` packages with their own systemd services (`sentineledgeai-brain`, `sentineledgeai-sensor`), started by `.path` units once the device has the role.
- [x] Link protocol: JSON over mutual-TLS HTTPS instead of gRPC/protobuf (same authentication and integrity, no code-generation toolchain). Built-in CA (EC P-256) on the brain; one-time enrolment codes; the sensor pins the brain CA by fingerprint; the sensor id is the certificate CN chosen by the brain; revocation is immediate (fingerprint check).
- [x] Ed25519-signed commands with per-sensor sequence numbers (persisted on the sensor) and 5-minute expiry; the enforcer re-checks the local whitelist.
- [x] Sensor disk buffer (SQLite WAL, 2 M records) with acknowledged delivery and replay; degraded mode keeps local detection and never auto-blocks on its own.
- [x] Lite profile unchanged (Standalone role); Sensor and Brain roles in the setup wizard and console API (`/api/brain/*`, `/api/sensor/*`).
- [x] Jetson installer (`deploy/jetson/install_brain.sh`): private uv-managed CPython 3.11, offline wheels; `sentinelctl` takes the interpreter from `/etc/sentinel/python`. **Not yet run on a Jetson.**
- [x] Event bus (`core/events.py`) replacing per-connection file and table polling: one poller reads alerts and live events by row id (nothing skipped or repeated within a second; fixes live events stopping after the first 200), numbered events in a ring buffer, WebSocket resume from a cursor, `resync` after an API restart or when too far behind, heartbeats every 15 s, stalled clients dropped instead of slowing others; the console resumes and reloads on resync.
- [x] PostgreSQL for the brain store (`SENTINEL_BRAIN_DATABASE_URL`, or `DATABASE_URL` like the engine); same tests on SQLite and on a real PostgreSQL 16, and the full sensor ↔ brain mutual-TLS suite passes with the brain on PostgreSQL.
- [x] Brain distributes sensor upgrades: `python -m brain upgrade stage --version X|--file`, `POST /api/brain/upgrade`; sensors fetch the package over the mutual-TLS link, verify the announced SHA-256, stage it, and the root `sentineledgeai-fleet-update.timer` installs it (health check, automatic rollback). Sensors report their version.
- [x] Console panel for sensors (**Operations → Sensors**).

Exit criteria evidence so far:
- Outage: `tests/test_brain_link.py` stops the brain while 1,500 flows queue and gets all 1,600 back in order with no duplicates; on the Pi (brain and sensor on one device) a 2-minute brain outage buffered 103 real flows, replayed them and stored 0 duplicates. **The one-hour Jetson unplug is pending hardware.**
- Forged and replayed commands: rejected in unit tests and over the live link (also after a sensor restart).
- 3 sensors: 9,000 flows from 3 concurrent sensors stored correctly on the Pi (~26,000 flows/s). **Target load on a Jetson pending hardware.**

---

## Phase 3 — Enforcement you can trust (v1.4)

**Goal:** blocking and quarantine are safe, precise and reversible in inline mode.

- Inline bridge mode (`br0` over WAN and LAN NICs) with nftables `bridge` and `inet` families; documented hardware bypass options; software watchdog that flushes rules if the enforcer dies.
- MAC-based device identity (DHCP and ARP observation, DHCP option fingerprints, OUI vendor lookup) so devices keep identity when IPs change.
- Quarantine: allow a device to reach only DNS, DHCP and a captive "quarantined" page; optional VLAN reassignment through managed-switch APIs later.
- Graduated playbooks: `alert → rate-limit → block (TTL) → quarantine`; per-severity approval gates ("require Operator approval above risk 75 for the first 30 days").
- Automatic protection of the gateway, DNS, DHCP, management hosts and the appliance itself; conflict and duplicate rule detection.
- Policy-as-code: response policy in versioned YAML with validation and a dry-run diff before apply.

**Exit criteria:** a 72-hour inline soak with enforcement enabled causes zero unintended blocks of protected hosts; every action rolls back in under 2 seconds; a killed enforcer leaves traffic flowing.

**Status (2026-10-31): built and verified on the real kernel in network namespaces; inline soak pending hardware.**
- [x] Inline bridge mode: a `bridge sentinel` table mirrors blocks and quarantines when placement is inline (`SENTINEL_BRIDGE`); `inet` rules keep covering traffic to and routed through the device. Bypass hardware is documented as a deployment choice; the software side is the fail-open watchdog.
- [x] Watchdog (`sentineledgeai-watchdog.timer`, every 20 s): if the engine or API is down for 3 checks while anything is enforced, all rules are removed and the event is audited.
- [x] MAC identity (`enforcement/identity.py`): ARP table, ARP and DHCP packets; IEEE OUI vendor, DHCP hostname, option-55 fingerprint, vendor class, IP history.
- [x] Quarantine: only DNS, DHCP, the console port (a public `/quarantined` page) and replies to existing connections; matched by IP, and by MAC on the bridge.
- [x] Graduated playbook alert → rate-limit → block → quarantine, escalation for repeat sources, Operator approval gate above a risk threshold for a period (default: risk ≥ 75); `/api/playbook/pending` + approve/deny.
- [x] Protected hosts found automatically (gateway, DNS, DHCP, the appliance's own addresses, loopback) plus management hosts and the whitelist; every block, quarantine and rate limit refuses them.
- [x] Policy as code (`python -m enforcement policy export|validate|diff|apply`, `/api/policy`): versioned YAML, validation with conflict and duplicate warnings, dry-run diff, history in `data/policy_history/`, audited.
- [ ] Optional VLAN reassignment through managed-switch APIs (later, as planned).
- [x] Console panels for restrictions, approvals and policy editing with a checked diff before apply (**Operations → Response / Policy**).

Exit criteria evidence so far (`sudo bash tests/firewall_netns/run_enforcement_netns.sh`, 22 checks, real nftables): block, quarantine and rate limit behave as specified on live traffic, routed and bridged; rollback took ~100 ms; the appliance refuses to block itself; rollback leaves no rules. Fail-open: the watchdog removes all rules when the enforcer is down (unit-tested). **The 72-hour inline soak with two NICs is pending hardware.**

---

## Phase 4 — Detection quality (v1.5)

**Goal:** catch more real attacks with fewer false alarms, and prove it with numbers.

- Per-protocol baselines and thresholds (DNS, TCP, UDP, HTTP/TLS) and time-of-day seasonality.
- Detectors: port and host scans (distinct ports and hosts per window), brute force (repeated short failed sessions), DNS tunnelling and DGA (query length, entropy, NXDOMAIN rate), beaconing (periodic connections), exfiltration (byte asymmetry plus new destination), new or rogue device.
- TLS metadata: JA3/JA4 client fingerprints, SNI, certificate anomalies — no decryption.
- GPU models on the Jetson: autoencoder (first), sequence model, graph model; exported to ONNX/TensorRT.
- Risk fusion with calibrated confidence; multi-stage confirmation before auto-block; per-alert explanation (top contributing features vs baseline).
- Model registry: versioned, Ed25519-signed models; shadow mode (score without acting) → canary → promote; hot reload without restart; one-click rollback.
- Feedback loop: analysts mark alerts true or false positive; offline retraining uses the feedback.
- Evaluation harness: replay labelled datasets (CIC-IDS2017, UNSW-NB15, CIC-IoT2023) plus our own captured lab attacks; publish precision, recall, false-positive rate and latency per release; compare against a Suricata baseline.

**Exit criteria (targets, measured on the evaluation set):** ≥ 90% detection on the covered attack classes, ≤ 1% false-positive rate on benign traffic after the warm-up period, and end-to-end decision latency under 1 second at the target flow rate.

**Status (2026-10-31): detectors, fusion, registry, feedback and evaluation harness built; real-dataset and GPU work pending.**
- [x] Detectors (`detection/detectors.py`, `dns_analysis.py`, `tls.py`): port scan, internal host sweep, brute force, beaconing (NTP exempt), exfiltration to new destinations, new device, DNS tunnelling, DGA, JA3/JA4 + SNI (blocklist, missing SNI, new client fingerprint). No decryption.
- [x] Per-protocol, hour-of-day baselines (`detection/fusion.py`) used for explanations.
- [x] Fusion with calibrated confidence; automatic response only when confirmed (≥ 0.8 confidence and two independent signals, a repeated finding, or one finding with ≥ 0.9 precision); every alert carries its evidence and the features furthest from baseline.
- [x] Model registry (`detection/registry.py`): Ed25519-signed, hash-pinned versions; shadow → canary (share of sources) → active; hot reload; rollback; refuses tampered models.
- [x] Autoencoder (`detection/autoencoder.py`) on CPU as the first registered model.
- [x] Feedback loop: `/api/alerts/feedback` (Analyst); labels recalibrate each detector's precision, which drives confirmation.
- [x] Evaluation harness (`python -m evaluation.harness`, `--cicids file.csv`), reports in `reports/eval/`.
- [ ] GPU models on the Jetson (TensorRT autoencoder, sequence and graph models) — pending hardware.
- [ ] Evaluation on CIC-IDS2017 / UNSW-NB15 / CIC-IoT2023 and captured lab attacks; Suricata comparison — the loader exists, datasets not yet run.
- [x] Console views for analyst feedback, the model registry (promote, roll back) and the latest evaluation (**Operations → Models & evaluation**).

Evidence on the labelled synthetic set (7 attack classes × 6 instances, 25 hosts, realistic false-positive bait such as NTP, backups, CDN browsing, management polling; 5 seeds and a 24-hour run): **100% detection, 0.0% false positives, p99 0.15 ms per event**. The harness was checked by an over-sensitive configuration, which it correctly scores at 1.4% false positives. These are upper-bound numbers on synthetic data; **the targets count as met only after the public datasets and lab captures.**

---

## Phase 5 — Integrations and operations (v1.6)

- SIEM export: syslog (RFC 5424) and CEF, HTTPS webhooks (signed), JSON lines for Filebeat/Splunk UF, Microsoft Sentinel via syslog/AMA; Slack, Teams and email notifications.
- Threat intelligence: offline import of STIX/TAXII feeds and IP/domain blocklists, with scheduled updates where the site allows.
- Optional Suricata on the sensor: its `eve.json` alerts become another detector input.
- Observability: flows/sec, queue depth, dropped packets, decision latency, model scores, CPU/GPU/temperature; Grafana dashboards and alert rules shipped; structured JSON logs everywhere.
- Reports: daily and weekly PDF security summary; per-device history; compliance-friendly exports.
- Backup and restore of configuration, policy, models and database.

**Exit criteria:** alerts appear in a test Splunk/ELK stack within 5 seconds; a full restore onto a fresh device works.

**Status (2026-10-31): built and tested; a real Splunk/ELK stack test is pending.**
- [x] SIEM export (`integrations/`): syslog RFC 5424 and CEF over UDP, TCP (RFC 6587 framing) or TLS; HMAC-signed HTTPS webhooks; JSON lines for Filebeat / Splunk UF / Vector; Slack, Teams and email. Non-blocking dispatcher with retries, per-sink minimum severity, delivery counters; `/api/integrations` (+ test send). Microsoft Sentinel ingests through its syslog/CEF (AMA) path.
- [x] Threat intelligence (`intel/`): STIX 2.1 bundles, TAXII 2.1 collections and plain lists; feeds updated daily (`sentineledgeai-intel.timer`); matched on flows, DNS names and TLS fingerprints.
- [x] Suricata `eve.json` alerts become detector input (rotation-safe tailing).
- [x] Observability: decision latency, findings, alerts, queue depth, dropped packets, CPU/memory/temperature, sensor buffer, SIEM deliveries; fixed the engine metrics endpoint (it served an empty registry) and moved it to port 9101; JSON logs (`SENTINEL_LOG_FORMAT=json`); Grafana operations dashboard and Prometheus alert rules shipped.
- [x] Reports: daily/weekly PDF + JSON summary (built-in PDF writer, `sentineledgeai-report.timer`), per-device CSV history, compliance export of alerts and audit entries.
- [x] Encrypted backup/restore (`sentinelctl backup|restore`): scrypt + AES-256-GCM, consistent SQLite snapshots, checksum and path checks before anything is written.
- [ ] GPU metrics on the Jetson (pending hardware).

Exit criteria evidence: alerts reach a syslog collector (UDP RFC 5424 and TCP CEF) well within 5 seconds of being raised (`tests/test_integrations_ops.py`); **a run against a real Splunk/ELK instance is pending**. A backup restored into an empty device layout yields intact databases, a working admin sign-in and the same audit-chain head; wrong passphrases, tampering and path traversal are refused.

---

## Phase 6 — Production release (v2.0)

- One-command installers and pre-built OS images for Pi and Jetson; configuration presets (Home, Office, OT/Industrial, Enterprise segment).
- Signed releases (Sigstore/cosign), SBOM (CycloneDX) per release, reproducible builds; minimal non-root container images.
- Secure OS baseline: SSH keys only, firewall on management ports, automatic security updates, LUKS disk encryption, read-only root filesystem where feasible.
- Over-the-air updates with A/B rollback.
- Performance: benchmark and optimise the capture path (AF_PACKET / batch processing, move hot loops out of Python where needed); publish sustained throughput for the Pi 5.
- Documentation: admin guide, operator runbooks, troubleshooting, API reference.
- External penetration test and remediation; beta deployments at 3–5 friendly sites for 30 days.

**Exit criteria:** 30-day beta with no outage caused by the appliance; pen-test high and critical findings fixed; published performance and detection numbers.

**Status (2026-10-31): software built; OS images, the external pen test and the beta are pending.**
- [x] One-command installer (`scripts/install.sh`: verified download, private Python when needed, preset) and presets Home / Office / OT / Enterprise (`sentinelctl preset`). **Pre-built OS images are not made yet.**
- [x] Releases: reproducible packages (verified byte-identical on the Pi and checked in CI), Sigstore/cosign keyless signatures, CycloneDX SBOM, build provenance; minimal non-root container (multi-stage, no compilers, uid 10001, 547 MB).
- [x] Secure OS baseline script (`deploy/pi/harden_os.sh`, dry run by default): SSH keys only with a lockout guard, management firewall, unattended upgrades, journald cap; LUKS and read-only root documented.
- [x] Over-the-air updates (`sentinelctl update`): GitHub release or offline mirror, SHA-256 enforced, signature verified with cosign, health-checked install with automatic rollback (A/B via versioned releases). Verified on the Pi, including refusal of a tampered package.
- [x] Performance (docs/PERFORMANCE.md): AF_PACKET fast-path capture (~121k packets/s effective, was ~4.9k), compiled Isolation Forest (3,843 decisions/s, was 124), throttled timeout scan; fixed a flow-expiry bug.
- [x] Documentation: admin guide, operator runbooks, troubleshooting, generated API reference (82 endpoints, kept current by a test), pen-test scope, beta plan.
- [ ] External penetration test (scope in docs/PENTEST_SCOPE.md).
- [ ] 30-day beta at 3–5 sites (plan in docs/BETA_PROGRAM.md).

---

## Phase 7 — Scale and advanced intelligence (v2.x and later)

- **Fleet manager:** central console for many sites (self-hosted), configuration templates, staged rollouts.
- **Zero-trust micro-segmentation:** per-device trust score drives allowed peers and ports; learned "allow-lists" for IoT/OT devices.
- **Federated learning:** sites share model updates, not data.
- **Reinforcement-learning response tuning:** learn which response level resolves incidents with least disruption — always inside human-approved bounds.
- **OT protocol awareness:** Modbus, DNP3, BACnet, OPC UA parsing for industrial sites.
- **High availability:** active/standby brains; dual sensors with bypass.
- **Compliance packs:** evidence mapping for ISO 27001, IEC 62443 (OT) and NIS2 — documentation support, not certification claims.

**Status (2026-10-31): all seven themes built — fleet manager, zero-trust segmentation, federated learning, response tuning, OT protocol awareness, high availability, compliance packs. Open follow-ups below.**
- [x] Fleet manager (`fleet/`): any appliance can be the fleet server (own CA, mutual TLS on 9444, one-time group-bound enrolment codes, sites pin the CA); sites report a compact status every 5 minutes (no flow or packet data); groups carry a configuration template (response policy, validated on both ends) and a target version rolled out in stages (stable-hash canaries, default 10% → 50% after 24 h → 100% after 48 h); a failed site update pauses the group; the unprivileged agent only records the target and a root timer installs it with the verified, health-checked `sentinelctl fleet-update` (`update --to`). Console **Fleet** panel, `/api/fleet/*`, `python -m fleet`. Live mutual-TLS end-to-end test.
- [x] Federated learning (`detection/federated.py`, `detection/samples.py`, fleet rounds): each site keeps a reservoir sample of normal flows (flows with no findings), trains the autoencoder locally from the global model and sends only weights, scaler statistics and counts; the fleet server validates each update (shapes, finite values, features), aggregates by FedAvg with an exact scaler merge, and every site recalibrates the threshold on its own traffic and registers the result as a signed *shadow* model. Updates are clipped around the global model, with optional noise. Simulated 3-site test: 100% of attacks caught after round 2 vs 45.5% for one site alone, 0% false alarms. Live two-site round over mutual TLS in the tests.
- [x] High availability (`brain/ha.py`): active/standby brains sharing key material (encrypted pairing bundle, scrypt + AES-GCM; each brain gets its own server certificate from the shared CA) and state (one PostgreSQL); a leader lease in the database (renewed every 10 s, 30 s takeover) decides which brain issues commands; sensors list several brains and fail over on their own (`python -m sensor add-brain`, only brains of the pinned CA); dual sensors per segment, commands go to the healthiest one. Tested on SQLite and a real PostgreSQL 16, including a live sensor failover between two brain servers with no flow lost. Bypass is hardware (documented); the software fail-open watchdog exists since Phase 3.
- [x] Compliance packs (`compliance/`): ISO/IEC 27001:2022 Annex A (23 controls), IEC 62443-3-3 (18) and NIS2 Art. 21(2)/23 (11), each control mapped to live evidence from 18 collectors (audit-log integrity, roles, MFA, TLS, device links, monitoring, detection and evaluation, response readiness, assets, OT, segmentation, threat intel, SIEM, backups — now recorded, HA, signed updates, policy history, reports) with met / partial / gap / manual / n/a and a plain disclaimer; JSON and PDF; `GET /api/compliance[/{pack}[/pdf]]` (Admin), `python -m compliance`, Operations → Compliance. Control descriptions are our own summaries, not the standards' text.
- [ ] Fleet: remote actions on sites (block/contain from the fleet console) and fleet-wide alert search.
- [x] OT protocol parsing (`detection/ot.py`): Modbus/TCP (incl. diagnostics restart / listen-only), DNP3 (master requests), BACnet/IP (confirmed and unconfirmed services, routed NPDUs), OPC UA binary (service of unencrypted messages; encrypted channels still give the connection). Request headers only; nothing is injected.
- [x] OT detector: learns each controller's masters and their functions (7 days); then reports a new master (T0886) and a first-time write/control function (T0855); always reports restart/stop/listen-only/communication-control commands (T0816/T0814), OT traffic crossing the internet edge (T0883) and Modbus unit-id sweeps (T0846). Fed from both capture paths and fused like every other finding.
- [x] OT asset inventory: learning persisted in SQLite (`data/ot.db`, so a restart does not reopen the learning period), `GET /api/ot/assets` (Viewer) and an **OT devices** console panel.
- [x] OT micro-segmentation from the learned allow-lists (`enforcement/segmentation.py`): off / monitor / enforce (Admin, inline only), a frozen snapshot with Admin exceptions and refresh, management hosts always allowed, protected hosts never guarded, inet + bridge nftables rules that leave replies alone, re-applied at boot, turned off by any rollback or watchdog fail-open; CLI `python -m enforcement segment`, `/api/ot/segmentation*`, console controls. Verified on the real kernel (`tests/firewall_netns/run_segmentation_netns.sh`).
- [x] Zero-trust for every device: learned peer profiles (`detection/peers.py`: internal peers exactly, internet as protocol/port, capped), a trust score 0–100 with reasons (`enforcement/trust.py`: identity, tenure, decaying alerts, analyst false positives, restrictions) and a `contain` response that keeps an untrusted device to its profile (+ DNS/DHCP) through the existing restriction machinery (TTL, protected hosts, rollback, watchdog). `GET /api/trust`, `GET /api/devices/{ip}/peers`, `POST /api/firewall/contain`, **Trust** console panel, `python -m enforcement trust|contain`. Verified on the real kernel (`tests/firewall_netns/run_containment_netns.sh`, 11/11).
- [x] Response tuning (`enforcement/tuning.py`), the "reinforcement-learning response tuning" theme as a contextual bandit: per kind of incident and response (alert < rate_limit < contain < block < quarantine) a Beta posterior of "resolved" (no new detection of the source within an hour; analyst false positives count as "an alert was enough"); Thompson sampling picks the least disruptive response that reaches the target. Never stronger than the playbook's step, never gentler than `min_action` (default rate_limit), always stronger after a failed response to the same incident, approval gate unchanged, pessimistic prior for gentler actions. Modes off / recommend (default: shadow, audited) / apply. Containment is now a playbook action (also usable as an explicit policy step). `GET/POST /api/tuning`, `python -m enforcement tuning`, Operations → Response.
- [ ] Captured lab traffic from real PLCs / BACnet controllers.

---

## 4. Engineering standards (all phases)

* **Tests:** unit tests for every module; integration tests for firewall, storage and the sensor–brain link; target ≥ 80% coverage on `core/`, `detection/` and `security/`.
* **CI gates:** tests, Bandit, pip-audit, npm audit, model-signature check, type checking (mypy) on new modules, lint (ruff, eslint).
* **Code review:** all changes by pull request; security-sensitive paths need two reviewers (see SECURITY.md §7).
* **Versioning:** Semantic Versioning; `CHANGELOG.md` updated in every pull request.
* **Performance budgets:** decision latency, sensor CPU (< 60% sustained on the Pi at the target load), console bundle size (enforced via `frontend/perfbudgets.json`).
* **Definition of done:** code, tests and documentation merged; CI green; behaviour demonstrated on real hardware for anything touching capture or enforcement.

---

## 5. Explicitly out of scope (for now)

* Decrypting TLS traffic (privacy and legal risk; metadata analysis only).
* Sending any data to a vendor cloud by default.
* Fully autonomous response without human-set bounds.
* Replacing endpoint protection, email security or a full firewall/UTM.

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| Python capture path cannot keep up on busy links | Benchmark early (Phase 0/6); AF_PACKET with batching; optional Suricata/Zeek front end; native extension for hot loops |
| False positives erode trust | Monitor-first rollout, approval gates, confidence scores, feedback loop, published FPR |
| Appliance causes an outage | Fail-open bypass, watchdog, TTLs, rollback guard, soak tests |
| Jetson supply or cost changes | Brain code also runs CPU-only on any arm64/x86 box; GPU models are optional accelerators |
| Small team, large scope | Strict phase gates; Lite profile remains useful at every stage |
