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

## 2. Target architecture (v1.0)

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
| **v0.9.x** | Correctness and hygiene | 0 |
| **v0.10** | Secure management plane | 1 |
| **v0.11** | Two-node architecture | 2 |
| **v0.12** | Enforcement you can trust | 3 |
| **v0.13** | Detection quality | 4 |
| **v0.14** | Integrations and operations | 5 |
| **v1.0** | Production release | 6 |
| **v1.x+** | Scale and advanced intelligence | 7 |

Each phase ends with a working, tested, merged build. The **exit criteria** must all be met before the phase is called done.

---

## Phase 0 — Correctness and hygiene (v0.9.x)

**Goal:** fix what is broken or unsafe in the current code before building on it.

- [x] Remove stray files and tracked runtime data, compiled files, the signing key and the credentials file; clean `.gitignore`.
- [x] Rewrite documentation (README, SECURITY, PLAN, EXPLAIN).
- [ ] **Rotate the model signing key** and health credentials (see SECURITY.md §4); update the GitHub secret; re-sign the model.
- [x] **Fix firewall command execution:** `_run_cmd` now runs only allowlisted `nft`/`iptables` binaries directly (the generic subprocess wrapper rejected them, so nothing was ever applied).
- [x] **Fix the nftables backend:** `input` and `forward` chains in `inet sentinel` drop traffic matching `@blacklist`; created idempotently.
- [x] **Fix iptables removal** so it matches the inserted rule (including the comment); cover `INPUT` and `FORWARD`; no duplicate rules on re-block.
- [x] Rollback flushes every SentinelEdgeAI kernel rule, including ones missing from the state file.
- [x] Container integration test checks the kernel ruleset after block, unblock and rollback.
- [ ] IPv6 blocking (`ipv6_addr` set and `ip6tables`).
- [x] Split dependencies: `requirements.txt` (runtime), `requirements-dev.txt` (pytest, bandit, pip-audit), `requirements-streamlit.txt` (legacy dashboard); upgrade `uvicorn` 0.23 → 0.54.
- [x] Pi package is built from `git archive HEAD` (no untracked secrets), includes the built web console, refuses secret-like files, and ships a SHA-256 checksum.
- [x] Package installer no longer deletes the device's database, firewall state or keys on upgrade.
- [ ] Choose a licence (Apache-2.0 recommended for an open-core product; or proprietary).
- [x] Delete the empty stubs `flow/timeout_manager.py` and `utils/config.py`.
- [x] Move superseded docs (`README_LOCAL.md`, `README_DEPLOY.md`, `BUILD_SUMMARY.md`, `SECURITY_AUDIT.md`, `docs/BUILD_PLAN.md`, `notes.txt`) to `docs/archive/`.

**Exit criteria:** a block issued with `FIREWALL_DRY_RUN=0` drops packets and unblock restores them, on both nft and iptables, proven in CI (the container test now checks this; it must pass on the privileged runner); no secrets in the tree; all tests green.

---

## Phase 1 — Secure management plane (v0.10)

**Goal:** the console and API are safe to expose on a management network.

- Users table (Argon2id hashes), login and logout, short-lived access token plus refresh token in an HttpOnly cookie.
- Roles: Viewer, Analyst, Operator, Admin; enforce them on every endpoint and in the UI.
- TOTP MFA (required for Operator and Admin); account lockout and rate limiting on login; API rate limits.
- Service accounts and API tokens (scoped, expiring) for automation, replacing the single shared key.
- HTTPS by default: certificate generated at install, with the option to import an organisation's own certificate; HSTS; secure WebSocket (WSS) with token auth.
- Security headers: CSP, X-Frame-Options, Referrer-Policy; CORS locked to the console's own origin.
- Hash-chained audit log of every login, policy change and response action, viewable by Admins.
- First-run setup wizard: create the admin user, set the network role, choose passive or inline mode.

**Exit criteria:** every endpoint has a role test; no unauthenticated endpoint except `/healthz`; OWASP ZAP baseline scan clean; login brute force is throttled.

---

## Phase 2 — Two-node architecture (v0.11)

**Goal:** the Pi senses and enforces; the Jetson does all AI work and management.

- Split the codebase into `sensor/`, `brain/` and `common/` packages, each with its own systemd service and installer.
- gRPC protobuf schema for flow batches, health and commands; mTLS with a small built-in certificate authority on the brain; sensor enrolment with a one-time code.
- Command signing (Ed25519) with sequence numbers and expiry; the enforcer verifies commands and re-checks its local whitelist.
- Sensor disk buffer and replay after reconnect; degraded mode with the local detector.
- Event bus inside the brain replacing file polling; WebSocket heartbeat, reconnect with resync cursor, server-side throttling.
- Move storage to PostgreSQL on the Jetson; keep SQLite for the Lite profile.
- Jetson installer (JetPack 6.x) and Pi installer; "Lite" profile keeps everything on one Pi.

**Exit criteria:** unplugging the Jetson for an hour loses no flow data and causes no network impact; a forged or replayed command is rejected; one Jetson handles 3 sensors at the target load.

---

## Phase 3 — Enforcement you can trust (v0.12)

**Goal:** blocking and quarantine are safe, precise and reversible in inline mode.

- Inline bridge mode (`br0` over WAN and LAN NICs) with nftables `bridge` and `inet` families; documented hardware bypass options; software watchdog that flushes rules if the enforcer dies.
- MAC-based device identity (DHCP and ARP observation, DHCP option fingerprints, OUI vendor lookup) so devices keep identity when IPs change.
- Quarantine: allow a device to reach only DNS, DHCP and a captive "quarantined" page; optional VLAN reassignment through managed-switch APIs later.
- Graduated playbooks: `alert → rate-limit → block (TTL) → quarantine`; per-severity approval gates ("require Operator approval above risk 75 for the first 30 days").
- Automatic protection of the gateway, DNS, DHCP, management hosts and the appliance itself; conflict and duplicate rule detection.
- Policy-as-code: response policy in versioned YAML with validation and a dry-run diff before apply.

**Exit criteria:** a 72-hour inline soak with enforcement enabled causes zero unintended blocks of protected hosts; every action rolls back in under 2 seconds; a killed enforcer leaves traffic flowing.

---

## Phase 4 — Detection quality (v0.13)

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

---

## Phase 5 — Integrations and operations (v0.14)

- SIEM export: syslog (RFC 5424) and CEF, HTTPS webhooks (signed), JSON lines for Filebeat/Splunk UF, Microsoft Sentinel via syslog/AMA; Slack, Teams and email notifications.
- Threat intelligence: offline import of STIX/TAXII feeds and IP/domain blocklists, with scheduled updates where the site allows.
- Optional Suricata on the sensor: its `eve.json` alerts become another detector input.
- Observability: flows/sec, queue depth, dropped packets, decision latency, model scores, CPU/GPU/temperature; Grafana dashboards and alert rules shipped; structured JSON logs everywhere.
- Reports: daily and weekly PDF security summary; per-device history; compliance-friendly exports.
- Backup and restore of configuration, policy, models and database.

**Exit criteria:** alerts appear in a test Splunk/ELK stack within 5 seconds; a full restore onto a fresh device works.

---

## Phase 6 — Production release (v1.0)

- One-command installers and pre-built OS images for Pi and Jetson; configuration presets (Home, Office, OT/Industrial, Enterprise segment).
- Signed releases (Sigstore/cosign), SBOM (CycloneDX) per release, reproducible builds; minimal non-root container images.
- Secure OS baseline: SSH keys only, firewall on management ports, automatic security updates, LUKS disk encryption, read-only root filesystem where feasible.
- Over-the-air updates with A/B rollback.
- Performance: benchmark and optimise the capture path (AF_PACKET / batch processing, move hot loops out of Python where needed); publish sustained throughput for the Pi 5.
- Documentation: admin guide, operator runbooks, troubleshooting, API reference.
- External penetration test and remediation; beta deployments at 3–5 friendly sites for 30 days.

**Exit criteria:** 30-day beta with no outage caused by the appliance; pen-test high and critical findings fixed; published performance and detection numbers.

---

## Phase 7 — Scale and advanced intelligence (v1.x and later)

- **Fleet manager:** central console for many sites (self-hosted), configuration templates, staged rollouts.
- **Zero-trust micro-segmentation:** per-device trust score drives allowed peers and ports; learned "allow-lists" for IoT/OT devices.
- **Federated learning:** sites share model updates, not data.
- **Reinforcement-learning response tuning:** learn which response level resolves incidents with least disruption — always inside human-approved bounds.
- **OT protocol awareness:** Modbus, DNP3, BACnet, OPC UA parsing for industrial sites.
- **High availability:** active/standby brains; dual sensors with bypass.
- **Compliance packs:** evidence mapping for ISO 27001, IEC 62443 (OT) and NIS2 — documentation support, not certification claims.

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
