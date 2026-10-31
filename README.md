<div align="center">

# SentinelEdgeAI

**Offline, AI-driven network detection and response with an adaptive firewall, for networks that have no security team.**

[![Release](https://img.shields.io/github/v/release/vishwa-10147/SentinelEdgeAI?label=release)](https://github.com/vishwa-10147/SentinelEdgeAI/releases/latest)
[![CI](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml)
[![Security Scans](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205%20%7C%20Jetson%20Orin%20Nano-555)
![Roadmap](https://img.shields.io/badge/roadmap-Phases%201--6%20built%2C%20field%20validation%20pending-yellow)

[Overview](#overview) ·
[Roadmap](#roadmap-and-progress) ·
[Use cases](#use-cases) ·
[Capabilities](#capabilities) ·
[Architecture](#architecture) ·
[Installation](#installation) ·
[Configuration](#configuration) ·
[API](#api) ·
[Contributing](#contributing)

</div>

---

## Overview

SentinelEdgeAI is a network appliance that learns how every device on a network normally behaves, detects attacks and compromised devices in real time, and responds automatically, from a console alert up to blocking a device. Its safety controls are built so that it never takes the network down. Everything runs on site: no cloud account is needed and no traffic data leaves the network.

| | |
|---|---|
| **Current release** | [`v2.1.0`](https://github.com/vishwa-10147/SentinelEdgeAI/releases/tag/v2.1.0): production candidate — single-node or sensor/brain deployment, trusted enforcement, detection fusion, SIEM integrations, signed OTA updates, OT protocol awareness (pen test and beta pending) |
| **Target hardware** | Raspberry Pi 5 (sensor) and NVIDIA Jetson Orin Nano (AI and management) |
| **Supply chain** | Signed ML model, reproducible packages, Sigstore/cosign signatures, SHA-256 checksums, CycloneDX SBOM, GitHub build-provenance attestation |
| **Supply chain** | Signed ML model, SHA-256 checksums, CycloneDX SBOM, GitHub build-provenance attestation |
| **Documentation** | [Admin guide](docs/ADMIN_GUIDE.md) · [Runbooks](docs/RUNBOOKS.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) · [API reference](docs/API.md) · [Performance](docs/PERFORMANCE.md) · [EXPLAIN.md](EXPLAIN.md) · [SECURITY.md](SECURITY.md) · [PLAN.md](PLAN.md) · [CHANGELOG.md](CHANGELOG.md) |

> **Status legend:** ✅ available · 🟡 partial · 🔜 planned (see [PLAN.md](PLAN.md))

### Why it exists

Small businesses, factories, clinics and IoT-heavy sites face the same attack tools as large enterprises, but cannot afford a security operations centre, an enterprise NDR licence, or a cloud service that ships their traffic metadata off site. Many of their devices, such as cameras, PLCs, printers and medical equipment, cannot run endpoint protection. The network is the only place they can be protected.

SentinelEdgeAI fills that gap: **behavioural detection and automated response on about USD 350 of hardware, fully offline.**

---

## Roadmap and progress

```text
Phase 0  Correctness, hygiene, release pipeline   v1.1   ████████████████████  done
Phase 1  Secure management plane                  v1.2   ████████████████████  done (exit checks met)
Phase 2  Two-node architecture (Pi + Jetson)      v1.3   ████████████████░░░░  built; Jetson validation pending
Phase 3  Enforcement you can trust                v1.4   ████████████████░░░░  built; 72 h inline soak pending
Phase 4  Detection quality                        v1.5   ███████████████░░░░░  built; public datasets + GPU pending
Phase 5  Integrations and operations              v1.6   ██████████████████░░  built; real SIEM test pending
Phase 6  Production release                       v2.0   ██████████████░░░░░░  built; OS images, pen test, beta pending
Phase 7  Scale and advanced intelligence          v2.x+  ░░░░░░░░░░░░░░░░░░░░  after v2.0
```

**All software for Phases 2–6 is built and tested** (simulations, real-kernel network-namespace tests and the Pi itself). What remains before v2.0 needs hardware or time rather than code: Jetson validation, a 72-hour inline soak, public-dataset evaluation and GPU models, a real SIEM run, pre-built OS images, an external penetration test and a 30-day beta. Each phase's evidence and open items are listed in [PLAN.md](PLAN.md).

| Phase | Release | Goal | Status |
|---|---|---|---|
| 0 | v1.1 | Fix broken firewall enforcement, remove secrets, safe packaging, signed and attested releases, `sentinelctl` device lifecycle | ✅ Released. Open: privileged-runner CI proof |
| 1 | v1.2 | User accounts, roles (Viewer, Analyst, Operator, Admin), MFA, HTTPS, audit log, setup wizard | ✅ Built and exit checks met (role test per endpoint, clean ZAP baseline); release pending |
| 2 | v1.3 | Pi senses and enforces, Jetson runs all AI and management; mTLS link, signed commands, offline buffering | 🟡 Built; brain outage, forged/replayed commands and 3 sensors verified in simulation and on the Pi. Pending: Jetson hardware |
| 3 | v1.4 | Inline bridge mode, MAC-based quarantine, graduated response playbooks with approval gates | 🟡 Built; 22/22 real-kernel checks (routed and bridged), rollback ~100 ms. Pending: 72 h inline soak |
| 4 | v1.5 | Attack-specific detectors, TLS fingerprints, GPU models, model registry, published accuracy numbers | 🟡 Built; 100% detection / 0% FP on the labelled synthetic set. Pending: CIC-IDS/UNSW evaluation, GPU models |
| 5 | v1.6 | SIEM export, threat-intel feeds, observability, reports, backup and restore | 🟡 Built; SIEM delivery < 5 s and full restore verified. Pending: real Splunk/ELK run |
| 6 | v2.0 | OS images, OTA updates with A/B rollback, hardened OS, external pen test, 30-day field beta | 🟡 Installer, OTA, reproducible signed builds, hardening, container, docs, 25–31× faster capture/decisions done. Pending: OS images, pen test, beta |
| 7 | v2.x+ | Fleet manager, micro-segmentation, federated learning, OT protocols, high availability | 🔜 |

Each phase has explicit exit criteria in [PLAN.md](PLAN.md) and is only marked done when all of them are met.

---

## Use cases

| Environment | What SentinelEdgeAI protects against |
|---|---|
| **Small and medium businesses** | Ransomware spreading between PCs, data exfiltration, compromised laptops, brute force against exposed services |
| **Industrial and OT networks** | Unexpected traffic from PLCs and SCADA, new devices, lateral movement into control networks. Offline operation suits air-gapped sites |
| **IoT and CCTV networks** | Hijacked cameras and smart devices joining botnets or calling out to unknown hosts |
| **Healthcare clinics** | Unpatchable medical devices, sensitive data leaving the network |
| **Schools, hostels, hotels and guest Wi-Fi** | Infected guest devices, scanning, network abuse |
| **Branch offices** | One sensor per branch reporting to a central brain (multi-sensor mode 🔜) |
| **Managed service providers** | One appliance per customer site; fleet console 🔜 |
| **Security training labs** | Explainable detection with a built-in attack demo |
| **Home labs** | The single-Pi "Lite" profile |

SentinelEdgeAI is the **network layer** of a defence-in-depth setup. It does not replace endpoint protection, email security or patching.

---

## Capabilities

### Detection

| Capability | Status |
|---|---|
| Live packet capture and flow assembly (5-tuple, idle timeout) | ✅ |
| 24 statistical features per flow (bytes, packet rates, inter-arrival times, TCP flags) | ✅ |
| Z-score anomaly detection against adaptive per-IP, per-protocol baselines | ✅ |
| Isolation Forest anomaly detection with a signed model verified at load time | ✅ |
| Per-device behavioural fingerprint and long-term drift detection | ✅ |
| Unified 0–100 risk score with MITRE ATT&CK tactic and technique mapping | ✅ |
| Attack-type classification | 🟡 Rule-based today |
| Per-protocol thresholds, confidence scores, multi-stage confirmation | 🔜 |
| GPU detectors on the Jetson (autoencoder, sequence model, graph model) | 🔜 |
| Encrypted-traffic analysis (JA3/JA4, SNI, certificate anomalies; no decryption) | 🔜 |
| Offline threat-intelligence feeds (STIX/TAXII, IP and domain blocklists) | 🔜 |

### Response (adaptive firewall)

| Capability | Status |
|---|---|
| Block and unblock IPv4 and IPv6 addresses via nftables or iptables/ip6tables on `INPUT` and `FORWARD`, with TTL expiry | ✅ |
| Whitelist, response modes (`monitor`, `alert`, `auto_block`), risk-threshold policy | ✅ |
| Dry run by default, full rollback, systemd rollback guard | ✅ |
| Inline bridge mode and MAC-based device quarantine | 🔜 |
| Graduated playbooks (alert → rate-limit → block → quarantine) with approval gates | 🔜 |
| Signed, authenticated commands from the AI node (mTLS) | 🔜 |

### Operations

| Capability | Status |
|---|---|
| FastAPI REST API and WebSocket live stream | ✅ |
| React console: topology map, device detail, analytics, firewall activity, demo mode | ✅ |
| SQLite storage with retention; optional PostgreSQL backend and migration script | ✅ |
| Prometheus metrics, Grafana dashboards, health endpoint | ✅ |
| Offline installer, `sentinelctl` upgrade with health check and automatic rollback | ✅ |
| Release pipeline: tests, signature check, dependency audit, SBOM, provenance attestation | ✅ |
| User accounts with Argon2id passwords, four roles, rotating sessions, login lockout | ✅ |
| Two-step sign-in (TOTP) for Operators and Admins, with recovery codes | ✅ |
| HTTPS by default, scoped API tokens, hash-chained audit log, API rate limits, security headers | ✅ |
| SIEM export (syslog/CEF, webhooks, JSON for Splunk, ELK and Microsoft Sentinel) | 🔜 |
| Model registry with shadow testing and hot reload | 🔜 |
| Multi-sensor and multi-site fleet management | 🔜 |

---

## Architecture

```text
                         ┌──────────────────────────────────────────────┐
   Admin / Analyst  ───► │  JETSON ORIN NANO  ·  "Brain"                │
   (browser, HTTPS)      │                                              │
                         │  Web console · REST API · WebSocket          │
                         │  Users, roles, MFA, audit log                │
                         │  AI detection: Isolation Forest + GPU models │
                         │  Risk fusion → policy engine → playbooks     │
                         │  Database · model registry · SIEM export     │
                         └───────────────▲───────────────┬──────────────┘
                     flow features,      │               │  signed response
                     sensor health       │  mTLS link    │  commands
                                         │               ▼
                         ┌───────────────┴──────────────────────────────┐
   Network traffic  ───► │  RASPBERRY PI 5  ·  "Sensor"                 │
   (mirror port or       │                                              │
    inline bridge)       │  Packet capture → flows → feature extraction │
                         │  Local fast-path detector (works offline)    │
                         │  Enforcement agent (nftables) + rollback     │
                         │  Disk buffer if the brain is unreachable     │
                         └──────────────────────────────────────────────┘
```

- **Today (v1.2):** everything runs as a single node on a Raspberry Pi. The Pi–Jetson link does not exist yet.
- **Target (v2.0):** the Pi only senses and enforces; the Jetson runs all AI work and owns users, data and the console. One Jetson can serve several sensors.
- **Fail-safe by design:** if the brain is offline, the sensor keeps basic detection running, buffers data to disk, and never blocks traffic because a link failed.

### Deployment profiles

| Profile | Hardware | Intended for | Available |
|---|---|---|---|
| **Lite** | 1 × Raspberry Pi 5 | Home labs, very small offices, evaluation | ✅ v1.1 |
| **Standard** | 1 × Pi 5 + 1 × Jetson Orin Nano | SMBs, clinics, OT cells (reference deployment) | 🔜 v1.3 |
| **Multi-sensor** | N × Pi 5 + 1 × Jetson | Several segments or floors | 🔜 v1.3 |
| **Fleet** | Many sites + central console | MSPs and multi-branch organisations | 🔜 v2.x |

### Network placement

- **Passive (recommended first):** a managed switch mirrors traffic to the Pi. No risk to the network; it can alert but cannot block forwarded traffic.
- **Inline 🔜:** the Pi bridges WAN and LAN and can block and quarantine. Needs two NICs and a bypass so traffic keeps flowing if the appliance fails.

### Hardware

| Component | Role | Notes |
|---|---|---|
| Raspberry Pi 5 (8 GB) | Sensor: capture, features, enforcement | Active cooling; NVMe or SSD for logs |
| NVIDIA Jetson Orin Nano (8 GB) | Brain: AI inference, database, console | JetPack 6.x; NVMe SSD |
| Second NIC (USB 3 or PCIe) | Inline mode | Gigabit or faster |
| Managed switch with port mirroring | Passive mode | 802.1Q VLAN support recommended |

Approximate hardware cost for the Standard profile: **USD 300–400**.

---

## Installation

### Raspberry Pi (production)

**Supported:** Raspberry Pi 5 or 4 with 64-bit Raspberry Pi OS Bookworm (Python 3.11) or Trixie (Python 3.13). The package bundles every Python dependency, so the Pi needs **no internet access**.

1. Download `sentineledgeai-pi-<version>.tar.gz` and its `.sha256` from [Releases](https://github.com/vishwa-10147/SentinelEdgeAI/releases) and copy both to the Pi.
2. Optionally verify where the package was built:

   ```bash
   gh attestation verify sentineledgeai-pi-2.1.0.tar.gz --repo vishwa-10147/SentinelEdgeAI
   ```

3. Install:

   ```bash
   sha256sum -c sentineledgeai-pi-2.1.0.tar.gz.sha256
   tar -xzf sentineledgeai-pi-2.1.0.tar.gz
   sudo bash sentineledgeai-pi-2.1.0/deploy/pi/provision_key.sh /path/to/model_signing.key
   sudo bash sentineledgeai-pi-2.1.0/packaging/sentinelctl install sentineledgeai-pi-2.1.0.tar.gz
   ```

4. Open `https://<pi-address>:9000` (the installer prints the address). The certificate is self-signed, so the browser warns once: check that the SHA-256 fingerprint matches `sentinelctl tls show` before continuing, or install your own certificate with `sudo sentinelctl tls import cert.pem key.pem`. Sign in as `admin` with the one-time password from `sudo cat /etc/sentinel/initial-admin-password`. You must choose a new password and set up an authenticator app (two-step sign-in), then delete that file. The setup wizard then asks for the network placement, the capture interface and the response mode (reopen it later from **Setup**). Add other users from the **Users** panel.

   For scripts and integrations, create an API token in the **Users** panel (or with `create-token` below) and send it as `Authorization: Bearer <token>`. The older shared key in `/etc/sentinel/sentinel.env` (`DASHBOARD_API_KEY`) still works. Users and tokens can also be managed on the device:

   ```bash
   cd /opt/sentineledgeai/current
   sudo -u sentinel .venv/bin/python -m core.auth list
   sudo -u sentinel .venv/bin/python -m core.auth create-user --username alice --role operator
   sudo -u sentinel .venv/bin/python -m core.auth reset-password --username alice --must-change-password
   sudo -u sentinel .venv/bin/python -m core.auth reset-mfa --username alice   # lost phone
   sudo -u sentinel .venv/bin/python -m core.auth create-token --owner admin --name grafana --role viewer --days 90
   sudo -u sentinel .venv/bin/python -m core.auth list-tokens
   sudo -u sentinel .venv/bin/python -m core.audit verify          # audit log integrity
   sudo -u sentinel .venv/bin/python -m core.audit tail -n 20
   ```

**Upgrades and rollback**

```bash
sudo sentinelctl upgrade sentineledgeai-pi-<version>.tar.gz   # health-checked; rolls back automatically on failure
sudo sentinelctl rollback                                  # return to the previous version
sentinelctl status                                         # active version and service state
sentinelctl tls show                                       # certificate, expiry and fingerprint
sudo sentinelctl tls import cert.pem key.pem               # use your organisation's certificate
sudo sentinelctl tls renew                                 # new self-signed certificate
```

**Device layout**

| Path | Contents | Changed by upgrades |
|---|---|---|
| `/opt/sentineledgeai/releases/<version>/` | Code and its own Python environment | Added; last 3 kept |
| `/opt/sentineledgeai/current` | Symlink to the active release | Switched atomically |
| `/etc/sentinel/` | `sentinel.env`, `config.yaml`, `model_signing.key` | Never |
| `/var/lib/sentinel/` | Database, firewall state, alerts, device profiles | Never |
| `/var/log/sentinel/` | Logs and the firewall action log | Never |

Services `sentineledgeai-engine`, `sentineledgeai-api` and the `sentineledgeai-rollback-guard` timer run as the unprivileged `sentinel` user with only `CAP_NET_RAW` and `CAP_NET_ADMIN`.

**Enabling real blocking:** the appliance installs in dry-run mode. After reviewing alerts, set `FIREWALL_DRY_RUN=0` and `ENABLE_ROLLBACK_GUARD=1` in `/etc/sentinel/sentinel.env`, then run `sudo systemctl restart sentineledgeai-engine sentineledgeai-api`. Read [SECURITY.md](SECURITY.md) §6 first.

### Development machine

> Runs the single-node build in **dry-run** mode; nothing is ever blocked.

**Requirements:** Python 3.11+, Node.js 20.19+, Linux or macOS. Packet capture needs root or `CAP_NET_RAW`; Windows needs Npcap.

```bash
git clone https://github.com/vishwa-10147/SentinelEdgeAI.git
cd SentinelEdgeAI
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
(cd frontend && npm ci && npm run build)
python dashboard/dashboard_api.py          # API and console on http://127.0.0.1:9000
```

| Task | Command |
|---|---|
| Simulated attack → alert → dry-run block | `python scripts/demo_attack.py --ip 192.168.1.50 --block` |
| Replay a capture through the pipeline | `python scripts/replay_pcap.py <file.pcap>` |
| Live capture and detection (needs root) | `sudo .venv/bin/python main.py` |
| Run the tests | `pytest -q` |
| Docker (API and console, dry run) | `docker compose up -d --build` |
| Build a Pi package locally | `bash scripts/build_pi_package.sh` |

Releases are built by CI when a `vX.Y.Z` tag matching the `VERSION` file is pushed. Older installers are kept for existing devices; see [deploy/pi/README.md](deploy/pi/README.md).

---

## Configuration

Detection tuning lives in [config.yaml](config.yaml) (risk thresholds, baseline window, Z-score threshold, flow timeouts, logging). Runtime behaviour is set with environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `FIREWALL_DRY_RUN` | `1` | `1` records actions only; `0` applies real firewall rules |
| `SENTINEL_FIREWALL_BACKEND` | `auto` | `auto`, `nft` or `iptables` |
| `DASHBOARD_API_KEY` | unset | Shared key for automation (`X-API-Key` or `Bearer`). With no key and no users, only localhost is accepted |
| `SENTINEL_API_KEY_ROLE` | `admin` | Role granted to the API key |
| `SENTINEL_AUTH_DB` | `data/auth.db` | User accounts and sessions |
| `SENTINEL_AUDIT_DB` | `data/audit.db` | Hash-chained audit log |
| `SENTINEL_SETUP_FILE` | `data/setup.json` | Settings saved by the setup wizard |
| `CAPTURE_IFACE` | unset | Overrides the capture interface chosen in the setup wizard |
| `SENTINEL_ACCESS_TOKEN_TTL` / `SENTINEL_SESSION_TTL` | `900` / `43200` | Access-token and session lifetime in seconds |
| `SENTINEL_CORS_ORIGINS` | Vite dev server | Comma-separated origins allowed to call the API from another site |
| `SENTINEL_CSP` | strict same-origin policy | Replaces the Content-Security-Policy header (only needed if the console is hosted on another origin) |
| `SENTINEL_RATE_LIMIT_READ` / `_WRITE` | `600` / `60` | API requests per client per minute (reads / writes); `0` turns a limit off |
| `SENTINEL_MFA_ROLES` | `operator,admin` | Roles that must use two-step sign-in (empty to turn the requirement off) |
| `SENTINEL_TLS_CERT` / `SENTINEL_TLS_KEY` | set by `sentinelctl` | PEM certificate and key; when both are set the API serves HTTPS. Empty for plain HTTP |
| `SENTINEL_HSTS_MAX_AGE` | `31536000` | `Strict-Transport-Security` lifetime in seconds (HTTPS only) |
| `SENTINEL_COOKIE_SECURE` | auto | `1` forces the `Secure` flag on the session cookie (set it behind an HTTPS proxy) |
| `SENTINEL_HOST` / `SENTINEL_PORT` | `127.0.0.1` / `9000` | API bind address and port |
| `SENTINEL_MODEL_SIGNING_KEY` / `_FILE` | unset | Key that verifies the ML model signature. **Never commit it** |
| `SENTINEL_ALLOW_UNSIGNED_MODELS` | `0` | Development only |
| `DATABASE_URL` | unset | Use PostgreSQL instead of SQLite |
| `SENTINEL_DB_PATH` | `data/sentinel.db` | SQLite file location |
| `CAPTURE_IN_PROCESS` / `CAPTURE_IFACE` | `0` / all | Capture inside the API process; capture interface |
| `REDACT_SENSITIVE` / `REDACT_SALT` | `0` / unset | Hash IPs and MACs in API responses |
| `HEALTH_USER` / `HEALTH_PASS` | unset | Basic auth for the health endpoint |
| `DISABLE_DB_MAINTENANCE` | `0` | Disable background retention and VACUUM |

Default ports: console and API `9000`, health `5000`, Prometheus metrics `8001`.

---

## API

Every endpoint except sign-in requires authentication: a console access token or an API token (`Authorization: Bearer …`), or the shared API key. Each endpoint has a minimum role.

| Role | Can |
|---|---|
| Viewer | Read dashboards, alerts, devices, firewall state, reports |
| Analyst | Viewer + `POST /api/alerts/explain` |
| Operator | Analyst + block, unblock, whitelist, expire, rollback, demos |
| Admin | Operator + `POST /api/firewall/policy` and user management |

Operators and Admins must set up two-step sign-in (an authenticator app) at their next sign-in. The first admin does this right after choosing a new password, so have a phone with an authenticator app ready.

| Method and path | Purpose |
|---|---|
| `GET /api/auth/status`, `POST /api/auth/login`, `/refresh`, `/logout`, `/password`, `GET /api/auth/me` | Sign-in and sessions |
| `GET /api/auth/mfa`, `POST /api/auth/mfa/setup`, `/mfa/enable` | Two-step sign-in status and enrolment |
| `GET/POST /api/users`, `PATCH/DELETE /api/users/{username}` | User management (Admin) |
| `GET/POST /api/tokens`, `DELETE /api/tokens/{id}` | API tokens (signed-in Admin) |
| `GET /api/audit?limit=&before=&action=&actor=`, `GET /api/audit/verify` | Hash-chained audit log and integrity check (Admin) |
| `GET/POST /api/setup` | Device setup: network role, placement, capture interface, response mode (Admin) |
| `GET /api/alerts`, `/api/flows`, `/api/device_profiles`, `/api/risk_timeline`, `/api/live_stats` | Detection data |
| `GET /api/incidents/timeline`, `/api/reports/security`, `POST /api/alerts/explain` | Investigation and reporting |
| `GET /api/device/{id}/logs` | Per-device history |
| `GET/POST /api/firewall/policy`, `GET /api/firewall/rules`, `GET /api/firewall/actions` | Firewall policy and audit trail |
| `POST /api/firewall/block`, `/unblock`, `/whitelist`, `/expire`, `/rollback` | Response actions |
| `GET /api/health`, `GET /metrics` | Health and Prometheus metrics |
| `WS /ws/packets` | Live alerts, flows and demo events. Send `{"type": "auth", "token": "…"}` as the first message |

The OpenAPI document is served at `/openapi.json` to authenticated clients only.

---

## Repository layout

```text
capture/      packet capture and the ingest loop (Scapy)
flow/         flow records and the flow table
features/     per-flow feature extraction
detection/    baselines, Z-score, Isolation Forest, fingerprinting, risk, MITRE mapping
core/         engine, firewall enforcement, storage (SQLite/PostgreSQL), health, config
security/     model signing and verification
dashboard/    FastAPI backend (and the legacy Streamlit dashboard)
frontend/     React web console (Vite)
packaging/    sentinelctl, systemd units, rollback guard, logrotate, Prometheus alerts
deploy/       Raspberry Pi, Jetson, monitoring and Grafana deployment files
scripts/      package build, demo and replay tools, training, signing, CI helpers
tests/        unit and integration tests
docs/         additional documentation and archived material
```

---

## Known limitations (v1.2)

1. **Self-signed certificate by default.** Browsers warn until you import a certificate from your own CA (`sentinelctl tls import`).
2. **Single node only.** The Jetson is not used until v1.3.
3. **No inline bridge mode.** Blocks cover traffic to and routed through the appliance; bridge filtering and MAC quarantine arrive in v1.4.

---

## Contributing

1. Open an issue describing the change.
2. Branch from `main` using `feature/…`, `fix/…` or `chore/…`.
3. Ensure `pytest -q`, Bandit and pip-audit pass, and add tests for new behaviour.
4. Update [CHANGELOG.md](CHANGELOG.md) and open a pull request. Changes to the firewall, authentication or signing need a second reviewer.

**Security issues:** do not open a public issue. Follow the disclosure process in [SECURITY.md](SECURITY.md).

## License

SentinelEdgeAI is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution. You may use, modify and distribute it, including commercially, provided you keep the licence and notice files.

Unless you state otherwise, any contribution you submit is licensed under the same terms (Apache-2.0 §5).
