<div align="center">

# SentinelEdgeAI

**Offline, AI-driven network detection and response with an adaptive firewall, for networks that have no security team.**

[![Release](https://img.shields.io/github/v/release/vishwa-10147/SentinelEdgeAI?label=release)](https://github.com/vishwa-10147/SentinelEdgeAI/releases/latest)
[![CI](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml)
[![Security Scans](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205%20%7C%20Jetson%20Orin%20Nano-555)
![Roadmap](https://img.shields.io/badge/roadmap-Phase%201%20of%206%20to%20v2.0-orange)

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
| **Current release** | [`v1.1.0`](https://github.com/vishwa-10147/SentinelEdgeAI/releases/tag/v1.1.0): single-node deployment on a Raspberry Pi |
| **Target hardware** | Raspberry Pi 5 (sensor) and NVIDIA Jetson Orin Nano (AI and management) |
| **Interfaces** | Web console, REST API, WebSocket event stream, Prometheus metrics |
| **Supply chain** | Signed ML model, SHA-256 checksums, CycloneDX SBOM, GitHub build-provenance attestation |
| **Documentation** | [EXPLAIN.md](EXPLAIN.md) (how it works) · [SECURITY.md](SECURITY.md) (security model) · [PLAN.md](PLAN.md) (roadmap) · [CHANGELOG.md](CHANGELOG.md) |

> **Status legend:** ✅ available · 🟡 partial · 🔜 planned (see [PLAN.md](PLAN.md))

### Why it exists

Small businesses, factories, clinics and IoT-heavy sites face the same attack tools as large enterprises, but cannot afford a security operations centre, an enterprise NDR licence, or a cloud service that ships their traffic metadata off site. Many of their devices, such as cameras, PLCs, printers and medical equipment, cannot run endpoint protection. The network is the only place they can be protected.

SentinelEdgeAI fills that gap: **behavioural detection and automated response on about USD 350 of hardware, fully offline.**

---

## Roadmap and progress

```text
Phase 0  Correctness, hygiene, release pipeline   v1.1   ███████████████████░  done, 2 small items open
Phase 1  Secure management plane                  v1.2   ░░░░░░░░░░░░░░░░░░░░  next
Phase 2  Two-node architecture (Pi + Jetson)      v1.3   ░░░░░░░░░░░░░░░░░░░░
Phase 3  Enforcement you can trust                v1.4   ░░░░░░░░░░░░░░░░░░░░
Phase 4  Detection quality                        v1.5   ░░░░░░░░░░░░░░░░░░░░
Phase 5  Integrations and operations              v1.6   ░░░░░░░░░░░░░░░░░░░░
Phase 6  Production release                       v2.0   ░░░░░░░░░░░░░░░░░░░░
Phase 7  Scale and advanced intelligence          v2.x+  ░░░░░░░░░░░░░░░░░░░░  after v2.0
```

**6 phases remain before the v2.0 production release** (Phases 1 to 6), followed by Phase 7, which is ongoing post-release work.

| Phase | Release | Goal | Status |
|---|---|---|---|
| 0 | v1.1 | Fix broken firewall enforcement, remove secrets, safe packaging, signed and attested releases, `sentinelctl` device lifecycle | ✅ Released. Open: licence choice, privileged-runner CI proof |
| 1 | v1.2 | User accounts, roles (Viewer, Analyst, Operator, Admin), MFA, HTTPS, audit log, setup wizard | 🔜 Next |
| 2 | v1.3 | Pi senses and enforces, Jetson runs all AI and management; mTLS link, signed commands, offline buffering | 🔜 |
| 3 | v1.4 | Inline bridge mode, MAC-based quarantine, graduated response playbooks with approval gates | 🔜 |
| 4 | v1.5 | Attack-specific detectors, TLS fingerprints, GPU models, model registry, published accuracy numbers | 🔜 |
| 5 | v1.6 | SIEM export, threat-intel feeds, observability, reports, backup and restore | 🔜 |
| 6 | v2.0 | OS images, OTA updates with A/B rollback, hardened OS, external pen test, 30-day field beta | 🔜 |
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
| User accounts, roles, MFA, audit log, HTTPS | 🔜 |
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

- **Today (v1.1):** everything runs as a single node on a Raspberry Pi. The Pi–Jetson link does not exist yet.
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

**Supported:** Raspberry Pi 5 or 4 with 64-bit Raspberry Pi OS Bookworm (Python 3.11). The package bundles every Python dependency, so the Pi needs **no internet access**.

1. Download `sentineledgeai-pi-<version>.tar.gz` and its `.sha256` from [Releases](https://github.com/vishwa-10147/SentinelEdgeAI/releases) and copy both to the Pi.
2. Optionally verify where the package was built:

   ```bash
   gh attestation verify sentineledgeai-pi-1.1.0.tar.gz --repo vishwa-10147/SentinelEdgeAI
   ```

3. Install:

   ```bash
   sha256sum -c sentineledgeai-pi-1.1.0.tar.gz.sha256
   tar -xzf sentineledgeai-pi-1.1.0.tar.gz
   sudo bash sentineledgeai-pi-1.1.0/deploy/pi/provision_key.sh /path/to/model_signing.key
   sudo bash sentineledgeai-pi-1.1.0/packaging/sentinelctl install sentineledgeai-pi-1.1.0.tar.gz
   ```

4. Open `http://<pi-address>:9000`. The API key generated during install is in `/etc/sentinel/sentinel.env` (`DASHBOARD_API_KEY`).

**Upgrades and rollback**

```bash
sudo sentinelctl upgrade sentineledgeai-pi-1.2.0.tar.gz   # health-checked; rolls back automatically on failure
sudo sentinelctl rollback                                  # return to the previous version
sentinelctl status                                         # active version and service state
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
| `DASHBOARD_API_KEY` | unset | Required on every API call when set (`X-API-Key` or `Bearer`); when unset, only localhost is accepted |
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

Every endpoint requires authentication as described above.

| Method and path | Purpose |
|---|---|
| `GET /api/alerts`, `/api/flows`, `/api/device_profiles`, `/api/risk_timeline`, `/api/live_stats` | Detection data |
| `GET /api/incidents/timeline`, `/api/reports/security`, `POST /api/alerts/explain` | Investigation and reporting |
| `GET /api/device/{id}/logs` | Per-device history |
| `GET/POST /api/firewall/policy`, `GET /api/firewall/rules`, `GET /api/firewall/actions` | Firewall policy and audit trail |
| `POST /api/firewall/block`, `/unblock`, `/whitelist`, `/expire`, `/rollback` | Response actions |
| `GET /api/health`, `GET /metrics` | Health and Prometheus metrics |
| `WS /ws/packets` | Live alerts, flows and demo events |

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

## Known limitations (v1.1)

1. **Single shared API key and no TLS.** Keep the API on a trusted management network until accounts and HTTPS ship in v1.2.
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

No licence has been chosen yet, so all rights are reserved by the author. Choosing one is tracked in [PLAN.md](PLAN.md) Phase 0.
