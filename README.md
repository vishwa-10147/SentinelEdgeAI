<div align="center">

# SentinelEdgeAI

**Offline, AI-driven network detection and response with an adaptive firewall, for networks that have no security team.**

[![Release](https://img.shields.io/github/v/release/vishwa-10147/SentinelEdgeAI?label=release)](https://github.com/vishwa-10147/SentinelEdgeAI/releases/latest)
[![CI](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml)
[![Security Scans](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205%20%7C%20Jetson%20Orin%20Nano-555)
![Roadmap](https://img.shields.io/badge/roadmap-v2.x%20%C2%B7%20Phase%207%20in%20progress-blue)

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
| **Current release** | [`v2.9.3`](https://github.com/vishwa-10147/SentinelEdgeAI/releases/tag/v2.9.3): production candidate, all phases (0–7) built — single-node or sensor/brain deployment, trusted enforcement, detection fusion, SIEM integrations, signed OTA updates, OT protocol awareness and micro-segmentation, device trust and containment, fleet manager, federated learning, response tuning, high availability, compliance packs (pen test and beta pending) |
| **Target hardware** | Raspberry Pi 5 (sensor) and NVIDIA Jetson Orin Nano (AI and management) |
| **Supply chain** | Signed ML model, reproducible packages, Sigstore/cosign signatures, SHA-256 checksums, CycloneDX SBOM, GitHub build-provenance attestation |
| **Supply chain** | Signed ML model, SHA-256 checksums, CycloneDX SBOM, GitHub build-provenance attestation |
| **Documentation** | [Admin guide](docs/ADMIN_GUIDE.md) · [Runbooks](docs/RUNBOOKS.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) · [API reference](docs/API.md) · [Performance](docs/PERFORMANCE.md) · [Evaluation](docs/EVALUATION.md) · [EXPLAIN.md](EXPLAIN.md) · [SECURITY.md](SECURITY.md) · [PLAN.md](PLAN.md) · [CHANGELOG.md](CHANGELOG.md) |

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
Phase 6  Production release                       v2.0   ██████████████░░░░░░  released; OS images, pen test, beta pending
Phase 7  Scale and advanced intelligence          v2.x   ████████████████████  all 7 themes built (v2.0–v2.9)
Phase 8  Proven in the field                      v3.0   ░░░░░░░░░░░░░░░░░░░░  next: pen test, beta, soak, Jetson, OS images
Phase 9  Deeper visibility                        v3.x   ░░░░░░░░░░░░░░░░░░░░  SMB/RDP/Kerberos, more OT, packet buffer, IPv6
Phase 10 Assisted operations                      v4.0   ░░░░░░░░░░░░░░░░░░░░  incidents, optional local assistant, SSO, mobile
Phase 11 Platform and ecosystem                   v4.x+  ░░░░░░░░░░░░░░░░░░░░  multi-tenant MSP fleet, x86 10 Gb/s, certification
```

**All phases (0–7) are built (v2.9).** Everything is tested in simulation, in real-kernel network-namespace tests, against real PostgreSQL and on a Raspberry Pi 5 running the released packages. What remains needs hardware, outside people or time rather than code: Jetson validation and GPU models, a 72-hour inline soak, a real SIEM run, pre-built OS images, an external penetration test and a 30-day beta, plus a few software follow-ups listed in [PLAN.md](PLAN.md) (UNSW-NB15 and CIC-IoT2023 loaders, fleet-wide remote actions and alert search, VLAN reassignment through switch APIs).

| Phase | Release | Goal | Status |
|---|---|---|---|
| 0 | v1.1 | Fix broken firewall enforcement, remove secrets, safe packaging, signed and attested releases, `sentinelctl` device lifecycle | ✅ Released |
| 1 | v1.2 | User accounts, roles (Viewer, Analyst, Operator, Admin), MFA, HTTPS, audit log, setup wizard | ✅ Released; exit checks met (role test per endpoint, clean ZAP baseline) |
| 2 | v1.3 | Pi senses and enforces, Jetson runs all AI and management; mTLS link, signed commands, offline buffering | 🟡 Built, including the event bus, brain PostgreSQL, brain-distributed sensor upgrades and the sensors panel (v2.5); brain outage, forged/replayed commands and 3 sensors verified in simulation and on the Pi. Pending: Jetson hardware |
| 3 | v1.4 | Inline bridge mode, MAC-based quarantine, graduated response playbooks with approval gates | 🟡 Built, with console panels for approvals, restrictions and policy (v2.5); 22/22 real-kernel checks (routed and bridged), rollback ~100 ms. Pending: 72 h inline soak |
| 4 | v1.5 | Attack-specific detectors, TLS fingerprints, GPU models, model registry, published accuracy numbers | 🟡 Built, with console views for models, feedback and evaluation (v2.5); CIC-IDS2017: brute force, port scan, infiltration detected, 4/8 bots, 0.02–0.05% false positives per flow ([results](docs/EVALUATION.md)). Pending: UNSW-NB15, GPU models |
| 5 | v1.6 | SIEM export, threat-intel feeds, observability, reports, backup and restore | 🟡 Built; SIEM delivery < 5 s and full restore verified. Pending: real Splunk/ELK run |
| 6 | v2.0 | OS images, OTA updates with A/B rollback, hardened OS, external pen test, 30-day field beta | 🟡 Released as v2.0; installer, OTA, reproducible Sigstore-signed builds, hardening, container, docs, 25–31× faster capture and decisions. Pending: OS images, pen test, beta |
| 7 | v2.x+ | Fleet manager, zero-trust segmentation, federated learning, RL response tuning, OT protocols, high availability, compliance packs | ✅ OT protocol awareness (v2.0–v2.1), OT micro-segmentation (v2.2), device trust and containment (v2.3), the fleet manager (v2.4), federated learning (v2.6), response tuning (v2.7), high availability (v2.8) and compliance packs (v2.9): all seven themes built |

Each phase has explicit exit criteria in [PLAN.md](PLAN.md) and is only marked done when all of them are met.

### Releases

| Version | Highlights |
|---|---|
| **v2.9.3** | Fix: device state files update again (2.9.2 regression) |
| v2.9.2 | Flood safety: bounded memory under spoofed floods (~460 MB at 322k packets/s, was 1.2 GB in 40 s), overload alert |
| v2.9.1 | CIC-IDS2017 evaluation published; loader fixed for the dataset's 12-hour clock and minute timestamps |
| v2.9.0 | Compliance packs: live evidence for ISO 27001, IEC 62443 and NIS2, as JSON and PDF |
| v2.8.0 | High availability: active/standby brains with automatic sensor failover, dual sensors per segment |
| v2.7.0 | Response tuning: learns the least disruptive response that resolves each kind of incident, inside the playbook's bounds |
| v2.6.0 | Federated learning: sites train the autoencoder together and share only model updates |
| v2.5.0 | Operations console, live-stream event bus (resume, resync, heartbeats), brain on PostgreSQL, sensor upgrades through the brain |
| v2.4.0 | Fleet manager: many sites in one console, configuration templates, staged rollouts that pause on failure |
| v2.3.1 | Trust scores calibrated on live traffic (one penalty per alert kind; protected hosts and loopback handled) |
| v2.3.0 | Device trust scores (0–100, with reasons), learned peer profiles, `contain` response (keep only normal peers) |
| v2.2.0 | OT micro-segmentation from learned allow-lists (off / monitor / enforce) |
| v2.1.0 | OT asset inventory (API and console), learning survives restarts |
| v2.0.1 | Offline package for both Python 3.11 (Bookworm) and 3.13 (Trixie) |
| v2.0.0 | Phases 2–6 and OT protocol awareness (Modbus, DNP3, BACnet, OPC UA) |
| v1.2.0 | Secure management plane: accounts, roles, MFA, HTTPS, audit log |

All releases: [Releases](https://github.com/vishwa-10147/SentinelEdgeAI/releases) · full notes: [CHANGELOG.md](CHANGELOG.md).

---

## Who it is for

Organisations that need network detection and response but have **no security team**:
- small and medium businesses
- industrial and OT sites (water, energy, manufacturing, building automation)
- clinics
- schools, hotels and guest Wi-Fi
- branch and retail networks
- the **MSPs** who look after them
- NIS2-regulated mid-size organisations preparing for an audit
- home labs and trainers

Inside an organisation, Viewers read, Analysts label alerts, Operators approve and undo responses, and Admins configure. PLAN.md has the [full list of users](PLAN.md#who-it-is-for), [where the product goes next](PLAN.md#where-it-goes-next) and [how far it can scale](PLAN.md#how-far-it-can-go).

## How the "AI" works (and what it is not)

It uses small classical models: an Isolation Forest, a compact autoencoder, per-device and per-hour baselines, attack-pattern detectors and an evidence-fusion step. Each decision takes well under a millisecond on a Raspberry Pi. **There is no large language model**: explanations are templates filled with evidence, so there is nothing to prompt-inject. The models can't act on their own either; every response passes the playbook, your policy, the protected-host list and, for high-impact steps, an Operator's approval. Every table the engine keeps has a size limit, so a flood of fake addresses can't run it out of memory: it raises a "capture overloaded" alert and keeps going. Details are in [EXPLAIN.md](EXPLAIN.md#what-the-ai-is-and-is-not) and [SECURITY.md](SECURITY.md).

## Use cases

| Environment | What SentinelEdgeAI protects against |
|---|---|
| **Small and medium businesses** | Ransomware spreading between PCs, data exfiltration, compromised laptops, brute force against exposed services |
| **Industrial and OT networks** | New masters commanding PLCs, first-time writes, restart/stop commands and unit-id sweeps over Modbus, DNP3, BACnet and OPC UA; OT micro-segmentation from learned allow-lists. Offline operation suits air-gapped sites |
| **IoT and CCTV networks** | Hijacked cameras and smart devices joining botnets or calling out to unknown hosts |
| **Healthcare clinics** | Unpatchable medical devices, sensitive data leaving the network |
| **Schools, hostels, hotels and guest Wi-Fi** | Infected guest devices, scanning, network abuse |
| **Branch offices** | One sensor per branch reporting to a central brain over mutual TLS |
| **Managed service providers** | One appliance per customer site, all in one self-hosted fleet console |
| **Security training labs** | Explainable detection with a built-in attack demo |
| **Home labs** | The single-Pi "Lite" profile |

SentinelEdgeAI is the **network layer** of a defence-in-depth setup. It does not replace endpoint protection, email security or patching.

---

## Capabilities

### Detection

| Capability | Status |
|---|---|
| Live packet capture (AF_PACKET fast path, ~121k packets/s on a Pi 5) and flow assembly | ✅ |
| 24 statistical features per flow; adaptive per-IP, per-protocol and hour-of-day baselines | ✅ |
| Isolation Forest (compiled, 3,800 decisions/s) and a CPU autoencoder, both signed and verified at load | ✅ |
| Detectors: port scan, host sweep, brute force, beaconing, exfiltration, new device, DNS tunnelling, DGA | ✅ |
| Encrypted-traffic metadata: JA3/JA4, SNI, ALPN (no decryption) | ✅ |
| Fusion with calibrated confidence, multi-stage confirmation and an explanation on every alert | ✅ |
| MITRE ATT&CK (and ATT&CK for ICS) technique on every finding | ✅ |
| OT protocols: Modbus/TCP, DNP3, BACnet/IP, OPC UA, with per-controller learning | ✅ |
| Threat intelligence: STIX 2.1, TAXII 2.1 and plain lists, matched on flows, DNS and TLS | ✅ |
| Suricata `eve.json` as a detector input | ✅ |
| Model registry: shadow → canary → active, hot reload, rollback; analyst feedback recalibrates detectors | ✅ |
| Device trust score (0–100) with reasons and a recommended response | ✅ |
| Federated learning across sites: only model updates leave a site, results arrive as shadow models | ✅ |
| GPU detectors on the Jetson (TensorRT autoencoder, sequence and graph models) | 🔜 hardware |

### Response (adaptive firewall)

| Capability | Status |
|---|---|
| Block and unblock IPv4 and IPv6 via nftables or iptables/ip6tables, with TTL expiry | ✅ |
| Quarantine (DNS, DHCP and a quarantine page only), per-source rate limiting | ✅ |
| **Containment:** an untrusted device keeps only the peers and ports it normally uses | ✅ |
| **OT micro-segmentation:** only learned masters reach a controller's industrial ports | ✅ |
| Graduated playbook (alert → rate-limit → contain → block → quarantine) with Operator approval above a risk threshold | ✅ |
| **Response tuning:** learns the least disruptive response that resolves each kind of incident, never beyond the playbook | ✅ |
| Protected hosts (gateway, DNS, DHCP, the appliance, management hosts) are never restricted | ✅ |
| Inline bridge mode with MAC-based quarantine; fail-open watchdog | ✅ |
| Response policy as code (YAML, validation, dry-run diff, history) | ✅ |
| Signed, sequenced, expiring commands from the brain to sensors (mTLS) | ✅ |
| High availability: active/standby brains (shared keys and PostgreSQL, leader lease), sensor failover, dual sensors per segment | ✅ |
| Dry run by default, full rollback in ~100 ms, systemd rollback guard | ✅ |
| Flood safety: bounded memory, load shedding and a capture-overload alert under spoofed floods | ✅ |

### Operations

| Capability | Status |
|---|---|
| Live stream: event bus with cursors, resume after reconnect, heartbeats | ✅ |
| Storage: SQLite by default, PostgreSQL for the engine and the brain | ✅ |
| FastAPI REST API (111 endpoints, [reference](docs/API.md)) and authenticated WebSocket stream | ✅ |
| React console: topology, device detail, analytics, firewall, operations (approvals, restrictions, policy, sensors, models, evaluation), trust, OT devices, fleet, users, audit, setup | ✅ |
| User accounts (Argon2id), four roles, TOTP two-step sign-in, scoped API tokens, login lockout | ✅ |
| HTTPS by default, security headers, API rate limits, hash-chained audit log | ✅ |
| SIEM export: syslog/CEF (UDP/TCP/TLS), signed webhooks, JSON lines, Slack, Teams, email | ✅ |
| Prometheus metrics, Grafana dashboard, alert rules, JSON logs | ✅ |
| Daily/weekly PDF reports, per-device history, compliance export | ✅ |
| Compliance packs: ISO 27001, IEC 62443, NIS2 evidence from the live appliance (documentation support, not certification) | ✅ |
| Encrypted backup and restore (`sentinelctl backup|restore`) | ✅ |
| One-command installer, presets (Home, Office, OT, Enterprise), hardened OS script | ✅ |
| Over-the-air updates: SHA-256 and cosign verified, health-checked, automatic rollback | ✅ |
| Releases: reproducible, Sigstore-signed, CycloneDX SBOM, build provenance | ✅ |
| Fleet manager: many sites, configuration templates, staged rollouts with automatic pause | ✅ |

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

- **Standalone (Lite):** everything runs on one Raspberry Pi. This is how most installs run today.
- **Sensor + brain:** the Pi senses and enforces, and the brain runs AI work and owns users, data and the console. The link is mutual TLS with signed commands, and one brain serves several sensors. This is built and tested in simulation; it has not yet run on Jetson hardware.
- **Fail-safe by design:** if the brain is offline, the sensor keeps basic detection running, buffers data to disk, and never blocks traffic because a link failed.

### Deployment profiles

| Profile | Hardware | Intended for | Available |
|---|---|---|---|
| **Lite** | 1 × Raspberry Pi 5 | Home labs, very small offices, evaluation | ✅ v1.1 |
| **Standard** | 1 × Pi 5 + 1 × Jetson Orin Nano | SMBs, clinics, OT cells (reference deployment) | 🟡 v2.0 (Jetson untested) |
| **Multi-sensor** | N × Pi 5 + 1 × Jetson | Several segments or floors | 🟡 v2.0 (Jetson untested) |
| **High availability** | N × Pi 5 + 2 brains + PostgreSQL | Sites that cannot lose their brain | 🟡 v2.8 (Jetson untested) |
| **Fleet** | Many sites + central console | MSPs and multi-branch organisations | ✅ v2.4 |

### Network placement

- **Passive (recommended first):** a managed switch mirrors traffic to the Pi. No risk to the network; it can alert but cannot block forwarded traffic.
- **Inline:** the Pi bridges WAN and LAN and can block, quarantine, contain and segment. It needs two NICs. A software watchdog fails open, and a hardware bypass is recommended so traffic keeps flowing if the appliance fails.

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
   gh attestation verify sentineledgeai-pi-2.9.3.tar.gz --repo vishwa-10147/SentinelEdgeAI
   ```

3. Install:

   ```bash
   sha256sum -c sentineledgeai-pi-2.9.3.tar.gz.sha256
   tar -xzf sentineledgeai-pi-2.9.3.tar.gz
   sudo bash sentineledgeai-pi-2.9.3/deploy/pi/provision_key.sh /path/to/model_signing.key
   sudo bash sentineledgeai-pi-2.9.3/packaging/sentinelctl install sentineledgeai-pi-2.9.3.tar.gz
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
| `SENTINEL_CAPTURE` | `auto` | `auto` (AF_PACKET when permitted), `afpacket` or `scapy` |
| `SENTINEL_MAX_FLOWS` | `100000` | Active flows tracked; beyond this the least recently active are evicted (flood safety, ~860 bytes each) |
| `SENTINEL_MAX_SOURCES` | `20000` | Sources each detector keeps state for (flood safety) |
| `SENTINEL_MAX_DEVICES` | `20000` | Rows in the device registry |
| `SENTINEL_BRIDGE` | from Setup | `1` mirrors enforcement into the bridge table (inline placement) |
| `SENTINEL_BRAIN_DATABASE_URL` | unset | PostgreSQL for the brain (falls back to `DATABASE_URL`); required for a standby brain |
| `SENTINEL_BRAIN_PORT` / `SENTINEL_FLEET_PORT` | `9443` / `9444` | Sensor-facing brain link / site-facing fleet server (mutual TLS) |
| `SENTINEL_UPDATE_URL` | GitHub releases | Release source for `sentinelctl update` (or a `file://` mirror) |
| `SENTINEL_REQUIRE_SIGNATURE` | `0` | `1` refuses updates whose cosign signature cannot be checked |
| `ENABLE_FILE_FALLBACK` | `1` | Also stream the engine's `live_stats.json` / `live_events.jsonl` to the console |

Default ports: console and API `9000`, engine metrics `9101`, brain link `9443`, fleet server `9444`.

---

## API

Every endpoint except sign-in requires authentication: a console access token, a scoped API token (`Authorization: Bearer …`) or the shared API key. Each endpoint has a minimum role, which a test enforces for every route. The full generated list of all 111 endpoints is in **[docs/API.md](docs/API.md)**.

| Role | Can |
|---|---|
| Viewer | Read dashboards, alerts, devices, trust scores, OT inventory, firewall state, reports |
| Analyst | Viewer + label alerts (true/false positive) and request explanations |
| Operator | Analyst + block, quarantine, rate-limit, contain, release, approve playbook actions, rollback |
| Admin | Operator + users, setup, response policy, integrations, threat intel, models, OT segmentation, fleet, audit log |

Operators and Admins must set up two-step sign-in (an authenticator app) at their next sign-in. The first admin does this right after choosing a new password, so have a phone with an authenticator app ready.

| Area | Main endpoints |
|---|---|
| Sign-in and accounts | `/api/auth/*`, `/api/users`, `/api/tokens`, `/api/audit` |
| Detection data | `/api/alerts`, `/api/flows`, `/api/device_profiles`, `/api/live_stats`, `/api/alerts/feedback` |
| Devices and trust | `/api/devices/identity`, `/api/trust`, `/api/devices/{ip}/peers`, `/api/devices/{ip}/history` |
| Response | `/api/firewall/block`, `/unblock`, `/quarantine`, `/ratelimit`, `/contain`, `/release`, `/rollback`, `/api/playbook/pending`, `/api/policy`, `/api/tuning` |
| OT | `/api/ot/assets`, `/api/ot/segmentation` (+ `/allow`, `/refresh`) |
| Two-node | `/api/brain/*` (incl. `/api/brain/upgrade`), `/api/sensor/*` |
| Fleet | `/api/fleet`, `/api/fleet/codes`, `/sites/{id}/revoke`, `/templates`, `/groups`, `/groups/{name}/rollout`, `/api/fleet/agent` |
| Models and evaluation | `/api/models`, `/api/eval/latest` |
| Integrations, reports, compliance | `/api/integrations`, `/api/intel`, `/api/reports/*`, `/api/export/compliance`, `/api/compliance/*` |
| Health | `/api/health`, `/metrics`, `WS /ws/packets` (send `{"type": "auth", "token": "…"}` first) |

The OpenAPI document is served at `/openapi.json` to authenticated clients only.

---

## Repository layout

```text
capture/      packet capture (AF_PACKET fast path, Scapy for deep inspection) and the ingest loop
flow/         flow records and the flow table
features/     per-flow feature extraction
detection/    baselines, Isolation Forest, autoencoder, detectors, DNS, TLS, OT protocols,
              fusion, model registry, feedback, peer profiles
enforcement/  playbook, response tuning, policy as code, protected hosts, device identity,
              OT segmentation, trust scores, watchdog
core/         engine, firewall (nftables/iptables), auth, audit, storage, setup, health
brain/        two-node brain: CA, enrolment, sensor registry, signed commands, upgrades, HA
sensor/       two-node sensor: link client, disk buffer, command executor
common/       link protocol and PKI shared by brain and sensor
fleet/        fleet server, site agent, staged rollouts, configuration templates, federated rounds
integrations/ SIEM export, webhooks, chat and email, Suricata input
intel/        threat-intelligence feeds (STIX/TAXII, lists)
reporting/    PDF and JSON reports
compliance/   ISO 27001, IEC 62443 and NIS2 evidence packs
ops/          encrypted backup and restore
evaluation/   evaluation harness and datasets
security/     model signing and verification
dashboard/    FastAPI backend
frontend/     React web console (Vite)
presets/      response presets: home, office, ot, enterprise
packaging/    sentinelctl, systemd units, rollback guard, logrotate, Prometheus alerts
deploy/       Raspberry Pi, Jetson, monitoring and Grafana deployment files
scripts/      installer, package build, demo and replay tools, training, signing, CI helpers
tests/        unit tests and real-kernel network-namespace tests (tests/firewall_netns/)
docs/         admin guide, runbooks, troubleshooting, API reference, performance, pen-test scope, beta plan
```

---

## Known limitations (v2.9.3)

1. **Self-signed certificate by default.** Browsers warn until you import a certificate from your own CA (`sentinelctl tls import`).
2. **Jetson brain not yet run on hardware.** Two-node mode is verified in simulation and on the Pi; GPU models wait for the Jetson.
3. **Passive placement cannot stop traffic.** Blocks, quarantine, containment and OT segmentation act on traffic to or through the device. On a mirror port SentinelEdgeAI alerts only.
4. **Containment and OT segmentation are IPv4 only.** Use quarantine for IPv6 hosts.
5. **Bridged traffic has no conntrack on this kernel.** In inline bridge mode, containment stops new TCP connections and off-profile UDP, but packets of existing connections pass.
6. **Not yet externally tested.** The penetration test and the 30-day field beta are still to come ([PENTEST_SCOPE](docs/PENTEST_SCOPE.md), [BETA_PROGRAM](docs/BETA_PROGRAM.md)).
7. **Floods degrade detection.** Under a flood of spoofed addresses memory stays bounded and you get a "capture overloaded" alert, but detection is partial until the flood stops; stopping it needs your router, switch or the inline rate limit.
8. **Service memory limits are inactive on stock Raspberry Pi OS**, which boots with the memory cgroup off. The in-process limits still apply; add `cgroup_enable=memory` to `/boot/firmware/cmdline.txt` to enable the systemd ones.
9. **Throughput.** A Pi 5 captures about 120,000 packets/s (~0.5–1 Gb/s of typical traffic). Busier links need the Jetson brain or, later, an x86 sensor.

---

## Contributing

1. Open an issue describing the change.
2. Add tests for new behaviour. `pytest -q`, Bandit and pip-audit must pass. For capture or enforcement changes, also run the real-kernel tests: `sudo bash tests/firewall_netns/run_enforcement_netns.sh`, `run_segmentation_netns.sh`, `run_containment_netns.sh` and `run_flood_netns.sh`.
3. Update [CHANGELOG.md](CHANGELOG.md) and the documentation the change affects.
4. Changes to the firewall, authentication, signing or the update path need a second reviewer.

**Security issues:** do not open a public issue. Follow the disclosure process in [SECURITY.md](SECURITY.md).

## License

SentinelEdgeAI is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution. You may use, modify and distribute it, including commercially, provided you keep the licence and notice files.

Unless you state otherwise, any contribution you submit is licensed under the same terms (Apache-2.0 §5).
