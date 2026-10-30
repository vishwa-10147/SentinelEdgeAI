# SentinelEdgeAI

**Offline, AI-driven network detection and response (NDR) appliance with an adaptive firewall — built for networks that have no security team.**

SentinelEdgeAI sits on a network, learns how every device normally behaves, detects attacks and compromised devices in real time, and responds automatically — from a dashboard alert up to blocking or quarantining a device — with safety controls that prevent it from ever taking the network down. Everything runs on-premises. No cloud account, no data leaves the site.

| | |
|---|---|
| **Current release** | `v1.1.0` — single-node (Raspberry Pi) release. Production hardening continues toward `v2.0` (see [PLAN.md](PLAN.md)) |
| **Target hardware** | Raspberry Pi 5 (sensor) + NVIDIA Jetson Orin Nano (AI & management) |
| **Interfaces** | Web console (HTTPS), REST API, WebSocket event stream, Prometheus metrics |
| **Docs** | [EXPLAIN.md](EXPLAIN.md) — how it works · [SECURITY.md](SECURITY.md) — security model · [PLAN.md](PLAN.md) — roadmap |

> **Status legend used in all docs:** ✅ available today · 🟡 partially implemented · 🔜 planned (see PLAN.md)

---

## Why it exists

Small and mid-sized organisations, factories, clinics and IoT-heavy sites are attacked with the same tools as large enterprises, but they cannot afford a security operations centre (SOC), an enterprise NDR licence, or a cloud service that ships their traffic metadata off-site. Many of their devices — cameras, PLCs, printers, medical and building-management equipment — cannot run antivirus at all. The network is the only place they can be protected.

SentinelEdgeAI targets exactly that gap: **enterprise-style behavioural detection and automated response, on ~$350 of hardware, fully offline.**

---

## Where it can be used

| Environment | What SentinelEdgeAI protects against |
|---|---|
| **Small & medium businesses** (offices, law/accounting firms, retail) | Ransomware spreading between PCs, data exfiltration, compromised laptops, brute-force on exposed services |
| **Industrial / OT networks** (factories, utilities, building management) | Unexpected traffic from PLCs/SCADA, new devices appearing, lateral movement into control networks. Offline operation suits air-gapped sites |
| **IoT & CCTV networks** | Hijacked cameras and smart devices joining botnets, devices calling out to unknown hosts |
| **Healthcare clinics** | Medical IoT devices that cannot be patched, sensitive data leaving the network |
| **Schools, colleges, hostels, hotels / guest Wi-Fi** | Infected student/guest devices, scanning, abuse of the network |
| **Branch & remote offices** | A sensor per branch reporting to one central brain (multi-sensor mode 🔜) |
| **Managed service providers (MSPs)** | Deploy one appliance per customer site; fleet console 🔜 |
| **Security labs & training** | Realistic, explainable detection with a built-in attack demo for teaching |
| **Home labs / smart homes** | The "Lite" single-Pi profile for advanced home users |

SentinelEdgeAI is **not** a replacement for endpoint protection, email security or patching — it is the network layer of a defence-in-depth setup.

---

## Capabilities

### Detection
| Capability | Status |
|---|---|
| Live packet capture and flow assembly (5-tuple, idle timeout) | ✅ |
| 24 statistical features per flow (bytes, packet rates, inter-arrival times, flags, …) | ✅ |
| Statistical anomaly detection (Z-score) against an adaptive per-IP, per-protocol baseline | ✅ |
| Isolation Forest ML anomaly detection (signed model, runtime verification) | ✅ |
| Per-device behavioural fingerprint and long-term drift detection | ✅ |
| Unified 0–100 risk score, MITRE ATT&CK tactic/technique mapping | ✅ |
| Attack-type classification | 🟡 rule-based today; richer detectors planned |
| Per-protocol thresholds (DNS / TCP / UDP / HTTP), confidence score, multi-stage confirmation | 🔜 |
| GPU deep-learning detectors on Jetson (autoencoder, sequence model for multi-step attacks, graph model for lateral movement) | 🔜 |
| Encrypted-traffic analysis (TLS/JA3/JA4 fingerprints, entropy) | 🔜 |
| Threat-intelligence feeds (STIX/TAXII, IP/domain blocklists) — imported offline | 🔜 |

### Response (adaptive firewall)
| Capability | Status |
|---|---|
| Block / unblock an IP via nftables or iptables (host `INPUT` and forwarded traffic), with time-to-live (TTL) expiry | ✅ |
| Whitelist, response modes (`monitor` / `alert` / `auto_block`), risk threshold policy | ✅ |
| Dry-run by default; atomic enable/disable; full rollback; systemd rollback guard | ✅ |
| Inline bridge mode (layer-2 filtering) and MAC-based device quarantine | 🔜 |
| Graduated response playbooks: alert → rate-limit → block → quarantine, with approval gates | 🔜 |
| Commands from the AI node signed and authenticated (mTLS) | 🔜 |

### Operations
| Capability | Status |
|---|---|
| FastAPI REST API + WebSocket live stream | ✅ |
| React web console: topology map, device detail, analytics, firewall activity, presenter demo | ✅ |
| SQLite storage with retention/VACUUM; optional PostgreSQL backend + migration script | ✅ |
| Prometheus metrics, Grafana dashboards, health endpoint | ✅ |
| Pi installer, packaged tarball, systemd services, Vault-based secret provisioning examples | ✅ |
| CI: unit tests, Bandit, pip-audit, model-signature checks, privileged firewall integration tests | ✅ |
| User accounts, roles (Viewer / Analyst / Operator / Admin), MFA, audit log | 🔜 |
| HTTPS everywhere, rate limiting, security headers | 🔜 |
| SIEM export (syslog/CEF, webhooks, JSON for Splunk/ELK/Microsoft Sentinel) | 🔜 |
| Model registry: versioned, signed, shadow-mode testing, hot reload | 🔜 |
| Multi-sensor and multi-site fleet management | 🔜 |

---

## Architecture

```text
                         ┌──────────────────────────────────────────────┐
   Admin / Analyst  ───► │  JETSON ORIN NANO  —  "Brain"                │
   (browser, HTTPS)      │                                              │
                         │  Web console (React) · REST API · WebSocket  │
                         │  Users, roles, MFA, audit log                │
                         │  AI detection: Isolation Forest + GPU models │
                         │  Risk fusion → Policy engine → Playbooks     │
                         │  Database · Model registry · SIEM export     │
                         └───────────────▲───────────────┬──────────────┘
                     flow features,      │               │  signed response
                     sensor health       │  mTLS link    │  commands
                                         │               ▼
                         ┌───────────────┴──────────────────────────────┐
   Network traffic  ───► │  RASPBERRY PI 5  —  "Sensor"                 │
   (mirror port or       │                                              │
    inline bridge)       │  Packet capture → Flows → Feature extraction │
                         │  Local fast-path detector (works offline)    │
                         │  Enforcement agent (nftables) + rollback     │
                         │  Disk buffer if the brain is unreachable     │
                         └──────────────────────────────────────────────┘
```

* **Today (v1.1)** everything runs as a single node — normally the Raspberry Pi — and the Pi ↔ Jetson link does not exist yet.
* **Target (v2.0)** splits the system as drawn above: the Pi only senses and enforces; the Jetson does all AI work and owns users, data and the console. One Jetson can serve several sensors.
* The sensor is **fail-safe**: if the brain is offline it keeps basic detection running, buffers data to disk, and never blocks traffic because a link failed.

See [EXPLAIN.md](EXPLAIN.md) for a step-by-step walkthrough.

### Deployment profiles

| Profile | Hardware | Intended for |
|---|---|---|
| **Lite** | 1 × Raspberry Pi 5 | Home labs, very small offices, evaluation (works today) |
| **Standard** 🔜 | 1 × Pi 5 + 1 × Jetson Orin Nano | SMBs, clinics, OT cells — the reference deployment |
| **Multi-sensor** 🔜 | N × Pi 5 + 1 × Jetson | Several network segments or floors |
| **Fleet** 🔜 | Many sites + central console | MSPs and multi-branch organisations |

### Network placement

* **Passive (recommended first):** a managed switch mirrors traffic (SPAN port) to the Pi. Zero risk to the network; can alert but cannot block forwarded traffic.
* **Inline 🔜:** the Pi bridges WAN ↔ LAN and can block and quarantine. Requires two NICs and a hardware or software bypass so traffic keeps flowing if the appliance fails.

---

## Hardware

| Component | Role | Notes |
|---|---|---|
| Raspberry Pi 5 (8 GB) | Sensor: capture, features, enforcement | Active cooling; NVMe/SSD for logs |
| NVIDIA Jetson Orin Nano (8 GB) | Brain: AI inference, database, console | JetPack 6.x; NVMe SSD |
| Second NIC (USB 3 / PCIe) | Required for inline mode | Gigabit or better |
| Managed switch with port mirroring | Required for passive mode | 802.1Q VLAN support recommended |

Approximate hardware cost for the Standard profile: **USD 300–400**.

---

## Quick start (developer machine)

> This runs the current single-node build in **dry-run** mode — nothing is ever blocked.

**Requirements:** Python 3.11+, Node.js 20.19+, Linux or macOS (packet capture needs root/`CAP_NET_RAW`; Windows needs Npcap).

```bash
git clone https://github.com/vishwa-10147/SentinelEdgeAI.git
cd SentinelEdgeAI
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt   # runtime deps + test/security tools

# build the web console
(cd frontend && npm ci && npm run build)

# start the API + console on http://127.0.0.1:9000 (localhost-only by default)
python dashboard/dashboard_api.py
```

Generate traffic and alerts without touching a real network:

```bash
python scripts/demo_attack.py --ip 192.168.1.50 --block   # simulated attack → alert → (dry-run) block
python scripts/replay_pcap.py <file.pcap> # replay a capture through the pipeline
```

Run the detection engine with live capture (needs root):

```bash
sudo .venv/bin/python main.py
```

Run the tests:

```bash
pytest -q
```

Docker (API + console, dry-run): `docker compose up -d --build` then open `http://localhost:9000`.

### Raspberry Pi installation

**Supported:** Raspberry Pi 5 (or 4) with 64-bit Raspberry Pi OS Bookworm (Python 3.11). The package contains every Python dependency, so the Pi needs **no internet access** to install.

1. Download `sentineledgeai-pi-<version>.tar.gz` and its `.sha256` from the [GitHub Releases](https://github.com/vishwa-10147/SentinelEdgeAI/releases) page and copy both to the Pi.
2. First install:

   ```bash
   sha256sum -c sentineledgeai-pi-1.1.0.tar.gz.sha256
   tar -xzf sentineledgeai-pi-1.1.0.tar.gz
   sudo bash sentineledgeai-pi-1.1.0/deploy/pi/provision_key.sh /path/to/model_signing.key
   sudo bash sentineledgeai-pi-1.1.0/packaging/sentinelctl install sentineledgeai-pi-1.1.0.tar.gz
   ```

3. Open `http://<pi-address>:9000`. The API key was generated during install and is in `/etc/sentinel/sentinel.env` (`DASHBOARD_API_KEY`).

Later versions:

```bash
sudo sentinelctl upgrade sentineledgeai-pi-1.2.0.tar.gz   # health-checked; rolls back automatically on failure
sudo sentinelctl rollback                                  # return to the previous version
sentinelctl status                                         # active version and service state
```

**Where things live on the device**

| Path | Contents | Touched by upgrades? |
|---|---|---|
| `/opt/sentineledgeai/releases/<version>/` | Code and its own Python environment | Added; old ones pruned (last 3 kept) |
| `/opt/sentineledgeai/current` → `releases/<version>` | The active version | Switched atomically |
| `/etc/sentinel/` | `sentinel.env` (settings, API key), `config.yaml`, `model_signing.key` | Never |
| `/var/lib/sentinel/` | Database, firewall rules/policy, alerts, device profiles | Never |
| `/var/log/sentinel/` | Logs and the firewall action log | Never |

Services: `sentineledgeai-engine` (capture and detection), `sentineledgeai-api` (API and console), and the `sentineledgeai-rollback-guard` timer. They run as the unprivileged `sentinel` user with only `CAP_NET_RAW`/`CAP_NET_ADMIN`.

**Enabling real blocking:** after reviewing alerts in dry-run mode, set `FIREWALL_DRY_RUN=0` and `ENABLE_ROLLBACK_GUARD=1` in `/etc/sentinel/sentinel.env`, then `sudo systemctl restart sentineledgeai-engine sentineledgeai-api`. See [SECURITY.md](SECURITY.md) §6 first.

**Building a package yourself:** `bash scripts/build_pi_package.sh` (needs Node.js 20.19+ and Python with pip) writes `dist/sentineledgeai-pi-<version>.tar.gz` and its checksum. Releases are normally built by CI when a `vX.Y.Z` tag is pushed.

The older installers (`packaging/pi/install_from_package.sh`, `deploy/pi/install_pi.sh`, `scripts/setup_pi.sh`) are kept for existing devices; see [deploy/pi/README.md](deploy/pi/README.md).

---

## Configuration

Detection tuning lives in [config.yaml](config.yaml) (risk thresholds, baseline window, Z-score threshold, flow timeouts, logging). Runtime behaviour is controlled with environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `FIREWALL_DRY_RUN` | `1` | `1` = record actions only; `0` = apply real firewall rules |
| `SENTINEL_FIREWALL_BACKEND` | `auto` | `auto`, `nft` or `iptables` |
| `DASHBOARD_API_KEY` | *(unset)* | If set, required on every API call (`X-API-Key` or `Bearer`). If unset, the API only accepts requests from localhost |
| `SENTINEL_HOST` / `SENTINEL_PORT` | `127.0.0.1` / `9000` | API bind address and port |
| `SENTINEL_MODEL_SIGNING_KEY` / `_FILE` | *(unset)* | Key used to verify the ML model signature. **Never commit it** |
| `SENTINEL_ALLOW_UNSIGNED_MODELS` | `0` | Development only — allow loading an unsigned model |
| `DATABASE_URL` | *(unset)* | Use PostgreSQL instead of SQLite |
| `SENTINEL_DB_PATH` | `data/sentinel.db` | SQLite file location |
| `CAPTURE_IN_PROCESS` / `CAPTURE_IFACE` | `0` / all | Run capture inside the API process; interface to capture on |
| `REDACT_SENSITIVE` / `REDACT_SALT` | `0` / — | Hash IPs/MACs in API responses (for demos and screenshots) |
| `HEALTH_USER` / `HEALTH_PASS` | *(unset)* | Basic auth for the health endpoint |
| `DISABLE_DB_MAINTENANCE` | `0` | Disable background retention/VACUUM |

Default ports: API/console `9000`, health `5000`, Prometheus metrics `8001`.

---

## API overview

All endpoints require authentication as described above. Selected endpoints:

| Method & path | Purpose |
|---|---|
| `GET /api/alerts`, `/api/flows`, `/api/device_profiles`, `/api/risk_timeline`, `/api/live_stats` | Detection data |
| `GET /api/incidents/timeline`, `/api/reports/security`, `POST /api/alerts/explain` | Investigation and reporting |
| `GET /api/device/{id}/logs` | Per-device history |
| `GET/POST /api/firewall/policy`, `GET /api/firewall/rules`, `GET /api/firewall/actions` | Firewall policy and audit trail |
| `POST /api/firewall/block`, `/unblock`, `/whitelist`, `/expire`, `/rollback` | Response actions |
| `GET /api/health`, `GET /metrics` | Health and Prometheus metrics |
| `WS /ws/packets` | Live alerts, flows and demo events |

The OpenAPI document is intentionally not public; it is served at `/openapi.json` to authenticated clients.

---

## Repository layout

```text
capture/      packet capture and the ingest loop (Scapy)
flow/         flow records and the flow table
features/     per-flow feature extraction
detection/    baseline, Z-score, Isolation Forest, fingerprinting, risk, MITRE mapping
core/         engine, firewall enforcement, storage (SQLite/PostgreSQL), health, config
security/     model signing and verification
dashboard/    FastAPI backend (and the legacy Streamlit dashboard)
frontend/     React web console (Vite)
deploy/       Raspberry Pi, Jetson, monitoring and Grafana deployment files
packaging/    systemd units, rollback guard, logrotate, Prometheus alerts
scripts/      installers, demo/replay tools, training, signing, CI helpers
tests/        unit and integration tests
docs/         additional documentation and archived material
```

---

## Known issues (v1.1)

1. **Single shared API key, no TLS.** Do not expose the API beyond a trusted management network until user accounts and HTTPS land (see [SECURITY.md](SECURITY.md)).
2. **No inline bridge mode yet.** Blocks cover traffic to the appliance and traffic it routes (`FORWARD`), but bridge-level filtering and MAC quarantine are Phase 3.

Fixed in `v1.1.0`: firewall commands were rejected by the subprocess wrapper so no rule was ever applied; the nftables backend never attached its blacklist set to a chain; iptables unblock did not match the inserted rule; rules only covered `INPUT`.

---

## Contributing

1. Open an issue describing the change first.
2. Branch from `main` (`feature/…`, `fix/…`, `chore/…`).
3. Make sure `pytest -q`, Bandit and pip-audit pass, and that new behaviour has tests.
4. Open a pull request. Security-sensitive changes (firewall, auth, signing) need a second reviewer.

Security issues: **do not open a public issue** — follow [SECURITY.md](SECURITY.md).

## License

No licence has been chosen yet, so all rights are reserved by the author. Choosing a licence is tracked in [PLAN.md](PLAN.md).

The previous, longer README is preserved at [docs/archive/README_v0_legacy.md](docs/archive/README_v0_legacy.md).
