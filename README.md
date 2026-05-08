<div align="center">

# 🛡️ SentinelEdgeAI

### AI-Powered Edge Cyber Defense Box

**Real-time network anomaly detection, behavioral profiling, and adaptive threat response — running fully on-premises, no cloud required.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205%20%2B%20Jetson%20Orin%20Nano-green?style=flat-square)](https://www.nvidia.com/en-us/autonomous-machines/embedded-systems/jetson-orin/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-purple?style=flat-square)](https://attack.mitre.org/)

## Deployment Validation & Firewall Integration Tests

Follow these steps to validate deployment, run the containerized firewall integration tests, and exercise rollback/playbook procedures.

- Run the normal test suite (already run in CI):

```bash
# from repo root
pytest -q
```

- Run the privileged containerized firewall integration tests (requires Docker and NET_ADMIN capabilities). Set the guard variable to enable these tests locally:

```bash
export SENTINEL_RUN_FIREWALL_CONTAINER_TESTS=1
sudo -E pytest -q tests/test_firewall_container_integration.py
```

Notes:
- The container tests build a small privileged container under `tests/firewall_container/` and exercise both `nft` and `iptables` backends. They are skipped by default to avoid requiring root in normal dev runs.

## Firewall Rollback Playbook (Emergency)

Use the API rollback endpoint to remove all active blocks (safe in dry-run mode; use caution if enforcement is enabled):

```bash
# Emergency rollback via API (requires API key if set)
curl -X POST http://localhost:9000/api/firewall/rollback \
  -H 'Content-Type: application/json' \
  -d '{"reason":"emergency_revert"}'
```

If you prefer a system-level rollback (when running enforcement on a Pi), create a small systemd drop-in that calls the rollback endpoint or runs the included helper script. Example snippet for a one-shot rollback script:

```bash
#!/bin/sh
# /usr/local/bin/sentinel_rollback.sh
curl -sS -X POST http://127.0.0.1:9000/api/firewall/rollback -H 'Content-Type: application/json' -d '{"reason":"system_recovery"}'
```

Wire this script into a recovery path (serial console, remote management) rather than relying on network-only access.

## Firewall Policy & Whitelist (API)

The new enforcement policy and whitelist endpoints let you manage runtime policy safely:

- Get current policy:

```bash
curl http://localhost:9000/api/firewall/policy | jq .
```

- Update policy (example) — default TTL and max TTL are enforced by the backend:

```bash
curl -X POST http://localhost:9000/api/firewall/policy \
  -H 'Content-Type: application/json' \
  -d '{"default_ttl":3600, "max_ttl":86400}'
```

- Add an IP to the whitelist (this prevents any blocks being applied to that IP):

```bash
curl -X POST http://localhost:9000/api/firewall/whitelist \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.0.2.55"}'
```

- Trigger TTL expiry processing immediately (normally runs periodically):

```bash
curl -X POST http://localhost:9000/api/firewall/expire
```

## PCAP Replay & Pi Benchmark

Replay a PCAP to exercise the detection pipeline and generate alerts/events:

```bash
python3 scripts/replay_pcap.py --pcap /path/to/sample.pcap --iface lo
```

Run the Pi benchmark (synthetic or PCAP-backed) to measure throughput/latency:

```bash
# synthetic 60s benchmark
python3 scripts/pi_benchmark.py --duration 60 --mode synthetic

# PCAP-backed benchmark
python3 scripts/pi_benchmark.py --duration 60 --mode pcap --pcap /path/to/sample.pcap
```

## Notes & Next Steps

- The enforcement policy manager supports whitelist, default/max TTL, TTL expiry, duplicate replacement, and emergency rollback. The backend chooses `nft` or `iptables` based on `SENTINEL_FIREWALL_BACKEND` environment variable.
- Before setting `FIREWALL_DRY_RUN=0` in a production device, run the containerized integration tests and add a system-level rollback guard (systemd or out-of-band management) to avoid accidental lockout.
- The repo includes `tests/test_firewall_container_integration.py` for privileged validation; it will run only when `SENTINEL_RUN_FIREWALL_CONTAINER_TESTS=1`.

### Recommended Next Steps (best practice)

1. Add the Actions secret `SENTINEL_MODEL_SIGNING_KEY` in the repository settings (Actions Secrets).
2. Push a small test commit to trigger `model-signing` and `check-model-signature` workflows and confirm both succeed.
3. On a test Pi, keep `FIREWALL_DRY_RUN=1`, provision the signing key to `/etc/sentinel/model_signing.key`, and verify the signature locally:

```bash
export SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model_signing.key
PYTHONPATH=/path/to/SentinelEdgeAI python3 scripts/sign_model.py model/isolation_forest.pkl --verify
```

4. Confirm the service is stable (`systemctl status sentineledgeai.service`) and logs show no signature errors.
5. Only after CI is green and device verification passes, remove any `SENTINEL_ALLOW_UNSIGNED_MODELS=1` drop-in and enable enforcement (`FIREWALL_DRY_RUN=0`) with a verified rollback guard in place.

Following this sequence ensures CI, key provisioning, and runtime verification are validated before enabling enforcement.

## Safe Rollout Checklist & One-Click Helper

Use the helper `scripts/enable_firewall_enforcement.sh` to perform prechecks and generate a local env file you can copy to a Pi.

Quick workflow:

- Run prechecks locally (health + privileged container tests):

```bash
./scripts/enable_firewall_enforcement.sh
```

- If prechecks pass, run with `--apply` to write `deploy/pi/firewall-rollback.env` (local file):

```bash
./scripts/enable_firewall_enforcement.sh --apply
```

- Copy the generated file to the Pi and enable the rollback timer (on the Pi):

```bash
sudo cp deploy/pi/firewall-rollback.env /etc/sentinel/firewall-rollback.env
sudo systemctl enable --now sentinel-firewall-rollback-guard.timer
```

- Once the guard/timer are installed and verified, flip enforcement by setting `FIREWALL_DRY_RUN=0` in your runtime environment (systemd unit drop-in or `/etc/default` file). Keep a recovery path (serial/console) available.

If you'd like, I can (A) add an automated test that runs the new PCAP replay test in CI (requires scapy), (B) expand `deploy/pi/install_pi.sh` to optionally copy the generated env file and enable the timer, or (C) create a small systemd drop-in template that sets `FIREWALL_DRY_RUN=0` for review.

### Self-hosted runner & rollback validation

For privileged firewall integration tests you must use a self-hosted runner with Docker and `NET_ADMIN`. See `deploy/pi/SELF_HOSTED_RUNNER.md` for setup details.

You can validate the rollback guard locally before enabling enforcement on a Pi with the included script:

```bash
# from repo root (venv activated)
python scripts/validate_rollback_guard.py
```

This script will:
- add a temporary block via `core.firewall.add_block()`;
- run `scripts/firewall_rollback_guard.sh` repeatedly while simulating failing health checks; and
- verify the guard calls `rollback_blocks()` and clears the block.

After validation, generate the env file and copy it to the Pi:

```bash
./scripts/enable_firewall_enforcement.sh --apply
scp deploy/pi/firewall-rollback.env pi@<pi_ip>:/tmp/
sudo cp /tmp/firewall-rollback.env /etc/sentinel/firewall-rollback.env
sudo systemctl enable --now sentinel-firewall-rollback-guard.timer
```

When the guard is installed and verified, use the interactive installer on the Pi to create the enforcement drop-in or copy the drop-in manually (see `deploy/pi/README_ENFORCEMENT.md`). Keep console access while flipping `FIREWALL_DRY_RUN=0`.

If you'd like, I can now:
- run the containerized firewall integration tests on this host (requires Docker + privileges), or
- add a small systemd rollback guard unit and example playbook to `packaging/` so Pi deployments include a recovery path.

</div>

---

## What is SentinelEdgeAI?

SentinelEdgeAI is a plug-and-play, hardware-accelerated cybersecurity appliance designed for small, medium, and scaling enterprise networks. It replaces traditional signature-based firewalls with a multi-layer AI detection engine that understands *behavioral patterns* — catching zero-day attacks, lateral movement, and novel threats that rule-based systems miss entirely.

The system runs on a dual-hardware architecture: a **Raspberry Pi 5** handles packet capture and network enforcement, while an **NVIDIA Jetson Orin Nano** runs GPU-accelerated AI inference. Everything stays local — no telemetry, no cloud dependency, no subscription.

```
Traditional Firewalls          SentinelEdgeAI
─────────────────────          ──────────────────────────────────
Static rules & signatures  →   Behavioral + anomaly-based AI
Cannot detect zero-days    →   Zero-day & unknown attack detection
Cloud dependency common    →   Fully local — air-gap capable
No adaptive response       →   Block / isolate / alert by risk score
```

---

## Current Build Status

> **v1.0 — Detection Core Complete. Enforcement + Hardware layers in active development.**

| Layer | Component | Status |
|-------|-----------|--------|
| **Capture** | Scapy packet sniffer | ✅ Working |
| **Capture** | Zeek / Suricata on Raspberry Pi 5 | 🔧 In progress |
| **Detection** | Z-score statistical anomaly engine | ✅ Working |
| **Detection** | Isolation Forest ML classifier | ✅ Working |
| **Detection** | Behavioral fingerprinting + drift detection | ✅ Working |
| **Detection** | MITRE ATT&CK tactic/technique mapping | ✅ Working |
| **Scoring** | Multi-layer risk engine (0–100) | ✅ Working |
| **Dashboard** | Streamlit SOC interface | ✅ Working |
| **Dashboard** | React SOC UI + WebSocket alerts | ✅ Working |
| **Enforcement** | iptables / nftables dynamic rule injection | 🔧 In progress |
| **Enforcement** | VLAN-based device isolation / quarantine | 🔧 In progress |
| **Backend** | FastAPI REST + WebSocket backend | ✅ Working |
| **Hardware** | Jetson Orin Nano GPU inference node | 🗓 Roadmap |
| **Security** | Secure boot + encrypted storage | 🗓 Roadmap |
| **Updates** | OTA firmware + model versioning | 🗓 Roadmap |

---

## Table of Contents

- [Architecture](#architecture)
- [Hardware Stack](#hardware-stack)
- [AI Models](#ai-models)
- [Detection Pipeline](#detection-pipeline)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Components](#components)
- [Monitoring & Observability](#monitoring--observability)
- [SOC Dashboard](#soc-dashboard)
- [Production Deployment](#production-deployment)
- [Threat Response Actions](#threat-response-actions)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Evaluation Metrics](#evaluation-metrics)
- [Future Roadmap](#future-roadmap)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Architecture

SentinelEdgeAI uses a layered, dual-hardware architecture that separates packet processing from AI inference — enabling high detection throughput without degrading network performance.

```
                        ┌─────────────────────────────────┐
                        │      NETWORK TRAFFIC (WAN/LAN)  │
                        └────────────────┬────────────────┘
                                         │
                        ┌────────────────▼────────────────┐
                        │   LAYER 1 — NETWORK MONITORING  │
                        │         Raspberry Pi 5           │
                        │                                  │
                        │  • Zeek / Suricata / Scapy       │
                        │  • Flow table (30s idle timeout) │
                        │  • 24-feature extraction         │
                        │  • Device fingerprinting         │
                        │  • DNS monitoring                │
                        │  • iptables / nftables enforce   │
                        └────────────────┬────────────────┘
                                         │  (gRPC / MQTT over TLS)
                        ┌────────────────▼────────────────┐
                        │   LAYER 2 — AI INFERENCE        │
                        │      Jetson Orin Nano (GPU)      │
                        │                                  │
                        │  • Isolation Forest (active)     │
                        │  • Z-score anomaly engine        │
                        │  • Behavioral fingerprinting     │
                        │  • Drift detection               │
                        │  • Attack classifier             │
                        │  • Risk escalation engine        │
                        │  • MITRE ATT&CK mapper           │
                        │  • LSTM sequence model (roadmap) │
                        └────────────────┬────────────────┘
                                         │
                        ┌────────────────▼────────────────┐
                        │   LAYER 3 — MANAGEMENT          │
                        │                                  │
                        │  • FastAPI REST backend          │
                        │  • WebSocket real-time alerts    │
                        │  • Streamlit SOC dashboard       │
                        │  • React UI (roadmap)            │
                        └────────────────┬────────────────┘
                                         │
               ┌─────────────────────────▼──────────────────────────┐
               │   LAYER 4 — PERSISTENCE & SECURITY                  │
               │                                                      │
               │  data/alerts.json · device_profiles.json                  │
               │  risk_timeline.json · live_stats.json · health.json  │
               │  sentinel.log (rotating, 5MB × 5 files)             │
               │  Secure boot · Encrypted storage · RBAC (roadmap)   │
               └──────────────────────────────────────────────────────┘
```

---

## Hardware Stack

| Component | Role | Specs |
|-----------|------|-------|
| **Raspberry Pi 5 (8GB)** | Network capture node — packet ingestion, feature extraction, firewall enforcement | ARM Cortex-A76, 8GB LPDDR4X |
| **NVIDIA Jetson Orin Nano** | AI inference node — behavioral modeling, anomaly detection, risk scoring | 6-core ARM + 1024-core Ampere GPU, 8GB |
| **Dual NIC** | Inline traffic monitoring — WAN + LAN separation | USB 3.0 or PCIe adapter |
| **SSD Storage** | Logs, model artifacts, threat intelligence | 256GB+ NVMe recommended |
| **Managed Switch** | Network segmentation, port mirroring for passive capture | Any 802.1Q VLAN-capable switch |
| **Cooling + Enclosure** | Thermal management for 24/7 operation | Active cooling recommended |

**Estimated hardware cost: ~$250–$350 USD**

---

## AI Models

| Model | Status | Purpose |
|-------|--------|---------|
| **Isolation Forest** | ✅ Active | Unsupervised anomaly detection on network flow features — no labeled data required |
| **Z-Score Statistical Engine** | ✅ Active | Baseline traffic profiling and threshold-based alerting with warmup period |
| **Behavioral Fingerprinting** | ✅ Active | Per-device behavior profiles with drift detection for insider threat and device compromise |
| **Attack Classifier** | ✅ Active | Multi-class threat type mapping (port scan, DDoS, exfiltration, etc.) |
| **LSTM Sequence Model** | 🗓 Roadmap | Temporal sequence modeling to detect multi-step attack chains across time |
| **RL Firewall Agent** | 🗓 Roadmap | Reinforcement learning — firewall rules that self-adapt from threat feedback |
| **GNN Lateral Movement** | 🗓 Roadmap | Graph Neural Network — detect lateral movement across device-to-device communication graph |

---

## Detection Pipeline

Every packet traverses the following pipeline end-to-end. Target latency: **< 2ms per flow**.

```
Step 01  CAPTURE       Raw packets ingested by Raspberry Pi (Zeek / Suricata / Scapy)
           ↓
Step 02  FLOW BUILD    Packets grouped into flows (5-tuple); 30s idle timeout expires flows
           ↓
Step 03  FEATURES      24 statistical features extracted per flow
                       (byte counts, packet rates, inter-arrival times, flag ratios, entropy...)
           ↓
Step 04  AI ANALYSIS   Jetson runs multi-layer detection in parallel:
                       ├── Z-score engine    (statistical deviation from baseline)
                       ├── Isolation Forest  (ML anomaly score)
                       ├── Behavioral engine (deviation from device profile)
                       └── Drift detector    (long-term behavioral shift)
           ↓
Step 05  RISK SCORE    Unified 0–100 risk score calculated from all detection layers
                       Normal < 25 │ Medium 25–50 │ High 50–75 │ Critical > 75
           ↓
Step 06  DECISION      Low:      Log to sentinel.log only
                       Medium:   Alert SOC dashboard
                       High:     Alert + iptables block rule injected
                       Critical: Alert + full VLAN isolation / quarantine
           ↓
Step 07  MITRE MAP     Threat classified against MITRE ATT&CK framework
                       (tactic, technique ID, technique name appended to alert)
           ↓
Step 08  PERSIST       data/alerts.json · device_profiles.json · risk_timeline.json updated
           ↓
Step 09  DASHBOARD     WebSocket pushes real-time alert to SOC dashboard
```

---

## What I implemented in this workspace (detailed changelog)

This repository now contains a full local-first pipeline with detection, live dashboard, and safe firewall enforcement primitives. Below is a comprehensive list of features, files added or modified, and how they integrate.

1) Backend & runtime
- `dashboard/dashboard_api.py` — FastAPI backend that exposes REST APIs and a WebSocket `/ws/packets` for live events. It now also serves the built frontend statically from `frontend/dist` when present.
- `capture/sniffer.py` — existing scapy-based sniffer; the backend can optionally run it in-process (`CAPTURE_IN_PROCESS=1`) and receive events via an asyncio queue.

2) Firewall enforcement (safe-by-default)
- `core/firewall.py` — a safe firewall wrapper module. Features:
  - Dry-run by default (`FIREWALL_DRY_RUN=1`) so no system firewall commands are executed until you opt in.
  - `add_block(ip, ttl, reason)`, `remove_block(ip)`, `list_rules()` APIs.
  - Policy controls for IPv4 whitelist, default/max TTL, TTL expiry, and emergency rollback.
  - Best-effort support for `nft` (preferred) and `iptables` fallback when real enforcement is enabled.
  - Action logs written to `logs/firewall_actions.jsonl`, policy at `firewall_policy.json`, and active rule list at `firewall_rules.json`.

3) Firewall API
- `dashboard/dashboard_api.py` additions:
  - `GET /api/firewall/rules` — list current recorded rules
  - `POST /api/firewall/block` — block an IP (body: `{ip, ttl, reason}`)
  - `POST /api/firewall/unblock` — remove a block (body: `{ip}`)
  - `GET /api/firewall/actions` — recent firewall action audit log
  - `GET/POST /api/firewall/policy` — inspect/update whitelist and TTL policy

  ## Frontend Build & Testing

  The React frontend lives in the `frontend/` directory. Source files are tracked in the branch `restore/frontend-tracked-files` and a PR has been opened: https://github.com/vishwa-10147/SentinelEdgeAI/pull/1

  To build and test the frontend locally (recommended):

  ```bash
  # from repo root (requires Node.js and npm)
  cd frontend
  npm ci            # install deps
  npm run build     # produce production build in frontend/dist
  npm run dev       # run dev server for interactive testing
  ```

  To serve the built production bundle with the backend (static files are ignored in git):

  ```bash
  # from repo root (venv activated)
  source venv/bin/activate
  python -m uvicorn dashboard.dashboard_api:app --reload
  # the backend will serve static files from frontend/dist when present
  ```

  I'll wait for your webpage prompt to incorporate into the frontend or update the homepage content.
  - `POST /api/firewall/whitelist` — add/remove a whitelisted IP
  - `POST /api/firewall/expire` — force TTL expiry cleanup
  - `POST /api/firewall/rollback` — remove all active block rules
  - All firewall endpoints are protected by `DASHBOARD_API_KEY` when the env var is set.

4) Frontend (React + Vite)
- `frontend/` is a modern React app (Vite). Key components:
  - `frontend/src/components/Topology.jsx` — Cytoscape network map with a Canvas overlay for animated particle trails and blocked-edge overlays.
    - Blocked/suspicious flows render as red dashed edges with a stop-icon overlay at midpoint.
    - Smooth particle trails with jitter and motion-blur style rendering.
  - `frontend/src/components/DeviceDetail.jsx` — device panel with live packet logs via WebSocket, Behavior Summary, MITRE chips and a `Quarantine` button.
    - Quarantine uses a confirmation modal and displays an `Undo` button that triggers `/api/firewall/unblock`.
  - `frontend/src/components/Legend.jsx` — risk legend including `BLOCKED` state.
  - `frontend/src/App.jsx` — top metrics (traffic volume, active devices, blocked count, system health), periodic refresh and immediate refresh on firewall changes (custom event `se:firewall-changed`).
  - Export snapshot functionality now embeds the rendered legend into the exported PNG.

5) Build & Dev
- `scripts/build_frontend.sh` — builds the frontend into `frontend/dist` (used by FastAPI static serving). Uses `npm install --legacy-peer-deps` to avoid peer conflicts during install.
- Dev server: `cd frontend && npm run dev` (Vite default http://127.0.0.1:5173)

6) Demo & tooling
- `scripts/demo_attack.py` — writes a simulated alert and live event to `data/alerts.json`/`data/live_events.jsonl`. Optionally calls the firewall API to request a block (useful for demos).

7) Tests & CI
- `tests/test_firewall.py` — pytest unit test for `core/firewall.py` (dry-run add/remove/list).
- `.github/workflows/ci.yml` — GitHub Actions: runs Python tests and builds the frontend on pushes to `main`.

8) Packaging / Ops
- `scripts/install_local_service.sh` — convenience installer to copy `deploy/pi/sentinel-local.service` and drop-ins to `/etc/systemd/system` and enable the service.
- `packaging/logrotate/sentinel-edgeai.conf` and `packaging/*.service` — existing packaging assets used by the setup script (`scripts/setup_pi.sh`).

9) Documentation
- `README_LOCAL.md` — updated with local run instructions, demo steps, and safe enforcement guide.

10) Safety & default behavior
- Firewall is dry-run by default. To enable real enforcement set `FIREWALL_DRY_RUN=0` in the environment (or in systemd drop-in). Do this only if you have console/serial access and a recovery plan.
- All firewall actions are logged to `core/logs/firewall_actions.jsonl` and can be reviewed via `GET /api/firewall/actions`.

---

## How to run the full local demo (recommended order)

1) Create and activate Python venv, install deps:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

2) Build the frontend for static serving (optional but recommended for plug & play):

```bash
./scripts/build_frontend.sh
```

3) Start the backend with in-process sniffer and static UI serving:

```bash
CAPTURE_IN_PROCESS=1 CAPTURE_IFACE=eth0 .venv/bin/python -u dashboard/dashboard_api.py
# Backend is on http://0.0.0.0:9000 and will serve the UI at / when frontend/dist exists
```

4) In another shell, run the demo attack (writes alert + live event):

```bash
python scripts/demo_attack.py --ip 192.0.2.55
# To request block via API (requires DASHBOARD_API_KEY if set):
DASHBOARD_API_URL=http://127.0.0.1:9000 DASHBOARD_API_KEY=$DASHBOARD_API_KEY python scripts/demo_attack.py --ip 192.0.2.55 --block
```

5) Open the dashboard:

- If frontend built and backend running: `http://127.0.0.1:9000/`
- If using Vite dev server: `http://127.0.0.1:5173`

6) Quarantine a device from the Device Panel:

- Click `Quarantine`, confirm the action. An `Undo` button appears for 30s to revert the block. The UI refreshes firewall state immediately.

---

## How enforcement works (internals)

- The detection engine runs scoring on flows produced by `capture/sniffer.py`. When a flow crosses thresholds, an alert is generated and written to `data/alerts.json` and `data/live_events.jsonl`.
- The FastAPI backend tails these files and pushes events to connected WebSocket clients (`/ws/packets`). The React UI consumes these events and animates flows on the topology.
- The decision engine (simple rule in this release) maps score -> action: Low=log, Medium=alert, High=block, Critical=isolate.
- Blocking is performed by `core/firewall.py`. By default it records the rule and logs the action; when `FIREWALL_DRY_RUN=0` it will attempt to call `nft` or `iptables` to insert/remove rules on the Pi.

---

## Operational Safety & Recommendations

- Keep `FIREWALL_DRY_RUN=1` while testing to avoid accidental network disruption.
- Keep management hosts, the appliance loopback address, and any recovery jump box in `firewall_policy.json` whitelist before enabling real enforcement.
- If enabling enforcement (`FIREWALL_DRY_RUN=0`):
  1. Ensure console or serial access to the Pi in case of lockout.
  2. Run the containerized `nft`/`iptables` integration tests on the target OS/kernel first.
  3. Use systemd drop-in to grant `CAP_NET_RAW` instead of running as root.
  4. Audit `logs/firewall_actions.jsonl` regularly and set up `logrotate` for long-term retention (packaging contains `packaging/logrotate/sentinel-edgeai.conf`).

### Enforcement Validation

Run the normal firewall policy tests:

```bash
.venv/bin/python -m pytest tests/test_firewall.py
```

Run real firewall command integration tests in Docker. These tests require Docker and `NET_ADMIN`; they are opt-in so regular CI does not need privileged containers.

```bash
SENTINEL_RUN_FIREWALL_CONTAINER_TESTS=1 \
  .venv/bin/python -m pytest tests/test_firewall_container_integration.py
```

The container tests exercise both backends:

- `SENTINEL_FIREWALL_BACKEND=nft`
- `SENTINEL_FIREWALL_BACKEND=iptables`

### Rollback Playbook

If a rule blocks expected traffic, first use the local API rollback endpoint:

```bash
curl -X POST http://127.0.0.1:9000/api/firewall/rollback \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $DASHBOARD_API_KEY" \
  -d '{"reason":"operator_rollback"}'
```

If the API is unavailable, use a local Python rollback from the repo:

```bash
cd /home/vishwa/SentinelEdgeAI
FIREWALL_DRY_RUN=0 .venv/bin/python - <<'PY'
import core.firewall as firewall
print(firewall.rollback_blocks("manual_local_rollback"))
PY
```

If both application paths fail, clear the SentinelEdgeAI-managed rules directly from the console:

```bash
sudo iptables -D INPUT -s <blocked-ip> -j DROP
sudo nft delete element inet sentinel blacklist '{ <blocked-ip> }'
```

After rollback, restore dry-run mode and restart the service:

```bash
sudo systemctl set-environment FIREWALL_DRY_RUN=1
sudo systemctl restart sentineledgeai.service
```

### Systemd Rollback Guard

For Pi deployments that enable real enforcement, install the rollback guard timer before switching `FIREWALL_DRY_RUN=0`. The guard checks the local dashboard health endpoint while active SentinelEdgeAI firewall rules exist. If health fails for `FAIL_THRESHOLD` consecutive timer runs, it calls `core.firewall.rollback_blocks("systemd_rollback_guard")`.

Install the example units:

```bash
sudo install -m 755 scripts/firewall_rollback_guard.sh /home/vishwa/SentinelEdgeAI/scripts/firewall_rollback_guard.sh
sudo install -m 644 deploy/pi/sentinel-firewall-rollback-guard.service.example /etc/systemd/system/sentinel-firewall-rollback-guard.service
sudo install -m 644 deploy/pi/sentinel-firewall-rollback-guard.timer.example /etc/systemd/system/sentinel-firewall-rollback-guard.timer
sudo mkdir -p /etc/sentinel
sudo install -m 600 deploy/pi/firewall-rollback.env.example /etc/sentinel/firewall-rollback.env
```

Edit `/etc/sentinel/firewall-rollback.env`:

```bash
ENABLE_ROLLBACK_GUARD=1
REPO_DIR=/home/vishwa/SentinelEdgeAI
VENV_PYTHON=/home/vishwa/SentinelEdgeAI/.venv/bin/python
HEALTH_URL=http://127.0.0.1:9000/api/health
FAIL_THRESHOLD=3
DASHBOARD_API_KEY=replace_if_api_key_is_enabled
```

Enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-firewall-rollback-guard.timer
sudo systemctl list-timers sentinel-firewall-rollback-guard.timer
```

Inspect guard logs:

```bash
sudo journalctl -u sentinel-firewall-rollback-guard.service -n 100 --no-pager
```

The guard is intentionally opt-in. The example environment file sets `ENABLE_ROLLBACK_GUARD=1`, but the script defaults to disabled if that variable is missing.

### PCAP Replay And Pi Benchmark

Replay a PCAP through flow building and feature extraction without live packet capture:

```bash
.venv/bin/python scripts/replay_pcap.py captures/sample.pcap --output-csv /tmp/replay_data/flows.csv
```

Run a quick synthetic benchmark on a Raspberry Pi:

```bash
.venv/bin/python scripts/pi_benchmark.py --packets 10000 --output-csv /tmp/pi_benchmark_data/flows.csv
```

Run a PCAP-backed benchmark:

```bash
.venv/bin/python scripts/pi_benchmark.py --pcap captures/sample.pcap
```

### Model Artifact Signing

SentinelEdgeAI refuses to load existing `joblib` model artifacts unless a valid signature file is present. This protects the unsafe pickle-style load path used by sklearn/joblib.

Set a signing key through an environment variable or a root-readable key file:

```bash
export SENTINEL_MODEL_SIGNING_KEY='replace-with-a-long-random-secret'
# or:
export SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model-signing.key
```

Sign a model:

```bash
.venv/bin/python scripts/sign_model.py model/isolation_forest.pkl --signer "release-2026-05-08"
```

Verify a model:

```bash
.venv/bin/python scripts/sign_model.py model/isolation_forest.pkl --verify
```

Runtime loading requires the same key:

```bash
SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model-signing.key \
  .venv/bin/python main.py
```

For local development only, unsigned loading can be explicitly enabled:

```bash
SENTINEL_ALLOW_UNSIGNED_MODELS=1 .venv/bin/python scripts/smoke_test.py
```

Do not use `SENTINEL_ALLOW_UNSIGNED_MODELS=1` in production.

### CI Model Signing

The GitHub Actions workflow `.github/workflows/model-signing.yml` signs and verifies `model/isolation_forest.pkl`, checks tamper detection, and uploads both files as the `signed-isolation-forest-model` artifact:

- `model/isolation_forest.pkl`
- `model/isolation_forest.pkl.sig`

Required GitHub secret:

```text
SENTINEL_MODEL_SIGNING_KEY
```

The workflow intentionally uses quiet signing output so the signing key and raw signature value are not printed to CI logs. It runs on manual dispatch and on pushes to `main` that touch model/signing-related paths.

Device key provisioning is documented in `deploy/pi/MODEL_KEY_PROVISIONING.md`. Production devices should use:

```bash
SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model-signing.key
```

The checked-in `model/isolation_forest.pkl` must be signed with the production key before production runtime. The `.sig` cannot be generated safely without the real key.

### Self-Hosted Privileged CI

Privileged firewall integration uses `.github/workflows/privileged-integration.yml` and must run only on a self-hosted runner labeled:

```text
self-hosted, linux, docker
```

Setup and hardening guidance is in `deploy/pi/SELF_HOSTED_RUNNER.md`. The workflow runs `nft`/`iptables` container tests and can optionally run rollback guard validation by setting `run_rollback_validation=true`.

### Pi Package Artifact

Build a tar package for Pi deployment:

```bash
./scripts/build_pi_package.sh
```

Install after extracting the artifact:

```bash
sudo bash packaging/pi/install_from_package.sh
sudo bash /opt/sentineledgeai/deploy/pi/install_pi.sh --install-rollback
```

Atomic enforcement control on the Pi:

```bash
sudo bash /opt/sentineledgeai/deploy/pi/enforcement_ctl.sh enable
sudo bash /opt/sentineledgeai/deploy/pi/enforcement_ctl.sh disable
sudo bash /opt/sentineledgeai/deploy/pi/enforcement_ctl.sh status
```

The control script backs up the existing enforcement drop-in to `/var/backups/sentineledgeai`, writes updates through a temporary file and atomic `mv`, reloads systemd, and restarts the service.

### Current Remaining Development

High-priority work is now mostly deployment hardening and production validation:

| Area | Status | Remaining |
|------|--------|-----------|
| Detection core | Mostly complete | PCAP corpus expansion, labeled evaluation, Pi throughput baselines |
| Firewall policy | Implemented | Production Pi soak testing with `FIREWALL_DRY_RUN=0` |
| Privileged firewall CI | Implemented | Provision and lock down the self-hosted runner |
| Rollback guard | Implemented | Enable on a test Pi and verify with real service failure scenarios |
| Model signing runtime | Implemented | Provide production signing key and commit/release `.sig` artifact |
| Model signing CI | Implemented | Add `SENTINEL_MODEL_SIGNING_KEY` to GitHub Secrets |
| Pi packaging | Implemented as tar artifact | Test install on clean Pi image; `.deb` packaging optional |
| FastAPI lifecycle | Pending | Replace deprecated `@app.on_event` with lifespan handlers |
| Frontend performance | Pending | Code-split large bundle and add build budget |
| Repo hygiene | Partial | Remove already-tracked generated runtime files from git history/index |

Approximate project completion: **75-80% prototype-to-production readiness**. Core features and safety scaffolding are in place; the remaining work is mainly production validation, device provisioning, cleanup, and performance hardening.

---

## Next recommended work (optional but high impact)

1. Add a persistent enforcement policy manager with whitelist/blacklist and scheduled rule expiry.
2. Replace file-tail with Redis pub/sub for multi-host streaming if you plan to centralize the dashboard.
3. Implement small rollback automation in systemd (watchdog) and integration tests for iptables/nft commands in a containerized environment.
4. Optimize frontend bundle size with dynamic imports and manual chunking in `vite.config.js`.

---

If you want, I can now:
- enable safe enforcement and create a rollback playbook, or
- add a demo-run button in the UI that triggers `scripts/demo_attack.py` through an authenticated backend endpoint, or
- begin packaging a production image for Raspberry Pi with everything prebuilt.

--

### Presenter-mode demo flow

I added a guided presenter-mode demo that orchestrates a sequence of visual steps for investor/demo presentations. Use it to run a story-driven demo without manually timing steps.

1. Start backend as normal (see Quick Start).
2. From the dashboard top bar click `Start Presenter Demo`.
3. The backend will run a short sequence: normal traffic → simulated attack → detection alert → block applied → visual blocked state → demo end.

Notes:
- Presenter demo uses `POST /api/demo/presenter` (protected by `DASHBOARD_API_KEY` if set).
- The endpoint emits `demo_step` events via the same WebSocket `/ws/packets` so the React UI displays overlay messages in sync with the demo.
- The demo also spawns `scripts/demo_attack.py` to generate real flow events — this is safe and runs in dry-run by default.


Tell me which direction you'd like and I'll continue.

---

## Installation

### Prerequisites

- Python 3.8+
- Administrator / root privileges (required for packet capture)
- `pip` package manager

### Hardware Setup

```bash
# On Raspberry Pi 5 — install capture dependencies
sudo apt update && sudo apt install -y zeek suricata nftables

# On Jetson Orin Nano — install CUDA + Python ML stack
# Follow NVIDIA JetPack SDK setup first: https://developer.nvidia.com/embedded/jetpack
```

### Software Setup

```bash
# Clone the repository
git clone https://github.com/vishwa-10147/SentinelEdgeAI.git
cd SentinelEdgeAI

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

# Install all dependencies
pip install -r requirements.txt
```

### Docker (recommended)

To avoid host Python/version incompatibilities we provide a Docker-based deployment. This is the recommended way to run the backend and the dashboard locally or on an edge device with Docker support.

Build and start the services with Compose:

```bash
# Build the backend image and start services (detached)
sudo docker compose build --no-cache backend
sudo docker compose up -d

# Tail backend logs
sudo docker compose logs -f backend
```

Notes:
- The Compose service maps the backend to port `9000` on the host. If that port is already in use stop the local server first.
- Keep `FIREWALL_DRY_RUN=1` in your environment while testing to avoid making real network changes.

### Requirements pin note

While building the container we encountered a wheel compatibility issue for `fastapi==0.99.3` on this environment. I pinned `fastapi==0.99.1` in `requirements.txt` to ensure a compatible distribution is available for Python 3.11 in the container. If you prefer a different constraint or range (for example `fastapi>=0.99.1,<0.100.0`) I can update `requirements.txt` and rebuild.

Verification (after `docker compose up -d`):

```bash
# Backend health
curl -s http://localhost:9000/api/health | jq

# Open browser: http://localhost:9000
```

### Dependencies (v1.0 locked)

| Package | Purpose |
|---------|---------|
| `scapy` | Network packet capture |
| `streamlit` | SOC dashboard UI |
| `pandas` | Data manipulation |
| `scikit-learn` | Isolation Forest ML model |
| `pyyaml` | Configuration management |
| `psutil` | System resource monitoring |
| `fastapi` | REST API backend *(in progress)* |
| `uvicorn` | ASGI server for FastAPI |

See `requirements.txt` for complete pinned versions.

---

## Quick Start

### 1. Configure the system

Edit `config.yaml` to tune detection thresholds for your network:

```yaml
risk_thresholds:
  critical: 75        # Score above this = block + quarantine
  high: 50            # Score above this = alert + block
  medium: 25          # Score above this = alert SOC

anomaly:
  z_threshold: 3.0    # Standard deviations from baseline (lower = more sensitive)
  warmup_flows: 50    # Flows required before anomaly detection activates

baseline:
  window_size: 100    # Rolling window size for adaptive baseline

logging:
  level: INFO
  max_bytes: 5242880  # 5MB per log file
  backup_count: 5     # Rotate through 5 backup files
```

### 2. Start the detection engine

```bash
# Requires root — starts packet capture and runs detection pipeline
sudo python main.py
```

### 3. Start the SOC dashboard

```bash
# In a separate terminal
streamlit run dashboard/streamlit_app.py
```

### 4. Access the dashboard

```
URL:          http://localhost:8501
Auto-refresh: Every 3 seconds
```

---

## Raspberry Pi Quick Start (consolidated)

This repository includes focused helpers for Raspberry Pi deployments under the `deploy/pi/` folder. Use these to validate the environment, install the systemd services, and run the services manually for debugging.

Recommended quick flow for a Pi:

1. Validate the environment and create any missing runtime JSON files:

```bash
./deploy/pi/validate_pi.sh
```

2. Install the systemd services (requires sudo):

```bash
./deploy/pi/install_pi.sh
# To install the Streamlit dashboard service as well:
./deploy/pi/install_pi.sh streamlit
```

3. Check the running services and logs:

```bash
sudo journalctl -u sentineledgeai.service -f
sudo journalctl -u sentineledgeai-streamlit.service -f
```

4. For manual debugging, run main or dashboard from the venv:

```bash
./deploy/pi/run_manual.sh main
./deploy/pi/run_manual.sh streamlit
```

Notes:
- `deploy/pi/validate_pi.sh` will run the smoke test and ensure `data/alerts.json`, `live_stats.json`, `device_profiles.json`, `risk_timeline.json`, and `health.json` exist.
- Keep `config.yaml` tuned to your network before enabling the systemd service.

Capability note for non-root packet capture:

 - The `sentineledgeai.service` runs as the non-root user `vishwa` by default. To allow packet capture via Scapy without running the process as root, the service requires the `CAP_NET_RAW` capability. The installer creates a systemd drop-in at `/etc/systemd/system/sentineledgeai.service.d/override.conf` which grants `CAP_NET_RAW` to the service. If you prefer not to grant capabilities, run the service as `root` or adjust the unit file accordingly.

Health agent note:

 - The `sentinel-health-agent.service` expects a file at `/etc/sentinel/health.env`. The installer creates a minimal one automatically; you can populate it with runtime secrets if needed. The agent writes a runtime copy to `/run/sentinel/health.env` with strict permissions.

Automated integration runner

 - A wrapper to run the repo integration test is available at `deploy/pi/run_integration.sh`. It runs `scripts/integration_test.py` using the repo `.venv` and appends output to `logs/integration_test.log`.
 - Example systemd unit and timer files are provided at `deploy/pi/integration_test.service.example` and `deploy/pi/integration_test.timer.example`. To enable periodic integration checks copy them to `/etc/systemd/system/` and enable the timer:

```bash
sudo cp deploy/pi/integration_test.service.example /etc/systemd/system/integration_test.service
sudo cp deploy/pi/integration_test.timer.example /etc/systemd/system/integration_test.timer
sudo systemctl daemon-reload
sudo systemctl enable --now integration_test.timer
sudo systemctl status integration_test.timer
```

 - To run a single integration invocation locally:

```bash
./deploy/pi/run_integration.sh
tail -n 200 logs/integration_test.log
```


## Configuration

Full `config.yaml` reference:

| Section | Parameter | Default | Description |
|---------|-----------|---------|-------------|
| `risk_thresholds` | `critical` | `75` | Score threshold for quarantine action |
| `risk_thresholds` | `high` | `50` | Score threshold for block action |
| `risk_thresholds` | `medium` | `25` | Score threshold for SOC alert |
| `anomaly` | `z_threshold` | `3.0` | Sensitivity — lower catches more, higher reduces false positives |
| `anomaly` | `warmup_flows` | `50` | Cold-start grace period before anomaly engine activates |
| `baseline` | `window_size` | `100` | Rolling window for adaptive traffic baseline |
| `drift` | `deviation_threshold` | — | Behavioral drift sensitivity per device |
| `flow` | `idle_timeout` | `30` | Flow idle timeout in seconds |
| `alerts` | `min_risk_score` | `25` | Minimum score for alert persistence |
| `persistence` | `history_limit` | — | Max entries retained in JSON files |
| `logging` | `level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `logging` | `max_bytes` | `5242880` | Log rotation size per file |
| `logging` | `backup_count` | `5` | Number of backup log files retained |

**Tuning guidance:**

```yaml
# More sensitive — catches more threats, higher false positive rate
anomaly:
  z_threshold: 2.5

# More conservative — fewer false positives, may miss subtle threats
anomaly:
  z_threshold: 3.5
```

---

## Components

### Module Map

| Module | File | Responsibility |
|--------|------|----------------|
| `SentinelEngine` | `core/engine.py` | Orchestrator — coordinates all detection layers |
| `HealthMonitor` | `core/health.py` | Engine uptime, CPU/memory tracking |
| `Config` | `core/config_loader.py` | YAML config with nested key access |
| `AnomalyEngine` | `detection/anomaly_engine.py` | Z-score statistical detection with warmup |
| `MLEngine` | `detection/ml_engine.py` | Isolation Forest classification |
| `BehavioralFingerprint` | `detection/behavioral_fingerprint.py` | Per-device behavioral profiles |
| `DriftDetector` | `detection/behavioral_fingerprint.py` | Long-term behavioral deviation tracking |
| `RiskEscalationEngine` | `detection/risk_engine.py` | Unified multi-layer risk calculation |
| `AttackClassifier` | `detection/attack_classifier.py` | Threat type classification |
| `MitreMapper` | `detection/mitre_mapper.py` | ATT&CK tactic and technique assignment |
| `FlowTable` | `flow/flow_table.py` | Stateful flow tracking with timeout |
| `FeatureExtractor` | `features/feature_extractor.py` | 24 statistical features per flow |
| `AlertLogger` | `utils/alert_logger.py` | Persistent alert storage to JSON |
| `Sniffer` | `capture/sniffer.py` | Packet capture loop (Scapy) |

### Suggested Project Structure

```
SentinelEdgeAI/
├── main.py                          # Entry point — starts capture + engine
├── config.yaml                      # All tunable parameters
├── requirements.txt
│
├── capture/
│   └── sniffer.py                   # Packet capture loop (Scapy / Zeek)
│
├── flow/
│   └── flow_table.py                # Flow state table, idle timeout
│
├── features/
│   └── feature_extractor.py         # 24-feature statistical extraction
│
├── core/
│   ├── engine.py                    # SentinelEngine orchestrator
│   ├── health.py                    # Health monitor
│   └── config_loader.py             # YAML config loader
│
├── detection/
│   ├── anomaly_engine.py            # Z-score engine
│   ├── ml_engine.py                 # Isolation Forest
│   ├── behavioral_fingerprint.py    # Device profiling + drift
│   ├── risk_engine.py               # Risk escalation
│   ├── attack_classifier.py         # Threat classification
│   └── mitre_mapper.py              # ATT&CK mapping
│
├── core/
│   └── firewall.py                  # Safe dry-run firewall wrapper; nftables / iptables when enabled
│
├── dashboard/
│   ├── dashboard_api.py             # FastAPI app + WebSocket alert streaming
│   └── streamlit_app.py             # Streamlit SOC dashboard
│
├── frontend/
│   └── src/                         # React / Vite SOC dashboard
│
├── ./                               # Runtime-generated files in the repo root
│   ├── data/alerts.json
│   ├── device_profiles.json
│   ├── risk_timeline.json
│   ├── live_stats.json
│   └── health.json
│
└── logs/
    └── sentinel.log                 # Rotating structured logs
```

---

## Monitoring & Observability

### Performance Metrics

The engine logs performance data every 100 flows:

```
[2026-02-15 10:30:45] INFO  Performance | Flows=100 | AvgProcessingTime=1.82 ms
[2026-02-15 10:30:45] INFO  System      | CPU=12.4% | Memory=148.32 MB
[2026-02-15 10:30:46] WARN  BEHAVIORAL DRIFT | IP=192.168.1.10 | Reason=unusual_port_count
```

### Health Status (`data/health.json`)

```json
{
  "status": "running",
  "uptime_seconds": 3600,
  "flows_processed": 1250,
  "cpu_usage_percent": 12.4,
  "memory_usage_mb": 148.32
}
```

### Log Rotation

| Parameter | Value |
|-----------|-------|
| File | `logs/sentinel.log` |
| Max size per file | 5 MB |
| Backup files retained | 5 |
| Format | Structured with timestamp, level, context |

### Alert Schema (`data/alerts.json`)

```json
{
  "timestamp": "2026-02-15 10:30:45",
  "initiator_ip": "192.168.1.10",
  "responder_ip": "8.8.8.8",
  "protocol": "TCP",
  "final_risk_score": 72,
  "severity": "HIGH",
  "attack_type": "Port Scanning",
  "mitre_tactic": "Reconnaissance",
  "mitre_technique_id": "T1046",
  "mitre_technique_name": "Network Service Discovery"
}
```

---

## SOC Dashboard

The Streamlit dashboard provides a real-time view of the detection engine. It auto-refreshes every 3 seconds.

| Section | What It Shows |
|---------|---------------|
| **Metrics (top bar)** | Total flows processed, active devices, total alerts |
| **Traffic & Threat Trend** | Line chart of flow risk scores over time |
| **Alert Severity Breakdown** | Bar chart: CRITICAL / HIGH / MEDIUM / LOW / NORMAL counts |
| **Recent Alerts** | Table: timestamp, IP, protocol, risk score, severity, attack type |
| **Device Risk Leaderboard** | Devices sorted by average risk score (highest first) |
| **Device Risk Timeline** | Per-device risk score trend visualization |
| **Engine Health** | Live health.json — uptime, flows, CPU, memory |
| **MITRE ATT&CK View** | IP, severity, attack type, tactic, technique ID and name |

---

## Threat Response Actions

| Risk Score | Severity | Automated Action |
|-----------|----------|-----------------|
| 0 – 24 | Normal | Log to `sentinel.log` only |
| 25 – 49 | Medium | Alert pushed to SOC dashboard |
| 50 – 74 | High | Alert + dynamic iptables block rule injected |
| 75 – 100 | Critical | Alert + source device moved to quarantine VLAN |

---

## MITRE ATT&CK Coverage

SentinelEdgeAI maps detected threats to the MITRE ATT&CK framework automatically. Example mappings:

| Attack Type | Tactic | Technique ID | Technique Name |
|-------------|--------|-------------|----------------|
| Port Scanning | Reconnaissance | T1046 | Network Service Discovery |
| Brute Force | Credential Access | T1110 | Brute Force |
| Data Exfiltration | Exfiltration | T1041 | Exfiltration Over C2 Channel |
| Lateral Movement | Lateral Movement | T1021 | Remote Services |
| DDoS | Impact | T1498 | Network Denial of Service |
| DNS Tunneling | Command and Control | T1071.004 | Application Layer Protocol: DNS |

---

## Evaluation Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Detection Accuracy** | % of true threats correctly identified | > 90% (post-baseline) |
| **False Positive Rate** | % of benign flows incorrectly flagged | < 5% (after warmup) |
| **Flow Processing Latency** | End-to-end time from capture to decision | < 2ms per flow |
| **Throughput Impact** | Network performance reduction caused by appliance | < 3% |
| **CPU Usage** | Raspberry Pi 5 under load | < 40% |
| **GPU Usage** | Jetson Orin Nano inference load | < 60% |
| **Memory Footprint** | Combined RAM across both nodes | ~150MB baseline |

---

## Production Deployment

### Interface Selection

```python
# Capture on all interfaces (default)
sudo python main.py

# Capture on a specific interface
from capture.sniffer import start_sniffing
start_sniffing(interface="eth0")
```

### Inline vs. Passive Mode

```
Passive (recommended for initial deployment):
  Network → Switch (port mirror) → Pi capture interface
  Advantage: Zero network impact if appliance fails

Inline (full enforcement):
  WAN → Pi WAN interface → Pi LAN interface → Network
  Advantage: Can actively block and redirect traffic
```

### SIEM Integration

Alerts written to `data/alerts.json` are in a standard structured format compatible with:

- **ELK Stack** — use Filebeat to ship `data/alerts.json`
- **Splunk** — use Universal Forwarder watching the file
- **Grafana** — expose via FastAPI endpoint and scrape with Prometheus
- **Webhooks** — planned in roadmap

### Production Logging Config

```yaml
logging:
  level: WARNING         # Reduce verbosity in production
  max_bytes: 10485760    # 10MB per file
  backup_count: 10       # Retain more history
```

---

## Future Roadmap

| Phase | Feature | Impact |
|-------|---------|--------|
| **R1** | Harden FastAPI backend + WebSocket alert streaming | Production-grade auth, schemas, and event delivery |
| **R2** | iptables / nftables adaptive firewall enforcement | Policy manager, validation, rollback, and expiry automation |
| **R3** | VLAN-based device quarantine | Full device isolation without manual intervention |
| **R4** | Jetson Orin Nano GPU inference node | 10x inference throughput, sub-1ms latency |
| **R5** | LSTM sequence modeling | Multi-step attack chain detection across time |
| **R6** | React SOC dashboard hardening | Production-grade UI replacing Streamlit |
| **R7** | Reinforcement learning firewall | Self-adapting rules from threat feedback loops |
| **R8** | Zero-trust micro-segmentation | Per-device trust scoring and network segmentation |
| **R9** | Multi-node distributed deployment | Centralized management of distributed SentinelEdgeAI mesh |
| **R10** | CVE feed + STIX/TAXII integration | Live threat intelligence sync without cloud dependency |
| **R11** | Autonomous response system | Fully automated threat response without human intervention |
| **R12** | PostgreSQL-backed persistence | Replace JSON files for high-throughput production environments |

---

## Limitations

- **Root privileges required** — packet capture needs administrator access on Linux/macOS/Windows
- **Cold-start period** — the anomaly engine requires ~50+ flows (configurable) before it activates; the first 2 weeks of deployment will have higher false positives while the baseline learns your network
- **JSON persistence** — not optimized for high-throughput environments; PostgreSQL migration is on the roadmap
- **No encrypted payload inspection** — TLS 1.3 payloads are opaque; detection relies on metadata, flow behavior, and JA3 fingerprinting (not decryption)
- **Designed for SME scale** — tested on networks up to ~1 Gbps throughput; high-bandwidth enterprise environments may need hardware upgrade
- **No HA / failover** — single-node deployment at prototype stage; hardware failure causes monitoring outage
- **ML model not pre-trained on labeled attack datasets** — Isolation Forest is unsupervised and learns your specific network's baseline

---

## Troubleshooting

### Dashboard shows no data

```bash
# Verify the data files exist
ls data/

# Check that the sniffer is running and processing flows
tail -f logs/sentinel.log

# Wait 30+ seconds — flows must expire (idle timeout) before appearing
```

### No alerts being generated

```bash
# Lower the z_threshold in config.yaml to increase sensitivity
# Check that warmup is complete (first 50+ flows)
grep "warmup" logs/sentinel.log

# Confirm min_risk_score is not set too high
cat config.yaml | grep min_risk_score
```

### Permission denied on packet capture

```bash
# Linux / macOS
sudo python main.py

# Or grant capability without sudo (Linux only)
sudo setcap cap_net_raw+eip $(which python3)

# Windows — run terminal as Administrator
```

### High CPU usage

```bash
# Reduce baseline window size
baseline:
  window_size: 50     # Default is 100

# Increase alert threshold to process fewer alerts
alerts:
  min_risk_score: 35
```

### High false positive rate

```bash
# Increase z_threshold (more conservative)
anomaly:
  z_threshold: 3.5

# Allow longer warmup period
anomaly:
  warmup_flows: 100
```

---

## Version History

### v1.0 — 2026-02-15

Initial stable engineered release.

- ✅ Scapy-based packet capture
- ✅ 24-feature statistical flow extraction
- ✅ Z-score anomaly engine with warmup period
- ✅ Isolation Forest ML classifier
- ✅ Behavioral fingerprinting with drift detection
- ✅ Multi-layer risk escalation engine (0–100)
- ✅ MITRE ATT&CK tactic/technique mapping
- ✅ Streamlit SOC dashboard (auto-refresh 3s)
- ✅ Rotating structured logging (5MB × 5 files)
- ✅ JSON persistence (alerts, profiles, timeline, health)
- ✅ Engine health monitoring (CPU, memory, uptime)
- ✅ YAML-driven configuration system
- ✅ Comprehensive exception handling on all critical paths

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request so the approach can be discussed first.

```bash
# Fork the repo, then:
git checkout -b feature/your-feature-name
git commit -m "feat: describe your change clearly"
git push origin feature/your-feature-name
# Open a pull request against main
```

**Areas actively looking for contributions:**

- FastAPI backend + WebSocket hardening
- iptables / nftables enforcement policy manager
- Jetson Orin Nano deployment guide and GPU inference optimization
- LSTM sequence model implementation
- Additional MITRE ATT&CK technique coverage

---

## License

Proprietary — SentinelEdge AI v1.0

For licensing inquiries, please open a GitHub issue.

---

<div align="center">

**SentinelEdgeAI** — Modular Behavioral Network Detection at the Edge

*Built for networks that can't afford to be breached, and can't afford enterprise pricing.*

</div>
