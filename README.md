<div align="center">

# 🛡️ SentinelEdgeAI

### AI-Powered Edge Cyber Defense Box

**Real-time network anomaly detection, behavioral profiling, and adaptive threat response — running fully on-premises, no cloud required.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205%20%2B%20Jetson%20Orin%20Nano-green?style=flat-square)](https://www.nvidia.com/en-us/autonomous-machines/embedded-systems/jetson-orin/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-purple?style=flat-square)](https://attack.mitre.org/)

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
| **Dashboard** | React SOC UI + WebSocket alerts | 🗓 Roadmap |
| **Enforcement** | iptables / nftables dynamic rule injection | 🔧 In progress |
| **Enforcement** | VLAN-based device isolation / quarantine | 🔧 In progress |
| **Backend** | FastAPI REST + WebSocket backend | 🔧 In progress |
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
               │  alerts.json · device_profiles.json                  │
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
Step 08  PERSIST       alerts.json · device_profiles.json · risk_timeline.json updated
           ↓
Step 09  DASHBOARD     WebSocket pushes real-time alert to SOC dashboard
```

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
| `flow` | `timeout` | `30` | Flow idle timeout in seconds |
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
├── enforcement/                     # ← In progress
│   ├── firewall.py                  # iptables / nftables rule injection
│   └── isolator.py                  # VLAN-based device quarantine
│
├── api/                             # ← In progress
│   ├── main.py                      # FastAPI app
│   └── ws.py                        # WebSocket alert streaming
│
├── dashboard/
│   └── streamlit_app.py             # Streamlit SOC dashboard
│
├── data/                            # Runtime-generated files
│   ├── alerts.json
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

- **ELK Stack** — use Filebeat to ship `alerts.json`
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
| **R1** | FastAPI backend + WebSocket alert streaming | Replaces Streamlit polling with real-time push |
| **R2** | iptables / nftables adaptive firewall enforcement | Active blocking becomes operational |
| **R3** | VLAN-based device quarantine | Full device isolation without manual intervention |
| **R4** | Jetson Orin Nano GPU inference node | 10x inference throughput, sub-1ms latency |
| **R5** | LSTM sequence modeling | Multi-step attack chain detection across time |
| **R6** | React SOC dashboard | Production-grade UI replacing Streamlit |
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

- FastAPI backend + WebSocket implementation
- iptables / nftables enforcement module
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
