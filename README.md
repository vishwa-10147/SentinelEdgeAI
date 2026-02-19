# 🚨 SentinelEdge AI v1.0

**Production-Ready Network Anomaly Detection Engine with Hybrid Detection Layers**

A complete IDS/IPS framework combining statistical analysis, machine learning, behavioral profiling, and MITRE ATT&CK mapping for enterprise-grade threat detection.

---

## 📋 Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Components](#components)
- [Monitoring & Observability](#monitoring--observability)
- [Dashboard](#dashboard)
- [Dashboard Preview](#-dashboard-preview)
- [Production Deployment](#production-deployment)
- [Limitations](#-limitations)
- [Future Roadmap](#-future-roadmap)

---

## ✨ Features

### Detection Capabilities
- **Hybrid Anomaly Detection** — Statistical z-score analysis + Isolation Forest-based anomaly detection
- **Adaptive Baseline Learning** — Self-tuning baseline per protocol/device
- **Behavioral Fingerprinting** — Device behavior profiling with drift detection
- **Unified Risk Engine** — Multi-layer risk calculation and escalation
- **MITRE ATT&CK Mapping** — Automatic threat classification against MITRE framework
- **Configurable Thresholds** — Risk levels (Critical/High/Medium/Low/Normal) via YAML

### Observability & Operations
- **Structured Logging** — RotatingFileHandler with 5MB rotation (5 backups)
- **Performance Monitoring** — Per-flow timing + 100-flow aggregate metrics
- **Health Monitoring** — Engine uptime, flow count, CPU/memory snapshots
- **SOC Dashboard** — Real-time Streamlit web interface
- **JSON Persistence** — Alerts, device profiles, risk timeline, health status

### Engineering Quality
- **Exception Handling** — Comprehensive try-except on all critical paths
- **Configuration Management** — Centralized YAML with nested key access
- **Clean Architecture** — Orchestrator pattern with dependency injection
- **Safe Data Loading** — JSON loaders with fallback defaults

---

## 🏗️ System Architecture

```
Network Traffic
      ↓
┌──────────────────────────┐
│  Packet Capture          │ (Scapy-based)
│  (capture/sniffer.py)    │
└──────────────┬───────────┘
               ↓
┌──────────────────────────────────────────┐
│  Flow Processing & Feature Extraction    │
│  - Flow Table (30s idle timeout)        │
│  - Feature Extractor (24 statistical)   │
└──────────────┬───────────────────────────┘
               ↓
┌──────────────────────────────────────────────────────────┐
│  Multi-Layer Detection (core/engine.py)                  │
├──────────────────────────────────────────────────────────┤
│  ├─ Anomaly Engine (z-score with warmup)               │
│  ├─ ML Engine (Isolation Forest classifier)            │
│  ├─ Behavioral Fingerprinting (device profiles)        │
│  ├─ Drift Detection (behavioral deviation tracking)    │
│  ├─ Attack Classifier (threat type mapping)            │
│  ├─ Risk Escalation Engine (unified scoring)           │
│  └─ MITRE Mapper (tactic/technique assignment)         │
└──────────────┬───────────────────────────────────────────┘
               ↓
┌──────────────────────────────────────────┐
│  Alert & Persistence                     │
│  - alerts.json (HIGH+ severity)         │
│  - device_profiles.json (fingerprints)  │
│  - risk_timeline.json (per-device)      │
│  - live_stats.json (flow history)       │
│  - health.json (engine status)          │
│  - sentinel.log (structured logging)    │
└──────────────┬───────────────────────────┘
               ↓
┌──────────────────────────────────────────┐
│  SOC Dashboard (Streamlit)               │
│  - Metrics & alerts                      │
│  - Device profiles & risk leaderboard   │
│  - Risk timeline visualization          │
│  - MITRE mapping view                   │
│  - Engine health monitoring              │
└──────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip package manager
- Administrator/root access (for packet capture)

### Setup

```bash
# Clone repository
git clone <repository-url>
cd SentinelEdgeAI

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies (v1.0 Locked)
See `requirements.txt` for complete pinned versions.

Key packages:
- **scapy** — Network packet capture
- **streamlit** — Dashboard UI
- **pandas** — Data manipulation
- **scikit-learn** — ML classification
- **pyyaml** — Configuration management
- **psutil** — System resource monitoring

---

## 🚀 Quick Start

### 1. Configure the System
Edit `config.yaml` to tune detection parameters:

```yaml
risk_thresholds:
  critical: 75
  high: 50
  medium: 25

anomaly:
  z_threshold: 3       # Standard deviations
  warmup_flows: 50     # Baseline learning period

baseline:
  window_size: 100     # Rolling window for feature baseline
  
logging:
  level: INFO          # DEBUG, INFO, WARNING, ERROR
  max_bytes: 5242880   # 5MB per file
  backup_count: 5      # Keep 5 backup files
```

### 2. Start the Engine

```bash
# Start packet sniffer (requires admin)
python main.py

# In separate terminal: start dashboard
streamlit run dashboard/streamlit_app.py
```

### 3. Access the Dashboard
- **URL**: `http://localhost:8501`
- **Auto-Refresh**: Every 3 seconds
- **Endpoints**: Metrics, alerts, device profiles, risk timeline, health status

---

## ⚙️ Configuration

### config.yaml Structure

| Section | Purpose | Key Parameters |
|---------|---------|-----------------|
| `risk_thresholds` | Alert severity levels | critical, high, medium |
| `anomaly` | Statistical detection | z_threshold, warmup_flows |
| `baseline` | Adaptive learning | window_size |
| `drift` | Behavioral deviation | deviation_threshold |
| `ml` | ML classification params | (currently placeholder) |
| `flow` | Flow processing | timeout |
| `alerts` | Alert filtering | min_risk_score |
| `persistence` | Data retention | history_limit |
| `logging` | Log rotation | level, max_bytes, backup_count |

### Tuning Detection

```yaml
# Stricter (fewer false negatives, more alerts)
anomaly:
  z_threshold: 2.5     # Lower = more sensitive
  
# Relaxed (fewer false positives, fewer alerts)
anomaly:
  z_threshold: 3.5     # Higher = more conservative
```

---

## 🔧 Components

### Core Modules

| Module | Purpose | Location |
|--------|---------|----------|
| **SentinelEngine** | Orchestrator for all detection layers | `core/engine.py` |
| **HealthMonitor** | Engine health & resource tracking | `core/health.py` |
| **Config** | YAML config loader with nested access | `core/config_loader.py` |
| **AnomalyEngine** | Z-score statistical detection | `detection/anomaly_engine.py` |
| **MLEngine** | Isolation Forest classification | `detection/ml_engine.py` |
| **BehavioralFingerprint** | Device profile tracking | `detection/behavioral_fingerprint.py` |
| **RiskEscalationEngine** | Unified risk calculation | `detection/risk_engine.py` |
| **MitreMapper** | ATT&CK framework mapping | `detection/mitre_mapper.py` |
| **FlowTable** | Flow state tracking | `flow/flow_table.py` |
| **FeatureExtractor** | 24-feature statistical extraction | `features/feature_extractor.py` |
| **AlertLogger** | Persistent alert storage | `utils/alert_logger.py` |

### Data Flow

```
Packet → Flow Table → Feature Extractor → SentinelEngine
  ↓
  └─→ [AnomalyEngine, MLEngine, BehavioralFingerprint, ...]
        ↓
      RiskEscalationEngine → MitreMapper
        ↓
      [alerts.json, device_profiles.json, risk_timeline.json]
        ↓
      Dashboard + Health Monitoring
```

---

## 📊 Monitoring & Observability

### Metrics Collection

#### Engine Metrics (sniffer.py)
- `flows_processed` — Total flow count
- `total_processing_time_ms` — Cumulative detection time

Logged every 100 flows:
```
INFO: Performance | Flows=100 | AvgProcessingTime=1.82 ms
INFO: System | CPU=12.4% | Memory=148.32 MB
```

#### Health Monitoring (health.json)
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
- **File**: `sentinel.log`
- **Max Size**: 5 MB per file
- **Backups**: 5 backup files retained
- **Format**: Structured logs with timestamps, severity, context

```
[2026-02-15 10:30:45,123] INFO: Performance | Flows=100 | AvgProcessingTime=1.82 ms
[2026-02-15 10:30:46,456] WARNING: BEHAVIORAL DRIFT DETECTED | IP=192.168.1.10 | Reason=unusual_port_count
```

---

## 📈 Dashboard

### Dashboard Sections

1. **Metrics** (Top)
   - Total Flows
   - Active Devices
   - Total Alerts

2. **Traffic & Threat Trend**
   - Line chart of flow risk scores over time

3. **Alert Severity Breakdown**
   - Bar chart: CRITICAL, HIGH, MEDIUM, LOW, NORMAL

4. **Recent Alerts** (Table)
   - timestamp, IP, protocol, risk score, severity, attack type

5. **Device Risk Leaderboard**
   - Sorted by avg_risk_score (highest first)

6. **Device Risk Timeline**
   - Per-device risk trend visualization

7. **Engine Health Status**
   - Real-time health.json display
   - Uptime, flows, CPU, memory

8. **MITRE ATT&CK Mapping**
   - initiator_ip, severity, attack_type, tactic, technique_id, technique_name

---

## 📸 Dashboard Preview

*(Add a screenshot of the dashboard here to visually showcase the SOC interface.)*

![Dashboard](docs/dashboard.png)

---

## 🔐 Production Deployment

### Network Interface Selection

```python
# Default: all interfaces
python main.py

# Specific interface
from capture.sniffer import start_sniffing
start_sniffing(interface="eth0")
```

### Logging Configuration

Adjust in `config.yaml`:
```yaml
logging:
  level: WARNING      # Reduce verbosity in production
  max_bytes: 10485760 # 10MB per file
  backup_count: 10    # Retain more history
```

### SIEM Integration

Alerts are written to `alerts.json` in standard format:
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

**Integration Options:**
- Stream to ELK/Splunk via log shipper
- Query alerts.json via API
- Webhook integration (future)

---

## ⚠️ Limitations

- Requires administrator/root privileges for packet capture
- Designed for lab/small network environments (not distributed scale)
- ML model not trained on labeled attack datasets
- JSON-based persistence (not optimized for high-throughput production)
- No automated response or active blocking

---

## 🚀 Future Roadmap

- Database-backed persistence (PostgreSQL)
- Distributed sensor architecture
- REST API interface
- SIEM streaming integration
- Model retraining pipeline

---

## 🐛 Troubleshooting

### Dashboard Not Showing Data
1. Verify `live_stats.json` exists
2. Check sniffer is running (look for `sentinel.log`)
3. Wait 30+ seconds for first flows to expire and be processed

### No Alerts Generated
1. Confirm `alerts.min_risk_score` is not too high in config.yaml
2. Check `anomaly.z_threshold` — lower = more alerts
3. Verify baseline is learned (first 50+ flows)

### CPU Usage Spike
1. Reduce `baseline.window_size` (default: 100)
2. Increase alert minimum threshold
3. Profile with `logger.setLevel(logging.DEBUG)`

### Permission Denied (Packet Capture)
```bash
# Linux/Mac: use sudo
sudo python main.py

# Windows: Run as Administrator
```

---

## 📝 Version History

### v1.0 (2026-02-15) — Stable engineered release
✅ Hybrid detection framework (anomaly + ML)
✅ Adaptive baseline learning
✅ Behavioral fingerprinting with drift detection
✅ Multi-layer risk engine
✅ MITRE ATT&CK mapping
✅ SOC dashboard
✅ Health monitoring
✅ Log rotation infrastructure
✅ Performance metrics
✅ Configuration-driven system
✅ Exception safety on all critical paths

---

## 📞 Support & Contribution

For issues, feature requests, or contributions, please open a GitHub issue.

---

## 📄 License

Proprietary — SentinelEdge AI v1.0

---

## 🎯 Architecture Highlights

### Design Patterns
- **Orchestrator Pattern** — SentinelEngine coordinates all detection components
- **Dependency Injection** — All engines passed as constructor dependencies
- **Safe Defaults** — JSON loaders with fallback structures
- **Graceful Degradation** — Try-except on critical paths + logging

### Performance
- **Sub-2ms Flow Processing** — Modern CPU, <1250 flows/sec typical
- **Minimal Memory Overhead** — ~150MB with profiles + baseline
- **Non-Blocking Logging** — Async file writes, no detection latency
- **Efficient Feature Extraction** — 24 statistical features per flow

### Security
- No external API dependencies during runtime
- All data persisted locally (JSON files)
- Config-driven thresholds (easy compliance auditing)
- Comprehensive audit logging with timestamps

---

