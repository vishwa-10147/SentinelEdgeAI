# SentinelEdgeAI Build Plan

## Product Goal

Build a real-time, behavioral, and visual cybersecurity appliance:

- Raspberry Pi: capture, flow aggregation, safe firewall enforcement.
- Jetson Orin Nano: ML and detection engine.
- Backend API: data, control, WebSocket streaming.
- React dashboard: topology, alerts, device action workflow.
- Storage layer: JSON history now, database later.

## System Layers

```text
Raspberry Pi       -> Capture + Enforcement
Jetson Orin Nano   -> ML / Detection Engine
Backend API        -> Data + Control + WebSocket
React Dashboard    -> Visualization + Actions
Storage Layer      -> History + Models
```

## Priority Backlog

1. Topology UI
   - Cytoscape.js device nodes and flow edges.
   - Risk-based node and edge coloring.
   - Limited flow animation, max 3-5 particles per edge.
   - Blocked flow animation stops midway.

2. Device Detail Panel
   - IP, MAC, risk score, last 20 flows.
   - Behavior summary and MITRE mapping.
   - Actions: block, whitelist, undo within 30 seconds.

3. Historical Data Storage
   - Store processed flows in `flows_history.jsonl`.
   - Store alerts in `alerts.json`.
   - Store profiles in `device_profiles.json`.
   - Keep database migration as a later step.

4. ML Training Pipeline
   - Offline trainer: `scripts/train_model.py`.
   - Input: `flows_history.jsonl`.
   - Output: `model/isolation_forest.pkl`.
   - Runtime loads trained model when present and falls back to online learning when absent.

5. Demo Mode
   - `POST /api/demo/run`.
   - Sequence: normal traffic, attack, alert, block.
   - Stream demo events over `/ws/packets`.

6. Docker Deployment
   - Backend container.
   - Frontend container.
   - One-command start through `docker compose up`.

## Edge Sensor Layer

- Optimize `capture/sniffer.py` for stable capture loops.
- Aggregate flows by 5-tuple; do not stream raw packet visualization.
- Send flow events to backend as JSON/WebSocket payloads.
- Keep `FIREWALL_DRY_RUN=1` as the default.
- Maintain TTL block expiry and whitelist support.

## Jetson Detection Layer

- Keep Z-score anomaly detection.
- Keep Isolation Forest with online fallback.
- Add offline Isolation Forest training from stored flows.
- Maintain per-device behavioral profiles:
  - average packets/sec,
  - common ports,
  - typical destinations.
- Increase risk on behavior deviation.
- Do not add deep learning, LSTM, or GNN models yet.

## Backend API

- `/api/health`
- `/api/alerts`
- `/api/firewall/*`
- `/api/demo/run`
- `/ws/packets`
- Persist JSON-first storage until database migration is justified.

## Firewall System

- Block IP.
- Unblock IP.
- TTL expiry.
- Rollback endpoint.
- Whitelist support.
- Action logging.
- Emergency rollback.
- No complex policy engine yet.

## Testing And Validation

- Unit tests for firewall and detection.
- Demo traffic script: `scripts/demo_attack.py`.
- PCAP replay script.
- Optional Docker integration tests later.

## Future AI Assistant

Plan only for now:

- Explain alerts.
- Summarize risk.
- Recommend operator actions.

Do not build the assistant in this phase.
