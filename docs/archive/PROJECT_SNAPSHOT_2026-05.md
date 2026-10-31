# Project Snapshot

Short summary of SentinelEdgeAI — what it is and what we've completed.

## What it is

SentinelEdgeAI is a compact, on-premises edge security appliance that performs
real-time packet capture, behavioral feature extraction, ML-based anomaly
detection, and automated enforcement. It exposes REST and WebSocket APIs for
dashboards and integrations and is designed to run on constrained devices
(Raspberry Pi / NVIDIA Jetson).

## Key completed pieces

- Packet capture and async ingestion (`capture/`)
- Feature extraction and detection pipeline (`detection/`)
- SQLite DB-first persistence with maintenance (`core/storage_sqlite.py`, `core/db_maintenance.py`)
- FastAPI backend with WebSocket streaming (`dashboard/dashboard_api.py`)
- Model signing and CI smoke checks (model signature guards, `scripts/check_db_streaming*.sh`)

## Recommended next steps

- Provision model-signing keys on devices (`SENTINEL_MODEL_SIGNING_KEY_FILE`).
- Disable legacy file fallback (`ENABLE_FILE_FALLBACK=0`) after client migration.
- Harden WebSocket schemas, add retention policy configuration, and expand CI matrix.

---

For more details see the repository and the concise `README.md` home page.
