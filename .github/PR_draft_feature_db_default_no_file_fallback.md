Title: Disable file fallback by default; add DB maintenance

Summary
-------
This change flips the default on-device behavior to prefer SQLite persistence and DB-driven streaming over legacy file-based fallbacks. It also adds a lightweight background DB maintenance thread to run periodic retention and `VACUUM` to keep the database compact.

Files Changed (high level)
- `scripts/install_on_device.sh` — installer service template now sets `ENABLE_FILE_FALLBACK=0` for the created systemd unit.
- `packaging/sentinel-health-agent.service` — service unit now sets `Environment=ENABLE_FILE_FALLBACK=0`.
- `core/db_maintenance.py` — new background maintenance worker (retention + VACUUM).
- `core/storage_sqlite.py` — added `vacuum()` method used by maintenance.
- `dashboard/dashboard_api.py` — starts/stops DB maintenance during FastAPI lifespan.
- `README.md` — documented `ENABLE_FILE_FALLBACK` and `DISABLE_DB_MAINTENANCE` usage.

Testing
-------
- Unit tests: `pytest -q` — 31 passed, 2 skipped (local CI run included in branch commits).
- Verified DB created at `data/sentinel.db` and contains alerts/flows/live_events from demo scripts.
- Installer template and packaging service were updated; unit file addition should be validated during device provisioning (systemctl daemon-reload + restart).

Migration & Rollout Notes
------------------------
- This change disables file-based fallbacks by default. For staged rollouts, set `ENABLE_FILE_FALLBACK=1` in device service drop-ins or environment.
- To disable automatic DB maintenance on devices that prefer external maintenance, set `DISABLE_DB_MAINTENANCE=1`.
- Operators should confirm any downstream integration that relied on JSON/JSONL files is migrated to the DB API/websocket before mass rollout.

Risks & Rollback
----------------
- Risk: older management scripts expecting file outputs may break. Rollback: create a systemd drop-in to set `ENABLE_FILE_FALLBACK=1` and restart the service.

Requested Reviewers / Labels
---------------------------
- Reviewers: @infra, @backend
- Labels: enhancement, infra, db

Follow-ups
----------
1. Add integration test validating websocket DB-only streaming end-to-end.
2. Add an opt-in config to expose retention windows via `config.yaml`.
