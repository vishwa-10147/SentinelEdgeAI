Project History & Technical Notes
================================

This document records major changes, design decisions, and setup steps for SentinelEdgeAI. It is intended to be a living document and updated automatically by the build/CI helper when releases or important changes are made.

2026-05-13: Release v2026.05.13
- Created branch `ci/compose-health-and-security` and merged to `main`.
- Added CI security workflow `.github/workflows/security-scans.yml` to run `pip-audit` and `bandit` and upload JSON artifacts.
- Hardened CI health server helper `scripts/run_ci_health_server.py` to auto-add repo root to `PYTHONPATH` and produce robust nohup logs.
- Updated `docker-compose.yml`: removed obsolete `version` field and added a `healthcheck` for the backend API.
- Upgraded `urllib3` to `>=2.7.0` to address CVEs CVE-2026-44431/44432.
- Added `scripts/install_on_device.sh` — a platform-detecting installer for Raspberry Pi / Jetson / x86 that installs system deps, creates a venv, installs Python packages, and can register a systemd service.
- Packaged a Raspberry Pi tarball under `packaging/pi/` and validated `packaging/pi/install_from_package.sh` by installing to `/opt/sentineledgeai_test`.
- Created/updated documentation: `README_LOCAL.md`, `BUILD_SUMMARY.md`, `docs/SELF_HOSTED_RUNNER.md`.

Earlier context (summary of prior work)
- Model signing: introduced `security/model_signing.py` and `scripts/sign_model.py` to sign and verify models used by `detection/ml_engine.py`.
- E2E smoke fixes: patched `scripts/e2e_smoke.py` to add timeouts, limited retries, and permission handling for health env files.
- Background CI health server helper added to run health endpoint for e2e tests.
- Frontend built with Vite; static assets served by `dashboard/dashboard_api.py` when `frontend/dist` exists.
- Unit tests: current suite shows `31 passed, 2 skipped` locally.

How to use this file
- This is the canonical project history file. Each release or significant CI change should append a short entry here (date, tag/branch, bullets of changes).
- I will update this file automatically when I apply repo-level changes during this session. Please review before releases.

Important files & locations
- Installer script: `scripts/install_on_device.sh` (supports `--install-deps` and `--enable-service`).
- Pi package installer: `packaging/pi/install_from_package.sh` and tarballs under `packaging/pi/`.
- CI security workflow: `.github/workflows/security-scans.yml`.
- CI health helper: `scripts/run_ci_health_server.py`.
- Docker compose: `docker-compose.yml` (backend healthcheck added).

Contact
- For packaging or CI questions, see `agents.md` or open an issue in the repo.
