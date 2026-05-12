Build summary - automated local run
=================================

Date: 2026-05-12

Overview:
- Environment: venv at `/home/vishwa/SentinelEdgeAI/venv` used.
- Python: 3.13.5

Steps performed and results:
- Install Python dependencies: completed (requirements satisfied in venv).
- Frontend build: completed (`frontend/dist` produced by Vite). Warning: some chunks >500KB.
- Unit tests: executed; no tests found.
- Security scans:
  - Bandit report: /tmp/bandit_report.json
  - pip-audit report: /tmp/pip_audit_report.txt (found 2 known vulnerabilities)
- Model signature smoke test: succeeded (packaging/model_sign_smoke.sh)
- Docker compose: backend image built successfully; containers did not fully start (see docker compose output). Buildx plugin warning present.
- E2E smoke: ran `scripts/e2e_smoke.py` — failed due to missing model signing key and permission error reading `/etc/sentinel/health.env`.

Next actions / fixes recommended:
- If you want to run e2e locally, set `SENTINEL_MODEL_SIGNING_KEY` or `SENTINEL_MODEL_SIGNING_KEY_FILE` and create `/etc/sentinel/health.env` with correct permissions or run the script with adjusted env pointing to a local test file.
- For Docker: install Docker Buildx plugin or use `docker buildx` where available. Ensure Docker daemon is running and user has permission to run docker commands.
- Review pip-audit output and remediate the two reported vulnerabilities.
- Consider code-splitting to reduce large frontend chunks.

Artifacts and logs:
- Bandit JSON: /tmp/bandit_report.json
- pip-audit report: /tmp/pip_audit_report.txt

If you want, I can open and apply fixes for the vulnerabilities and attempt to re-run the failing steps.
