Release notes for feature/dashboard-redesign

- Frontend: lazy-loaded charts and topology to reduce initial bundle size.
  - `AnalyticsTrend`, `AnalyticsPie` now dynamically import `recharts`.
  - `TopologyCytoscape` now dynamically imports `react-cytoscapejs`.
- Security: Bandit findings remediated where practical.
  - Replaced silent `except: pass` with debug logging in `capture/sniffer.py` and `detection/ml_engine.py`.
  - Hardened subprocess invocation in `core/firewall.py` with input validation and logging.
  - Health server shutdown logs improved and binding rationale annotated.
- Tests: all unit tests passing locally (31 passed, 2 skipped).
- CI: workflow `containerized-firewall-integration.yml` previously fixed; recent runs completed successfully on self-hosted runner.

Next recommended steps (need confirmation):
- Run Pi smoke tests (`scripts/README_pi_setup.md` / `scripts/smoke_anomaly_engine.py`).
- Open PR and merge `feature/dashboard-redesign` into `main` and create a release tag.
- Additional frontend chunk tuning (optional).

## 2026-05-23 — Security patch release (local)

- Bumped `starlette` to `1.0.1` to address a host-header reconstruction vulnerability found by `pip-audit`.
- Ran full test suite locally: `pytest` — 31 passed, 2 skipped.
- Ran `bandit` and project-scoped scans; no actionable findings in project source files.
- Built Raspberry Pi package: `dist/sentineledgeai-pi-20260523064829.tar.gz`.

Notes:
- No automatic PRs were opened; changes are on branch `chore/security-updates` and merged to `main` locally. A remote branch `chore/security-updates` was also pushed.
- Recommend tagging a release (e.g., `v0.0.1-security-20260523`) after review.
