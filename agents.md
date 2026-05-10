Agents used in this workspace

Purpose
- Capture the set of IDE/subagents and explain what each one does and how it maps to common tasks (CI, security scans, frontend build, test, runner provisioning, monitoring).

Agents (IDE / subagents)
- Explore: quick, read-only codebase exploration and Q&A. Use for locating files, summarizing code, and answering repo-structure questions. Good for rapid discovery (quick/medium/thorough modes).
- CI Monitor (conceptual): polls GitHub Actions `gh run view` loops, fetches logs and saves to `/tmp/run_<id>.log`. Useful to watch self-hosted runs (privileged Docker) and collect logs for triage.
- Security Scanner (conceptual): runs `pip-audit` and `bandit` across the repo, produces JSON/ text reports in `/tmp` and suggests minimal remediations.
- Frontend Builder (conceptual): executes `npm install` and `npm run build` in `frontend/`, reports chunk sizes and identifies heavy modules for lazy-loading.
- Test Runner (conceptual): runs `pytest -q`, captures results in `/tmp/pytest_local.txt` and `/tmp/pytest_after_bandit.txt`.
- Runner Provisioner (conceptual): assists in preparing and registering self-hosted runners, adjusting labels (e.g. adding `docker`) and fixing filesystem ownership issues in the runner workspace.

How these agents are used in this project
- Typical flow: Explore → Frontend Builder → Security Scanner → Test Runner → CI Monitor → Runner Provisioner.
- Example tasks performed recently: fixed `requirements.txt` dependency conflict; patched `.github/workflows/containerized-firewall-integration.yml`; labeled self-hosted runner (`docker`); ran privileged CI on runner and saved logs; resolved EACCES by `chown` on runner workspace.

Files & artifacts they output
- CI logs: `/tmp/run_<id>.log` and `/tmp/ci_run_<id>.log` (saved by CI Monitor polling scripts)
- Bandit: `/tmp/bandit_report.json` (or similar JSON output)
- pip-audit: `/tmp/pip_audit_report.txt`
- pytest: `/tmp/pytest_local.txt`, `/tmp/pytest_after_bandit.txt`
- Frontend build: `frontend/dist/` (chunk sizes printed to console)

How you can invoke them (manual commands)
- CI Monitor: `gh run view <id> --log` (or run the provided poll loop in background)
- pip-audit: `pip-audit --output /tmp/pip_audit_report.txt`
- bandit: `bandit -r capture core detection features flow utils -x venv,actions-runner -f json -o /tmp/bandit_report.json`
- frontend build: `cd frontend && npm install && npm run build`
- local tests: `pytest -q`

Notes / Best practices
- When running Bandit in CI or locally, exclude runner workspace directories and venvs to avoid duplicate `.bandit` config collisions.
- Use dynamic imports for heavy frontend libs (`recharts`, `react-cytoscapejs`) to reduce initial bundle size.
- When invoking system commands from Python, validate input and avoid `shell=True`. Prefer `subprocess.run([...], check=True)` with vetted args (we added input validation in `core/firewall.py`).

If you want, I can:
- Add concrete shell helper scripts under `/scripts/` to run these agents consistently.
- Create a short README for on-device smoke tests and runner provisioning steps.
