# Current Security Audit (automated scan snapshot)

Date: 2026-05-08

Summary: `pip-audit` run against the project's virtualenv found several known vulnerabilities. Run `./venv/bin/pip-audit --progress=off` locally to reproduce.

Findings and recommended fixes:

- fastapi 0.99.1 — multiple issues (PYSEC-2024-38). Recommended upgrade: `fastapi>=0.109.1`.
- gitpython 3.1.46 — multiple CVEs (CVE-2026-42215, CVE-2026-42284, CVE-2026-44244). Recommended upgrade: `gitpython>=3.1.49`.
- pillow 12.1.1 — multiple CVEs. Recommended upgrade: `pillow>=12.2.0`.
- requests 2.32.5 — CVE-2026-25645. Recommended upgrade: `requests>=2.33.0`.
- starlette 0.27.0 — CVEs. Recommended upgrade: `starlette>=0.40.0` (or the latest compatible with FastAPI).
- tornado 6.5.4 — GHSA/CVEs. Recommended upgrade: `tornado>=6.5.5`.

Notes:
- Some upgrades may require pinning compatible versions in `requirements.txt` and running full test suite. Test locally after upgrades.
- `requirements.txt` in the repo appears to contain corrupted content in this workspace; ensure `requirements.txt` is valid before applying blanket upgrades in CI.

Next steps I can take for you:
- Create a PR that updates the pinned package versions and runs the test suite. (I can do this.)
- Add Dependabot config to propose dependency upgrades automatically.
- Run `bandit` results triage and apply low-risk fixes (e.g., use `shlex` for shell args, avoid shell=True, etc.).
