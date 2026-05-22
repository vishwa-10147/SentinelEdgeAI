# Local-only deployment

This project is intended to run locally and within internal networks for security and privacy. There is no remote hosting or Render integration enabled by default.

If you change your mind later and want to enable remote deploys (e.g., Render), the previous instructions and auxiliary scripts are preserved in the repository history and `deploy/` notes. You can re-add a deploy job to `.github/workflows/ci.yml` that reads `RENDER_API_KEY` and `RENDER_SERVICE_ID` from a GitHub Environment at runtime.

Key guidance for local use
- Run the backend locally: `uvicorn dashboard.dashboard_api:app --host 127.0.0.1 --port 8000`
- Run the frontend locally (development):

```bash
cd frontend
npm ci --legacy-peer-deps
npm run dev
```

- Keep packet capture on the Pi or local devices and only surface aggregated telemetry to any other systems.

If you want me to remove the auxiliary deploy scripts and docs entirely, say so and I will delete them.

Create a GitHub Environment (recommended)
---------------------------------------
For stricter control over deploy secrets prefer a GitHub Environment named `render`. You can create it via the UI or with the `gh` CLI. If you run into a 404 when using the API, it's usually because your personal token (or the GH session) lacks the `repo` scope or environment administration rights.

CLI (recommended)
- Ensure `gh` is authenticated with an account that has repository admin rights.
- Create the environment and set secrets (prompts for missing values):

```bash
chmod +x scripts/create_github_environment.sh
./scripts/create_github_environment.sh render
```

This script will create the `render` environment and optionally set `RENDER_API_KEY`, `RENDER_SERVICE_ID`, and `DATABASE_URL` as environment secrets. If the API returns a 404, open the repository Settings → Environments and create the `render` environment via the web UI instead.

UI (manual)
- Go to GitHub: Settings → Environments → New environment. Name it `render`.
- After creating the environment, add the secrets `RENDER_API_KEY`, `RENDER_SERVICE_ID`, and `DATABASE_URL` under the Environment's "Secrets" section.

Why use an Environment?
- Environments allow approvals, protected branches, and narrower access to secrets during workflow runs. They are strongly recommended for production deploy keys.

