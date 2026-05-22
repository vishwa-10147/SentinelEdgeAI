# Render Deployment (optional)

This project is intended to run locally for security. If you choose to deploy the frontend/backend to Render for remote access, follow these notes.

Prereqs
- A Render account and a created Service for the frontend (static) and backend (web service). Note the backend `serviceId`.
- Repository secrets set in GitHub:
  - `RENDER_API_KEY` — your Render API key (keep secret)
  - `RENDER_SERVICE_ID` — the Render service ID to deploy (backend)

What the CI does
- The workflow `.github/workflows/ci.yml` runs unit tests, integration test, builds the frontend, and — if both `RENDER_API_KEY` and `RENDER_SERVICE_ID` are provided in repo secrets and the push is on `main` — triggers a Render deploy via the Render API.

How to add secrets
1. Go to your GitHub repository -> Settings -> Secrets -> Actions.
2. Add `RENDER_API_KEY` and `RENDER_SERVICE_ID`.

Render tips
- For the backend, set the start command to: `uvicorn dashboard.dashboard_api:app --host 0.0.0.0 --port $PORT`.
- For the frontend static site, use `npm run build` and `npm run preview` or configure as a static site.
- Keep capture on the Pi — do not run packet capture on the hosted Render service. Instead, have the Pi push sanitized events to the hosted UI via a secure relay if remote capture is required.

Security
- DO NOT store raw capture files or secrets in the repository. Use Vault or Render's environment variables to manage secrets.
- Use `REDACT_SENSITIVE=1` and `REDACT_SALT` on hosted instances if you must expose any telemetry.

If you want, I can prepare a Render `render.yaml` tailored to your Render service IDs and automate the deploy step fully once you provide `RENDER_SERVICE_ID` and `RENDER_API_KEY`.

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

