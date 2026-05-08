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
