# Render & GitHub Secrets Example

This file documents the secrets and environment variables you should set when using Render + GitHub Actions to deploy the dashboard (optional).

GitHub repository secrets (Settings → Secrets → Actions)
- RENDER_API_KEY: your Render API key (personal or service key). Required for the CI deploy job.
- RENDER_SERVICE_ID: the Render service id of the backend to trigger a deploy (optional if you won't use CI deploy).

Render service environment variables (set in Render Dashboard → Service → Environment)
- DASHBOARD_API_KEY: a strong API key for your dashboard (keep secret). The backend will enforce it if present.
- REDACT_SENSITIVE: set to `1` if you want the deployed instance to redact IP/MAC data shown in the UI.
- REDACT_SALT: a strong random value used to salt the redaction hash (do not commit this to the repo).
- VITE_API_BASE (frontend service): set to the backend URL if not autodiscovered. Example: `https://your-backend.onrender.com`

Notes & guidance
- Do NOT push secret values to the repo. Use Render's environment settings and GitHub repository secrets.
- Keep `REDACT_SALT` confidential; changing the salt will change hashed identifiers in the UI.
- The CI deploy added in `.github/workflows/ci.yml` will only trigger a Render deploy when both `RENDER_API_KEY` and `RENDER_SERVICE_ID` are set in GitHub secrets on pushes to `main`.

Security recommendation
- Keep packet capture on the Pi and never run raw capture on hosted Render instances.
- If you need remote UI access, push sanitized aggregates only and keep raw telemetry local.

Example steps
1. Create a Render service for backend and frontend. Note the backend service ID.
2. In GitHub, add `RENDER_API_KEY` and `RENDER_SERVICE_ID` secrets.
3. In the Render backend service, set the environment variables `DASHBOARD_API_KEY` and `REDACT_SALT`.
4. Push to `main` — CI will run tests and trigger the Render deploy if secrets are present.
