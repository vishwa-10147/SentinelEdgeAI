# Frontend (React + Vite)

This folder contains the React-based SOC UI built with Vite.

Quick Commands

Install dependencies:

```bash
cd frontend
npm ci
```

Run dev server:

```bash
npm run dev
# open http://127.0.0.1:5173
```

Build production bundle:

```bash
npm run build
# output -> frontend/dist
```

Notes
- `frontend/dist/` is intentionally ignored in git; CI builds the artifact and uploads it to the PR.
- Keep `node_modules/` out of the repo; use `npm ci` to install using `package-lock.json` for reproducible builds.

If you want me to update the homepage content, provide the prompt and I'll edit `frontend/src` accordingly and open a PR update.
Frontend scaffold (React + Vite)

Quick start (local):

```bash
cd frontend
npm install
npm run dev
```

The frontend expects a backend API at `VITE_API_BASE` (default `http://localhost:9000`). Run the dashboard API:

```bash
pip install -r requirements.txt
python dashboard/dashboard_api.py
```

When deploying to Render, build the frontend (`npm run build`) and serve as a static site, or deploy both frontend and `dashboard_api.py` as separate services.

Render quick deploy (example)

1. Create two services on Render or use `render.yaml` in the repo root.
2. Frontend: set as a static site, build command: `cd frontend && npm install && npm run build`, publish directory `frontend/dist`.
3. Backend: set as a web service (Python), start command: `uvicorn dashboard.dashboard_api:app --host 0.0.0.0 --port $PORT`.

After deploy, set `VITE_API_BASE` in the frontend environment to the backend URL (e.g., https://sentinel-backend.onrender.com).
