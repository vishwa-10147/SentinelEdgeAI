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
