# Streamlit Dashboard

Quick instructions to run the in-repo Streamlit dashboard which reads from Postgres when `DATABASE_URL` is set, otherwise falls back to JSON files.

Run with the repo virtualenv (recommended):

```bash
# ensure venv is active or use the helper script
source venv/bin/activate
# use local Postgres container credentials (adjust if needed)
export DATABASE_URL=postgresql://sentinel:sentinel@127.0.0.1:5432/sentinel
bash scripts/run_streamlit.sh
```

The dashboard is available at http://localhost:8501 by default.

If you prefer Grafana for visualization, I can add a `docker-compose` snippet to run Grafana and a starter dashboard.
