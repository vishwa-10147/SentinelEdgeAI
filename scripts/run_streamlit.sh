#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -x "$ROOT/venv/bin/python" ]; then
    PY="$ROOT/venv/bin/python"
else
    PY=${PYTHON:-python3}
fi

# Default DATABASE_URL if not provided (local container created earlier)
DATABASE_URL=${DATABASE_URL:-postgresql://sentinel:sentinel@127.0.0.1:5432/sentinel}

echo "Starting Streamlit (DATABASE_URL=$DATABASE_URL)"
env DATABASE_URL="$DATABASE_URL" $PY -m streamlit run dashboard/streamlit_app.py --server.port 8501
