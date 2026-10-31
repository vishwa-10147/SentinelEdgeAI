# Streamlit dashboard (legacy)

`dashboard/streamlit_app.py` is the original prototype dashboard. The supported console is the React web console served by the API (`https://<device>:9000`, see `frontend/README.md`). Streamlit isn't installed on devices.

For development only:

```bash
pip install -r requirements-streamlit.txt
export DATABASE_URL=postgresql://sentinel:sentinel@127.0.0.1:5432/sentinel   # optional; otherwise it reads the JSON files
bash scripts/run_streamlit.sh                                               # http://localhost:8501
```
