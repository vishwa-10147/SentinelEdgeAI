Raspberry Pi deployment

This folder contains helper scripts to install and run SentinelEdgeAI on a Raspberry Pi.

Quick installer (preferred):

```bash
chmod +x scripts/setup_pi.sh
sudo bash scripts/setup_pi.sh        # installs main service
sudo bash scripts/setup_pi.sh streamlit   # installs Streamlit service
```

Manual run (useful for debugging):

```bash
source $HOME/.venv/sentineledgeai/bin/activate
python main.py
# or run the dashboard
streamlit run dashboard/streamlit_app.py --server.port 8501 --server.address 0.0.0.0
```

Helpers in this folder:
- `install_pi.sh` — wrapper that invokes `scripts/setup_pi.sh` with sudo.
- `run_manual.sh` — convenience helper to run main or Streamlit from the venv.
