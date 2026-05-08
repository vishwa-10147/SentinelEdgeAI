Jetson (NVIDIA) deployment

This folder contains helper steps for running on NVIDIA Jetson devices. Jetson runs Ubuntu-based images but may require additional native packages (CUDA, cuDNN) for GPU-accelerated ML.

Basic steps (CPU-only / quick start):

```bash
# create venv and install deps
python3 -m venv $HOME/.venv/sentineledgeai
source $HOME/.venv/sentineledgeai/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# run main
python main.py

# run dashboard
streamlit run dashboard/streamlit_app.py --server.port 8501 --server.address 0.0.0.0
```

If you need GPU support, install appropriate CUDA and system packages from NVIDIA Jetson docs before installing Python packages.

Helper script: `setup_jetson.sh` — creates venv and installs Python dependencies.
