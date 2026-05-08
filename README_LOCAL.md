# Local Development & Secure Local-Only Run

This project is designed to run fully locally (recommended for security-sensitive environments). This document shows minimal steps to run the backend + sniffer + frontend safely.

Prereqs
- Python 3.11+ (virtualenv)
- Node 18+ (for frontend dev)
- Optional: `ngrok` for temporary external webhook testing

Start backend with in-process sniffer (local only)
```bash
# create venv and install
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# run backend and start sniffer in-process (CAPTURE_IFACE optional)
CAPTURE_IN_PROCESS=1 CAPTURE_IFACE=eth0 .venv/bin/python -u dashboard/dashboard_api.py
```

Start frontend locally
```bash
cd frontend
npm ci
npm run dev
# open http://localhost:5173 (vite default)
```

Security best-practices for local run
- Keep `REDACT_SENSITIVE=1` enabled to redact IPs/MACs before sending to the UI when you plan to share screenshots. Set `REDACT_SALT` to a short secret to make hashes non-deterministic for outsiders.
- Do NOT expose the sniffer-capable host directly to the public internet. Use `ngrok` only for temporary testing and revoke the URL after tests.
- Set `DASHBOARD_API_KEY` if you want a shared key for local team access.

Systemd example (Pi) — run locally on a Pi (optional)
Create `/etc/systemd/system/sentinel-local.service` with content:

```
[Unit]
Description=SentinelEdgeAI Local Dashboard + Sniffer
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/SentinelEdgeAI
Environment=CAPTURE_IN_PROCESS=1
Environment=CAPTURE_IFACE=eth0
Environment=REDACT_SENSITIVE=1
Environment=REDACT_SALT=your_local_salt_here
ExecStart=/home/pi/SentinelEdgeAI/.venv/bin/python -u dashboard/dashboard_api.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

If you need raw socket capability, prefer granting `CAP_NET_RAW` on the service (drop-in) rather than running as root. Example drop-in at `/etc/systemd/system/sentinel-local.service.d/override.conf`:

```
[Service]
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
```

Notes
- By default the backend serves the API on port `9000` and the frontend dev server runs on `5173`. You can change `VITE_API_BASE` in frontend env or use `npm run build` + `npm run preview`.
- Use `REDACT_SENSITIVE=1` when capturing screenshots or sharing local UI results.
If you want, I can create the systemd unit file and enable it for you (requires `sudo`).

Demo and enforcement
--------------------
To run a full local demo (build frontend, start backend, generate an alert, and optionally block):

1. Build frontend for static serving (optional, required for `dashboard/dashboard_api.py` to serve UI):

```bash
./scripts/build_frontend.sh
```

2. Start the backend (example):

```bash
source .venv/bin/activate
# run backend; this will serve API on :9000 and static frontend if built
CAPTURE_IN_PROCESS=1 CAPTURE_IFACE=eth0 .venv/bin/python -u dashboard/dashboard_api.py
```

3. In another shell, generate a demo attack event:

```bash
python scripts/demo_attack.py --ip 192.0.2.55
# optionally call the firewall API to request a block (requires DASHBOARD_API_KEY if set):
DASHBOARD_API_URL=http://127.0.0.1:9000 DASHBOARD_API_KEY=$DASHBOARD_API_KEY python scripts/demo_attack.py --ip 192.0.2.55 --block
```

4. Inspect the UI at `http://127.0.0.1:9000/` (if frontend built) or run the dev server at `frontend/`.

Enabling real firewall enforcement
----------------------------------
By default the firewall module runs in dry-run mode to avoid accidental lockout. To enable system-level blocking:

1. Confirm you have console access to the Pi (serial/SSH) in case of misconfiguration.
2. Set environment variable: `export FIREWALL_DRY_RUN=0` before starting the backend (or add to systemd drop-in).
3. The system will attempt to use `nft` if available, otherwise fall back to `iptables`.

To roll back a block:

```bash
# remove block via API
curl -X POST http://127.0.0.1:9000/api/firewall/unblock -d '{"ip":"192.0.2.55"}' -H 'Content-Type: application/json'
```

Safety notes
------------
- Always test enforcement in a controlled environment before deploying to production.
- Keep `FIREWALL_DRY_RUN=1` until you have validated rule removal and recovery.
- Use systemd drop-ins to grant `CAP_NET_RAW` rather than running as root.
- Before enabling `FIREWALL_DRY_RUN=0`, install the rollback guard examples in `deploy/pi/sentinel-firewall-rollback-guard.*.example` and configure `/etc/sentinel/firewall-rollback.env`.
- Existing joblib model artifacts must be signed before production runtime. For local smoke tests with the current unsigned checked-in model, use `SENTINEL_ALLOW_UNSIGNED_MODELS=1`; do not use that override in production.

Install helper
----------------
I included a convenience installer that copies the service and drop-in into `/etc/systemd` and enables it:

```bash
sudo bash scripts/install_local_service.sh
```

Edit `deploy/pi/sentinel-local.service` to update paths or `REDACT_SALT` before running the installer.
