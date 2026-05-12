#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON=${PYTHON:-python3}

echo "Starting FastAPI server (uvicorn) on 127.0.0.1:9000"
env ENABLE_FILE_FALLBACK=0 DISABLE_DB_MAINTENANCE=1 $PYTHON -m uvicorn dashboard.dashboard_api:app --host 127.0.0.1 --port 9000 --log-level warning &
UVICORN_PID=$!
trap 'echo "Cleaning up..."; kill $UVICORN_PID 2>/dev/null || true' EXIT

echo "Waiting for server to become responsive..."
for i in {1..12}; do
  if curl -sS http://127.0.0.1:9000/api/health >/dev/null 2>&1; then
    echo "server up"
    break
  fi
  sleep 1
done

if ! curl -sS http://127.0.0.1:9000/api/health >/dev/null 2>&1; then
  echo "Server did not become ready" >&2
  kill $UVICORN_PID 2>/dev/null || true
  exit 2
fi

echo "Ensuring websockets package is available"
$PYTHON - <<'PY'
import importlib, sys, subprocess
try:
    importlib.import_module('websockets')
except Exception:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'websockets'])
print('websockets ok')
PY

echo "Running websocket listener and DB marker insertion"
$PYTHON - <<'PY'
import asyncio, json, time
from core.storage_sqlite import SQLiteStorage
import websockets

db = SQLiteStorage(path='data/sentinel.db')
db.create_tables()
ts = int(time.time())
marker = f"ws_smoke_test_marker_{ts}"
try:
    # insert marker alert
    db.insert_alert(ts, '127.0.0.1', '127.0.0.1', 0, 0, 'tcp', 0.1, 0.5, marker)

    async def listen():
        uri = 'ws://127.0.0.1:9000/ws/packets'
        try:
            async with websockets.connect(uri, open_timeout=5) as ws:
                deadline = time.time() + 12
                while time.time() < deadline:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                    try:
                        obj = json.loads(msg)
                    except Exception:
                        continue
                    # look for alert payload with our marker in details
                    if obj.get('type') == 'alert':
                        payload = obj.get('payload', {})
                        details = payload.get('details') if isinstance(payload, dict) else None
                        if details and marker in str(details):
                            print('SUCCESS: websocket received marker alert')
                            return 0
        except Exception as e:
            print('WebSocket error:', e)
            return 2
        print('Timed out waiting for websocket message')
        return 3

    rc = asyncio.get_event_loop().run_until_complete(listen())
    raise SystemExit(rc)
finally:
    try:
        db.connect()
        cur = db.conn.cursor()
        cur.execute('DELETE FROM alerts WHERE details=?', (marker,))
        db.conn.commit()
    except Exception:
        pass

PY

echo "Done websocket smoke check"
