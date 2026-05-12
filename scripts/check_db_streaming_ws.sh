#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# prefer repo venv if present
if [ -x "$ROOT/venv/bin/python" ]; then
    PYTHON="$ROOT/venv/bin/python"
else
    PYTHON=${PYTHON:-python3}
fi

echo "Starting FastAPI server (uvicorn) on 127.0.0.1:9000"
# Start uvicorn only if the server port is not already in use
UVICORN_PID=0
if ! curl -sS http://127.0.0.1:9000/api/health >/dev/null 2>&1; then
    env ENABLE_FILE_FALLBACK=0 DISABLE_DB_MAINTENANCE=1 $PYTHON -m uvicorn dashboard.dashboard_api:app --host 127.0.0.1 --port 9000 --log-level warning &
    UVICORN_PID=$!
    trap 'echo "Cleaning up..."; if [ "$UVICORN_PID" -ne 0 ]; then kill $UVICORN_PID 2>/dev/null || true; fi' EXIT

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
        if [ "$UVICORN_PID" -ne 0 ]; then kill $UVICORN_PID 2>/dev/null || true; fi
        exit 2
    fi
else
    echo "Using existing server on 127.0.0.1:9000"
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
# use a slightly-future timestamp to ensure server sees it as new
ts = int(time.time()) + 60
marker = f"ws_smoke_test_marker_{ts}"
try:
    # insert marker alert
    db.insert_alert(ts, '127.0.0.1', '127.0.0.1', 0, 0, 'tcp', 0.1, 0.5, marker)

    async def listen():
        uri = 'ws://127.0.0.1:9000/ws/packets'
        try:
            async with websockets.connect(uri, open_timeout=5) as ws:
                # wait for any message (alert/flow/event) to confirm websocket is delivering
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=12)
                    print('SUCCESS: websocket delivered a message')
                    return 0
                except Exception as e:
                    print('Timed out waiting for any websocket message', repr(e))
                    return 3
        except Exception as e:
            import traceback
            traceback.print_exc()
            print('WebSocket error:', repr(e))
            return 2

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
