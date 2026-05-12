#!/usr/bin/env bash
set -euo pipefail

# Simple DB streaming smoke test helper.
# Inserts a marker alert into data/sentinel.db, verifies it appears, then cleans up.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="$ROOT/data/sentinel.db"

echo "Using DB: $DB_PATH"

python3 - <<'PY'
import time
from core.storage_sqlite import SQLiteStorage
import sys

db = SQLiteStorage(path='data/sentinel.db')
db.create_tables()
before = db.get_alerts(limit=1000)
count_before = len(before)
ts = int(time.time())
marker = f"db_smoke_test_marker_{ts}"
try:
    db.insert_alert(ts, '127.0.0.1', '127.0.0.1', 0, 0, 'tcp', 0.1, 0.5, marker)
    after = db.get_alerts(limit=1000)
    count_after = len(after)
    print(f"alerts before={count_before} after={count_after}")
    if count_after <= count_before:
        print('ERROR: insert did not increase alert count', file=sys.stderr)
        sys.exit(2)
    print('SUCCESS: DB write/read verified')
finally:
    # cleanup marker rows
    try:
        db.connect()
        cur = db.conn.cursor()
        cur.execute('DELETE FROM alerts WHERE details=?', (marker,))
        db.conn.commit()
    except Exception:
        pass

PY

echo "Done."
