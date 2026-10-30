"""Durable on-disk queue of flow records waiting to reach the brain.

The engine appends records; the uplink reads the oldest ones, sends them,
and deletes them only after the brain acknowledged them, so a brain outage
or a sensor restart loses nothing. When the buffer reaches its limit the
oldest records are dropped and counted.
"""
import json
import os
import sqlite3
import threading

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# ~1 GB at ~500 bytes a record; at 100 flows/s that is over 5 hours of outage
DEFAULT_MAX_RECORDS = 2_000_000


def default_path():
    return os.environ.get('SENTINEL_SENSOR_BUFFER') or os.path.join(ROOT, 'data', 'sensor_buffer.db')


class DiskBuffer:
    def __init__(self, path=None, max_records=None):
        self.path = path or default_path()
        self.max_records = int(max_records or os.environ.get('SENTINEL_SENSOR_BUFFER_MAX', DEFAULT_MAX_RECORDS))
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10, isolation_level=None)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY AUTOINCREMENT, record TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)')
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def put(self, records):
        """Append one record (dict) or a list of them."""
        if isinstance(records, dict):
            records = [records]
        rows = [(json.dumps(r, separators=(',', ':'), default=str),) for r in records]
        if not rows:
            return
        with self._lock:
            db = self._db()
            db.execute('BEGIN IMMEDIATE')
            try:
                db.executemany('INSERT INTO queue(record) VALUES (?)', rows)
                excess = db.execute('SELECT COUNT(*) FROM queue').fetchone()[0] - self.max_records
                if excess > 0:
                    db.execute('DELETE FROM queue WHERE id IN (SELECT id FROM queue ORDER BY id LIMIT ?)', (excess,))
                    db.execute("INSERT INTO meta(key, value) VALUES ('dropped', ?) "
                               "ON CONFLICT(key) DO UPDATE SET value = value + excluded.value", (excess,))
                db.execute('COMMIT')
            except Exception:
                db.execute('ROLLBACK')
                raise

    def peek(self, limit=500):
        """Oldest records as [(id, record)], without removing them."""
        with self._lock:
            rows = self._db().execute('SELECT id, record FROM queue ORDER BY id LIMIT ?', (int(limit),)).fetchall()
        return [(row[0], json.loads(row[1])) for row in rows]

    def ack(self, ids):
        """Remove records the brain has stored."""
        if not ids:
            return
        with self._lock:
            self._db().execute('DELETE FROM queue WHERE id <= ? AND id >= ?', (max(ids), min(ids)))

    def __len__(self):
        with self._lock:
            return self._db().execute('SELECT COUNT(*) FROM queue').fetchone()[0]

    def dropped(self):
        with self._lock:
            row = self._db().execute("SELECT value FROM meta WHERE key = 'dropped'").fetchone()
        return row[0] if row else 0
