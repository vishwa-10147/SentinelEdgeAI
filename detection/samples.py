"""A site's local training sample: feature vectors of flows that raised no finding (Phase 7).

Reservoir sampling keeps a fixed-size, uniformly random sample of everything
seen so far (data/samples.db, SENTINEL_SAMPLES_DB), so it represents weeks of
normal traffic rather than the last hour. Flows with findings are left out,
so attacks are not learned as normal. Used to train models locally for
federated learning; the samples never leave the site.
"""
import json
import os
import random
import sqlite3
import threading

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CAPACITY = 20000
BATCH = 200


def default_path():
    return os.environ.get('SENTINEL_SAMPLES_DB') or os.path.join(ROOT, 'data', 'samples.db')


class SampleStore:
    def __init__(self, path=None, capacity=CAPACITY, rng=None):
        self.path = path or default_path()
        self.capacity = capacity
        self.rng = rng or random.Random()  # nosec B311 - sampling, not security
        self._lock = threading.Lock()
        self._conn = None
        self._seen = None
        self._size = None
        self._pending = []

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.execute('CREATE TABLE IF NOT EXISTS samples (slot INTEGER PRIMARY KEY, features TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)')
            conn.commit()
            row = conn.execute("SELECT v FROM meta WHERE k = 'seen'").fetchone()
            self._seen = row[0] if row else 0
            self._size = conn.execute('SELECT COUNT(*) FROM samples').fetchone()[0]
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            self._flush()
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def observe(self, features):
        """Offer one flow's features (a dict of numbers)."""
        if not features:
            return
        with self._lock:
            self._db()
            self._seen += 1
            if self._size < self.capacity:
                slot = self._size
                self._size += 1
            else:
                slot = self.rng.randrange(self._seen)
                if slot >= self.capacity:
                    return
            self._pending.append((slot, json.dumps(features, separators=(',', ':'))))
            if len(self._pending) >= BATCH:
                self._flush()

    def _flush(self):
        if not self._pending or self._conn is None:
            return
        self._conn.executemany('INSERT OR REPLACE INTO samples VALUES (?, ?)', self._pending)
        self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('seen', ?)", (self._seen,))
        self._conn.commit()
        self._pending = []

    def flush(self):
        with self._lock:
            self._flush()

    def rows(self, limit=None):
        with self._lock:
            self._flush()
            sql = 'SELECT features FROM samples' + (' LIMIT ?' if limit else '')  # nosec B608 - constant, parameterised
            return [json.loads(r[0]) for r in self._db().execute(sql, (int(limit),) if limit else ()).fetchall()]

    def stats(self):
        with self._lock:
            self._db()
            return {'samples': self._size, 'seen': self._seen, 'capacity': self.capacity}
