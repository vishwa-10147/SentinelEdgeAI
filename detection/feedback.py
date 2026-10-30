"""Analyst feedback: alerts marked true or false positive.

The labels recalibrate each detector's probability (a Bayesian update of its
prior precision), which feeds fusion's confidence and therefore whether a
detection is confirmed for automatic response. False-positive flows can be
exported as extra 'normal' examples for retraining the autoencoder.
"""
import json
import os
import sqlite3
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PRIOR_WEIGHT = 10     # the prior counts as this many labelled alerts


def default_path():
    return os.environ.get('SENTINEL_FEEDBACK_DB') or os.path.join(ROOT, 'data', 'feedback.db')


class FeedbackStore:
    def __init__(self, path=None):
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("""CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL,
                src TEXT, label TEXT NOT NULL, alert TEXT, by TEXT, note TEXT)""")
            conn.commit()
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def add(self, kind, label, src=None, alert=None, by=None, note=''):
        if label not in ('tp', 'fp'):
            raise ValueError("label must be 'tp' (true positive) or 'fp' (false positive)")
        if not kind:
            raise ValueError('the alert has no attack type to attribute the feedback to')
        with self._lock:
            db = self._db()
            cur = db.execute('INSERT INTO feedback(ts, kind, src, label, alert, by, note) VALUES (?,?,?,?,?,?,?)',
                             (int(time.time()), str(kind)[:64], src, label,
                              json.dumps(alert, default=str)[:8192] if alert else None, by, str(note)[:500]))
            db.commit()
            return cur.lastrowid

    def counts(self):
        """{kind: {'tp': n, 'fp': n}}"""
        with self._lock:
            rows = self._db().execute('SELECT kind, label, COUNT(*) AS n FROM feedback GROUP BY kind, label').fetchall()
        out = {}
        for r in rows:
            out.setdefault(r['kind'], {'tp': 0, 'fp': 0})[r['label']] = r['n']
        return out

    def calibrated(self, kind, prior):
        c = self.counts().get(kind)
        if not c:
            return prior
        return (c['tp'] + prior * PRIOR_WEIGHT) / (c['tp'] + c['fp'] + PRIOR_WEIGHT)

    def summary(self):
        out = []
        for kind, c in sorted(self.counts().items()):
            total = c['tp'] + c['fp']
            out.append({'kind': kind, 'true_positives': c['tp'], 'false_positives': c['fp'],
                        'precision': round(c['tp'] / total, 3) if total else None})
        return out

    def false_positive_alerts(self, limit=10000):
        with self._lock:
            rows = self._db().execute("SELECT alert FROM feedback WHERE label = 'fp' AND alert IS NOT NULL "
                                      "ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [json.loads(r['alert']) for r in rows]


_store = None


def get_store():
    global _store
    if _store is None or _store.path != default_path():
        _store = FeedbackStore()
    return _store
