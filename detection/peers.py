"""Learned peer profiles: who each device normally talks to (Phase 7, zero-trust).

For every internal IPv4 device the engine records the (peer, protocol, port)
it opens connections to. Internal peers are kept exactly; destinations on the
internet are kept as (protocol, port) only, so browsing does not fill the
table. Profiles are capped per device. The containment response
(core.firewall 'contain') restricts an untrusted device to this profile.
"""
import ipaddress
import os
import sqlite3
import threading
import time
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
EXTERNAL = '*'
MAX_INTERNAL = 256
MAX_EXTERNAL = 128
MAX_HOSTS = 20000                                         # devices with a profile (flood safety)
TOUCH_SECONDS = 300
LEARNING = 7 * 86400


def default_path():
    return os.environ.get('SENTINEL_PEERS_DB') or os.path.join(ROOT, 'data', 'peers.db')


def _private4(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4:
        return None
    return a.is_private or a.is_link_local or a in ipaddress.ip_network('100.64.0.0/10')


class PeerStore:
    def __init__(self, path=None):
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None
        self._written = {}
        self._counts = None                               # src -> [internal, external]
        self._hosts = None                                # number of devices with a profile

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.execute("""CREATE TABLE IF NOT EXISTS peers (
                src TEXT NOT NULL, dst TEXT NOT NULL, proto TEXT NOT NULL, dport INTEGER NOT NULL,
                first_seen REAL NOT NULL, last_seen REAL NOT NULL, PRIMARY KEY (src, dst, proto, dport))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS peer_hosts (
                src TEXT PRIMARY KEY, first_seen REAL NOT NULL)""")
            conn.commit()
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _load_counts(self, db):
        counts = defaultdict(lambda: [0, 0])
        for src, external, n in db.execute(
                "SELECT src, dst = ?, COUNT(*) FROM peers GROUP BY src, dst = ?", (EXTERNAL, EXTERNAL)):
            counts[src][1 if external else 0] = n
        return counts

    def observe(self, record):
        """Record one finished flow (a common.protocol.flow_record dict)."""
        src, dst = record.get('src'), record.get('dst')
        proto = str(record.get('proto') or '').lower()
        dport = int(record.get('dport') or 0)
        if proto not in ('tcp', 'udp') or not dport or not _private4(src):
            return
        internal = _private4(dst)
        if internal is None:
            return
        dst = dst if internal else EXTERNAL
        ts = record.get('ts') or time.time()
        key = (src, dst, proto, dport)
        if ts - self._written.get(key, -1e18) < TOUCH_SECONDS:
            return
        with self._lock:
            db = self._db()
            if self._counts is None:
                self._counts = self._load_counts(db)
            known = key in self._written or db.execute(
                'SELECT 1 FROM peers WHERE src=? AND dst=? AND proto=? AND dport=?', key).fetchone()
            if not known:
                if src not in self._counts:
                    if self._hosts is None:
                        self._hosts = db.execute('SELECT COUNT(*) FROM peer_hosts').fetchone()[0]
                    if self._hosts >= MAX_HOSTS:
                        return                            # a flood of spoofed sources: no new profiles
                    self._hosts += 1
                n = self._counts[src]
                if n[0 if internal else 1] >= (MAX_INTERNAL if internal else MAX_EXTERNAL):
                    return
                n[0 if internal else 1] += 1
            db.execute('INSERT OR IGNORE INTO peer_hosts VALUES (?, ?)', (src, ts))
            db.execute('INSERT INTO peers VALUES (?,?,?,?,?,?) ON CONFLICT DO UPDATE SET last_seen = ?',
                       (*key, ts, ts, ts))
            db.commit()
            self._written[key] = ts

    def profile(self, src):
        """{'first_seen', 'internal': [(dst, proto, port)], 'external': [(proto, port)]} or None."""
        with self._lock:
            db = self._db()
            row = db.execute('SELECT first_seen FROM peer_hosts WHERE src = ?', (src,)).fetchone()
            if not row:
                return None
            rows = db.execute('SELECT dst, proto, dport FROM peers WHERE src = ? ORDER BY dst, proto, dport',
                              (src,)).fetchall()
        return {'first_seen': row[0],
                'internal': [(d, p, n) for d, p, n in rows if d != EXTERNAL],
                'external': [(p, n) for d, p, n in rows if d == EXTERNAL]}

    def first_seen(self):
        with self._lock:
            return dict(self._db().execute('SELECT src, first_seen FROM peer_hosts').fetchall())


def learned(profile, now=None, learning=LEARNING):
    return bool(profile) and (now or time.time()) - profile['first_seen'] >= learning \
        and bool(profile['internal'] or profile['external'])
